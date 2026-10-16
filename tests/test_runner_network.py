"""Network provenance and destination counterexamples, without Docker."""

import json
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
from fmst_analyzer.runner.schema import InteractionProbe, RuntimeNetwork


def network(**changes):
    return RuntimeNetwork(**{
        "subnet": "192.168.7.0/24", "gateway": "192.168.7.254",
        "target_address": "192.168.7.1", "probe_destination": "interface", **changes})


def sandbox(tmp_path, config=None):
    return DockerRootfsSandbox(rootfs=tmp_path, workdir=tmp_path, target_binary="fixture",
        executable_path="/guest", guest_arch="arm", runtime_workspace=tmp_path,
        env_script=None, network=config)


@pytest.mark.parametrize("changes", [
    {"gateway": None}, {"subnet": "192.168.7.1/24"}, {"target_address": "192.168.8.1"},
    {"target_address": "192.168.7.0"}, {"target_address": "192.168.7.255"},
    {"gateway": "192.168.7.1"}, {"subnet": "::/64"}, {"probe_destination": "host"},
    {"subnet": "127.0.0.0/8", "gateway": "127.0.0.2", "target_address": "127.0.0.1"},
])
def test_rejects_incoherent_network(changes):
    with pytest.raises(ValidationError):
        network(**changes)


def test_reconfiguration_is_owned_and_fails_with_live_container(tmp_path, monkeypatch):
    box = sandbox(tmp_path)
    calls = []
    live = []
    def docker(*args):
        calls.append(args)
        return SimpleNamespace(stdout="\n".join(live) if args[0] == "ps" else "")
    monkeypatch.setattr(box, "_docker", docker)
    box._ensure_network()
    box._prepared = True
    live.append("owned-container")
    with pytest.raises(RuntimeError, match="container still exists"):
        box.configure_network(network())
    assert box.network == RuntimeNetwork()
    assert not any(call[:2] == ("network", "rm") for call in calls)
    live.clear()
    box.configure_network(network())
    assert ("network", "rm", box.network_name) in calls
    creation = calls[-1]
    assert creation[:3] == ("network", "create", "--internal")
    assert creation[creation.index("--subnet") + 1] == "192.168.7.0/24"
    assert creation[creation.index("--gateway") + 1] == "192.168.7.254"
    assert f"fmst.runner.session={box.session_id}" in creation
    assert box.cleanup_records[-1]["removed"]
    count = len(calls)
    box.configure_network(network())
    assert len(calls) == count


def test_failed_network_creation_can_retry_without_stale_success(tmp_path, monkeypatch):
    box = sandbox(tmp_path)
    box._prepared = True
    def fail(*args):
        raise subprocess.CalledProcessError(1, args, stderr="overlapping subnet")
    monkeypatch.setattr(box, "_docker", fail)
    with pytest.raises(subprocess.CalledProcessError):
        box.configure_network(network())
    assert not box._network_created
    monkeypatch.setattr(box, "_docker", lambda *args: SimpleNamespace(stdout="network-id"))
    box.configure_network(network())
    assert box._network_created


@pytest.mark.parametrize("route,address,expected", [
    ("auto", "192.168.7.1", "127.0.0.1"),
    ("loopback", None, "127.0.0.1"),
    ("interface", "192.168.7.1", "192.168.7.1"),
    ("interface", None, None), ("interface", "127.0.0.1", None),
    ("interface", "192.168.7.2", None),
])
@pytest.mark.parametrize("response", [b"HTTP/1.0 401 Unauthorized\r\nContent-Length: 0\r\n\r\n", b""])
def test_probe_destination_never_silently_changes_origin(tmp_path, monkeypatch, route, address, expected, response):
    box = sandbox(tmp_path, network(probe_destination=route))
    def inspect(*args, **kwargs):
        assert route != "loopback", "explicit loopback needs no interface lookup"
        return address
    monkeypatch.setattr(box, "_container_ip", inspect)
    calls = []
    def request(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, response, b"")
    monkeypatch.setattr(box, "_process", request)
    received = []
    watch = SimpleNamespace(interrupted=threading.Event(), stall_seconds=30, probe_attempted=lambda: None,
                            response_received=lambda: received.append(True))
    ledger = tmp_path / "probe-connections.jsonl"
    result = box._run_tcp_probe_in_container("owned", InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n"),
        deadline=time.monotonic() + 10, observer=watch, connection_record_path=ledger, step_index=1)
    if expected is None:
        assert result.attempts == 0 and not result.connected and result.error
        assert not calls and not ledger.exists()
    else:
        assert result.status_code == (401 if response else None) and len(calls) == 1
        records = [json.loads(line) for line in ledger.read_text().splitlines()]
        assert {record["destination_host"] for record in records} == {expected}
        assert expected in calls[0]
        assert (tmp_path / "step-01-response.bin").read_bytes() == response
        assert bool(received) == bool(response)
