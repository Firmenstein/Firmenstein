import json
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner import peer_readiness as gate
from fmst_analyzer.runner.budget import RunnerStopped
from fmst_analyzer.runner.docker_sandbox import _render_companion_supervisor
from fmst_analyzer.runner.schema import CompanionProcess, PeerReadiness


HEADER = "Num RefCount Protocol Flags Type St Inode Path\n"


def peer(timeout=1):
    return CompanionProcess(executable_path="/peer", evidence_ref="fixture",
        readiness=PeerReadiness(unix_socket="/run/peer.sock", timeout_seconds=timeout))


def test_endpoint_must_be_listening_not_merely_present_or_bound():
    assert gate.unix_listeners(HEADER + "000: 2 0 00000000 0001 01 111 /run/peer.sock\n", "/run/peer.sock") == []
    assert gate.unix_listeners(HEADER + "000: 2 0 00010000 0002 01 111 /run/peer.sock\n", "/run/peer.sock") == []
    assert gate.unix_listeners(HEADER + "000: 2 0 00010000 0001 01 111 /run/other.sock\n", "/run/peer.sock") == []
    assert gate.unix_listeners(HEADER + "000: 2 0 00010000 0001 01 111 /run/peer.sock\n", "/run/peer.sock") == ["111"]
    with pytest.raises(RuntimeError):
        gate.unix_listeners("garbled observation", "/run/peer.sock")


@pytest.fixture
def clocked(tmp_path, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(gate.time, "monotonic", lambda: now[0])
    event = SimpleNamespace(is_set=lambda: False, wait=lambda seconds: now.__setitem__(0, now[0] + seconds))
    observer = SimpleNamespace(interrupted=event, observation_error=None, termination_reason="peer_exit",
        last_sample_monotonic=0.0, last_processes=[dict(role="peer-01", pid=4, state="S", started="identity")])
    args = dict(companions=[peer()], observer=observer, deadline=5,
        evidence_path=tmp_path / "readiness.json", check_budget=lambda: None)
    return now, observer, args


def test_slow_peer_is_waited_for_before_release(clocked):
    now, observer, args = clocked
    gate.wait_for_peers(**args, observe_endpoint=lambda p: ["111"] if now[0] >= 0.3 else [])
    assert 0.3 <= now[0] < 1
    assert json.loads(args['evidence_path'].read_text())["state"] == "ready"


@pytest.mark.parametrize("fault", ["dead", "unobserved", "expired", "no_listener", "exit", "cancel"])
def test_failed_or_stale_observation_never_releases_target(clocked, fault):
    now, observer, args = clocked
    if fault == "dead": observer.last_processes[0]['state'] = 'Z'
    if fault == "unobserved": observer.observation_error = 'lost Docker observation'
    if fault == "expired": observer.last_sample_monotonic = -10
    if fault == "exit": observer.interrupted.is_set = lambda: True
    if fault == "cancel":
        def cancel(): raise RunnerStopped("user_cancelled")
        args['check_budget'] = cancel
    with pytest.raises((RuntimeError, RunnerStopped)):
        gate.wait_for_peers(**args, observe_endpoint=lambda p: [] if fault == "no_listener" else ["111"])
    assert json.loads(args['evidence_path'].read_text())["state"] == "failed"


def test_gate_is_opt_in_and_precedes_target_exec():
    script = _render_companion_supervisor(harness_name="harness", companion_processes=[peer()], target_arguments=["/target"])
    assert script.index("target-ready") < script.index("/fmst-host/lib /target")
    plain = peer().model_copy(update={"readiness": None})
    assert "target-ready" not in _render_companion_supervisor(harness_name="harness", companion_processes=[plain], target_arguments=["/target"])
