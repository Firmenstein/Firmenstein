"""Portable inputs and service lifecycle counterexamples, without Docker."""
import json
import subprocess
import tomllib
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner import docker_sandbox as sandbox_module
from fmst_analyzer.runner import delivery
from fmst_analyzer.runner.delivery import _inventory, _rewrite_api, _operation_lock, run_service
from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
from fmst_analyzer.runner.probe import build_probe_result
from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario
from fmst_analyzer.runner.supervision import TargetProgressWatchdog


@pytest.mark.parametrize("daemon_available", [True, False])
def test_image_load_requires_live_daemon_and_rechecks_exact_identity(tmp_path, monkeypatch, daemon_available):
    commands = []
    package = SimpleNamespace(builder_image_id="exact-image", builder_archive="builder.tar")
    def process(command, **kwargs):
        commands.append(command)
        if len(commands) == 1 or (command[:2] == ["docker", "info"] and not daemon_available):
            raise subprocess.CalledProcessError(1, command, stderr="unavailable")
        return subprocess.CompletedProcess(command, 0, json.dumps([{"Id":"exact-image", "Architecture":"amd64"}]))
    monkeypatch.setattr(delivery, "_process", process)
    if daemon_available:
        delivery._ensure_image(tmp_path, package)
        assert commands[2] == ["docker", "load", "--input", str(tmp_path / "builder.tar")]
        assert commands[3] == commands[0]
    else:
        with pytest.raises(subprocess.CalledProcessError):
            delivery._ensure_image(tmp_path, package)
        assert len(commands) == 2


@pytest.mark.parametrize("build_returncode,cleanup", [
    (0, subprocess.CompletedProcess([], 1, "", "removal failed")),
    (0, subprocess.TimeoutExpired("docker rm", 10)),
    (1, subprocess.TimeoutExpired("docker rm", 10)),
])
def test_incomplete_build_keeps_previous_pointer_and_both_errors(tmp_path, monkeypatch, build_returncode, cleanup):
    (tmp_path / "state").mkdir()
    pointer = tmp_path / "state/current-build.json"
    pointer.write_text('{"build_id":"previous"}')
    package = SimpleNamespace(package_id="package", host_platform="linux/amd64", builder_image_id="image")
    monkeypatch.setattr(delivery, "_ensure_image", lambda *args: None)

    def build(command, **kwargs):
        output = next((tmp_path / "state/builds").iterdir())
        (output / "runtime").mkdir()
        (output / "build-complete.json").write_text('{}')
        return subprocess.CompletedProcess(command, build_returncode)

    def remove(command, **kwargs):
        assert pointer.read_text() == '{"build_id":"previous"}'
        if isinstance(cleanup, BaseException):
            raise cleanup
        return cleanup

    monkeypatch.setattr(delivery, "run_process", build)
    monkeypatch.setattr(delivery.subprocess, "run", remove)
    with pytest.raises(RuntimeError, match="source build failed" if build_returncode else "cleanup incomplete"):
        delivery.build_package(tmp_path, package)
    assert pointer.read_text() == '{"build_id":"previous"}'
    receipt = json.loads(next((tmp_path / "state/builds").glob('*/receipt.json')).read_text())
    assert receipt["state"] == "failed"
    assert receipt["returncode"] == build_returncode
    assert receipt["cleanup"].get("error") or receipt["cleanup"]["returncode"] != 0
    if build_returncode:
        assert "source build failed" in receipt["error"]


@pytest.mark.parametrize("log_error", [subprocess.TimeoutExpired("docker logs", 10, output=b"partial log"), OSError("collector unavailable")])
def test_down_stops_even_when_log_collection_fails(tmp_path, monkeypatch, log_error):
    workdir = tmp_path / "state/services/service"
    workdir.mkdir(parents=True)
    session = "a" * 12
    path = tmp_path / "state/service.json"
    path.write_text(json.dumps(dict(package_id="package", sandbox_session_id=session,
        workdir=str(workdir), session_root=str(workdir / "runner_sessions/guest" / session),
        container_name="container")))
    closed = []

    class Sandbox:
        target_slug = "guest"
        def __init__(self, **kwargs):
            self.cleanup_records = []
            self.runtime_builder = SimpleNamespace(handoff_output=lambda *args, **kwargs: None)
        def close(self):
            closed.append(True)
            self.cleanup_records.append({"container": "container", "returncode": 0})

    monkeypatch.setattr(delivery, "DockerRootfsSandbox", Sandbox)
    monkeypatch.setattr(delivery, "DockerRuntimeBuilder", lambda **kwargs: None)
    monkeypatch.setattr(delivery, "load_model_json", lambda *args: SimpleNamespace(executable_path="/guest"))
    def logs(*args, **kwargs):
        raise log_error
    monkeypatch.setattr(delivery.subprocess, "run", logs)
    package = SimpleNamespace(package_id="package", target_binary="guest", guest_arch="arm",
        builder_image_id="image", host_platform="linux/amd64")
    record = delivery.down_service(tmp_path, package)
    assert closed == [True]
    assert record["state"] == "stopped" and not path.exists()
    assert type(log_error).__name__ in record["log_collection"]["error"]
    assert json.loads((workdir / "stopped.json").read_text())["log_collection"] == record["log_collection"]
    if isinstance(log_error, subprocess.TimeoutExpired):
        assert (workdir / "service.log").read_bytes() == b"partial log"


def test_package_inventory_keeps_links_and_rejects_changed_input(tmp_path):
    root = tmp_path / "package"
    root.mkdir()
    (root / "file").write_bytes(b"original")
    (root / "guest-link").symlink_to("/absent/guest/path")
    first = _inventory(root)
    (root / "state").mkdir()
    (root / "state/receipt.json").write_text("state changes are separate")
    assert _inventory(root) == first
    assert first["guest-link"] == {"link": "/absent/guest/path"}
    (root / "file").write_bytes(b"changed")
    assert _inventory(root) != first


def test_relative_api_binding_changes_only_derived_dependency(tmp_path):
    root = tmp_path / "authored"
    crate = root / "interventions/service"
    crate.mkdir(parents=True)
    framework = tmp_path / "GuestWeave"
    path = crate / "Cargo.toml"
    original = '[package]\nname="fixture"\nversion="0.1.0"\n[dependencies]\nfmst-iib-api = { path = "/old/checkout/api", features = ["mock"] }\nlog="0.4"\n'
    path.write_text(original)
    before = tomllib.loads(original)
    records = _rewrite_api(root, framework)
    actual = tomllib.loads(path.read_text())
    before["dependencies"]["fmst-iib-api"]["path"] = "../../../GuestWeave/fmst-iib-api"
    assert actual == before
    assert len(records) == 1
    assert _rewrite_api(root, framework) == []


def test_package_operations_reject_overlapping_writers_and_release_lock(tmp_path):
    with _operation_lock(tmp_path):
        with pytest.raises(ValueError, match="another operation"):
            with _operation_lock(tmp_path):
                pytest.fail("a second writer entered")
    with _operation_lock(tmp_path):
        assert (tmp_path / "state/operation.lock").is_file()


def test_fixed_subnet_verification_refuses_to_start_over_active_service(tmp_path):
    (tmp_path / "state").mkdir()
    (tmp_path / "state/service.json").write_text("active service")
    original = SimpleNamespace(attempt=SimpleNamespace(network=SimpleNamespace(subnet="192.168.0.0/24")))
    with pytest.raises(ValueError, match="run down before verify"):
        run_service(tmp_path, None, original)


@pytest.mark.parametrize("expose", [False, True])
def test_only_explicit_service_network_can_publish_localhost(tmp_path, monkeypatch, expose):
    box = DockerRootfsSandbox(rootfs=tmp_path, workdir=tmp_path, target_binary="guest",
        executable_path="/guest", guest_arch="arm", runtime_workspace=tmp_path, env_script=None,
        expose_service=expose)
    commands = []
    monkeypatch.setattr(box, "_docker", lambda *args: commands.append(args))
    box._ensure_network()
    assert ("--internal" in commands[0]) == (not expose)


@pytest.mark.parametrize("success,child_failure", [(True, False), (False, False), (True, True)])
def test_scenario_instance_always_cleans_even_when_it_passes(tmp_path, monkeypatch, success, child_failure):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    box = DockerRootfsSandbox(rootfs=rootfs, workdir=tmp_path, target_binary="guest",
        executable_path="/guest", guest_arch="arm", runtime_workspace=tmp_path / "runtime", env_script=None,
        expose_service=True)
    box._prepared, box._active_rootfs = True, rootfs
    box.bundle_dir.mkdir(parents=True)
    monkeypatch.setattr(TargetProgressWatchdog, "start", lambda watch: None)
    monkeypatch.setattr(TargetProgressWatchdog, "_read_processes", lambda watch: [])
    commands = []

    def command(argv, **kwargs):
        commands.append(argv)
        return subprocess.CompletedProcess(argv, 0, "true 0" if argv[:2] == ["docker", "inspect"] else "", "")

    monkeypatch.setattr(box, "_process", command)
    probe = InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n")

    def response(container, item, *, observer, **kwargs):
        observer.response_received()
        wire = b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\ngood" if success else b"HTTP/1.0 403 Denied\r\nContent-Length: 3\r\n\r\nbad"
        return build_probe_result(item, connected=True, response=wire, attempts=1)

    monkeypatch.setattr(box, "_run_tcp_probe_in_container", response)
    if child_failure:
        def assess(**kwargs):
            kwargs["scenario_result"].status = "blocked"
            return {"status": "failed", "failures": ["associated child failed"]}
        monkeypatch.setattr(sandbox_module, "assess_child_failures", assess)
    scenario = InteractionScenario(protocol="http", port=80, evidence_refs=["fixture"], steps=[dict(request_text=probe.request_text, expected_status_code=200)])
    result = box.run_attempt(attempt_number=1, intervention_so=None, executable_path="/guest",
        guest_args=[], guest_working_directory="/", guest_environment={}, companion_processes=[],
        probe=probe, scenario=scenario, timeout_seconds=20)
    assert (result.scenario_result.status == "success") == (success and not child_failure)
    removals = [c for c in commands if c[:3] == ["docker", "rm", "--force"]]
    assert len(removals) == 1
    run = next(c for c in commands if c[:2] == ["docker", "run"])
    assert "--publish" not in run
