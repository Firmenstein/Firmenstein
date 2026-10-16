"""Partial execution records survive startup, collection and budget failures."""

import json
import subprocess
from types import SimpleNamespace

import pytest

import fmst_analyzer.runner.docker_sandbox as sandbox_module
from fmst_analyzer.runner.budget import RunnerStopped
from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
from fmst_analyzer.runner.schema import InteractionProbe


@pytest.mark.parametrize("guest_environment", [{}, {"LD_LIBRARY_PATH": "/lib:/usr/lib"}])
@pytest.mark.parametrize("startup_failure,collector_failure", [(False, False), (True, False), (False, True)])
def test_partial_attempt_retains_trace_and_attempts_owned_cleanup(tmp_path, monkeypatch, startup_failure, collector_failure, guest_environment):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    sandbox = DockerRootfsSandbox(rootfs=rootfs, workdir=tmp_path, target_binary="guest",
        executable_path="/guest", guest_arch="arm", runtime_workspace=tmp_path / "runtime", env_script=None)
    sandbox._prepared = True
    sandbox._active_rootfs = rootfs
    sandbox.bundle_dir.mkdir(parents=True)
    commands = []

    class Observer:
        triggered = False
        def __init__(self, **kwargs): pass
        def start(self): pass
        def begin_step(self, index): pass
        def stop(self, reason): pass
        def join(self): pass

    monkeypatch.setattr(sandbox_module, "TargetProgressWatchdog", Observer)

    def process(command, **kwargs):
        commands.append(command)
        if command[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(command, 1 if startup_failure else 0, "", "controlled start failure" if startup_failure else "")
        if command[:2] == ["docker", "logs"]:
            if collector_failure:
                raise subprocess.TimeoutExpired(command, 10)
            kwargs["stdout"].write(b"partial logs retained\n")
        return subprocess.CompletedProcess(command, 0, "", "")

    def probe(*args, **kwargs):
        (sandbox.output_root / "attempt-01/runtime_trace.json").write_text('{"partial": true}')
        raise RunnerStopped("session_budget_exhausted")

    monkeypatch.setattr(sandbox, "_process", process)
    monkeypatch.setattr(sandbox, "_run_tcp_probe_in_container", probe)
    with pytest.raises(RuntimeError if startup_failure else RunnerStopped):
        sandbox.run_attempt(attempt_number=1, intervention_so=None, executable_path="/guest",
            guest_args=[], guest_working_directory="/", guest_environment=guest_environment, companion_processes=[],
            probe=InteractionProbe(port=80, request_text="request"), timeout_seconds=20)
    launch = next(command for command in commands if command[:2] == ["docker", "run"])
    loader_environment = [launch[index + 1] for index, value in enumerate(launch[:-1])
                          if value == "--env" and launch[index + 1].startswith("LD_LIBRARY_PATH=")]
    assert loader_environment == (["LD_LIBRARY_PATH=" + guest_environment["LD_LIBRARY_PATH"]]
                                  if "LD_LIBRARY_PATH" in guest_environment else [])
    receipt_path = sandbox.session_root / "attempt_receipts/attempt-01.json"
    receipt = json.loads(receipt_path.read_text())
    assert receipt["state"] == ("error" if startup_failure else "interrupted")
    assert receipt["stop_reason"] == ("RuntimeError" if startup_failure else "session_budget_exhausted")
    assert receipt["finished_unix_ns"] is not None
    assert receipt["cleanup"]["remove_returncode"] == 0
    assert "logs_error" in receipt["cleanup"] if collector_failure else receipt["cleanup"]["logs_returncode"] == 0
    assert commands[-1] == ["docker", "rm", "--force", receipt["container_name"]]
    assert receipt_path.parent != sandbox.output_root / "attempt-01"
    if not startup_failure:
        assert (sandbox.output_root / "attempt-01/runtime_trace.json").is_file()
        assert (sandbox.output_root / "attempt-01/runtime-dump/manifest.json").is_file()
