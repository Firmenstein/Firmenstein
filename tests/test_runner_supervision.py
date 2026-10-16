"""Process/probe counterexamples; no Docker, ELF or wall-clock sleeps in g0."""

import json
import os
import subprocess
import sys
import time

import pytest
from pydantic import ValidationError

from fmst_analyzer.runner import docker_sandbox as sandbox_module
from fmst_analyzer.runner import supervision
from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped
from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
from fmst_analyzer.runner.schema import (
    InteractionProbe, InteractionScenario, InteractionStep, ObservationAssertion,
    ProbeResult, RehostingResult, RuntimeNetwork,
)
from fmst_analyzer.runner.supervision import TargetProgressWatchdog, parse_process_table


def process(pid=2, ppid=1, role="target", state="S", started="Mon Sep 21 00:00:00 2026"):
    trace = "runtime_trace.json" if role == "target" else f"runtime_trace.{role}.json"
    return dict(pid=pid, ppid=ppid, state=state, started=started,
                command=f"/fmst-host/fmst-harness-arm --trace-output /fmst-output/{trace} --")


def observer(tmp_path, **kwargs):
    return TargetProgressWatchdog(container_name="owned", attempt_dir=tmp_path,
                                  stall_seconds=60, **kwargs)


def run_samples(monkeypatch, watch, samples, *, seconds=1):
    """Drive the real observer loop with deterministic process tables/time."""
    tables = iter(samples)
    ticks = iter(range(1000))
    monkeypatch.setattr(supervision.time, "monotonic", lambda: next(ticks) * seconds)
    monkeypatch.setattr(watch._stop, "wait", lambda _: False)

    def read():
        try:
            value = next(tables)
        except StopIteration:
            watch.stop("test_finished")
            return watch.last_processes
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(watch, "_read_processes", read)
    watch._run()
    return json.loads(watch.path.read_text())


def test_parse_docker_table_keeps_pid_start_identity_and_command():
    table = "PID PPID STAT STARTED COMMAND\n42 1 Sl Mon Sep 21 09:00:01 2026 /harness --binary /httpd\n"
    parsed = parse_process_table(table)
    assert parsed[0]["pid"] == 42
    assert parsed[0]["started"] == "Mon Sep 21 09:00:01 2026"
    assert parsed[0]["command"] == "/harness --binary /httpd"
    with pytest.raises(ValueError, match="incomplete"):
        parse_process_table("PID PPID STAT STARTED COMMAND\n42 truncated\n")
    with pytest.raises(ValueError, match="header"):
        parse_process_table("Docker unavailable")


def test_parent_terminal_checkpoint_does_not_hide_surviving_child(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    (tmp_path / "target-exit.json").write_text('{"exit_code":0}')
    (tmp_path / "runtime_trace.heartbeat.json").write_text('{"terminal_reason":"parent exit"}')
    evidence = run_samples(monkeypatch, watch, [[process(3)], [process(3)]], seconds=120)
    assert not watch.triggered  # No requests, even >60s idle is not a stall.
    assert watch.target_alive
    assert evidence["last_heartbeat"]["terminal_reason"] == "parent exit"


def test_all_targets_exit_wakes_probe_even_without_terminal_heartbeat(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    evidence = run_samples(monkeypatch, watch, [[process()], []])
    assert watch.interrupted.is_set()
    assert watch.termination_reason == "target_exit"
    assert not watch.target_alive
    assert evidence["events"][-1]["kind"] == "target_exit"


def test_exit_before_first_sample_uses_exit_receipt(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    (tmp_path / "target-exit.json").write_text('{"exit_code":1}')
    run_samples(monkeypatch, watch, [[]])
    assert watch.termination_reason == "target_exit"


def test_daemon_exec_descendant_keeps_role_after_reparenting(tmp_path):
    watch = observer(tmp_path)
    child = {**process(3, ppid=2), "command": "/guest/worker"}
    roles, unknown = watch._classify([process(2), child])
    assert roles == {"target"} and not unknown
    roles, unknown = watch._classify([{**child, "ppid": 1}])
    assert roles == {"target"} and not unknown
    roles, unknown = watch._classify([{**child, "started": "different start", "ppid": 1}])
    assert roles == set() and unknown  # A reused PID is not the same process.


def test_reparented_harness_child_keeps_trace_role_without_original_ancestry(tmp_path):
    """A daemon child may retain the Controller trace identity after reparenting."""
    watch = observer(tmp_path)
    child = process(9, ppid=1)
    roles, unknown = watch._classify([child])
    assert roles == {"target"} and not unknown


def test_unattributed_live_process_prevents_false_all_exited_claim(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    (tmp_path / "target-exit.json").write_text('{"exit_code":0}')
    unknown = {**process(), "command": "/unknown-exec-child"}
    run_samples(monkeypatch, watch, [[unknown]])
    assert not watch.triggered
    assert not watch.target_alive


def test_peer_failure_is_separate_from_target_exit(tmp_path, monkeypatch):
    watch = observer(tmp_path, peer_count=1)
    run_samples(monkeypatch, watch, [[process(), process(3, role="peer-01")], [process()]])
    assert watch.termination_reason == "peer_exit"
    assert watch.target_alive


def test_zombie_is_not_a_live_service(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    run_samples(monkeypatch, watch, [[process()], [process(state="Z")]])
    assert watch.termination_reason == "target_exit"
    assert not watch.target_alive


def test_stale_heartbeat_does_not_kill_idle_listener(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    (tmp_path / "runtime_trace.heartbeat.json").write_text('{"last_pc":4096}')
    run_samples(monkeypatch, watch, [[process()] for _ in range(5)], seconds=60)
    assert not watch.triggered


def test_no_response_after_requests_has_bounded_evidence_not_spin_proof(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    monkeypatch.setattr(supervision.time, "monotonic", lambda: 0)
    watch.begin_step(1)
    watch.probe_attempted()
    evidence = run_samples(monkeypatch, watch, [[process()] for _ in range(5)], seconds=60)
    assert watch.termination_reason == "no_progress_watchdog"
    assert "not proof" in evidence["events"][-1]["basis"]


def test_observation_failure_is_not_relabelled_guest_stall(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    run_samples(monkeypatch, watch, [RuntimeError("Docker unavailable")], seconds=60)
    assert watch.termination_reason == "observation_failed"
    assert "Docker unavailable" in watch.observation_error


def test_observer_never_deletes_a_container(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    commands = []

    def docker(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "PID PPID STAT STARTED COMMAND\n", "")

    monkeypatch.setattr(supervision.subprocess, "run", docker)
    (tmp_path / "target-exit.json").write_text('{"exit_code":1}')
    watch._run()
    assert commands == [["docker", "top", "owned", "-eo", "pid,ppid,stat,lstart,args"]]
    assert watch.interrupted.is_set()


def test_probe_returns_incorrect_response_for_feedback_instead_of_retrying(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    sandbox = object.__new__(DockerRootfsSandbox)
    sandbox.network = RuntimeNetwork()
    monkeypatch.setattr(sandbox, "_container_ip", lambda *a, **kw: None)
    monkeypatch.setattr(sandbox_module.time, "monotonic", lambda: 0)
    calls = []

    def request(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, b"HTTP/1.0 500 Error\r\n\r\nfailed", b"")

    monkeypatch.setattr(sandbox_module.subprocess, "run", request)
    result = sandbox._run_tcp_probe_in_container("owned", InteractionProbe(
        port=80, request_text="GET / HTTP/1.0\r\n\r\n", response_contains="expected page",
    ), deadline=3600, observer=watch)
    assert not result.interacted
    assert result.status_code == 500
    assert len(calls) == 1


def test_probe_wakes_on_target_exit_without_container_inspection(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    watch._interrupt("target_exit")
    sandbox = object.__new__(DockerRootfsSandbox)
    sandbox.network = RuntimeNetwork()
    result = sandbox._run_tcp_probe_in_container("owned", InteractionProbe(
        port=80, request_text="request",
    ), deadline=supervision.time.monotonic() + 3600, observer=watch)
    assert result.attempts == 0
    assert "target_exit" in result.error


def test_old_result_version_cannot_be_mistaken_for_positive_process_observation():
    old = RehostingResult(target_binary="guest", guest_arch="arm", selected_recipe_id="fixture",
                          status="stopped", final_summary="fixture").model_dump()
    old["schema_version"] = 11
    with pytest.raises(ValidationError) as error:
        RehostingResult.model_validate(old)
    assert [item["loc"] for item in error.value.errors()] == [("schema_version",)]


@pytest.mark.parametrize("final_table", [[], [process(state="Z")]])
def test_final_sample_does_not_reuse_liveness_from_before_response(tmp_path, monkeypatch, final_table):
    watch = observer(tmp_path)
    run_samples(monkeypatch, watch, [[process()]])
    assert watch.target_alive
    historical = watch.process_path.read_bytes()
    watch.response_received()
    assert not watch.target_alive_after_probe
    monkeypatch.setattr(watch, "_read_processes", lambda: final_table)
    watch.sample_after_probe()
    assert watch.termination_reason == "target_exit"
    assert not watch.target_alive_after_probe
    final = json.loads(watch.final_process_path.read_text())
    assert final["status"] == "complete" and final["after_last_response"]
    assert final["last_response_unix_ns"] <= final["sample_started_unix_ns"] <= final["sample_finished_unix_ns"]
    assert watch.process_path.read_bytes() == historical


def test_final_sample_keeps_live_daemon_descendant_and_full_identity(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    child = {**process(3, ppid=2), "command": "/guest/worker"}
    run_samples(monkeypatch, watch, [[process(2), child]])
    watch.response_received()
    monkeypatch.setattr(watch, "_read_processes", lambda: [{**child, "ppid": 1}])
    watch.sample_after_probe()
    assert watch.target_alive_after_probe
    final = json.loads(watch.final_process_path.read_text())
    assert final["processes"][0]["role"] == "target"
    assert final["processes"][0]["pid"] == 3
    assert final["processes"][0]["started"] == child["started"]
    assert not watch.triggered


def test_final_sample_needs_a_preceding_response(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    monkeypatch.setattr(watch, "_read_processes", lambda: [process()])
    watch.sample_after_probe()
    assert watch.target_alive
    assert not watch.target_alive_after_probe
    assert watch.final_observation["last_response_unix_ns"] is None


def test_failed_final_observation_retains_history_without_asserting_exit_or_alive(tmp_path, monkeypatch):
    watch = observer(tmp_path)
    run_samples(monkeypatch, watch, [[process()]])
    historical = watch.process_path.read_bytes()
    watch.response_received()

    def unavailable():
        raise subprocess.TimeoutExpired("docker top", 2)

    monkeypatch.setattr(watch, "_read_processes", unavailable)
    watch.sample_after_probe()
    assert not watch.target_alive_after_probe
    assert watch.termination_reason == "observation_failed"
    final = json.loads(watch.final_process_path.read_text())
    assert final["status"] == "error" and "timed out" in final["error"]
    assert not final["processes"]
    assert watch.process_path.read_bytes() == historical


def test_final_sample_preserves_original_stop_reason(tmp_path, monkeypatch):
    watch = observer(tmp_path, peer_count=1)
    run_samples(monkeypatch, watch, [[process(), process(3, role="peer-01")], [process()]])
    assert watch.termination_reason == "peer_exit"
    monkeypatch.setattr(watch, "_read_processes", lambda: [])
    watch.sample_after_probe()
    assert watch.termination_reason == "peer_exit"
    assert not watch.target_alive_after_probe


@pytest.mark.parametrize("cancelled", [False, True])
def test_final_sample_stops_on_shared_budget_without_starting_docker(tmp_path, monkeypatch, cancelled):
    clock = [0.0]
    monkeypatch.setattr(supervision.time, "monotonic", lambda: clock[0])
    budget = ExecutionBudget(10, cleanup_seconds=2)
    watch = observer(tmp_path, budget=budget)
    if cancelled:
        budget.cancelled.set()
    else:
        clock[0] = 8
    reason = "user_cancelled" if cancelled else "session_budget_exhausted"
    monkeypatch.setattr(supervision.subprocess, "Popen", lambda *a, **kw: pytest.fail("Docker started after stop"))
    with pytest.raises(RunnerStopped, match=reason):
        watch.sample_after_probe()
    assert watch.final_observation["status"] == "stopped"
    assert watch.final_observation["error"] == reason
    assert watch.termination_reason == reason


def test_monitor_cancellation_is_controller_stop_not_observation_failure(tmp_path, monkeypatch):
    budget = ExecutionBudget(10)
    budget.cancelled.set()
    watch = observer(tmp_path, budget=budget)
    monkeypatch.setattr(supervision.subprocess, "Popen", lambda *a, **kw: pytest.fail("Docker started after stop"))
    watch._run()
    assert watch.interrupted.is_set()
    assert watch.termination_reason == "user_cancelled"
    assert "user_cancelled" in watch.observation_error


@pytest.mark.parametrize("final_state", ["alive", "exited", "unavailable"])
def test_sandbox_scenario_uses_post_response_observation(tmp_path, monkeypatch, final_state):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    sandbox = DockerRootfsSandbox(rootfs=rootfs, workdir=tmp_path, target_binary="guest",
        executable_path="/guest", guest_arch="arm", runtime_workspace=tmp_path / "runtime", env_script=None)
    sandbox._prepared, sandbox._active_rootfs = True, rootfs
    sandbox.bundle_dir.mkdir(parents=True)
    # Establish the same initial live sample that the old implementation used.
    # The real final-sampling and scenario-evaluation code must replace it.
    def start(watch):
        watch.last_processes = [process()]
        watch._classify(watch.last_processes)

    def read(watch):
        if final_state == "unavailable":
            raise RuntimeError("controlled observation unavailable")
        return [process()] if final_state == "alive" else []

    def probe(*args, observer, **kwargs):
        observer.response_received()
        return ProbeResult(connected=True, interacted=True, attempts=1,
            response_text="HTTP/1.0 200 OK\r\n\r\nhello", status_code=200)

    def command(argv, **kwargs):
        if argv[:2] == ["docker", "logs"]:
            kwargs["stdout"].write(b"retained logs\n")
        return subprocess.CompletedProcess(argv, 0, "true 0" if argv[:2] == ["docker", "inspect"] else "", "")

    monkeypatch.setattr(TargetProgressWatchdog, "start", start)
    monkeypatch.setattr(TargetProgressWatchdog, "_read_processes", read)
    monkeypatch.setattr(sandbox, "_run_tcp_probe_in_container", probe)
    monkeypatch.setattr(sandbox, "_process", command)
    scenario = InteractionScenario(protocol="http", port=80,
        steps=[InteractionStep(request_text="request", expected_status_code=200, response_contains="hello")],
        required_state_changes=["target process is alive at probe"],
        observation_requirements=["target_process_alive"],
        observation_assertions=[ObservationAssertion(target="state_change", target_index=1,
            predicate="target_process_alive_at_probe")], evidence_refs=["controlled scenario"])
    result = sandbox.run_attempt(attempt_number=1, intervention_so=None, executable_path="/guest",
        guest_args=[], guest_working_directory="/", guest_environment={}, companion_processes=[],
        probe=InteractionProbe(port=80, request_text="request"), scenario=scenario, timeout_seconds=20)
    assert result.probe_result.interacted  # An HTTP response alone is insufficient.
    assert result.scenario_result.status == ("success" if final_state == "alive" else "blocked")
    live = [o for o in result.scenario_result.observations if o.kind == "target_process_alive"]
    assert bool(live) == (final_state == "alive")
    if live:
        assert live[0].evidence_path.endswith("processes-final.json")
    assert (result.watchdog_path.parent / "processes-final.json").is_file()
    assert result.container_log_path.read_text() == "retained logs\n"


@pytest.mark.external
def test_monitor_cancel_reaps_the_actual_observation_client(tmp_path, monkeypatch):
    """Use a blocked real subprocess in place of Docker; keep production budget wiring."""
    budget = ExecutionBudget(10)
    watch = observer(tmp_path, budget=budget)
    pid_path = tmp_path / "client.pid"
    real_run = supervision.run_process

    def blocked_client(command, **kwargs):
        assert command[:2] == ["docker", "top"]
        assert kwargs["budget"] is budget
        return real_run([sys.executable, "-c",
            "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(60)",
            str(pid_path)], **kwargs)

    monkeypatch.setattr(supervision, "run_process", blocked_client)
    watch.start()
    try:
        deadline = time.monotonic() + 3
        while not pid_path.is_file() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_path.is_file()
        budget.cancelled.set()
        watch.join()
        assert watch.termination_reason == "user_cancelled"
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_path.read_text()), 0)
        assert json.loads(watch.path.read_text())["termination_reason"] == "user_cancelled"
    finally:
        budget.cancelled.set()
        watch.stop("test_cleanup")
        watch.join()


def test_sandbox_hands_outputs_off_after_final_observation_before_collection(tmp_path, monkeypatch):
    import fmst_analyzer.runner.docker_sandbox as module
    from fmst_analyzer.runner.runtime_builder import HostRuntimeBuilder

    order = []
    class Builder(HostRuntimeBuilder):
        def handoff_output(self, root, *, cleanup=False):
            order.append("handoff_cleanup" if cleanup else "handoff")

    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    sandbox = DockerRootfsSandbox(rootfs=rootfs, workdir=tmp_path, target_binary="guest",
        executable_path="/guest", guest_arch="arm", runtime_workspace=tmp_path / "runtime",
        env_script=None, runtime_builder=Builder())
    sandbox._prepared, sandbox._active_rootfs = True, rootfs
    sandbox.bundle_dir.mkdir(parents=True)
    def sample(watch):
        order.append("final_sample")
    def probe(*args, **kwargs):
        order.append("probe")
        return ProbeResult(connected=True, interacted=True, attempts=1, response_text="hello")
    def command(argv, **kwargs):
        order.append(" ".join(argv[:2]))
        if argv[:2] == ["docker", "logs"]:
            kwargs["stdout"].write(b"logs\n")
        return subprocess.CompletedProcess(argv, 0, "true 0" if argv[1] == "inspect" else "", "")
    original_collect = module.collect_runtime_dump
    def collect(**kwargs):
        order.append("collect")
        return original_collect(**kwargs)
    monkeypatch.setattr(TargetProgressWatchdog, "start", lambda watch: None)
    monkeypatch.setattr(TargetProgressWatchdog, "sample_after_probe", sample)
    monkeypatch.setattr(sandbox, "_run_tcp_probe_in_container", probe)
    monkeypatch.setattr(sandbox, "_process", command)
    monkeypatch.setattr(module, "collect_runtime_dump", collect)
    sandbox.run_attempt(attempt_number=1, intervention_so=None, executable_path="/guest",
        guest_args=[], guest_working_directory="/", guest_environment={}, companion_processes=[],
        probe=InteractionProbe(port=80, request_text="request"), timeout_seconds=20)
    assert order.index("probe") < order.index("final_sample") < order.index("docker pause")
    assert order.index("docker pause") < order.index("handoff") < order.index("collect") < order.index("docker rm")
    assert "handoff_cleanup" not in order
