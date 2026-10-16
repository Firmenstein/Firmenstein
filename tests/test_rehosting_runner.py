from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

import fmst_analyzer.runner.agent as runner_agent_module
import fmst_analyzer.runner.docker_sandbox as docker_sandbox_module
import fmst_analyzer.runner.trace_context as trace_context_module
from fmst_analyzer.runner.probe import build_probe_result
from fmst_analyzer.runner.reports import render_index
from fmst_analyzer.runner.runner import (
    _generation_readiness_errors,
    _initial_environment_preparation,
    _run_enabled_tests,
    _protected_files,
    RehostingRunner,
    _validate_bootstrap_decision,
    _validate_workspace_files,
    _validate_protected_files,
)
from fmst_analyzer.runner.docker_sandbox import (
    DockerRootfsSandbox,
    _harness_arguments,
    _container_probe_command,
    _container_runtime_mounts,
    _host_loader_guest_path,
    _render_companion_supervisor,
    _render_target_lifecycle,
    _materialize_docker_reserved_paths,
    _restore_executable_mode,
)
from fmst_analyzer.runner.agent import _find_rootfs_paths, make_runner_tools
from fmst_analyzer.synthesizer.intervention_skill import (
    REHOSTING_PLANNING_SKILL,
)
from fmst_analyzer.synthesizer.intervention_generator.environment import (
    EnvironmentGenerationResult,
)
from fmst_analyzer.runner.rootfs_actions import RootfsAction, apply_rootfs_actions
from fmst_analyzer.synthesizer.intervention_generator.schema import (
    InterventionGenerationResult,
    UnitGenerationResult,
)
from fmst_analyzer.synthesizer.intervention_generator.baseline import (
    create_generation_baseline,
    materialize_generation_workspace,
    restore_generation_baseline,
)
from fmst_analyzer.runner.schema import (
    CompanionProcess,
    EnvironmentPreparation,
    InteractionProbe,
    ProbeResult,
    RehostingResult,
    RunnerDecision,
    RuntimeAttempt,
)
from fmst_analyzer.runner.trace_context import build_runtime_trace_context


def test_workspace_changed_paths_accept_crate_prefixed_agent_spelling(tmp_path):
    intervention = tmp_path / "intervention" / "httpd"
    intervention.mkdir(parents=True)
    (intervention / "before.txt").write_text("before")
    snapshots = {"intervention": _protected_files(intervention)}
    (intervention / "before.txt").write_text("after")
    changed_units, changed_paths = _validate_workspace_files(
        snapshots,
        intervention_root=intervention,
        test_root=None,
        environment_root=None,
        declared_paths=["intervention/httpd/before.txt"],
        declared_unit_ids=[],
        editable_unit_ids=set(),
    )
    assert changed_units == set()
    assert changed_paths == ["intervention/before.txt"]


def test_runner_decision_requires_probe_and_concrete_args() -> None:
    with pytest.raises(ValidationError):
        RunnerDecision(action="run", summary="ready")
    with pytest.raises(ValidationError):
        RunnerDecision(
            action="run",
            probe=InteractionProbe(port=80, request_text="GET /\r\n\r\n"),
            guest_args=["bad\x00argument"],
            summary="ready",
        )
    with pytest.raises(ValidationError):
        RunnerDecision(
            action="run",
            probe=InteractionProbe(port=80, request_text="GET /\r\n\r\n"),
            guest_working_directory="../tmp",
            summary="ready",
        )
    with pytest.raises(ValidationError):
        RunnerDecision(
            action="run",
            probe=InteractionProbe(port=80, request_text="GET /\r\n\r\n"),
            guest_environment={"PORT": "bad\x00value"},
            summary="ready",
        )
    decision = RunnerDecision(
        action="edit_unit",
        probe=InteractionProbe(port=80, request_text="GET /\r\n\r\n"),
        guest_args=["-D"],
        changed_unit_ids=["unit-a", "unit-a"],
        summary=" ready ",
    )
    assert decision.changed_unit_ids == ["unit-a"]
    assert decision.summary == "ready"

    decision = RunnerDecision(
        action="run",
        probe=InteractionProbe(port=80, request_text="GET /\r\n\r\n"),
        rootfs_actions=[RootfsAction(
            action="write_file",
            path="/etc/service.conf",
            content="port=80\n",
        )],
        disabled_unit_ids=["unit-config"],
        summary="use an ordinary configuration file",
    )
    assert decision.rootfs_actions[0].path == "/etc/service.conf"
    assert decision.disabled_unit_ids == ["unit-config"]

    stopped = RunnerDecision(
        action="continue",
        rootfs_actions=[RootfsAction(
            action="write_file",
            path="/etc/service.conf",
            content="port=80\n",
        )],
        disabled_unit_ids=["unit-config"],
        summary="runtime evidence is insufficient",
    )
    assert stopped.probe is None
    assert stopped.disabled_unit_ids == ["unit-config"]


def test_runner_cannot_create_a_second_generation_workflow() -> None:
    with pytest.raises(ValidationError):
        RunnerDecision(action="add_unit", summary="invent a runtime Unit")
    with pytest.raises(ValidationError, match="edit_unit requires"):
        RunnerDecision(
            action="edit_unit",
            probe=InteractionProbe(port=80, request_text="GET /\r\n\r\n"),
            summary="missing edited Unit",
        )
    with pytest.raises(ValidationError, match="continue decisions"):
        RunnerDecision(
            action="continue",
            probe=InteractionProbe(port=80, request_text="GET /\r\n\r\n"),
            summary="invalid probe",
        )

def test_first_attempt_must_run_the_unmodified_generator_baseline() -> None:
    decision = RunnerDecision(
        action="run",
        probe=InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n"),
        summary="execute the baseline",
    )
    _validate_bootstrap_decision(
        decision,
        changed_unit_ids=set(),
    )
    with pytest.raises(RuntimeError, match="must run"):
        _validate_bootstrap_decision(
            RunnerDecision(action="continue", summary="premature"),
            changed_unit_ids=set(),
        )
    with pytest.raises(RuntimeError, match="cannot modify"):
        _validate_bootstrap_decision(
            decision,
            changed_unit_ids={"unit-ok"},
        )
    with pytest.raises(RuntimeError, match="complete"):
        _validate_bootstrap_decision(
            decision.model_copy(update={"disabled_unit_ids": ["unit-ok"]}),
            changed_unit_ids=set(),
        )


def test_runner_rejects_generation_until_every_planned_unit_is_ok() -> None:
    generation = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="service",
        arch="arm",
        total_units=2,
        ok_count=1,
        not_ready_count=1,
        skipped_count=0,
        units=[
            UnitGenerationResult(
                unit_id="unit-ok",
                report_stem="ok",
                strategy="function_stub",
                status="ok",
            ),
            UnitGenerationResult(
                unit_id="unit-failed",
                report_stem="failed",
                strategy="callsite_hook",
                status="test_failed",
            ),
        ],
        cargo_build_status="ok",
        cargo_test_status="failed",
        environment=EnvironmentGenerationResult(),
    )

    errors = _generation_readiness_errors(
        generation,
        planned_unit_ids={"unit-ok", "unit-failed"},
    )

    assert any("unit-failed:test_failed" in error for error in errors)
    assert any("not_ready=1" in error for error in errors)


def test_runner_fails_when_an_enabled_unit_has_no_generated_self_test(
    tmp_path: Path,
) -> None:
    class Builder:
        def run_cargo(self, *_args, **_kwargs):
            raise AssertionError("missing tests must fail before cargo is invoked")

    test_root = tmp_path / "tests"
    (test_root / "tests").mkdir(parents=True)
    result = _run_enabled_tests(
        Builder(), test_root, {"unit-abc"}, timeout=1,
    )

    assert result.returncode == 1
    assert "missing generated self-test" in result.stderr


def test_runner_cargo_check_preserves_dependency_lock(tmp_path):
    class Builder:
        def run_cargo(self, manifest, subcommand, *, timeout, extra_args=()):
            assert manifest == tmp_path / "Cargo.toml"
            assert subcommand == "check" and timeout == 600
            if "--locked" in extra_args:
                return subprocess.CompletedProcess([], 101, "", "lock file needs to be updated")
            (manifest.parent / "Cargo.lock").write_text("unexpected source change")
            return subprocess.CompletedProcess([], 0, "", "")

    tools = make_runner_tools(
        view=None, rootfs=tmp_path, diagnostic_reports_root=tmp_path,
        intervention_manifest=tmp_path / "Cargo.toml",
        evidence_state=runner_agent_module.RuntimeEvidenceState(), runtime_builder=Builder(),
    )
    output = next(tool for tool in tools if tool.name == "cargo_check").invoke({})
    assert "exit_code=101" in output and "lock file needs to be updated" in output
    assert not (tmp_path / "Cargo.lock").exists()


def test_runner_accepts_ready_environment_only_generation(tmp_path: Path) -> None:
    """Static environment preparation can run without an IIB crate."""
    script = tmp_path / "setup_rootfs.py"
    script.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1], 'etc').mkdir(exist_ok=True)\n",
        encoding="utf-8",
    )
    generation = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="service",
        arch="arm",
        total_units=1,
        ok_count=1,
        not_ready_count=0,
        skipped_count=0,
        units=[
            UnitGenerationResult(
                unit_id="unit-env",
                report_stem="env",
                strategy="environment_setup",
                status="ok",
                generated_files=[str(script)],
            ),
        ],
        cargo_build_status="not_run",
        cargo_test_status="not_run",
        intervention_crate_path=None,
        test_crate_path=None,
        environment=EnvironmentGenerationResult(
            status="completed",
            unit_ids=["unit-env"],
            script_path=str(script),
            reason="generated static rootfs preparation",
        ),
    )

    assert _generation_readiness_errors(
        generation,
        planned_unit_ids={"unit-env"},
    ) == []


def test_runner_requires_generation_to_cover_the_exact_plan() -> None:
    generation = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="service",
        arch="arm",
        total_units=1,
        ok_count=0,
        not_ready_count=0,
        skipped_count=1,
        units=[
            UnitGenerationResult(
                unit_id="unit-a",
                report_stem="a",
                strategy="function_stub",
                status="skipped",
            ),
        ],
        cargo_build_status="not_run",
        cargo_test_status="not_run",
        environment=EnvironmentGenerationResult(),
    )

    errors = _generation_readiness_errors(
        generation,
        planned_unit_ids={"unit-a", "unit-b"},
    )

    assert any("identities" in error for error in errors)
    assert any("unit-a:skipped" in error for error in errors)


def test_runner_rejects_missing_completed_environment_script(tmp_path: Path) -> None:
    generation = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="service",
        arch="arm",
        total_units=1,
        ok_count=1,
        not_ready_count=0,
        skipped_count=0,
        units=[UnitGenerationResult(
            unit_id="unit-env",
            report_stem="config",
            strategy="environment_setup",
            status="ok",
        )],
        cargo_build_status="not_run",
        cargo_test_status="not_run",
        environment=EnvironmentGenerationResult(
            status="completed",
            unit_ids=["unit-env"],
            script_path=str(tmp_path / "missing" / "setup_rootfs.py"),
        ),
    )

    errors = _generation_readiness_errors(
        generation,
        planned_unit_ids={"unit-env"},
    )

    assert any("setup_rootfs.py is missing" in error for error in errors)
    preparation = _initial_environment_preparation(generation)
    assert preparation.status == "failed"
    assert "setup_rootfs.py is missing" in (preparation.failure_reason or "")


def test_runner_rootfs_actions_are_not_tied_to_intervention_units() -> None:
    action = RootfsAction(
        action="write_file",
        path="/etc/runtime.conf",
        content="runner=1\n",
    )
    assert "unit_id" not in action.model_dump(mode="json")


def test_runner_allows_environment_script_to_create_copy_source(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    decision = RunnerDecision(
        action="run",
        probe=InteractionProbe(port=80, request_text="PING\n"),
        rootfs_actions=[RootfsAction(
            action="copy_file",
            path="/etc/runtime.conf",
            source_path="/opt/generated.conf",
        )],
        summary="copy the source prepared by setup_rootfs.py",
    )

    RehostingRunner._validate_decision(decision, set(), rootfs)
    assert decision.rootfs_actions[0].source_path == "/opt/generated.conf"


def test_rootfs_action_resolves_guest_absolute_symlink_inside_staged_tree(tmp_path: Path) -> None:
    rootfs = tmp_path / "rootfs"
    (rootfs / "tmp").mkdir(parents=True)
    (rootfs / "var").symlink_to("/tmp", target_is_directory=True)

    apply_rootfs_actions([
        RootfsAction(action="mkdir", path="/var/run"),
        RootfsAction(action="chmod", path="/var/run", mode=0o777),
    ], rootfs)

    assert (rootfs / "tmp/run").is_dir()
    assert (rootfs / "tmp/run").stat().st_mode & 0o777 == 0o777


def test_rootfs_action_remove_and_replace_keep_final_symlink_target(tmp_path: Path) -> None:
    (tmp_path / "data").write_text("keep")
    (tmp_path / "alias").symlink_to("/data")
    for action in ("write_file", "chmod"):
        args = {"content": "bad"} if action == "write_file" else {"mode": 0o777}
        with pytest.raises(ValueError, match="existing symlink"):
            apply_rootfs_actions([RootfsAction(action=action, path="/alias", **args)], tmp_path)
    apply_rootfs_actions([RootfsAction(action="remove", path="/alias")], tmp_path)
    assert not (tmp_path / "alias").is_symlink()
    assert (tmp_path / "data").read_text() == "keep"
    (tmp_path / "alias").symlink_to("/data")
    apply_rootfs_actions([RootfsAction(action="symlink", path="/alias", target="/other")], tmp_path)
    assert (tmp_path / "alias").readlink().as_posix() == "/other"
    assert (tmp_path / "data").read_text() == "keep"


def test_rootfs_action_copy_follows_guest_source_and_rejects_loop(tmp_path: Path) -> None:
    (tmp_path / "data").write_text("copied")
    (tmp_path / "source").symlink_to("/data")
    apply_rootfs_actions([
        RootfsAction(action="copy_file", path="/copy", source_path="/source"),
    ], tmp_path)
    assert (tmp_path / "copy").read_text() == "copied"
    (tmp_path / "loop").symlink_to("loop/child")
    with pytest.raises(ValueError, match="escapes rootfs through symlink"):
        apply_rootfs_actions([RootfsAction(action="mkdir", path="/loop/x")], tmp_path)


def test_harness_arguments_separate_firmware_options() -> None:
    arguments = _harness_arguments(
        harness_name="fmst-harness-mips",
        intervention_so="/fmst-host/intervention.so",
        executable_path="/usr/sbin/thttpd",
        trace_output="/fmst-output/runtime_trace.json",
        guest_args=["-C", "/var/www/thttpd.conf", "-l", "/dev/null"],
    )
    separator = arguments.index("--")
    assert arguments[separator + 1:] == [
        "-C", "/var/www/thttpd.conf", "-l", "/dev/null",
    ]


def test_harness_arguments_support_trace_only_without_intervention() -> None:
    arguments = _harness_arguments(
        harness_name="fmst-harness-arm",
        intervention_so=None,
        executable_path="/usr/sbin/httpd",
        trace_output="/fmst-output/runtime_trace.json",
        guest_args=[],
    )
    assert "--trace-only" in arguments
    assert "--intervention-so" not in arguments
    assert arguments[arguments.index("--") + 1:] == []


def test_companion_process_is_concrete_and_supervisor_uses_trace_only() -> None:
    process = CompanionProcess(
        executable_path="/usr/sbin/peer",
        args=["--foreground"],
        working_directory="/tmp",
        environment={"MODE": "service"},
        evidence_ref="dependency:verified-peer",
    )
    script = _render_companion_supervisor(
        harness_name="fmst-harness-mips",
        companion_processes=[process],
        target_arguments=["/fmst-host/fmst-harness-mips", "--trace-only"],
    )
    assert "--trace-only --binary /usr/sbin/peer" in script
    assert "cd /tmp" in script
    assert "MODE=service" in script
    assert "companion-01.log" in script
    with pytest.raises(ValidationError):
        CompanionProcess(
            executable_path="../peer",
            evidence_ref="invalid",
        )


def test_target_supervisor_keeps_container_alive_after_daemon_parent_exit() -> None:
    script = "\n".join(_render_target_lifecycle([
        "/fmst-host/fmst-harness-arm",
        "--trace-only",
        "--binary",
        "/usr/sbin/httpd",
    ]))
    assert ") &" in script
    assert 'wait "$target_pid"' in script
    assert "/fmst-output/target-exit.json" in script
    assert "/fmst-host/ld.so --library-path /fmst-host/lib /fmst-host/sleep 60" in script


def test_docker_reserved_etc_alias_is_materialized_after_staging(tmp_path):
    (tmp_path / "var" / "etc").mkdir(parents=True)
    (tmp_path / "var" / "etc" / "service.conf").write_text("ready\n")
    (tmp_path / "etc").symlink_to("var/etc")
    assert _materialize_docker_reserved_paths(tmp_path)
    assert not (tmp_path / "etc").is_symlink()
    assert (tmp_path / "etc" / "service.conf").read_text() == "ready\n"


def test_staged_target_recovers_lost_executable_mode(tmp_path: Path) -> None:
    target = tmp_path / "usr" / "sbin" / "service"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELFpayload")
    target.chmod(0o644)
    _restore_executable_mode(tmp_path, "/usr/sbin/service")
    assert target.stat().st_mode & 0o111 == 0o111


def test_runner_agent_loads_application_and_selected_framework_skills(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    framework = tmp_path / "selected-framework"
    (framework / "docs").mkdir(parents=True)
    (framework / "skills" / "intervention-engineering").mkdir(parents=True)
    (framework / "skills" / "intervention-engineering" / "SKILL.md").write_text(
        "---\nname: guestweave-intervention-engineering\n"
        "description: test skill\n---\n# GuestWeave\n"
    )

    def fake_create_analysis_agent(**kwargs):
        captured.update(kwargs)
        return object()

    monkeypatch.setattr(runner_agent_module, "make_analyzer_tools", lambda _view: [])
    monkeypatch.setattr(runner_agent_module, "make_runner_tools", lambda **_kwargs: [])
    monkeypatch.setattr(
        runner_agent_module,
        "create_analysis_agent",
        fake_create_analysis_agent,
    )
    monkeypatch.setattr(
        runner_agent_module,
        "AgentTraceHandler",
        lambda **_kwargs: object(),
    )
    runner_agent_module.RunnerAgentSession(
        view=object(),
        rootfs=tmp_path,
        diagnostic_reports_root=tmp_path,
        intervention_root=tmp_path,
        trace_path=tmp_path / "trace.md",
        evidence_state=runner_agent_module.RuntimeEvidenceState(),
        readable_roots=[tmp_path / "reports"],
        writable_roots=[tmp_path],
        runtime_workspace=framework,
    )
    selected, = captured["skills"]
    assert selected.name == "guestweave-intervention-engineering"
    assert selected.skill_dir == framework / "skills" / "intervention-engineering"
    assert selected.reference_roots == (framework / "docs",)
    from fmst_basic.agent.config import configured_claude_model, configured_codex_model, DEFAULT_AGENT_PROVIDER
    expected_model = configured_claude_model() if DEFAULT_AGENT_PROVIDER == "claude" else configured_codex_model()
    assert captured["model"] == expected_model
    from fmst_analyzer.synthesizer.intervention_skill import APPLICATION_READ_ROOTS, APPLICATION_CONTRACT
    assert captured["readable_roots"] == [tmp_path / "reports", *APPLICATION_READ_ROOTS]
    assert str(APPLICATION_CONTRACT) in captured["developer_instructions"]
    assert captured["writable_roots"] == [tmp_path]


def test_tcp_probe_requires_nonempty_matching_response() -> None:
    result = build_probe_result(
        InteractionProbe(port=1234, request_text="PING\n", response_contains="PONG"),
        connected=True,
        response=b"PONG\n",
        attempts=1,
    )
    assert result.connected is True
    assert result.interacted is True
    assert result.response_text == "PONG\n"


def test_in_container_probe_command_does_not_publish_ports() -> None:
    command = _container_probe_command(
        "fmst-target-test",
        "127.0.0.1",
        InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n"),
    )
    assert command[:4] == ["docker", "exec", "--interactive", "fmst-target-test"]
    assert "-p" not in command
    assert "-P" not in command
    assert "--publish" not in command
    assert "/fmst-host/nc" in command

    source = _container_probe_command(
        "fmst-target-test", "127.0.0.1",
        InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n"),
        source_port=55001,
    )
    assert "-p" not in source[:source.index("/fmst-host/ld.so")]
    assert source[source.index("/fmst-host/nc") + 1:] == [
        "-n", "-v", "-w", "2", "-p", "55001", "127.0.0.1", "80",
    ]


@pytest.mark.parametrize("times_out", [False, True])
def test_slow_native_response_uses_interaction_window_without_duplicate_request(tmp_path, times_out):
    import subprocess
    import threading
    import time
    from types import SimpleNamespace
    from fmst_analyzer.runner.schema import RuntimeNetwork

    sandbox = object.__new__(DockerRootfsSandbox)
    sandbox.budget = None
    sandbox.network = RuntimeNetwork(probe_destination="loopback")
    observer = SimpleNamespace(interrupted=threading.Event(), stall_seconds=15,
        probe_attempted=lambda: None, response_received=lambda: None)
    calls = []
    partial = b"HTTP/1.0 200 OK\r\nContent-Length: 99\r\n\r\npartial"

    def process(command, **kwargs):
        calls.append(command)
        assert kwargs["timeout"] > 3
        assert int(command[command.index("-w") + 1]) >= 15
        if times_out:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=partial)
        return subprocess.CompletedProcess(command, 0, b"HTTP/1.0 200 OK\r\n\r\nnative CGI", b"")

    sandbox._process = process
    result = sandbox._run_tcp_probe_in_container("fixture",
        InteractionProbe(port=80, request_text="GET /slow HTTP/1.0\r\n\r\n"),
        deadline=time.monotonic() + 60, observer=observer, step_index=1,
        connection_record_path=tmp_path / "probe-connections.jsonl")
    assert len(calls) == 1 and result.attempts == 1
    if times_out:
        assert result.error == "in-container probe timed out"
        assert "partial" in result.response_text
        assert any(p.read_bytes() == partial for p in tmp_path.glob("*.bin"))
    else:
        assert result.interacted and "native CGI" in result.response_text


def test_runtime_mounts_separate_current_output_from_readonly_history(
    tmp_path: Path,
) -> None:
    mounts = _container_runtime_mounts(
        tmp_path / "host_runtime",
        tmp_path / "attempts" / "attempt-02",
        tmp_path / "attempts",
    )
    assert "dst=/fmst-output" in mounts[3]
    assert "dst=/fmst-history,readonly" in mounts[5]
    assert f"src={tmp_path / 'attempts'}" in mounts[5]


def test_runtime_mounts_follow_bundle_host_interpreter_metadata(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "host_runtime"
    bundle.mkdir()
    (bundle / "host-interpreter.path").write_text(
        "/lib64/ld-linux-x86-64.so.2\n",
        encoding="utf-8",
    )
    mounts = _container_runtime_mounts(
        bundle,
        tmp_path / "attempts" / "attempt-01",
        tmp_path / "attempts",
        host_loader=bundle / "ld.so",
        host_loader_guest_path=_host_loader_guest_path(bundle),
    )
    assert any(
        "dst=/lib64/ld-linux-x86-64.so.2,readonly" in mount
        for mount in mounts
    )


def test_old_runtime_bundle_keeps_arm64_loader_fallback(tmp_path: Path) -> None:
    assert _host_loader_guest_path(tmp_path) == "/lib/ld-linux-aarch64.so.1"


def test_environment_script_is_snapshotted_per_runner_session(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    source = tmp_path / "env_scripts" / "setup_rootfs.py"
    source.parent.mkdir()
    source.write_text("first", encoding="utf-8")
    sandbox = DockerRootfsSandbox(
        rootfs=rootfs,
        workdir=tmp_path,
        target_binary="service",
        executable_path="/usr/sbin/service",
        guest_arch="x86_64",
        runtime_workspace=tmp_path / "runtime",
        env_script=source,
    )
    sandbox.session_root.mkdir(parents=True)
    sandbox.preparation_root.mkdir()
    sandbox._snapshot_environment_script()

    source.write_text("changed", encoding="utf-8")
    assert sandbox._env_script_snapshot is not None
    assert sandbox._env_script_snapshot.read_text(encoding="utf-8") == "first"


def test_missing_environment_script_fails_before_runtime_setup(
    tmp_path: Path,
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    sandbox = DockerRootfsSandbox(
        rootfs=rootfs,
        workdir=tmp_path,
        target_binary="service",
        executable_path="/usr/sbin/service",
        guest_arch="x86_64",
        runtime_workspace=tmp_path / "runtime",
        env_script=tmp_path / "missing-setup-rootfs.py",
    )
    sandbox.session_root.mkdir(parents=True)
    sandbox.preparation_root.mkdir()
    with pytest.raises(RuntimeError, match="setup_rootfs.py is missing"):
        sandbox._snapshot_environment_script()


@pytest.mark.external
def test_environment_script_runs_on_staged_rootfs_before_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    source = tmp_path / "setup_rootfs.py"
    source.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1], 'environment.marker').write_text('prepared')\n",
        encoding="utf-8",
    )
    sandbox = DockerRootfsSandbox(
        rootfs=rootfs,
        workdir=tmp_path,
        target_binary="service",
        executable_path="/usr/sbin/service",
        guest_arch="x86_64",
        runtime_workspace=tmp_path / "runtime",
        env_script=source,
    )
    sandbox.session_root.mkdir(parents=True)
    sandbox.preparation_root.mkdir()
    sandbox._snapshot_environment_script()
    imported: list[Path] = []
    monkeypatch.setattr(
        sandbox,
        "_import_rootfs",
        lambda staged: imported.append(staged),
    )
    monkeypatch.setattr(
        docker_sandbox_module,
        "_restore_executable_mode",
        lambda _rootfs, _path: None,
    )

    sandbox.update_rootfs_actions([])

    assert len(imported) == 1
    assert (imported[0] / "environment.marker").read_text() == "prepared"
    assert not (rootfs / "environment.marker").exists()


@pytest.mark.external
def test_environment_script_is_reapplied_to_each_fresh_staged_rootfs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    source = tmp_path / "setup_rootfs.py"
    source.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "Path(sys.argv[1], 'environment.marker').write_text('prepared')\n",
        encoding="utf-8",
    )
    sandbox = DockerRootfsSandbox(
        rootfs=rootfs,
        workdir=tmp_path,
        target_binary="service",
        executable_path="/usr/sbin/service",
        guest_arch="x86_64",
        runtime_workspace=tmp_path / "runtime",
        env_script=source,
    )
    sandbox.session_root.mkdir(parents=True)
    sandbox.preparation_root.mkdir()
    sandbox._snapshot_environment_script()
    imported: list[Path] = []
    monkeypatch.setattr(sandbox, "_import_rootfs", imported.append)
    monkeypatch.setattr(
        docker_sandbox_module,
        "_restore_executable_mode",
        lambda _rootfs, _path: None,
    )

    sandbox.update_rootfs_actions([])
    first = imported[-1]
    (first / "environment.marker").write_text("mutated", encoding="utf-8")
    sandbox.update_rootfs_actions([])
    second = imported[-1]

    assert len(imported) == 2
    assert first == second
    assert (second / "environment.marker").read_text() == "prepared"
    assert sandbox.environment_script_applications == 2


def test_tcp_probe_rejects_nonmatching_response() -> None:
    result = build_probe_result(
        InteractionProbe(port=1234, request_text="PING\n", response_contains="PONG"),
        connected=True,
        response=b"NOPE\n",
        attempts=1,
    )
    assert result.connected is True
    assert result.interacted is False
    assert "response" in (result.error or "")


def test_rootfs_path_discovery_is_exact_and_complete(tmp_path: Path) -> None:
    (tmp_path / "var" / "www").mkdir(parents=True)
    (tmp_path / "var.tar_extract" / "var" / "www").mkdir(parents=True)
    (tmp_path / "var" / "www" / "thttpd.conf").write_text("native")
    (tmp_path / "var.tar_extract" / "var" / "www" / "thttpd.conf").write_text(
        "archive"
    )
    (tmp_path / "var" / "www" / "thttpd.conf.old").write_text("old")

    assert _find_rootfs_paths(tmp_path, "thttpd.conf") == [
        "/var.tar_extract/var/www/thttpd.conf",
        "/var/www/thttpd.conf",
    ]
    assert _find_rootfs_paths(tmp_path, "var/www/thttpd.conf") == [
        "/var.tar_extract/var/www/thttpd.conf",
        "/var/www/thttpd.conf",
    ]


def test_read_rootfs_text_reports_directory_without_tool_failure(
    tmp_path: Path,
) -> None:
    (tmp_path / "var" / "run").mkdir(parents=True)
    tools = make_runner_tools(
        view=object(),
        rootfs=tmp_path,
        diagnostic_reports_root=tmp_path,
        intervention_manifest=tmp_path / "manifest.json",
        evidence_state=runner_agent_module.RuntimeEvidenceState(),
    )
    read_text = next(tool for tool in tools if tool.name == "read_rootfs_text")
    assert read_text.invoke({"path": "/var/run"}) == (
        "Rootfs path is not a regular text file: /var/run. Use "
        "find_rootfs_paths to locate a concrete file."
    )


def test_read_rootfs_text_routes_elf_to_static_inspection_without_tool_failure(
    tmp_path: Path,
) -> None:
    elf = tmp_path / "usr" / "libexec" / "webctrl.cgi"
    elf.parent.mkdir(parents=True)
    elf.write_bytes(b"\x7fELF\x00binary")
    tools = make_runner_tools(
        view=object(),
        rootfs=tmp_path,
        diagnostic_reports_root=tmp_path,
        intervention_manifest=tmp_path / "manifest.json",
        evidence_state=runner_agent_module.RuntimeEvidenceState(),
    )
    read_text = next(tool for tool in tools if tool.name == "read_rootfs_text")

    assert read_text.invoke({"path": "/usr/libexec/webctrl.cgi"}) == (
        "Rootfs path is an ELF binary, not text: /usr/libexec/webctrl.cgi. "
        "Use inspect_static_elf for headers/bytes/disassembly, or onboard_binary for semantic decompilation."
    )


def test_protected_generator_files_cannot_change(tmp_path: Path) -> None:
    (tmp_path / "src" / "unit_a").mkdir(parents=True)
    editable = tmp_path / "src" / "unit_a" / "logic.rs"
    editable.write_text("old")
    (tmp_path / "Cargo.toml").write_text("old")
    protected = _protected_files(tmp_path)
    editable.write_text("new")
    assert _validate_protected_files(
        tmp_path,
        protected,
        declared_unit_ids=["unit-a"],
        editable_unit_ids={"unit-a"},
    ) == {"unit-a"}
    protected = _protected_files(tmp_path)
    (tmp_path / "Cargo.toml").write_text("changed")
    with pytest.raises(RuntimeError, match="Cargo.toml"):
        _validate_protected_files(tmp_path, protected)
    assert (tmp_path / "Cargo.toml").read_text() == "old"
    protected = _protected_files(tmp_path)
    (tmp_path / "src" / "unit_a" / "extra.rs").write_text("new file")
    with pytest.raises(RuntimeError, match="extra.rs"):
        _validate_protected_files(tmp_path, protected)
    assert not (tmp_path / "src" / "unit_a" / "extra.rs").exists()


def test_runner_restores_immutable_generator_baseline(tmp_path: Path) -> None:
    intervention = tmp_path / "interventions" / "service"
    tests = tmp_path / "tests" / "service"
    (intervention / "src").mkdir(parents=True)
    (tests / "tests").mkdir(parents=True)
    (intervention / "Cargo.toml").write_text("[package]\nname='service'\n")
    (intervention / "src" / "lib.rs").write_text("pub fn initial() {}\n")
    (tests / "Cargo.toml").write_text("[package]\nname='tests'\n")
    (tests / "tests" / "unit.rs").write_text("#[test] fn initial() {}\n")
    (intervention / "target").mkdir()
    (intervention / "target" / "cached").write_text("keep")

    baseline = create_generation_baseline(
        workdir=tmp_path,
        target_binary="service",
        intervention_root=intervention,
        test_root=tests,
    )
    (intervention / "src" / "lib.rs").write_text("pub fn refined() {}\n")
    (intervention / "src" / "extra.rs").write_text("temporary\n")
    (tests / "tests" / "unit.rs").write_text("#[test] fn refined() {}\n")

    restore_generation_baseline(
        baseline,
        intervention_root=intervention,
        test_root=tests,
    )

    assert (intervention / "src" / "lib.rs").read_text() == "pub fn initial() {}\n"
    assert not (intervention / "src" / "extra.rs").exists()
    assert (tests / "tests" / "unit.rs").read_text() == "#[test] fn initial() {}\n"
    assert (intervention / "target" / "cached").read_text() == "keep"
    assert baseline.root.is_dir()

    same_sources = create_generation_baseline(
        workdir=tmp_path,
        target_binary="service",
        intervention_root=intervention,
        test_root=tests,
    )
    assert same_sources.baseline_id == baseline.baseline_id

    project_src = tmp_path / "checkout" / "src"
    project_src.mkdir(parents=True)
    workspace = materialize_generation_workspace(
        baseline,
        workdir=tmp_path / "work",
        target_binary="service",
        project_src=project_src,
    )
    assert workspace.intervention_root != intervention
    assert (
        workspace.intervention_root / "src" / "lib.rs"
    ).read_text() == "pub fn initial() {}\n"
    (workspace.intervention_root / "src" / "lib.rs").write_text(
        "pub fn runner_refined() {}\n"
    )
    assert (intervention / "src" / "lib.rs").read_text() == "pub fn initial() {}\n"
    assert (baseline.root / "intervention" / "src" / "lib.rs").read_text() == (
        "pub fn initial() {}\n"
    )
    assert (tmp_path / "work" / "runner_workspaces" / "src").resolve() == project_src

def test_cargo_outputs_are_not_treated_as_agent_source_edits(
    tmp_path: Path,
) -> None:
    (tmp_path / "src" / "unit_a").mkdir(parents=True)
    (tmp_path / "src" / "unit_a" / "logic.rs").write_text("source")
    before = _protected_files(tmp_path)
    artifact = tmp_path / "target" / "debug" / ".fingerprint" / "output"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("cargo generated")
    assert _validate_protected_files(tmp_path, before) == set()


def test_runner_markdown_renders_attempt_evidence() -> None:
    attempt = RuntimeAttempt(
        tree_identity_version=2,
        attempt_number=1,
        probe=InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n"),
        guest_args=["-D"],
        guest_working_directory="/var/www",
        guest_environment={"PATH": "/bin:/usr/bin"},
        rootfs_actions=[],
        disabled_unit_ids=["unit-config"],
        intervention_sha256="a" * 64,
        intervention_source_path="attempts/attempt-01/intervention_src",
        intervention_binary_path="attempts/attempt-01/intervention.so",
        outcome="success",
        probe_result=ProbeResult(
            connected=True,
            interacted=True,
            attempts=1,
            response_text="HTTP/1.0 200 OK",
        ),
        runtime_trace_path="attempts/attempt-01/runtime_trace.json",
        runtime_trace_context_path="attempts/attempt-01/runtime_trace_context.json",
        container_log_path="attempts/attempt-01/container.log",
        runtime_trace_available=True,
        runtime_trace_context_available=True,
        agent_summary="first probe",
    )
    result = RehostingResult(
        target_binary="httpd",
        guest_arch="arm",
        selected_recipe_id="launch-a",
        status="success",
        completion={"attempt_number": 1, "attempt_sha256": "0" * 64,
                    "coverage": "Offline rendering fixture; no real runtime claim."},
        environment_preparation=EnvironmentPreparation(
            status="applied",
            source_script_path="env_scripts/httpd/setup_rootfs.py",
            application_count=1,
        ),
        attempts=[attempt],
        final_summary="connected",
    )
    rendered = render_index(result)
    assert "status: `success`" in rendered
    assert "HTTP/1.0 200 OK" in rendered
    assert "runtime_trace_path" in rendered
    assert "runtime_trace_context_path" in rendered
    assert "guest_working_directory: `/var/www`" in rendered
    assert "disabled_unit_ids: `['unit-config']`" in rendered
    assert "rootfs_actions:" in rendered
    assert "intervention_binary_path" in rendered
    assert "environment_preparation:" in rendered
    assert "application_count: `1`" in rendered




def test_runtime_trace_maps_non_pie_and_pie_to_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assembly_root = tmp_path / "assembly"
    decompiled_root = tmp_path / "decompiled"
    for binary, stem, entry in (
        ("service", "main", 0x401000),
        ("libpeer.so", "peer_call", 0x120),
    ):
        (assembly_root / binary).mkdir(parents=True)
        (decompiled_root / binary).mkdir(parents=True)
        (assembly_root / binary / f"{stem}.s").write_text(
            "\n".join([
                f"; binary: {binary}",
                f"; function: {stem}",
                f"; entry_ea: 0x{entry:x}",
                f"; chunk: 0x{entry:x}-0x{entry + 0x20:x}",
                f"0x{entry:08x}:  00 00  nop",
            ])
        )
        (decompiled_root / binary / f"{stem}.c").write_text("void f(void) {}\n")

    class Binary:
        def __init__(self, name: str) -> None:
            self.name = name
            self.binary_path = tmp_path / name
            self.binary_path.write_bytes(b"\x7fELF")

    binaries = [Binary("service"), Binary("libpeer.so")]

    class LibGraph:
        def get_nodes(self):
            return set(binaries)

        def get_callgraph_by_name(self, _name):
            return None

    class Config:
        disassembled_code_dir = assembly_root
        decompiled_code_dir = decompiled_root

    class Root:
        name = "service"

    class View:
        lib_dep_graph = LibGraph()
        global_config = Config()
        root = Root()

    class Parsed:
        def __init__(self, imagebase: int) -> None:
            self.imagebase = imagebase

    monkeypatch.setattr(
        trace_context_module.lief,
        "parse",
        lambda path: Parsed(0x400000 if Path(path).name == "service" else 0),
    )
    raw = tmp_path / "trace.json"
    raw.write_text(json.dumps({
        "schema_version": 5,
        "main_load_address": 0x400000,
        "total_block_executions": 3,
        "blocks": [
            {"pc": 0x401000, "hit_count": 2},
            {"pc": 0x700120, "hit_count": 1},
        ],
        "recent_blocks": [
            {"pc": 0x700120, "consecutive_hits": 1},
        ],
        "focus_images": ["service", "libpeer.so"],
        "recent_focus_blocks": [
            {"pc": 0x401000, "consecutive_hits": 2},
            {"pc": 0x700120, "consecutive_hits": 1},
        ],
        "events": [
            {"sequence": 1, "kind": "image_load", "detail": "service@0x400000", "pc": None, "registers": []},
            {"sequence": 2, "kind": "image_load", "detail": "libpeer.so@0x700000", "pc": None, "registers": []},
            {"sequence": 3, "kind": "iib_hook", "detail": "peer", "pc": 0x700120, "registers": [{"name": "pc", "value": 0x700120}]},
        ],
    }))

    context = build_runtime_trace_context(raw, View())
    assert [(item.binary_name, item.function_ea) for item in context.functions] == [
        ("service", 0x401000),
        ("libpeer.so", 0x120),
    ]
    location = context.events[-1].location
    assert location is not None
    assert location.binary_name == "libpeer.so"
    assert location.static_ea == 0x120
    assert location.assembly_context == ["0x00000120:  00 00  nop"]
    assert context.events[-1].registers[0].value == 0x700120
    assert [item.location.binary_name for item in context.recent_focus_blocks] == [
        "service",
        "libpeer.so",
    ]
    from fmst_analyzer.runner.trace_compaction import expand_trace_context
    saved, _ = trace_context_module.persist_runtime_trace_context(raw, tmp_path / "saved", View())
    compact = json.loads(saved.with_suffix(".compact.json").read_text())
    assert expand_trace_context(compact) == json.loads(saved.read_text())
