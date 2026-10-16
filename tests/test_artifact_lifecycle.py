import inspect
import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from fmst_analyzer.analysis.base.artifact_lifecycle import archive_stage_outputs, preserve_stage_attempt
from fmst_analyzer.analysis.base.execution import AnalysisExecution
from fmst_analyzer.runner import RehostingRunner
from fmst_analyzer.synthesizer.intervention_generator import InterventionGenerator


def _config(workdir: Path, target: str = "httpd"):
    reports = workdir / "diagnostic_reports" / target
    traces = workdir / "agent_debug" / target
    return SimpleNamespace(
        workdir=workdir,
        current_target=target,
        target_diagnostic_reports_dir=lambda: reports,
        target_agent_debug_dir=lambda: traces,
    )


def _touch_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "artifact").write_text("managed", encoding="utf-8")


def test_network_rerun_archives_only_its_own_outputs(tmp_path: Path):
    config = _config(tmp_path)
    reports = config.target_diagnostic_reports_dir()
    traces = config.target_agent_debug_dir()
    for name in (
        "ipc_reports",
        "file_reports",
        "network_reports",
        "process_lifecycle_reports",
        "init_launch_reports",
        "intervention_planner_inputs",
        "intervention_plan_reports",
        "intervention_generation_reports",
        "runner_reports",
    ):
        _touch_dir(reports / name)
    for name in (
        "network_analyzer",
        "process_lifecycle",
        "intervention_plan",
        "intervention_generator",
        "runner",
    ):
        _touch_dir(traces / name)
    for name in (
        "interventions",
        "test_harnesses",
        "env_scripts",
        "intervention_baselines",
        "runner_workspaces",
        "runner_sessions",
    ):
        _touch_dir(tmp_path / name / "httpd")
        _touch_dir(tmp_path / name / "other-target")
    _touch_dir(tmp_path / "diagnostic_reports" / "other-target" / "network_reports")

    attempt = archive_stage_outputs(config, "network")
    assert (attempt / "previous/reports/artifact").read_text() == "managed"
    assert (attempt / "previous/traces/artifact").read_text() == "managed"
    assert not (reports / "network_reports").exists()

    assert (reports / "ipc_reports").is_dir()
    assert (reports / "file_reports").is_dir()
    assert (reports / "init_launch_reports").is_dir()
    for name in (
        "process_lifecycle_reports",
        "intervention_planner_inputs",
        "intervention_plan_reports",
        "intervention_generation_reports",
        "runner_reports",
    ):
        assert (reports / name / "artifact").read_text() == "managed"
    for name in (
        "interventions",
        "test_harnesses",
        "env_scripts",
        "intervention_baselines",
        "runner_workspaces",
        "runner_sessions",
    ):
        assert (tmp_path / name / "httpd" / "artifact").read_text() == "managed"
        assert (tmp_path / name / "other-target").is_dir()
    assert (
        tmp_path / "diagnostic_reports" / "other-target" / "network_reports"
    ).is_dir()


def test_generation_invalidation_preserves_plan_and_analyzer_json(tmp_path: Path):
    config = _config(tmp_path)
    reports = config.target_diagnostic_reports_dir()
    for name in (
        "ipc_reports",
        "intervention_plan_reports",
        "intervention_generation_reports",
        "runner_reports",
    ):
        _touch_dir(reports / name)

    attempt = archive_stage_outputs(config, "generation")

    assert (reports / "ipc_reports").is_dir()
    assert (reports / "intervention_plan_reports").is_dir()
    assert not (reports / "intervention_generation_reports").exists()
    assert (reports / "runner_reports").exists()
    assert (attempt / "previous/reports/artifact").read_text() == "managed"


def test_failed_attempt_preserves_previous_and_partial_output_and_trace(tmp_path):
    config = _config(tmp_path)
    reports = config.target_diagnostic_reports_dir()
    traces = config.target_agent_debug_dir()

    class Analyzer:
        global_config = config

        @preserve_stage_attempt("network")
        async def run(self, *, fail=False, phase="full"):
            output = reports / "network_reports"
            output.mkdir(parents=True)
            (output / "result.json").write_text(json.dumps({"partial": fail}))
            trace = traces / "network_analyzer"
            trace.mkdir(parents=True)
            (trace / "trace.md").write_text("exact attempted work")
            if fail:
                raise ValueError("rejected references")
            return SimpleNamespace(execution=AnalysisExecution(tasks={}))

    asyncio.run(Analyzer().run())
    first = next((reports / ".attempts/network").iterdir())
    before = {p.relative_to(first): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in first.rglob("*") if p.is_file()}
    import pytest
    with pytest.raises(ValueError, match="rejected references"):
        asyncio.run(Analyzer().run(fail=True))
    assert before == {p.relative_to(first): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in first.rglob("*") if p.is_file()}
    second = next(p for p in (reports / ".attempts/network").iterdir() if p != first)
    assert json.loads((second / "attempt.json").read_text())["status"] == "failed"
    assert json.loads((second / "previous/reports/result.json").read_text()) == {"partial": False}
    assert json.loads((second / "artifacts/reports/result.json").read_text()) == {"partial": True}
    assert (second / "artifacts/traces/trace.md").read_text() == "exact attempted work"


def test_real_config_set_values_are_preserved_without_pre_dispatch_failure(tmp_path):
    from fmst_analyzer.global_config import GlobalConfig
    config = GlobalConfig()
    config.setup_workdir(tmp_path)
    config.current_target = "fixture"

    class Analyzer:
        global_config = config

        @preserve_stage_attempt("init_launch")
        async def run(self):
            return SimpleNamespace(execution=AnalysisExecution(tasks={}))

    asyncio.run(Analyzer().run())
    record = next(config.target_diagnostic_reports_dir().glob(".attempts/init_launch/*/attempt.json"))
    data = json.loads(record.read_text())
    assert data["status"] == "complete"
    assert data["settings"]["file_resolver_normal_fs_ext_allowlist"] == sorted(config.file_resolver_normal_fs_ext_allowlist)


def test_public_generator_and_runner_entries_do_not_accept_stage_models():
    generator_parameters = inspect.signature(InterventionGenerator.run).parameters
    runner_parameters = inspect.signature(RehostingRunner.run).parameters

    assert "plan" not in generator_parameters
    assert "catalog" not in generator_parameters
    assert "plan" not in runner_parameters
    assert "catalog" not in runner_parameters
    assert "generation" not in runner_parameters
