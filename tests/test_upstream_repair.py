"""Source-bound recovery through the production pipeline; zero native dispatch."""
import asyncio
import errno
import json
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fmst_basic.agent import AgentProviderError
from fmst_analyzer.analysis.base.execution import AnalysisIncompleteError, ExecutionTracker
from fmst_analyzer.runner.repair_intake import UpstreamRepairInput, blocks_new_runner
from test_firmprobe_admission import static_elf, dynamic_elf


def inputs(tmp_path):
    root = tmp_path / "rootfs"
    target = root / "bin/service"
    target.parent.mkdir(parents=True)
    target.write_bytes(static_elf())
    reports = tmp_path / "reports"
    config = SimpleNamespace(workdir=tmp_path, current_target="service", fw_rootfs_path=root,
        runtime_workspace=tmp_path / "framework", runner_backend="agent_container",
        target_diagnostic_reports_dir=lambda: reports, target_agent_debug_dir=lambda: tmp_path / "debug")
    config.runtime_workspace.mkdir()
    return root, target, reports, config


def incomplete(error):
    async def run():
        tracker = ExecutionTracker()
        await tracker.call("probe", "good", AsyncMock(return_value="fact"))
        async def fail(): raise error
        await tracker.call("probe", "bad", fail)
        with pytest.raises(AnalysisIncompleteError) as caught:
            tracker.record.require_complete()
        return caught.value
    return asyncio.run(run())


@pytest.mark.parametrize("error", [AgentProviderError("response interrupted", provider="test"),
    OSError(errno.EMFILE, "fds"), OSError(errno.ENFILE, "global fds"), OSError(errno.ENOMEM, "memory"),
    OSError(errno.ENOSPC, "disk"), asyncio.CancelledError()])
def test_stops_survive_wrappers_groups_and_aggregate(error):
    wrapped = RuntimeError("outer failure")
    wrapped.__cause__ = error
    assert blocks_new_runner(wrapped)
    assert blocks_new_runner(BaseExceptionGroup("group", [ValueError("ordinary"), error]))
    if isinstance(error, Exception):
        aggregate = incomplete(wrapped)
        assert blocks_new_runner(aggregate)
        assert aggregate.execution.status == "partial"
        assert aggregate.execution.tasks["probe:good"].failure is None


@pytest.mark.parametrize("error", [ValueError("unsupported loader"), RuntimeError("CTree mapping"),
                                   TimeoutError("Bash exceeded 120s")])
def test_ordinary_failures_are_recoverable_with_failed_ledger(error):
    aggregate = incomplete(error)
    assert not blocks_new_runner(aggregate)
    assert aggregate.execution.tasks["probe:bad"].status == "failed"
    assert aggregate.execution.tasks["probe:bad"].failure.reason.endswith(str(error))


def test_resource_and_nested_provider_close_analysis_dispatch_gate():
    async def run(error):
        tracker = ExecutionTracker()
        async def fail(): raise error
        await tracker.call("probe", "bad", fail)
        never = AsyncMock(return_value="should not run")
        await tracker.call("probe", "withheld", never)
        never.assert_not_called()
        return tracker.record
    wrapped = RuntimeError("SDK wrapper")
    wrapped.__cause__ = AgentProviderError("response interrupted", provider="test")
    for error in (wrapped, OSError(errno.EMFILE, "fds")):
        record = asyncio.run(run(error))
        assert record.tasks["probe:withheld"].status == "not_started"


def test_repair_source_is_bound_and_keeps_missing_loader_as_evidence(tmp_path):
    root, target, reports, config = inputs(tmp_path)
    target.write_bytes(dynamic_elf(needed="absent.so"))
    repair = UpstreamRepairInput.capture(error=ValueError("missing dependency"), stage="dependency_graph",
                                        rootfs=root, target=target)
    assert repair.validate_source(root) == target
    (root / "new-file").write_text("source mutation")
    with pytest.raises(ValueError, match="identity changed"):
        repair.validate_source(root)


@pytest.mark.parametrize("stage", ["dependency_graph", "decompile", "ctree_validation", "ipc", "file", "network",
                                   "process", "init_launch", "plan", "generation", "runner_input_preparation"])
def test_pipeline_upstream_failure_enters_one_runner_with_original_budget(tmp_path, monkeypatch, stage):
    module = import_module("fmst_analyzer.FirmAnalyzer")
    root, target, reports, config = inputs(tmp_path)
    obj = module.FirmAnalyzer({"image_name":"fixture", "rootfs_path":str(root), "all_binaries":[str(target)]},
                              "service", config, run_after_generation=True, runner_timeout_seconds=3303.72)
    failure = incomplete(RuntimeError("exact upstream tool failure"))
    async def pipeline():
        obj._stage = stage
        failed_report = reports / ".attempts/file/current/artifacts/reports/failed.json"
        failed_report.parent.mkdir(parents=True)
        failed_report.write_text(failure.execution.model_dump_json())
        raise failure
    obj._run_pipeline = pipeline
    calls = []
    class Runner:
        async def run(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(status="success")
    budgets = []
    def runner(config, **options):
        budgets.append(options["runtime_timeout_seconds"])
        return Runner()
    monkeypatch.setattr(import_module("fmst_analyzer.runner"), "create_runner", runner)
    asyncio.run(obj.run())
    assert budgets == [3303.72] and len(calls) == 1
    assert calls[0]["repair_input"].failed_stage == stage
    assert calls[0]["view"] is None
    assert json.loads((reports / "pipeline_failure.json").read_text())["execution"]["status"] == "partial"
    assert (reports / ".attempts/file/current/artifacts/reports/failed.json").exists()


@pytest.mark.parametrize("reason", ["provider", "resource", "no_authorization", "skip_synthesis", "legacy",
                                     "runner_entered", "source_changed", "invalid_target"])
def test_pipeline_does_not_bypass_stop_identity_or_second_runner(tmp_path, monkeypatch, reason):
    module = import_module("fmst_analyzer.FirmAnalyzer")
    root, target, reports, config = inputs(tmp_path)
    config.runner_backend = "legacy" if reason == "legacy" else "agent_container"
    obj = module.FirmAnalyzer({"image_name":"fixture", "rootfs_path":str(root), "all_binaries":[str(target)]},
        "service", config, run_after_generation=reason != "no_authorization", skip_synthesis=reason == "skip_synthesis")
    stop_error = (incomplete(AgentProviderError("response interrupted", provider="test")) if reason == "provider"
                  else incomplete(OSError(errno.EMFILE, "fds")) if reason == "resource" else None)
    async def pipeline():
        obj._stage = "file"
        if reason == "source_changed": (root / "new").write_text("mutation")
        if reason == "runner_entered": obj._runner_entered = True
        if stop_error is not None: raise stop_error
        raise ValueError("upstream failed")
    obj._run_pipeline = pipeline
    if reason == "invalid_target": target.write_bytes(b"not an ELF")
    monkeypatch.setattr(import_module("fmst_analyzer.runner"), "create_runner",
                        lambda *a, **k: pytest.fail("Must not dispatch"))
    with pytest.raises((ValueError, AnalysisIncompleteError)):
        asyncio.run(obj.run())


def test_explicit_runner_stage_rejects_upstream_source_mutation(tmp_path, monkeypatch):
    module = import_module("fmst_analyzer.testing.stages.test_intervention_runner")
    root, target, reports, config = inputs(tmp_path)
    async def prepare():
        (root / "new").write_text("mutation")
        raise ValueError("IDA failed")
    tester = SimpleNamespace(global_config=config, fw_rootfs_path=root, target_binary_path=target,
                             ensure_analysis_view=prepare)
    monkeypatch.setattr(module, "create_runner", lambda *a, **k: pytest.fail("Must not dispatch changed source"))
    ok, reason = asyncio.run(module.test_intervention_runner(tester))
    assert not ok and "identity changed" in reason


def test_runner_failure_after_handoff_is_recorded_without_second_runner(tmp_path, monkeypatch):
    module = import_module("fmst_analyzer.FirmAnalyzer")
    root, target, reports, config = inputs(tmp_path)
    obj = module.FirmAnalyzer({"image_name":"fixture", "rootfs_path":str(root), "all_binaries":[str(target)]},
                              "service", config, run_after_generation=True)
    async def pipeline():
        obj._stage = "decompile"
        raise ValueError("CTree mapping")
    obj._run_pipeline = pipeline
    primary = AgentProviderError("response interrupted", provider="test")
    runner = SimpleNamespace(run=AsyncMock(side_effect=primary))
    factories = []
    def create(*a, **k):
        factories.append(k)
        return runner
    monkeypatch.setattr(import_module("fmst_analyzer.runner"), "create_runner", create)
    with pytest.raises(AgentProviderError) as caught:
        asyncio.run(obj.run())
    assert caught.value is primary and len(factories) == 1 and runner.run.await_count == 1
    assert json.loads((reports / "pipeline_failure.json").read_text())["failed_stage"] == "decompile"
    second = json.loads((reports / "runner_handoff_failure/pipeline_failure.json").read_text())
    assert second["failed_stage"] == "runner" and second["dispatch_blocked"]
