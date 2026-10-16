"""Execution failures must never masquerade as completed semantic analysis."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from fmst_basic.agent import AgentProviderError
from fmst_analyzer.analysis.base.execution import (
    AnalysisExecution, ExecutionTracker, diagnostic_reason, execution_tracker, record_analysis_execution,
)
from fmst_analyzer.testing.pipeline_tester import _cache_matches_phase

FIXTURES = Path(__file__).parent / "fixtures/g2_integrity"


def test_status_is_derived_and_static_cannot_contain_agent_work():
    raw = {"tasks": {"resource:r1": {"subject_id": "r1", "status": "failed",
           "failure": {"kind": "provider", "reason": "budget_exceeded"}}}, "status": "complete"}
    execution = AnalysisExecution.model_validate(raw)
    assert execution.status == "failed"
    assert AnalysisExecution.model_validate_json(execution.model_dump_json()) == execution
    with pytest.raises(ValueError, match="budget_exceeded"):
        execution.require_complete()
    with pytest.raises(ValueError, match="static"):
        execution.validate_phase("static")
    with pytest.raises(ValidationError, match="tasks"):
        AnalysisExecution.model_validate({"status": "complete"})


def test_diagnostic_redaction_preserves_error_code_and_complete_reason():
    error = RuntimeError('budget_exceeded: {"api_key": "private-key-value"}; Authorization=Bearer hidden-token; details=' + "x" * 10000)
    reason = diagnostic_reason(error)
    assert "private-key-value" not in reason and "hidden-token" not in reason
    assert "budget_exceeded" in reason and reason.endswith("x" * 10000)


def test_cancelled_task_records_uncompleted_subject():
    async def run():
        tracker = ExecutionTracker()
        ready = asyncio.Event()
        async def pending():
            ready.set()
            await asyncio.Event().wait()
        task = asyncio.create_task(tracker.call("resource", "r1", pending))
        await ready.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return tracker.record
    execution = asyncio.run(run())
    assert execution.status == "failed"
    assert execution.tasks["resource:r1"].failure.kind == "cancelled"


def test_network_provider_failure_persists_and_cli_fails(tmp_path, monkeypatch):
    from fmst_analyzer.analysis.network_analyzer.analyzer import NetworkAnalyzer
    from fmst_analyzer.analysis.network_analyzer.analyzer_schema import NetworkAnalysisResult
    from fmst_analyzer.analysis.network_analyzer.interaction_agent import NetworkInteractionAgent
    from fmst_analyzer.testing.stages.test_network_analyzer import test_network_analyzer as stage
    sample = NetworkAnalysisResult.model_validate_json((FIXTURES / "network_static.json").read_bytes())
    rootfs = tmp_path / "rootfs"
    binary = rootfs / "userfs/bin/ntpclient"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"synthetic target identity")
    reports = tmp_path / "reports"
    config = SimpleNamespace(workdir=tmp_path, fw_rootfs_path=rootfs,
        agent_concurrency_limit=1, target_diagnostic_reports_dir=lambda: reports,
        target_agent_debug_dir=lambda: tmp_path / "traces")
    monkeypatch.setattr(NetworkAnalyzer, "_collect_callsites", lambda *_: sample.callsites)
    calls = []
    async def fail(self, view, root, seed, catalog, *, phase):
        calls.append(seed.callsite_id)
        raise AgentProviderError("budget_exceeded", provider="test", model="test")
    monkeypatch.setattr(NetworkInteractionAgent, "_analyze_resource", fail)
    result = asyncio.run(NetworkAnalyzer(config).run(SimpleNamespace(root=SimpleNamespace(name="ntpclient", binary_path=binary))))
    assert calls and len(calls) == 1
    assert result.execution.status == "failed"
    assert result.analyses == [] and result.planning_findings == {}
    assert result.execution.unsuccessful_subjects("network") == set(sample.callsites)
    assert not _cache_matches_phase(result, "full")
    source = reports / "network_reports/network_analysis_result.json"
    assert not source.exists()
    diagnostic = next(reports.glob(".attempts/network/*/artifacts/reports/network_analysis_result.json"))
    assert NetworkAnalysisResult.model_validate_json(diagnostic.read_bytes()) == result
    passed, reason = asyncio.run(stage(SimpleNamespace(ensure_network_analyzer_result=AsyncMock(return_value=result))))
    assert not passed and "budget_exceeded" in reason
    attempts = list((reports / ".attempts/network").glob("*/attempt.json"))
    assert len(attempts) == 1
    assert json.loads(attempts[0].read_text())["status"] == "failed"


def test_ipc_failed_site_is_execution_accounting_not_semantic_unknown(tmp_path):
    from fmst_analyzer.analysis.ipc_analyzer.schema import IPCAnalysisResult, CallsiteDisposition
    from fmst_analyzer.analysis.ipc_analyzer.controller import IPCResultController
    from fmst_analyzer.analysis.ipc_analyzer.reports import persist_result, render_index
    sample = IPCAnalysisResult.model_validate_json((FIXTURES / "ipc30/ipc_static.json").read_bytes())
    @record_analysis_execution
    async def run():
        async def fail():
            raise AgentProviderError("budget_exceeded", provider="test")
        for fact in sample.callsites:
            await execution_tracker().call("site", fact.callsite_id, fail)
        return IPCResultController(tmp_path).merge_site_resolutions(sample, [])
    result = asyncio.run(run())
    assert result.execution.status == "failed"
    assert result.channels == [] and result.planning_findings == {}
    assert {item.disposition for item in result.callsite_accounting} == {CallsiteDisposition.EXECUTION_FAILED}
    loaded = persist_result(result, tmp_path / "ipc_reports")
    assert loaded == result
    assert "budget_exceeded" in render_index(result)


@pytest.mark.parametrize("kind", ["file", "network", "process", "ipc", "init"])
def test_execution_is_required_and_partial_full_is_not_cacheable(kind):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog.assembler import SOURCE_MODELS
    types = {"file": "file", "network": "network", "process": "process", "ipc": "ipc", "init": "init_launch"}
    model = next(model for source, (_, model) in SOURCE_MODELS.items() if source.value == types[kind])
    path = (FIXTURES / "ipc30" if kind == "ipc" else FIXTURES) / f"{kind}_full.json"
    data = json.loads(path.read_text())
    data.pop("execution")
    with pytest.raises(ValidationError, match="execution"):
        model.model_validate(data)
    result = model.model_validate_json(path.read_bytes())
    execution = AnalysisExecution(tasks={
        "probe:complete": {"subject_id": "complete", "status": "completed", "failure": None},
        "probe:failed": {"subject_id": "failed", "status": "failed", "failure": {"kind": "provider", "reason": "budget_exceeded"}},
    })
    assert execution.status == "partial"
    assert not _cache_matches_phase(result.model_copy(update={"execution": execution}), "full")
