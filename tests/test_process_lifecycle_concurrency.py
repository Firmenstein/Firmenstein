"""Bounded fan-out, phase gate, and fail-closed Agent behavior."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_basic.agent.analysis_agent import AgentProviderError
from fmst_analyzer.analysis.process_lifecycle import (
    ProcessCodeEvidence,
    ProcessEventCallsite,
    ProcessEventDisposition,
    ProcessEventKind,
    ProcessLifecycleAgentResult,
)
from fmst_analyzer.analysis.process_lifecycle import process_lifecycle_agent as module
from fmst_analyzer.analysis.process_lifecycle.process_lifecycle_agent import (
    ProcessLifecycleAgent,
)


def _callsites(count: int) -> list[ProcessEventCallsite]:
    return [ProcessEventCallsite(
        callsite_id=f"process-event:{index}",
        binary_name="httpd",
        function_name=f"fn_{index}",
        function_ea=0x1000 + index,
        snapshot_hash=f"snap-{index}",
        ctree_index=index,
        source_ea=0x2000 + index,
        line_number=10,
        column_number=2,
        api_name="exit",
        event_kind=ProcessEventKind.TERMINATION,
    ) for index in range(count)]


def _config(tmp_path: Path, limit: int = 3):
    return SimpleNamespace(
        workdir=tmp_path,
        agent_provider="codex",
        diagnosis_model="test-model",
        agent_concurrency_limit=limit,
        target_agent_debug_dir=lambda: tmp_path / "agent_debug",
    )


def test_fanout_is_bounded_and_one_result_per_callsite(tmp_path):
    state = SimpleNamespace(in_flight=0, peak=0, total=0)
    lock = asyncio.Lock()

    class FakeAgent:
        def __init__(self, **kwargs):
            pass

        async def analyze(self, **kwargs):
            async with lock:
                state.in_flight += 1
                state.total += 1
                state.peak = max(state.peak, state.in_flight)
            try:
                await asyncio.sleep(0.01)
                function_name = kwargs["function_name"]
                return ProcessLifecycleAgentResult(
                    finding={
                        "summary": "Runtime failure reaches exit.",
                        "claims": [{"kind": "guarantee", "statement": "Failure terminates the runtime handler.",
                                    "evidence_refs": ["/evidence/0"], "unknown_kind": None}],
                        "reachability_refs": ["/evidence/0"], "coverage_refs": [],
                    },
                    disposition=ProcessEventDisposition.RUNTIME_ONLY,
                    summary="runtime handler exit",
                    evidence=[ProcessCodeEvidence(
                        claim="runtime path reaches exit",
                        binary_name="httpd",
                        function_name=function_name,
                        line_number=10,
                        api_name="exit",
                    )],
                )
            finally:
                async with lock:
                    state.in_flight -= 1

    async def run():
        runner = ProcessLifecycleAgent(
            _config(tmp_path), asyncio.Semaphore(3)
        )
        with patch.object(module, "CodeAnalyzerAgent", FakeAgent):
            return await runner.analyze_callsites(
                view=None,
                callsites=_callsites(17),
                phase="full",
            )

    assessments = asyncio.run(run())
    assert state.total == 17
    assert state.peak <= 3
    assert len(assessments) == 17


def test_static_phase_gates_agent_at_dispatch_boundary(tmp_path):
    class MustNotConstruct:
        def __init__(self, **kwargs):
            raise AssertionError("Agent constructed in static phase")

    async def run():
        runner = ProcessLifecycleAgent(
            _config(tmp_path), asyncio.Semaphore(1)
        )
        with patch.object(module, "CodeAnalyzerAgent", MustNotConstruct):
            return await runner.analyze_callsites(
                view=None,
                callsites=_callsites(2),
                phase="static",
            )

    assert asyncio.run(run()) == {}


def test_agent_failure_has_no_semantic_assessment(tmp_path):
    class FailingAgent:
        def __init__(self, **kwargs):
            pass

        async def analyze(self, **kwargs):
            raise RuntimeError("structured output failure")

    async def run():
        runner = ProcessLifecycleAgent(_config(tmp_path), asyncio.Semaphore(1))
        with patch.object(module, "CodeAnalyzerAgent", FailingAgent):
            results = await runner.analyze_callsites(view=None, callsites=_callsites(1), phase="full")
        return results, runner.execution.record

    results, execution = asyncio.run(run())
    assert results == {}
    assert execution.status == "failed"
    assert "structured output failure" in next(iter(execution.tasks.values())).failure.reason


def test_provider_error_preserves_completed_siblings_and_stops_queued_requests(tmp_path):
    state = SimpleNamespace(started=0)

    class FailingProviderAgent:
        def __init__(self, **kwargs):
            pass

        async def analyze(self, **kwargs):
            state.started += 1
            if kwargs["function_name"] == "fn_0":
                # Let one sibling enter the provider before returning the failure.
                await asyncio.sleep(0)
                raise AgentProviderError("用户速率限制", provider="claude", model="test", http_status=429)
            await asyncio.sleep(0.01)
            return ProcessLifecycleAgentResult(
                finding={"summary": "Known runtime-only exit.",
                    "claims": [{"kind": "guarantee", "statement": "The runtime branch exits.", "evidence_refs": ["/evidence/0"], "unknown_kind": None}],
                    "reachability_refs": ["/evidence/0"], "coverage_refs": []},
                disposition=ProcessEventDisposition.RUNTIME_ONLY, summary="runtime exit",
                evidence=[ProcessCodeEvidence(claim="exit branch", binary_name="httpd",
                    function_name=kwargs["function_name"], line_number=10, api_name="exit")],
            )

    async def run():
        runner = ProcessLifecycleAgent(_config(tmp_path, limit=2), asyncio.Semaphore(2))
        with patch.object(module, "CodeAnalyzerAgent", FailingProviderAgent):
            results = await runner.analyze_callsites(view=None, callsites=_callsites(5), phase="full")
        return results, runner.execution.record

    results, execution = asyncio.run(run())
    assert "process-event:0" not in results
    assert results
    assert execution.status == "partial"
    assert len(execution.tasks) == 5
    assert execution.tasks["process:process-event:0"].failure.kind == "provider"
    assert state.started < 5
    assert any(item.status == "not_started" for item in execution.tasks.values())
