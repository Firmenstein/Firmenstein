"""Concurrency invariants for FileResolver's shared LLM Semaphore.

Verifies the property documented at
``FileResolver.__init__:_llm_concurrency_sem``: a single sem shared
across Node 3 path fallback + Node 5 small/map/reduce bounds peak in-flight LLM
calls to ``agent_concurrency_limit`` AND never deadlocks under nested
fan-out (large groups whose map workers must acquire from the same pool
their parent task is dispatched on).

LLM agents are mocked — the test runs in milliseconds and burns no
provider tokens. The mock substitutes ``CodeAnalyzerAgent`` at the import
site inside ``resource_analysis_agent``;
the real ``async with self._concurrency_sem`` wrappers stay intact.
Every fake LLM call increments a shared in-flight counter, sleeps
briefly to give other tasks a chance to enter, then decrements. We
assert the recorded peak is ≤ the configured limit.

Deadlock detection: the whole gather is wrapped in ``asyncio.wait_for``
with a generous timeout. If the orchestrator + sem combination would
deadlock under the test's fan-out shape, the timeout fires and the
test fails loudly.
"""
import asyncio
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


class _FakeAnalysisView:
    """Minimal structural view required before an LLM call is dispatched."""

    root = SimpleNamespace(name="binX")
    adg = SimpleNamespace(get_binary_callgraphs=lambda: {})

    def collect_effective_callsites(self, binary_name, function_name):
        return [], 0


class _Tracker:
    """Atomic peak / total counter shared by all fake LLM calls."""

    def __init__(self):
        self.in_flight = 0
        self.peak = 0
        self.total = 0
        self.lock = asyncio.Lock()

    async def enter(self):
        async with self.lock:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            self.total += 1

    async def exit(self):
        async with self.lock:
            self.in_flight -= 1


def _make_fake_code_analyzer_agent(tracker: _Tracker, sleep_s: float):
    """Return a class drop-in for CodeAnalyzerAgent.

    Real CodeAnalyzerAgent.analyze() makes the actual LLM round-trip.
    The fake tracks concurrent entries via ``tracker``, sleeps to give
    other tasks the chance to also enter, then returns a synthetic
    instance of whatever output_format the constructor was given.
    """

    class _FakeCodeAnalyzerAgent:
        def __init__(self, *, task_prompt, output_format,
                     model=None, max_corrections=None, **kwargs):
            self._output_format = output_format

        async def analyze(self, *, user_message, view, binary_name=None,
                          function_name=None, trace_dir=None, callsite_line=None,
                          output_validator=None, trace_name=None):
            await tracker.enter()
            try:
                await asyncio.sleep(sleep_s)
                output = _make_synthetic_output(self._output_format, user_message)
                if output_validator is not None:
                    output_validator(output)
                return output
            finally:
                await tracker.exit()

    return _FakeCodeAnalyzerAgent


def _make_synthetic_output(output_format, user_message):
    """Build a minimal-valid instance of FileResourceReport or
    FileResourceMapResult depending on which schema the agent expects."""
    from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
        FileResourceAnalysisOutput,
        FileResourceMapResult,
        FileResourceReduceResult,
        FileResourceClass,
    )
    from fmst_analyzer.analysis.base.report_schema import CallSiteReport

    reports = [
        CallSiteReport(
            callsite_id=callsite_id,
            containing_function_purpose="synthetic",
            setup_details="synthetic",
            usage_reports=[],
        )
        for callsite_id in re.findall(r"callsite_id: `([^`]+)`", user_message)
    ]

    finding = dict(
        summary="Synthetic concurrency fixture; semantics unassessed.",
        claims=[dict(kind="unknown", statement="No semantic analysis in concurrency test.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[],
    )
    if output_format is FileResourceAnalysisOutput:
        return FileResourceAnalysisOutput(
            callsite_reports=reports,

            summary="synthetic",
            finding=finding,
        )
    if output_format is FileResourceMapResult:
        return FileResourceMapResult(callsite_reports=reports)
    if output_format is FileResourceReduceResult:
        return FileResourceReduceResult(

            summary="synthetic",
            finding=finding,
        )
    raise AssertionError(
        f"unexpected output_format in test: {output_format!r}"
    )


def _make_callsites(group_idx: int, n: int):
    """Build n synthetic FileCallsites belonging to one resource."""
    from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
        FileCallsite, FileResourceClass,
    )

    cs_list = []
    for j in range(n):
        cs_id = f"binX::funcG{group_idx}::L{j}::open"
        cs_list.append(FileCallsite(
            callsite_id=cs_id,
            candidate_idx=0,
            profile_key=f"{cs_id}#0",
            binary_name="binX",
            function_name=f"funcG{group_idx}",
            line_number=j,
            api_name="open",
            path_arg_index=0,
            requested_path=f"/dev/test{group_idx}",
            path_value=f"/dev/test{group_idx}",
            path_kind="concrete",
            resolution_source="literal_static",
            resource_class=FileResourceClass.PSEUDO_FS_DEV,
        ))
    return cs_list


def _make_resource(group_idx: int, n_callsites: int):
    from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
        FileResource, FileResourceClass,
    )

    return FileResource(
        resource_group_id=f"rg_{group_idx:03d}",
        path_value=f"/dev/test{group_idx}",
        path_kind="concrete",
        resource_class=FileResourceClass.PSEUDO_FS_DEV,
        callsites=_make_callsites(group_idx, n_callsites),
    )


class TestFileResourceAnalysisConcurrency(unittest.IsolatedAsyncioTestCase):
    """Bounded peak + no-deadlock under heavy nested fan-out.

    Pre-fix: each fan-out point owned its own ``Semaphore(limit)`` so
    a 20-large-groups × 5-map-workers shape would let the provider see
    up to 100 concurrent calls, defeating the configured limit.

    Post-fix: a single shared ``Semaphore(limit)`` lives on
    ``FileResolver`` and is acquired only at the actual LLM-call
    layer (``agent.analyze`` / ``agent.ainvoke``). The orchestrator
    layer never holds a permit while waiting on inner workers,
    eliminating the otherwise inevitable deadlock when limit is
    saturated by parent tasks.
    """

    LIMIT = 4
    CHUNK_SIZE = 5
    N_LARGE_GROUPS = 20
    N_CALLSITES_PER_LARGE = 25  # → 5 chunks per group
    SLEEP_S = 0.005             # tiny per-call delay to force overlap
    DEADLOCK_TIMEOUT_S = 10.0   # generous; real run completes in <1s

    async def _run_with_mocks(self, resources: dict) -> _Tracker:
        from fmst_analyzer.analysis.file_resolver import (
            analyzer as fr_analyzer_mod,
        )
        from fmst_analyzer.analysis.file_resolver import (
            resource_analysis_agent as resource_agent_mod,
        )
        from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
            FileResolverResult,
        )
        from fmst_analyzer.global_config import GlobalConfig

        gc = GlobalConfig()
        gc.agent_concurrency_limit = self.LIMIT
        gc.file_resolver_resource_chunk_size = self.CHUNK_SIZE
        # _node5_analyze_resources touches global_config.target_agent_debug_dir().
        # Stub it to a temp path so the call doesn't blow up on the
        # missing-current_target assertion.
        import tempfile
        tmp = tempfile.mkdtemp(prefix="fr_concurrency_test_")
        gc.workdir = Path(tmp)
        gc.current_target = "binX"
        (Path(tmp) / "agent_debug" / "binX").mkdir(parents=True, exist_ok=True)

        tracker = _Tracker()

        # Patch the imported names at the call sites (resource_analysis_agent module)
        # so the real CodeAnalyzerAgent / provider adapter are never
        # constructed. The shared sem stays in the loop because
        # FileResourceAnalysisAgent's `async with self._concurrency_sem:` blocks are
        # executed verbatim against the fake call.
        fake_cag = _make_fake_code_analyzer_agent(tracker, self.SLEEP_S)
        with patch.object(resource_agent_mod, "CodeAnalyzerAgent", fake_cag):
            resolver = fr_analyzer_mod.FileResolver(gc)
            analyses = await asyncio.wait_for(
                resolver._node5_analyze_resources(
                    view=_FakeAnalysisView(), resources=resources, phase="full",
                ),
                timeout=self.DEADLOCK_TIMEOUT_S,
            )
            self.assertEqual(set(analyses), set(resources))

        return tracker

    async def test_large_group_fanout_bounded_and_no_deadlock(self):
        """20 large groups × 5 chunks each = 100 map calls + 20 reduces.

        The pre-fix code would have allowed peak ~100. Post-fix the peak
        must stay ≤ LIMIT (4) and the gather must not deadlock.
        """
        resources = {
            f"rg_{g:03d}": _make_resource(g, self.N_CALLSITES_PER_LARGE)
            for g in range(self.N_LARGE_GROUPS)
        }
        tracker = await self._run_with_mocks(resources)

        expected_total = self.N_LARGE_GROUPS * (
            (self.N_CALLSITES_PER_LARGE + self.CHUNK_SIZE - 1)
            // self.CHUNK_SIZE   # map workers
            + 1                  # reduce
        )
        self.assertEqual(
            tracker.total, expected_total,
            msg=(
                f"expected {expected_total} fake LLM calls "
                f"({self.N_LARGE_GROUPS} groups × "
                f"({self.N_CALLSITES_PER_LARGE // self.CHUNK_SIZE} maps + "
                f"1 reduce)), saw {tracker.total}"
            ),
        )
        self.assertLessEqual(
            tracker.peak, self.LIMIT,
            msg=(
                f"peak in-flight LLM calls = {tracker.peak} > "
                f"limit = {self.LIMIT}; the shared Semaphore is not "
                f"correctly gating one of small / map / reduce paths."
            ),
        )

    async def test_small_group_path_also_bounded(self):
        """Small groups (≤ chunk_size) take the _analyze_small_group path,
        which uses a different sem-acquire site than the map / reduce
        paths. Verify it's gated too."""
        n_small = 30
        resources = {
            f"rg_s_{g:03d}": _make_resource(g, self.CHUNK_SIZE - 1)
            for g in range(n_small)
        }
        tracker = await self._run_with_mocks(resources)

        # Each small group → exactly 1 LLM call (the _analyze_small_group call).
        self.assertEqual(tracker.total, n_small)
        self.assertLessEqual(
            tracker.peak, self.LIMIT,
            msg=(
                f"peak in-flight LLM calls = {tracker.peak} > "
                f"limit = {self.LIMIT}; small-group path's "
                f"_concurrency_sem wrap is missing or broken."
            ),
        )

    async def test_mixed_small_and_large_no_deadlock(self):
        """Worst-case shape: small + large mixed, where without proper
        gating the orchestrator might saturate with large groups holding
        permits and deadlock waiting for inner map workers."""
        resources = {}
        for g in range(10):  # 10 large
            resources[f"rg_L_{g:03d}"] = _make_resource(
                g, self.N_CALLSITES_PER_LARGE,
            )
        for g in range(20):  # 20 small
            resources[f"rg_S_{g:03d}"] = _make_resource(
                100 + g, self.CHUNK_SIZE - 1,
            )

        tracker = await self._run_with_mocks(resources)

        n_chunks_per_large = (
            (self.N_CALLSITES_PER_LARGE + self.CHUNK_SIZE - 1)
            // self.CHUNK_SIZE
        )
        expected_total = 10 * (n_chunks_per_large + 1) + 20
        self.assertEqual(tracker.total, expected_total)
        self.assertLessEqual(
            tracker.peak, self.LIMIT,
            msg=f"peak {tracker.peak} > limit {self.LIMIT}",
        )

    async def test_one_resource_failure_is_execution_failure(self):
        import tempfile

        from fmst_analyzer.analysis.file_resolver import analyzer as analyzer_mod
        from fmst_analyzer.analysis.file_resolver import (
            resource_analysis_agent as resource_agent_mod,
        )
        from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
            FileResolverResult,
        )
        from fmst_analyzer.global_config import GlobalConfig

        class _FailingAgent:
            def __init__(self, *args, **kwargs):
                pass

            async def analyze_resource(self, **kwargs):
                raise RuntimeError("synthetic resource failure")

        config = GlobalConfig()
        config.workdir = Path(tempfile.mkdtemp(prefix="fr_gap_test_"))
        config.current_target = "binX"
        resolver = analyzer_mod.FileResolver(config)
        resource = _make_resource(0, 1)

        with patch.object(
            resource_agent_mod,
            "FileResourceAnalysisAgent",
            _FailingAgent,
        ):
            analyses = await resolver._node5_analyze_resources(
                view=_FakeAnalysisView(),
                resources={resource.resource_group_id: resource},
                phase="full",
            )

        self.assertEqual(analyses, {})
        self.assertEqual(
            resolver.execution.record.tasks[f"resource:{resource.resource_group_id}"].failure.reason,
            "RuntimeError: synthetic resource failure",
        )
        self.assertEqual(resolver.execution.record.status, "failed")


if __name__ == "__main__":
    unittest.main()
