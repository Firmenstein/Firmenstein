"""FileResourceAnalysisAgent — lifecycle analysis for one exact resource.

Produces one ``FileResourceReport`` per exact typed resource. Size-gated:

- **Small group** (≤ ``file_resolver_resource_chunk_size`` open callsites):
  single ``CodeAnalyzerAgent`` call emits the entire FileResourceReport
  (per-callsite captures + top-level synthesis in one turn).
- **Large group** (> threshold): two-stage map-reduce.
    * Map: Python sorts callsites by (binary, function, line), slices
      into chunks of ≤ threshold; each chunk runs a CodeAnalyzerAgent
      worker returning ``FileResourceMapResult{callsite_reports}``. Workers
      run concurrently, gated by ``asyncio.Semaphore``.
    * Python concatenates all map workers' ``callsite_reports`` losslessly.
    * Reduce: a single provider call (no code tools — input
      is already structured) emits ``FileResourceReduceResult`` with
      ``coverage_flows`` / ``summary``. The
      ``observed_apis`` field on the final ``FileResourceReport`` is
      computed in Python from ``callsite_reports`` and never passes
      through reduce.
    * Python assembles the final ``FileResourceReport`` from Python-known
      metadata + map's callsite_reports + reduce's top-level fields.

Both paths produce identical ``FileResourceReport`` shape — downstream
consumers (persistence, reports rendering, synthesizer) cannot
distinguish which path was taken.
"""
from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError, validate_code_reference

import asyncio
import json
from pathlib import Path
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

from loguru import logger

from fmst_basic.agent.analysis_agent import gather_agent_tasks
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import (
    AnalysisView,
    EffectiveCallsite,
)
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    CodeAnalyzerAgent,
)
from fmst_analyzer.analysis.base.coverage_flow import resolve_coverage_flows
from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICallResolver
from fmst_analyzer.analysis.base.report_schema import CallSiteAnalysis
from fmst_analyzer.global_config import GlobalConfig

from .analyzer_schema import (
    CallSiteReport,
    FileResourceMapResult,
    FileResourceAnalysisOutput,
    FileResourceReduceResult,
    FileCallsite,
    FileResource,
    FileResourceReport,
)
from .resource_analysis_prompt import (
    FILE_RESOURCE_FULL_REPORT_TASK,
    FILE_RESOURCE_FULL_REPORT_USER,
    FILE_RESOURCE_MAP_TASK,
    FILE_RESOURCE_MAP_USER,
    FILE_RESOURCE_REDUCE_TASK,
    FILE_RESOURCE_REDUCE_USER,
)
from .grouping import CREATING_APIS
from .findings import FileResourceAnalysis


def _render_callsite_bullets(callsites: List[FileCallsite]) -> str:
    """Render a chunk of FileCallsites into the bulleted form the agent
    prompts expect. Stable ordering (binary, function, line)."""
    ordered = sorted(
        callsites,
        key=lambda cs: (cs.binary_name, cs.function_name, cs.line_number),
    )
    bullets = []
    for cs in ordered:
        bullets.append(
            f"  - callsite_id: `{cs.callsite_id}`\n"
            f"      binary: `{cs.binary_name}`, "
            f"function: `{cs.function_name}`, "
            f"line: L{cs.line_number}, "
            f"api: `{cs.api_name}`\n"
            f"      resolved path: `{cs.path_value}` "
            f"({cs.path_kind}, via `{cs.resolution_source}`)"
        )
    return "\n".join(bullets)


def _creating_callsites(resource: FileResource) -> List[FileCallsite]:
    """Filter the resource's callsites to just the creating ones.

    Normally all callsites in a FileResource are creating by construction,
    but the
    filter is defensive — if the input model ever gets loosened, the
    agent still only sees what it's contracted to report on.
    """
    return [cs for cs in resource.callsites if cs.api_name in CREATING_APIS]


def _validate_callsite_reports(
    callsites: List[FileCallsite],
    reports: List[CallSiteReport],
) -> None:
    """Require one report for every supplied creating callsite."""
    expected = Counter(cs.callsite_id for cs in callsites)
    actual = Counter(report.callsite_id for report in reports)
    if actual != expected:
        missing = list((expected - actual).elements())
        unexpected = list((actual - expected).elements())
        raise OutputValidationError(
            "FileResourceAnalysisAgent callsite accounting mismatch: "
            f"missing={missing}, unexpected_or_duplicate={unexpected}"
        )


def _validate_report_positions(callsite_reports, coverage_flows, view) -> None:
    positions = []
    for ri, report in enumerate(callsite_reports):
        positions.extend((f"/callsite_reports/{ri}/usage_reports/{ui}", usage)
                         for ui, usage in enumerate(report.usage_reports))
    for fi, flow in enumerate(coverage_flows):
        for field in ("setup", "use", "termination"):
            positions.extend((f"/coverage_flows/{fi}/{field}/{i}", entry)
                             for i, entry in enumerate(getattr(flow, field)))
    errors = []
    for label, entry in positions:
        try:
            validate_code_reference(view, binary_name=entry.binary_name,
                function_name=entry.function_name, line_number=entry.line_number)
        except OutputValidationError as error:
            errors.append(f"{label}: {error}")
    if errors:
        raise OutputValidationError("File source validation failed:\n" + "\n".join(errors))


def _has_position_claims(callsite_reports, coverage_flows) -> bool:
    return any(report.usage_reports for report in callsite_reports) or any(
        flow.setup or flow.use or flow.termination
        for flow in coverage_flows
    )


def _precompute_resource_usage_sites(
    view: AnalysisView,
    creating: List[FileCallsite],
) -> Dict[str, Tuple[List[EffectiveCallsite], int]]:
    """Collect per-callsite evidence before agent dispatch. Returns
    {callsite_id: (sites, total_count)} for every creating callsite
    used to assemble resource_usage_sites and total_usage_sites before binding."""
    out: Dict[str, Tuple[List[EffectiveCallsite], int]] = {}
    for cs in creating:
        sites, total = view.collect_effective_callsites(
            cs.binary_name, cs.function_name,
        )
        if not sites:
            logger.debug(
                f"[FileResolver] no usage sites from {view.root.name} "
                f"to {cs.binary_name}::{cs.function_name}"
            )
        out[cs.callsite_id] = (sites, total)
    return out


def _assemble_callsite_reports(
    analyses: List[CallSiteAnalysis],
    usage_sites_by_id: Dict[str, Tuple[List[EffectiveCallsite], int]],
) -> List[CallSiteReport]:
    """Attach verified evidence by source identity, preserving the Agent's order."""
    reports = []
    for analysis in analyses:
        sites, total = usage_sites_by_id[analysis.callsite_id]
        reports.append(CallSiteReport(
            **analysis.model_dump(include=set(CallSiteAnalysis.model_fields)),
            resource_usage_sites=[site.model_copy(deep=True) for site in sites],
            total_usage_sites=total,
        ))
    return reports


class FileResourceAnalysisAgent:
    """Produce one FileResourceReport per exact typed resource.

    Concurrency: every actual LLM request inside this agent (small-group
    full-report call, large-group map-worker call, large-group reduce
    call) is wrapped in ``async with self._concurrency_sem``. The same
    sem is shared with the FileResolver's other LLM-issuing nodes
    (Node 3 path fallback), so the provider sees at most
    ``agent_concurrency_limit`` in-flight requests across the whole
    pipeline regardless of how many resources are dispatched in
    parallel by the orchestrator.
    """

    def __init__(
        self,
        global_config: GlobalConfig,
        concurrency_sem: asyncio.Semaphore,
    ) -> None:
        self.global_config = global_config
        self._concurrency_sem = concurrency_sem
        self.model = global_config.diagnosis_model
        self.chunk_size = global_config.file_resolver_resource_chunk_size
        self._coverage_resolver_by_view: Dict[int, CoveredAPICallResolver] = {}


    def _coverage_resolver(
        self, view: AnalysisView,
    ) -> CoveredAPICallResolver:
        key = id(view)
        if key not in self._coverage_resolver_by_view:
            self._coverage_resolver_by_view[key] = CoveredAPICallResolver(view)
        return self._coverage_resolver_by_view[key]

    # ---------------------------------------------------------------
    # Public entry
    # ---------------------------------------------------------------

    async def analyze_resource(
        self,
        view: AnalysisView,
        resource: FileResource,
        trace_dir: Optional[Path] = None,
        *, phase: str,
    ) -> FileResourceAnalysis:
        """Return a FileResourceReport for ``resource``.

        Picks small-group or large-group path based on
        ``file_resolver_resource_chunk_size``. Output shape is identical
        either way.
        """
        if phase != "full":
            raise ValueError("FileResourceAnalysisAgent requires full phase")
        creating = _creating_callsites(resource)
        n = len(creating)
        if n == 0:
            raise ValueError(
                f"FileResource {resource.resource_group_id} has no creating "
                "callsites"
            )

        # One evidence view for both the Agent input and the final source records.
        usage_sites_by_id = _precompute_resource_usage_sites(view, creating)

        if n <= self.chunk_size:
            logger.info(
                f"[FileResourceAnalysisAgent] {resource.resource_group_id} "
                f"small-group path ({n} callsites, threshold {self.chunk_size})"
            )
            return await self._analyze_small_group(
                view, resource, creating, trace_dir, usage_sites_by_id, phase=phase,
            )

        logger.info(
            f"[FileResourceAnalysisAgent] {resource.resource_group_id} "
            f"large-group path ({n} callsites > threshold {self.chunk_size}) "
            f"— splitting into map workers"
        )
        return await self._analyze_large_group(
            view, resource, creating, trace_dir, usage_sites_by_id, phase=phase,
        )

    # ---------------------------------------------------------------
    # Small-group path
    # ---------------------------------------------------------------

    async def _analyze_small_group(
        self,
        view: AnalysisView,
        resource: FileResource,
        creating: List[FileCallsite],
        trace_dir: Optional[Path],
        usage_sites_by_id: Dict[str, Tuple[List[EffectiveCallsite], int]],
        *, phase: str,
    ) -> FileResourceAnalysis:
        """One Agent call produces resource evidence and its semantic finding."""
        if phase != "full":
            raise ValueError("File resource analysis requires full phase")
        agent = CodeAnalyzerAgent(
            agent_name="FileResourceAnalysisAgent",
            task_prompt=FILE_RESOURCE_FULL_REPORT_TASK,
            output_format=FileResourceAnalysisOutput,
            model=self.model,
            provider=self.global_config.agent_provider,
        )

        user_msg = FILE_RESOURCE_FULL_REPORT_USER.format(
            resource_group_id=resource.resource_group_id,
            primary_path=resource.path_value,
            resource_class=resource.resource_class.value,
            n_callsites=len(creating),
            open_callsites_bullets=_render_callsite_bullets(creating),
        )
        user_msg += "\n\nController-verified reachability by callsite_id:\n" + json.dumps(
            {key: {"resource_usage_sites": [site.model_dump(mode="json") for site in sites],
                   "total_usage_sites": total}
             for key, (sites, total) in sorted(usage_sites_by_id.items())},
            ensure_ascii=False, indent=2,
        )

        # Anchor the CodeAnalyzerAgent at the first callsite's function —
        # this is what drives its "Initial Function Code" injection + trace
        # filename. Any creating callsite works; first (binary, function,
        # line)-sorted entry is stable.
        anchor = sorted(
            creating,
            key=lambda cs: (cs.binary_name, cs.function_name, cs.line_number),
        )[0]
        group_trace_dir = (
            (trace_dir / resource.resource_group_id) if trace_dir else None
        )

        accepted_report = None
        def validate(output):
            nonlocal accepted_report
            accepted_report = self._validate_full_output(view, resource, output, usage_sites_by_id)

        async with self._concurrency_sem:
            output = await agent.analyze(
                user_message=user_msg,
                view=view,
                binary_name=anchor.binary_name,
                function_name=anchor.function_name,
                trace_dir=group_trace_dir,
                callsite_line=anchor.line_number,
                output_validator=validate,
            )
        if accepted_report is None:
            raise RuntimeError("File output validator did not produce a report")
        return FileResourceAnalysis(accepted_report, output.finding)

    # ---------------------------------------------------------------
    # Large-group path: map + reduce
    # ---------------------------------------------------------------

    async def _analyze_large_group(
        self,
        view: AnalysisView,
        resource: FileResource,
        creating: List[FileCallsite],
        trace_dir: Optional[Path],
        usage_sites_by_id: Dict[str, Tuple[List[EffectiveCallsite], int]],
        *, phase: str,
    ) -> FileResourceAnalysis:
        if phase != "full":
            raise ValueError("File resource analysis requires full phase")
        ordered = sorted(
            creating,
            key=lambda cs: (cs.binary_name, cs.function_name, cs.line_number),
        )
        chunks = [
            ordered[i:i + self.chunk_size]
            for i in range(0, len(ordered), self.chunk_size)
        ]
        logger.info(
            f"[FileResourceAnalysisAgent] {resource.resource_group_id} → "
            f"{len(chunks)} map chunks (each ≤ {self.chunk_size})"
        )

        group_trace_dir = (
            (trace_dir / resource.resource_group_id) if trace_dir else None
        )

        # ---- Map ----
        # No local Semaphore here: per-LLM-call gating lives inside
        # _run_map_worker via self._concurrency_sem (shared with the
        # whole FileResolver). All chunk workers dispatch as orchestrator
        # coroutines simultaneously and naturally serialize on the sem
        # at the actual provider request point.
        map_results: List[FileResourceMapResult] = await gather_agent_tasks(
            *(
                self._run_map_worker(
                    view=view,
                    resource=resource,
                    chunk_idx=i,
                    chunk=c,
                    trace_dir=group_trace_dir, phase=phase,
                )
                for i, c in enumerate(chunks)
            )
        )

        # Lossless concat
        combined_analyses: List[CallSiteAnalysis] = []
        for mr in map_results:
            combined_analyses.extend(mr.callsite_reports)
        combined_callsite_reports = _assemble_callsite_reports(combined_analyses, usage_sites_by_id)
        logger.info(
            f"[FileResourceAnalysisAgent] {resource.resource_group_id} map produced "
            f"{len(combined_callsite_reports)} CallSiteReports total "
            f"(from {len(chunks)} chunks)"
        )

        # ---- Reduce ----
        reduce_result = await self._run_reduce(
            view=view,
            resource=resource,
            callsite_reports=combined_callsite_reports,
            trace_dir=group_trace_dir, phase=phase,
        )

        # ---- Assemble ----
        report = FileResourceReport(
            resource_group_id=resource.resource_group_id,
            primary_path=resource.path_value,
            resource_class=resource.resource_class,
            callsite_reports=combined_callsite_reports,
            coverage_flows=list(reduce_result.coverage_flows),
            summary=reduce_result.summary,
        )
        reduce_result.finding.validate_references(
            report.model_dump(mode="json"), allowed_roots={"callsite_reports", "coverage_flows"},
        )
        return FileResourceAnalysis(report, reduce_result.finding)


    async def _run_map_worker(
        self,
        view: AnalysisView,
        resource: FileResource,
        chunk_idx: int,
        chunk: List[FileCallsite],
        trace_dir: Optional[Path],
        *, phase: str,
    ) -> FileResourceMapResult:
        if phase != "full":
            raise ValueError("File resource map requires full phase")
        agent = CodeAnalyzerAgent(
            agent_name="FileResourceAnalysisMapAgent",
            task_prompt=FILE_RESOURCE_MAP_TASK,
            output_format=FileResourceMapResult,
            model=self.model,
            provider=self.global_config.agent_provider,
        )

        user_msg = FILE_RESOURCE_MAP_USER.format(
            resource_group_id=resource.resource_group_id,
            primary_path=resource.path_value,
            resource_class=resource.resource_class.value,
            n_callsites=len(chunk),
            open_callsites_bullets=_render_callsite_bullets(chunk),
        )

        # Anchor at first callsite of this chunk for trace filename +
        # initial code injection. Gives each worker a distinct trace md.
        anchor = chunk[0]
        worker_trace_dir = (
            (trace_dir / f"map_{chunk_idx:02d}") if trace_dir else None
        )

        async with self._concurrency_sem:
            result = await agent.analyze(
                user_message=user_msg,
                view=view,
                binary_name=anchor.binary_name,
                function_name=anchor.function_name,
                trace_dir=worker_trace_dir,
                callsite_line=anchor.line_number,
                output_validator=lambda output: self._validate_map_output(
                    view,
                    chunk,
                    FileResourceMapResult.model_validate(output),
                ),
            )
        return result

    async def _run_reduce(
        self,
        view: AnalysisView,
        resource: FileResource,
        callsite_reports: List[CallSiteReport],
        trace_dir: Optional[Path],
        *, phase: str,
    ) -> FileResourceReduceResult:
        """Reduce stage — no code tools, only structured input."""
        if phase != "full":
            raise ValueError("File resource reduce requires full phase")
        # Serialize the map-produced list as JSON for the user message.
        # Compact enough to fit even when there are 100+ reports.
        reports_json = json.dumps(
            [cr.model_dump() for cr in callsite_reports],
            indent=2,
            ensure_ascii=False,
        )

        user_msg = FILE_RESOURCE_REDUCE_USER.format(
            resource_group_id=resource.resource_group_id,
            primary_path=resource.path_value,
            resource_class=resource.resource_class.value,
            n_reports=len(callsite_reports),
            callsite_reports_json=reports_json,
        )

        # Reduce has no code tools; CodeAnalyzerAgent is reused only for its
        # structured-output correction boundary.
        agent = CodeAnalyzerAgent(
            agent_name="FileResourceAnalysisReduceAgent",
            task_prompt=FILE_RESOURCE_REDUCE_TASK,
            output_format=FileResourceReduceResult,
            model=self.model,
            provider=self.global_config.agent_provider,
            include_analyzer_tools=False,
        )
        async with self._concurrency_sem:
            result = await agent.analyze(
                user_message=user_msg,
                view=view,
                trace_dir=trace_dir,
                trace_name="reduce",
                output_validator=lambda output: self._validate_reduce_output(
                    view,
                    FileResourceReduceResult.model_validate(output), callsite_reports,
                ),
            )
        if not isinstance(result, FileResourceReduceResult):
            result = FileResourceReduceResult.model_validate(result)
        return result

    def _validate_full_output(
        self,
        view: AnalysisView,
        resource: FileResource,
        output: FileResourceAnalysisOutput,
        usage_sites_by_id: Dict[str, Tuple[List[EffectiveCallsite], int]],
    ) -> FileResourceReport:
        _validate_callsite_reports(_creating_callsites(resource), output.callsite_reports)
        report = FileResourceReport(
            resource_group_id=resource.resource_group_id,
            primary_path=resource.path_value, resource_class=resource.resource_class,
            **output.model_dump(exclude={"finding", "callsite_reports", "coverage_flows"}),
            callsite_reports=_assemble_callsite_reports(output.callsite_reports, usage_sites_by_id),
            coverage_flows=resolve_coverage_flows(self._coverage_resolver(view), output.coverage_flows),
        )
        if _has_position_claims(report.callsite_reports, report.coverage_flows):
            _validate_report_positions(
                report.callsite_reports,
                report.coverage_flows,
                view,
            )
        output.finding.validate_references(
            report.model_dump(mode="json"), allowed_roots={"callsite_reports", "coverage_flows"},
        )
        return report

    def _validate_map_output(
        self,
        view: AnalysisView,
        creating: List[FileCallsite],
        report: FileResourceMapResult,
    ) -> None:
        _validate_callsite_reports(creating, report.callsite_reports)
        if _has_position_claims(report.callsite_reports, []):
            _validate_report_positions(
                report.callsite_reports,
                [],
                view,
            )

    def _validate_reduce_output(
        self,
        view: AnalysisView,
        report: FileResourceReduceResult,
        callsite_reports: List[CallSiteReport],
    ) -> FileResourceReduceResult:
        report = report.model_copy(update={
            "coverage_flows": resolve_coverage_flows(self._coverage_resolver(view), report.coverage_flows),
        })
        report.finding.validate_references(
            {**report.model_dump(mode="json"), "callsite_reports": [item.model_dump(mode="json") for item in callsite_reports]},
            allowed_roots={"callsite_reports", "coverage_flows"},
        )
        if _has_position_claims([], report.coverage_flows):
            _validate_report_positions(
                [], report.coverage_flows, view,
            )
        return report
