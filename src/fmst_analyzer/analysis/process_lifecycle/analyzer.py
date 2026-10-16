"""Process-event anchored startup lifecycle analysis."""
from __future__ import annotations

from fmst_analyzer.analysis.base.execution import execution_tracker, execution_snapshot, record_analysis_execution

import asyncio
from pathlib import Path

from loguru import logger

from fmst_basic.agent.usage_registry import scoped

from fmst_analyzer.analysis.base.artifact_lifecycle import preserve_stage_attempt
from fmst_analyzer.analysis.base.finding_binding import FindingTarget
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.report_io import (
    load_model_json,
    write_model_json,
    write_text,
)
from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.graphs.api_dep_graph import ImplStatus
from fmst_analyzer.nodes.common import FunctionAttr

from .analyzer_schema import (
    PROCESS_LIFECYCLE_SCHEMA_VERSION,
    ProcessEventCallsite,
    ProcessEventKind,
    ProcessLifecycleAnalysisResult,
)
from .controller import normalize_api_name, stable_ctree_id
from .findings import build_findings


PROCESS_EVENT_API_REGISTRY: dict[str, ProcessEventKind] = {
    "exit": ProcessEventKind.TERMINATION,
    "_exit": ProcessEventKind.TERMINATION,
    "_Exit": ProcessEventKind.TERMINATION,
    "quick_exit": ProcessEventKind.TERMINATION,
    "abort": ProcessEventKind.TERMINATION,
    "__assert_fail": ProcessEventKind.TERMINATION,
    "daemon": ProcessEventKind.PROCESS_TRANSITION,
    "fork": ProcessEventKind.PROCESS_TRANSITION,
    "vfork": ProcessEventKind.PROCESS_TRANSITION,
    "clone": ProcessEventKind.PROCESS_TRANSITION,
    "setsid": ProcessEventKind.PROCESS_TRANSITION,
}
class ProcessLifecycleAnalyzer:
    def __init__(self, global_config: GlobalConfig) -> None:
        self.global_config = global_config
        self._llm_concurrency_sem = asyncio.Semaphore(
            max(1, global_config.agent_concurrency_limit)
        )

    @scoped("ProcessLifecycleAnalyzer")
    @record_analysis_execution
    @preserve_stage_attempt("process")
    async def run(
        self,
        view: AnalysisView,
        phase: str = "full",
    ) -> ProcessLifecycleAnalysisResult:
        if phase not in {"static", "full"}:
            raise ValueError("phase must be 'static' or 'full'")
        root_binary = view.root.name
        target = FindingTarget.from_file(self.global_config.fw_rootfs_path, Path(view.root.binary_path))
        callsites = self._collect_callsites(view)
        logger.info(f"[ProcessLifecycleAnalyzer] root={root_binary} phase={phase}: {len(callsites)} callsites")

        if phase == "static":
            result = ProcessLifecycleAnalysisResult(execution=execution_snapshot(),
                schema_version=PROCESS_LIFECYCLE_SCHEMA_VERSION,
                phase="static",
                root_binary=root_binary,
                finding_target=target,
                planning_findings=build_findings(target, callsites, {}, {}),
                callsites=callsites,
            )
            return self.publish_reports(result)

        from .process_lifecycle_agent import ProcessLifecycleAgent

        pending = [
            fact for callsite_id, fact in callsites.items()
        ]
        analyses = await ProcessLifecycleAgent(
            global_config=self.global_config,
            concurrency_sem=self._llm_concurrency_sem,
        ).analyze_callsites(view, pending, phase=phase)
        result = ProcessLifecycleAnalysisResult(execution=execution_snapshot(),
            schema_version=PROCESS_LIFECYCLE_SCHEMA_VERSION,
            phase="full",
            root_binary=root_binary,
            finding_target=target,
            planning_findings=build_findings(target, callsites, execution_snapshot().unsuccessful_subjects("process"), analyses),
            callsites=callsites,
            assessments={key: item.assessment for key, item in analyses.items()},
        )
        return self.publish_reports(result)

    def _collect_callsites(
        self,
        view: AnalysisView,
    ) -> dict[str, ProcessEventCallsite]:
        selected: set[str] = set()
        for node in sorted(
            view.adg.get_reachable_nodes(),
            key=lambda item: (item.module, item.name, item.ea),
        ):
            if not node.has_attr(FunctionAttr.EXTERNAL):
                continue
            if view.adg.get_impl_status(node) is ImplStatus.RESOLVED_IN_SCOPE:
                continue
            api_name = normalize_api_name(node.name)
            if api_name in PROCESS_EVENT_API_REGISTRY:
                selected.add(api_name)

        facts: dict[str, ProcessEventCallsite] = {}
        for api_name in sorted(selected):
            for callsite in dict.fromkeys(view.collect_api_callsites(api_name)):
                if callsite.snapshot_hash is None or callsite.ctree_index is None:
                    raise RuntimeError(
                        f"reachable process event {callsite} lacks stable CTree identity"
                    )
                function_name = view.get_decompiled_name(
                    callsite.binary_name,
                    callsite.caller_ea,
                )
                callsite_id = stable_ctree_id(
                    "process-event",
                    callsite.binary_name,
                    callsite.caller_ea,
                    callsite.snapshot_hash,
                    callsite.ctree_index,
                )
                fact = ProcessEventCallsite(
                    callsite_id=callsite_id,
                    binary_name=callsite.binary_name,
                    function_name=function_name,
                    function_ea=callsite.caller_ea,
                    snapshot_hash=callsite.snapshot_hash,
                    ctree_index=callsite.ctree_index,
                    source_ea=callsite.source_ea,
                    line_number=callsite.line_number,
                    column_number=callsite.column_number,
                    api_name=api_name,
                    event_kind=PROCESS_EVENT_API_REGISTRY[api_name],
                )
                previous = facts.get(callsite_id)
                if previous is not None and previous != fact:
                    raise RuntimeError(
                        f"conflicting process event facts for {callsite_id}"
                    )
                facts[callsite_id] = fact
        return dict(sorted(
            facts.items(),
            key=lambda item: (
                item[1].binary_name,
                item[1].function_ea,
                item[1].ctree_index,
                item[1].api_name,
            ),
        ))

    def publish_reports(
        self,
        result: ProcessLifecycleAnalysisResult,
        *,
        persist_json: bool = True,
    ) -> ProcessLifecycleAnalysisResult:
        """Publish JSON and deterministic Markdown views for ``result``."""
        if self.global_config.workdir is None:
            logger.warning(
                "[ProcessLifecycleAnalyzer] workdir is None; skipping persistence"
            )
            return result
        from . import reports
        from .analyzer_schema import ProcessEventAssessmentReport

        out_dir = (
            self.global_config.target_diagnostic_reports_dir()
            / "process_lifecycle_reports"
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        for path in (*out_dir.glob("*.md"), *out_dir.glob("*.json")):
            if not persist_json and path.name in {"input_provenance.json", "input_provenance.md"}:
                continue
            if path.name not in {
                "index.md",
                "process_lifecycle_analysis_result.json",
            } and (persist_json or path.suffix == ".md"):
                path.unlink()
        if persist_json:
            result_path = out_dir / "process_lifecycle_analysis_result.json"
            write_model_json(result_path, result)
            result = load_model_json(result_path, ProcessLifecycleAnalysisResult)

        for callsite_id, assessment in result.assessments.items():
            report = ProcessEventAssessmentReport(
                root_binary=result.root_binary,
                callsite=result.callsites[callsite_id],
                assessment=assessment,
            )
            stem = reports.assessment_report_stem(assessment)
            report_path = out_dir / f"{stem}.json"
            if persist_json:
                write_model_json(report_path, report)
                report = load_model_json(report_path, ProcessEventAssessmentReport)
            write_text(
                out_dir / f"{stem}.md",
                reports.render_assessment_report(report),
            )
        write_text(out_dir / "index.md", reports.render_index(result))
        logger.info(f"[ProcessLifecycleAnalyzer] persisted output at {out_dir}")
        return result


__all__ = ["PROCESS_EVENT_API_REGISTRY", "ProcessLifecycleAnalyzer"]
