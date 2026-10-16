"""Independent, resource-seeded NetworkAnalyzer."""
from __future__ import annotations

from fmst_analyzer.analysis.base.execution import execution_tracker, execution_snapshot, record_analysis_execution

import asyncio
import hashlib
import json
from pathlib import Path

from loguru import logger

from fmst_basic.agent.usage_registry import scoped
from fmst_analyzer.analysis.base.artifact_lifecycle import preserve_stage_attempt
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
    NETWORK_ANALYSIS_SCHEMA_VERSION,
    NetworkAPIBinding,
    NetworkAnalysisResult,
    NetworkCallsite,
    NetworkCodeLocation,
    NetworkInteractionReport,
    NetworkRawArgument,
)
from .interaction_agent import NetworkInteractionAgent
from .findings import build_findings
from fmst_analyzer.analysis.base.finding_binding import FindingTarget
from .registry import lookup_network_api, normalize_api_name


def _stable_callsite_id(
    binary_path: str,
    binary_sha256: str,
    function_ea: int,
    snapshot_hash: str,
    ctree_index: int,
) -> str:
    payload = json.dumps(
        [binary_path, binary_sha256, function_ea, snapshot_hash, ctree_index],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return f"network-cs:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:24]}"


class NetworkAnalyzer:
    """Analyze target-local network-stack interactions.

    Static phase collects immutable CTree facts. Full phase analyzes resource
    anchors independently of any other analyzer's coverage.
    """

    def __init__(self, global_config: GlobalConfig):
        self.global_config = global_config
        self._llm_concurrency_sem = asyncio.Semaphore(
            max(1, global_config.agent_concurrency_limit)
        )
        self._hash_cache: dict[Path, str] = {}

    @scoped("NetworkAnalyzer")
    @record_analysis_execution
    @preserve_stage_attempt("network")
    async def run(
        self,
        view: AnalysisView,
        phase: str = "full",
    ) -> NetworkAnalysisResult:
        if phase not in {"static", "full"}:
            raise ValueError("phase must be 'static' or 'full'")
        root_binary = view.root.name
        target = FindingTarget.from_file(self.global_config.fw_rootfs_path, view.root.binary_path)
        callsites = self._collect_callsites(view)
        pending = sorted(callsites)

        logger.info(
            f"[NetworkAnalyzer] collected {len(callsites)} reachable callsites; "
            f"{len(pending)} require Network analysis (phase={phase})"
        )

        if phase == "static":
            result = NetworkAnalysisResult(execution=execution_snapshot(),
                schema_version=NETWORK_ANALYSIS_SCHEMA_VERSION, finding_target=target, planning_findings={},
                phase=phase,
                root_binary=root_binary,
                callsites=callsites,
                pending_callsite_ids=pending,
            )
            return self.publish_reports(result)

        agent = NetworkInteractionAgent(
            global_config=self.global_config,
            concurrency_sem=self._llm_concurrency_sem,
        )
        outcomes = await agent.analyze(
            view,
            root_binary,
            [callsites[callsite_id] for callsite_id in pending],
            phase=phase,
        )
        result = NetworkAnalysisResult(execution=execution_snapshot(),
            schema_version=NETWORK_ANALYSIS_SCHEMA_VERSION, finding_target=target, planning_findings=build_findings(target, outcomes),
            phase=phase,
            root_binary=root_binary,
            callsites=callsites,
            analyses=[outcome.analysis for outcome in outcomes],
            pending_callsite_ids=[],
        )
        return self.publish_reports(result)

    def _collect_callsites(
        self,
        view: AnalysisView,
    ) -> dict[str, NetworkCallsite]:
        selected: set[str] = set()
        for node in sorted(
            view.adg.get_reachable_nodes(),
            key=lambda item: (item.module, item.name, item.ea),
        ):
            if not node.has_attr(FunctionAttr.EXTERNAL):
                continue
            if view.adg.get_impl_status(node) is ImplStatus.RESOLVED_IN_SCOPE:
                continue
            normalized = normalize_api_name(node.name)
            if lookup_network_api(normalized) is not None:
                selected.add(normalized)

        facts: dict[str, NetworkCallsite] = {}
        for api_name in sorted(selected):
            registry_entry = lookup_network_api(api_name)
            assert registry_entry is not None
            # CallSite.callee_name stores the normalized source-level symbol
            # (``connect``), while the ADG import node may be named
            # ``__imp_connect``.  Select via the ADG node but query the CTree
            # semantic index with the normalized name, matching the other
            # analyzers and the rendered pseudocode.
            for callsite in dict.fromkeys(
                view.collect_api_callsites(api_name)
            ):
                if callsite.snapshot_hash is None or callsite.ctree_index is None:
                    raise RuntimeError(
                        f"reachable callsite {callsite} lacks immutable CTree identity"
                    )
                binary = view.lib_dep_graph.get_node_by_name(callsite.binary_name)
                if binary is None:
                    raise RuntimeError(
                        f"callsite binary {callsite.binary_name!r} is absent from LibDepGraph"
                    )
                source_path = Path(binary.binary_path).absolute().resolve()
                binary_path = self._rootfs_relative(source_path)
                binary_sha256 = self._sha256(source_path)
                function_name = view.get_decompiled_name(
                    callsite.binary_name,
                    callsite.caller_ea,
                )
                identity = _stable_callsite_id(
                    binary_path,
                    binary_sha256,
                    callsite.caller_ea,
                    callsite.snapshot_hash,
                    callsite.ctree_index,
                )
                fact = NetworkCallsite(
                    callsite_id=identity,
                    location=NetworkCodeLocation(
                        binary_name=callsite.binary_name,
                        binary_path=binary_path,
                        binary_sha256=binary_sha256,
                        function_name=function_name,
                        function_ea=callsite.caller_ea,
                        snapshot_hash=callsite.snapshot_hash,
                        ctree_index=callsite.ctree_index,
                        source_ea=callsite.source_ea,
                        line_number=callsite.line_number,
                        column_number=callsite.column_number,
                    ),
                    api_name=api_name,
                    api_family=registry_entry.family,
                    api_binding=NetworkAPIBinding(
                        symbol=api_name,
                        call_kind=callsite.call_kind,
                        verified=(
                            not callsite.is_indirect
                            and callsite.call_kind == "direct"
                        ),
                    ),
                    expression_text=callsite.expression_text,
                    arguments=[
                        NetworkRawArgument(
                            index=argument.index,
                            expression=argument.value,
                        )
                        for argument in sorted(
                            callsite.args,
                            key=lambda argument: argument.index,
                        )
                    ],
                    return_expression=(
                        callsite.return_var.value
                        if callsite.return_var is not None
                        else None
                    ),
                )
                previous = facts.get(identity)
                if previous is not None and previous != fact:
                    raise RuntimeError(
                        f"conflicting Network callsite facts for {identity}"
                    )
                facts[identity] = fact
        return dict(sorted(
            facts.items(),
            key=lambda item: (
                item[1].location.binary_path,
                item[1].location.function_ea,
                item[1].location.ctree_index,
                item[1].api_name,
            ),
        ))

    def _rootfs_relative(self, path: Path) -> str:
        rootfs = self.global_config.fw_rootfs_path
        if rootfs is None:
            return path.as_posix()
        try:
            return path.relative_to(Path(rootfs).absolute().resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def _sha256(self, path: Path) -> str:
        cached = self._hash_cache.get(path)
        if cached is not None:
            return cached
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        value = digest.hexdigest()
        self._hash_cache[path] = value
        return value

    def publish_reports(
        self,
        result: NetworkAnalysisResult,
        *,
        persist_json: bool = True,
    ) -> NetworkAnalysisResult:
        """Publish JSON and deterministic Markdown views for ``result``."""
        if self.global_config.workdir is None:
            logger.warning("[NetworkAnalyzer] workdir is unset; skipping persistence")
            return result
        from . import reports

        out_dir = (
            self.global_config.target_diagnostic_reports_dir()
            / "network_reports"
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        # Every direct child JSON/Markdown other than the two top-level files
        # is a renderer-owned per-interaction artifact.  Clear that set before
        # publishing so stale pages cannot survive a schema change or a new
        # analysis that changes an interaction's disposition or identity.
        for old_path in out_dir.iterdir():
            if old_path.name in {"network_analysis_result.json", "index.md"}:
                continue
            if not persist_json and old_path.name in {"input_provenance.json", "input_provenance.md"}:
                continue
            removable_suffixes = {".json", ".md"} if persist_json else {".md"}
            if old_path.is_file() and old_path.suffix in removable_suffixes:
                old_path.unlink()
        if persist_json:
            result_path = out_dir / "network_analysis_result.json"
            write_model_json(result_path, result)
            result = load_model_json(result_path, NetworkAnalysisResult)

        for analysis in result.analyses:
            stem = reports.interaction_report_stem(analysis)
            interaction_report = NetworkInteractionReport(
                root_binary=result.root_binary,
                analysis=analysis,
                callsites={
                    callsite_id: result.callsites[callsite_id]
                    for callsite_id in analysis.callsite_ids
                },
            )
            report_path = out_dir / f"{stem}.json"
            if persist_json:
                write_model_json(report_path, interaction_report)
                interaction_report = load_model_json(
                    report_path, NetworkInteractionReport
                )
            write_text(
                out_dir / f"{stem}.md",
                reports.render_interaction(interaction_report),
            )
        write_text(out_dir / "index.md", reports.render_index(result))
        logger.info(f"[NetworkAnalyzer] persisted output at {out_dir}")
        return result


__all__ = ["NetworkAnalyzer"]
