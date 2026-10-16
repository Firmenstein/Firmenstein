"""FileResolver — filesystem resource diagnosis.

    Node 1    enumerate reachable path callsites             (pure Python)
    Node 2    static path resolution                     (pure Python + CTree)
    Node 3    file-path fallback agent                   (LLM, phase="full" only)
    Node 4    classify per candidate                     (pure Python)
    Node 4.5  exact typed-resource construction          (pure Python)
    Node 5    per-resource lifecycle analysis            (LLM, phase="full" only)
    Node 6    persist markdown + JSON                    (pure Python)

``phase="static"`` runs Nodes 1, 2, 4, 4.5, 6 — zero LLM. Gate enforcement
is per-node (AGENTS.md §8 invariant).

Pipeline entrypoint: :meth:`FileResolver.run`.
"""
from __future__ import annotations

from fmst_analyzer.analysis.base.execution import execution_tracker, execution_snapshot, record_analysis_execution

import asyncio
import json
import posixpath
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from loguru import logger

from fmst_basic.agent.analysis_agent import (
    gather_agent_tasks,
)
from fmst_basic.agent.usage_registry import scoped

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    CodeAnalyzerAgent,
)
from fmst_analyzer.analysis.base.code_analyzer.dataflow.types import (
    TraceDirection,
    VariableNodeType,
)
from fmst_analyzer.analysis.base.artifact_lifecycle import preserve_stage_attempt
from fmst_analyzer.analysis.base.report_io import (
    load_model_json,
    write_model_json,
    write_text,
)
from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.graphs.api_dep_graph import ApiDepGraph, ImplStatus
from fmst_analyzer.nodes.callsite import ArgType, CallSite
from fmst_analyzer.nodes.common import FunctionAttr

from fmst_analyzer.analysis.base.finding_binding import FindingTarget
from .findings import FileResourceAnalysis, build_findings

from .analyzer_schema import (
    FileCallsite,
    FilePathResolution,
    FileResolverResult,
    FileResource,
    FileResourceClass,
)
from .classifier import resolve_and_classify_resource
from .grouping import CREATING_APIS, build_file_resources


# Path-arg position (0-based). Scope limited to
# creating + querying APIs per v4 plan decision D2; modify / navigate /
# glob APIs are out of scope.
FILE_API_PATH_ARG: Dict[str, int] = {
    # Creating (agent anchor when resource_class ∈ PSEUDO_FS_* or full mode)
    "open": 0, "open64": 0,
    "openat": 1, "openat64": 1, "openat2": 1,
    "creat": 0, "creat64": 0,
    "fopen": 0, "fopen64": 0,
    "freopen": 0, "freopen64": 0,
    "opendir": 0,
    "mkstemp": 0, "mkostemp": 0, "mkstemps": 0,
    # Querying (no fd, shallow record)
    "stat": 0, "lstat": 0, "stat64": 0, "lstat64": 0,
    "access": 0,
    "statfs": 0, "statfs64": 0,
    "statvfs": 0, "statvfs64": 0,
    "realpath": 0, "readlink": 0, "canonicalize_file_name": 0,
}


FILE_PATH_FALLBACK_PROMPT = """
<role>
You analyze one filesystem API callsite in decompiled firmware code.
</role>

<goal>
Recover every compile-time-provable concrete path or stable format pattern
for the controller-named path argument. Preserve distinct caller and branch
values. The result supports filesystem resource classification, so do not
make IPC, roadblock, or intervention judgments.
</goal>

<criteria>
- A candidate must be supported by exact binary/function/line evidence.
- Caller parameters, wrapper chains, globals, return values, and string
  construction may determine the path.
- A format such as `/dev/mtd%d` is one pattern candidate; do not enumerate it.
- Emit only absolute guest paths or absolute stable patterns as candidates.
  A relative result whose runtime base directory is unknown belongs in
  missing_evidence, not candidates.
- Runtime I/O, opaque external values, unresolved indirect calls, and missing
  cross-binary propagation are missing evidence, not guessed candidates.
- If some branches resolve and others do not, return both the proven
  candidates and the remaining missing evidence.
</criteria>

<termination>
Stop once all statically visible branches are accounted for or their precise
dynamic boundary is named. Return the supplied structured schema only.
</termination>
"""


def _normalize_api_name(api_name: str) -> str:
    """Strip the ``__imp_`` IDA thunk prefix, matching IPCAnalyzer's
    ``_normalize_api_name``."""
    return api_name[len("__imp_"):] if api_name.startswith("__imp_") else api_name


def _callsite_id(binary: str, func: str, line: int, api: str) -> str:
    """Canonical callsite identifier used in both IPCAnalysisResult
    ``covered_api_calls`` entries and FileCallsite.callsite_id."""
    return f"{binary}::{func}::L{line}::{api}"


def _file_callsite_id(
    binary: str,
    func: str,
    line: int,
    api: str,
    callsite: CallSite,
) -> str:
    """Return a persisted identity that cannot collapse same-line calls.

    The unsuffixed :func:`_callsite_id` remains a legacy display-coordinate
    fallback. FileResolver's own result uses the stronger CTree identity.
    """
    ctree_index = getattr(callsite, "ctree_index", None)
    return _file_callsite_id_from_parts(
        binary=binary,
        func=func,
        line=line,
        api=api,
        ctree_index=ctree_index,
        callsite_ea=getattr(callsite, "callsite_ea", 0),
        column_number=getattr(callsite, "column_number", 0),
    )


def _file_callsite_id_from_parts(
    *,
    binary: str,
    func: str,
    line: int,
    api: str,
    ctree_index: Optional[int],
    callsite_ea: int = 0,
    column_number: int = 0,
) -> str:
    display_id = _callsite_id(binary, func, line, api)
    if ctree_index is not None:
        return f"{display_id}@ctree{ctree_index}"
    return f"{display_id}@ea{callsite_ea:x}_col{column_number}"


def _is_concrete_pattern(value: str) -> bool:
    """Return True if a resolved string looks like a format pattern
    (``%d``, ``%s``, ...). Static dataflow can yield pattern literals."""
    return "%" in value


def _strip_c_string_quotes(raw: str) -> str:
    """IDA / CTree returns C string literals with the surrounding double
    quotes embedded in the value (``'"/dev/foo"'``). Strip one outer pair
    so downstream classification (prefix match) and reporting both see
    the canonical path. Single-char or unterminated inputs pass through.
    """
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    return raw


def _query_only_path_gap(api_name: str) -> str:
    return (
        f"query-only API {api_name} has no statically resolved absolute path; "
        "FilePathFallbackAgent is intentionally not invoked because this "
        "callsite cannot create a lifecycle-analyzed resource"
    )


class FileResolver:
    """Diagnose filesystem resource usage for a firmware service binary.

    Produces a :class:`FileResolverResult` with one
    entry per (callsite × resolved candidate path), exact typed resources,
    and full-phase resource reports.

    The resource-analysis Agent is imported lazily so phase="static" runs do
    not pay its import cost or require LLM configuration.
    """

    def __init__(self, global_config: GlobalConfig):
        self.global_config = global_config
        self.execution = execution_tracker()
        # One Semaphore shared across every LLM-issuing call site in this
        # FileResolver instance (Node 3 path fallback + Node 5 resource analysis).
        # Gating at the LLM-call layer rather than the orchestrator layer
        # is deliberate: it bounds the actual provider request rate to
        # ``agent_concurrency_limit`` regardless of nesting depth, and
        # avoids the deadlock that nested orchestrator-layer Semaphores
        # would create (outer holds a permit while waiting for inner to
        # acquire from the same pool).
        self._llm_concurrency_sem = asyncio.Semaphore(
            max(1, global_config.agent_concurrency_limit)
        )

    # ------------------------------------------------------------------
    # Public entrypoint
    # ------------------------------------------------------------------

    @scoped("FileResolver")
    @record_analysis_execution
    @preserve_stage_attempt("file")
    async def run(
        self,
        view: AnalysisView,
        phase: str = "full",
    ) -> FileResolverResult:
        """Run the FileResolver pipeline.

        Args:
            view: analyzer AnalysisView bound to one root binary.
            phase: ``"full"`` runs all nodes (requires LLM);
                ``"static"`` persists after exact-resource construction and skips all
                LLM nodes. Default ``"full"``.
        """
        if phase not in {"static", "full"}:
            raise ValueError("phase must be 'static' or 'full'")
        self.execution = execution_tracker()
        root_binary = view.root.name
        logger.info(
            f"[FileResolver] Starting pipeline for root={root_binary} "
            f"(phase={phase}, scope={self.global_config.file_resolver_scope})"
        )

        survived = await self._node1_enumerate(view)

        # --- Node 2: static resolution tier ---
        (
            static_callsites,
            needs_path_fallback,
            static_path_gaps,
        ) = await self._node2_static_resolve(view, survived)

        # --- Node 3: path fallback on the remainder (skipped in static phase) ---
        if phase == "static":
            fallback_callsites: List[FileCallsite] = []
            path_resolution_gaps = {
                key: list(values) for key, values in static_path_gaps.items()
            }
            queued_for_path_agent = [
                cs.file_resolver_id  # type: ignore[attr-defined]
                for cs in needs_path_fallback
            ]
            logger.info(
                f"[FileResolver] phase=static — skipping Node 3 (path fallback); "
                f"{len(queued_for_path_agent)} callsites queued"
            )
        else:
            fallback_callsites, fallback_path_gaps = (
                await self._node3_path_fallback_resolve(
                    view, needs_path_fallback, phase=phase,
                )
            )
            path_resolution_gaps = {
                key: list(values) for key, values in static_path_gaps.items()
            }
            for callsite_id, gaps in fallback_path_gaps.items():
                path_resolution_gaps.setdefault(callsite_id, []).extend(gaps)
            queued_for_path_agent = []

        all_callsites: List[FileCallsite] = static_callsites + fallback_callsites

        # --- Node 4: classify ---
        rootfs_path = self.global_config.fw_rootfs_path
        if rootfs_path is None:
            raise RuntimeError(
                "FileResolver requires GlobalConfig.fw_rootfs_path to be set "
                "(populated by FirmAnalyzer / PipelineTester at init)"
            )
        classified_callsites: List[FileCallsite] = []
        for cs in all_callsites:
            classification = resolve_and_classify_resource(
                path_value=cs.path_value,
                path_kind=cs.path_kind,
                rootfs_path=rootfs_path,
            )
            if classification.resource_class is None:
                path_resolution_gaps.setdefault(cs.callsite_id, []).append(
                    classification.error
                    or f"cannot classify guest path {cs.path_value!r}"
                )
                continue
            if classification.path_value is None:
                raise RuntimeError(
                    "successful guest-path classification has no path_value"
                )
            cs.path_value = classification.path_value
            cs.resource_class = classification.resource_class
            if len(classification.symlink_chain) > 1:
                cs.resolution_evidence.append(
                    "guest symlink chain: "
                    + " -> ".join(classification.symlink_chain)
                )
            classified_callsites.append(cs)

        all_callsites = classified_callsites

        callsites = {cs.profile_key: cs for cs in all_callsites}
        target = FindingTarget.from_file(rootfs_path, Path(view.root.binary_path))
        resources = build_file_resources(
            callsites, self.global_config.file_resolver_scope,
            self.global_config.file_resolver_normal_fs_ext_allowlist,
        )
        analyses = await self._node5_analyze_resources(
            view, resources, phase=phase,
        )
        result = FileResolverResult(execution=execution_snapshot(),
            schema_version=12, phase=phase, root_binary=root_binary,
            finding_target=target,
            planning_findings=build_findings(target, resources, analyses,
                failed_resources=execution_snapshot().unsuccessful_subjects("resource")),
            callsites=callsites,
            path_resolution_gaps=path_resolution_gaps,
            queued_for_path_agent=queued_for_path_agent, resources=resources,
            resource_reports={key: analysis.report for key, analysis in analyses.items()},
        )
        return self.publish_reports(result)

    # ------------------------------------------------------------------
    # Node 1
    # ------------------------------------------------------------------

    async def _node1_enumerate(
        self,
        view: AnalysisView,
    ) -> List[CallSite]:
        """Collect every reachable path API; observations never transfer ownership."""
        candidate_apis = self._select_candidate_apis(view.adg)

        survived: List[CallSite] = []
        for api_name in candidate_apis:
            raw = view.collect_api_callsites(api_name)
            for cs in raw:
                try:
                    caller_name = view.get_decompiled_name(
                        cs.binary_name, cs.caller_ea,
                    )
                except Exception:
                    caller_name = cs.caller_name
                cs_id = _file_callsite_id(
                    cs.binary_name,
                    caller_name,
                    cs.line_number,
                    api_name,
                    cs,
                )
                # Stash api_name + caller_name on the CallSite for downstream
                # nodes; avoids re-decompiling in Node 2/3.
                cs.file_resolver_api_name = api_name  # type: ignore[attr-defined]
                cs.file_resolver_caller_name = caller_name  # type: ignore[attr-defined]
                cs.file_resolver_id = cs_id  # type: ignore[attr-defined]
                survived.append(cs)
        logger.info(
            f"[FileResolver] Node 1: {len(survived)} candidates survived; "
            f"(from {len(candidate_apis)} candidate APIs)"
        )
        return survived

    def _select_candidate_apis(self, adg: ApiDepGraph) -> List[str]:
        """Select reachable file APIs — mirror of IPCAnalyzer's approach:
        terminal externals (EXTERNAL + not RESOLVED_IN_SCOPE) whose name
        (after stripping the ``__imp_`` import thunk prefix) appears in
        ``FILE_API_PATH_ARG``.
        """
        wanted = set(FILE_API_PATH_ARG.keys())
        candidates: List[str] = []
        for node in sorted(
            adg.get_reachable_nodes(),
            key=lambda func: (func.module, func.name, func.ea),
        ):
            if not node.has_attr(FunctionAttr.EXTERNAL):
                continue
            if adg.get_impl_status(node) is ImplStatus.RESOLVED_IN_SCOPE:
                continue
            name = _normalize_api_name(node.name)
            if name in wanted:
                candidates.append(name)
        candidates = sorted(set(candidates))
        logger.info(
            f"[FileResolver] Selected {len(candidates)} candidate APIs: {candidates}"
        )
        return candidates

    # ------------------------------------------------------------------
    # Node 2
    # ------------------------------------------------------------------

    async def _node2_static_resolve(
        self,
        view: AnalysisView,
        survived: List[CallSite],
    ) -> Tuple[
        List[FileCallsite],
        List[CallSite],
        Dict[str, List[str]],
    ]:
        """Resolve absolute static candidates and account relative paths.

        Tiers (stop-on-success, per CallSite):
          1. args[i].type == LITERAL → take .value.
          2. args[i].type == GLOBAL  → AnalysisView.get_global_variable_value.
          3. args[i].type == LOCAL   → local backward dataflow, collect any
             LITERAL_STRING sources found within ``max_rise_depth=3``.
          4. resolved relative/empty candidates → path_resolution_gaps.
          5. otherwise (CALL / OTHER / no value) → fallback queue for
             creating APIs, or an explicit gap for query-only APIs.
        """
        static_profiles: List[FileCallsite] = []
        needs_path_fallback: List[CallSite] = []
        path_resolution_gaps: Dict[str, List[str]] = {}

        for cs in survived:
            api_name = cs.file_resolver_api_name  # type: ignore[attr-defined]
            path_idx = FILE_API_PATH_ARG[api_name]
            # CallSite.args is 1-based; FILE_API_PATH_ARG is 0-based
            # Convert the controller's 0-based table to CallSite's 1-based args.
            arg = cs.get_argument(path_idx + 1)
            if arg is None:
                if api_name in CREATING_APIS:
                    needs_path_fallback.append(cs)
                else:
                    path_resolution_gaps.setdefault(
                        cs.file_resolver_id,  # type: ignore[attr-defined]
                        [],
                    ).append(_query_only_path_gap(api_name))
                continue

            candidates: List[Tuple[str, str, str]] = []  # (value, kind, source)

            if arg.type == ArgType.LITERAL and arg.value is not None:
                cleaned = _strip_c_string_quotes(arg.value)
                kind = "pattern" if _is_concrete_pattern(cleaned) else "concrete"
                candidates.append((cleaned, kind, "literal_static"))
            elif arg.type == ArgType.GLOBAL and arg.value:
                resolved = self._resolve_global(view, cs.binary_name, arg.value)
                if resolved is not None:
                    cleaned = _strip_c_string_quotes(resolved)
                    kind = "pattern" if _is_concrete_pattern(cleaned) else "concrete"
                    candidates.append((cleaned, kind, "global_static"))
            elif arg.type == ArgType.LOCAL and arg.value:
                literals = self._resolve_local_via_dataflow(
                    view, cs, arg.value,
                )
                for lit in literals:
                    cleaned = _strip_c_string_quotes(lit)
                    kind = "pattern" if _is_concrete_pattern(cleaned) else "concrete"
                    candidates.append((cleaned, kind, "dataflow_static"))

            if not candidates:
                if api_name in CREATING_APIS:
                    needs_path_fallback.append(cs)
                else:
                    path_resolution_gaps.setdefault(
                        cs.file_resolver_id,  # type: ignore[attr-defined]
                        [],
                    ).append(_query_only_path_gap(api_name))
                continue

            for idx, (value, kind, source) in enumerate(candidates):
                if not value or not posixpath.isabs(value):
                    cs_id = cs.file_resolver_id  # type: ignore[attr-defined]
                    path_resolution_gaps.setdefault(cs_id, []).append(
                        f"resolved {source} candidate {value!r}, but its "
                        "runtime base directory is not established"
                    )
                    continue
                static_profiles.append(
                    self._make_callsite(
                        cs, idx, path_value=value, path_kind=kind,
                        resolution_source=source,
                    )
                )

        logger.info(
            f"[FileResolver] Node 2: {len(static_profiles)} candidates resolved statically; "
            f"{len(needs_path_fallback)} creating-API callsites queued for "
            "path fallback; "
            f"{len(path_resolution_gaps)} callsites have path gaps"
        )
        return static_profiles, needs_path_fallback, path_resolution_gaps

    def _resolve_global(
        self, view: AnalysisView, binary_name: str, gvar_name: str,
    ) -> Optional[str]:
        """Return the statically resolved string value of a global, or None
        if the global isn't a string literal."""
        try:
            result = view.get_global_variable_value(
                gvar_name, binary_name,
            )
        except Exception as e:
            logger.debug(
                f"[FileResolver] get_global_variable_value({binary_name}, "
                f"{gvar_name}) failed: {e}"
            )
            return None
        if result is None:
            return None
        # AnalysisView returns (value_type, value_repr) — mirrors the
        # analyzer_tools view_global wrapper. Only "string" type counts
        # as a resolved path; everything else is metadata / sentinel.
        try:
            value_type, value_repr = result
        except (TypeError, ValueError):
            return None
        if value_type != "string" or not value_repr:
            return None
        return value_repr

    def _resolve_local_via_dataflow(
        self,
        view: AnalysisView,
        cs: CallSite,
        var_name: str,
    ) -> List[str]:
        """Backward-trace ``var_name`` inside the caller to collect
        LITERAL_STRING propagation sources. Intra-+shallow inter-procedural
        (``max_rise_depth=3``). Returns empty list when no literal source
        is reachable.
        """
        caller_name = cs.file_resolver_caller_name  # type: ignore[attr-defined]
        try:
            graph = view.trace_variables(
                binary_name=cs.binary_name,
                func_name=caller_name,
                var_name=var_name,
                direction=TraceDirection.BACKWARD,
                max_sink_depth=0,
                max_rise_depth=3,
            )
        except Exception as e:
            logger.debug(
                f"[FileResolver] dataflow trace({cs.binary_name}::{caller_name}::"
                f"{var_name}) raised: {e}"
            )
            return []

        hits: List[str] = []
        seen: Set[str] = set()
        for node in graph.nodes:
            if node.node_type != VariableNodeType.LITERAL_STRING:
                continue
            if not node.literal_value:
                continue
            if node.literal_value in seen:
                continue
            seen.add(node.literal_value)
            hits.append(node.literal_value)
        return hits

    # ------------------------------------------------------------------
    # Node 3
    # ------------------------------------------------------------------

    async def _node3_path_fallback_resolve(
        self,
        view: AnalysisView,
        queued: List[CallSite],
        *,
        phase: str = "full",
    ) -> Tuple[List[FileCallsite], Dict[str, List[str]]]:
        """Resolve statically-unknown creating-API paths with a CodeAgent.

        Returns resolved candidate profiles plus explicit missing evidence
        keyed by callsite. A partially-resolved callsite may appear in both.
        Query-only APIs are defensively converted to gaps before the Agent is
        constructed, even if a caller bypasses Node 2's eligibility gate.
        """
        if phase != "full":
            logger.info(
                "[FileResolver] path fallback skipped outside full phase"
            )
            return [], {}
        if not queued:
            return [], {}

        agent_queued: List[CallSite] = []
        gaps: Dict[str, List[str]] = {}
        for cs in queued:
            api_name = cs.file_resolver_api_name  # type: ignore[attr-defined]
            if api_name in CREATING_APIS:
                agent_queued.append(cs)
                continue
            cs_id = cs.file_resolver_id  # type: ignore[attr-defined]
            gaps.setdefault(cs_id, []).append(
                _query_only_path_gap(api_name)
            )
        if not agent_queued:
            logger.info(
                "[FileResolver] path fallback received no unresolved "
                "creating-API callsites; zero Agent calls"
            )
            return [], gaps

        agent = CodeAnalyzerAgent(
            agent_name="FilePathFallbackAgent",
            task_prompt=FILE_PATH_FALLBACK_PROMPT,
            output_format=FilePathResolution,
            model=self.global_config.diagnosis_model,
            provider=self.global_config.agent_provider,
        )

        async def _resolve_one(cs: CallSite):
            async with self._llm_concurrency_sem:
                api_name = cs.file_resolver_api_name  # type: ignore[attr-defined]
                caller_name = cs.file_resolver_caller_name  # type: ignore[attr-defined]
                path_idx = FILE_API_PATH_ARG[api_name]
                user_message = (
                    "Resolve the filesystem path argument at this exact callsite.\n\n"
                    f"- Binary: {cs.binary_name}\n"
                    f"- Function: {caller_name}\n"
                    f"- API: {api_name}\n"
                    f"- Line: L{cs.line_number}\n"
                    f"- Path argument: arg[{path_idx}]"
                )
                return cs, await self.execution.call(
                    "path", cs.file_resolver_id, lambda: agent.analyze(
                        user_message=user_message,
                        view=view,
                        binary_name=cs.binary_name,
                        function_name=caller_name,
                        trace_dir=(
                            self.global_config.target_agent_debug_dir()
                            / "file_resolver" / "path_resolution"
                        ),
                        callsite_line=cs.line_number,
                        trace_name=(
                            f"{cs.binary_name}__{caller_name}__"
                            f"L{cs.line_number}__{api_name}__"
                            f"ctree{getattr(cs, 'ctree_index', None)}"
                        ),
                        initial_focus_lines=[cs.line_number],
                    ),
                )

        outcomes = await gather_agent_tasks(
            *(_resolve_one(cs) for cs in agent_queued)
        )

        profiles: List[FileCallsite] = []
        for cs, outcome in outcomes:
            cs_id = cs.file_resolver_id  # type: ignore[attr-defined]
            if outcome is None:
                continue
            resolution = FilePathResolution.model_validate(outcome)
            if resolution.missing_evidence:
                gaps[cs_id] = list(resolution.missing_evidence)
            for idx, candidate in enumerate(resolution.candidates):
                cleaned = _strip_c_string_quotes(candidate.value)
                if not posixpath.isabs(cleaned):
                    gaps.setdefault(cs_id, []).append(
                        f"file path fallback returned relative candidate "
                        f"{cleaned!r}; runtime base directory is not established"
                    )
                    continue
                profiles.append(
                    self._make_callsite(
                        cs, idx,
                        path_value=cleaned,
                        path_kind=candidate.kind,
                        resolution_source="file_path_agent",
                        resolution_evidence=list(candidate.evidence),
                    )
                )

        logger.info(
            f"[FileResolver] Node 3: path fallback resolved {len(profiles)} "
            f"candidates from {len(agent_queued)} creating-API callsites; "
            f"{len(gaps)} callsites retain missing evidence"
        )
        return profiles, gaps

    # ------------------------------------------------------------------
    # FileCallsite constructor helper
    # ------------------------------------------------------------------

    def _make_callsite(
        self,
        cs: CallSite,
        candidate_idx: int,
        *,
        path_value: str,
        path_kind: str,
        resolution_source: str,
        resolution_evidence: Optional[List[str]] = None,
    ) -> FileCallsite:
        api_name = cs.file_resolver_api_name  # type: ignore[attr-defined]
        caller_name = cs.file_resolver_caller_name  # type: ignore[attr-defined]
        cs_id = cs.file_resolver_id  # type: ignore[attr-defined]
        profile_key = f"{cs_id}#{candidate_idx}"
        # Resource class is overwritten by Node 4 before the result is exposed.
        return FileCallsite(
            callsite_id=cs_id,
            candidate_idx=candidate_idx,
            profile_key=profile_key,
            binary_name=cs.binary_name,
            function_name=caller_name,
            function_ea=getattr(cs, "caller_ea", None),
            snapshot_hash=getattr(cs, "snapshot_hash", None),
            line_number=cs.line_number,
            column_number=getattr(cs, "column_number", 0),
            callsite_ea=getattr(cs, "source_ea", None) or 0,
            ctree_index=getattr(cs, "ctree_index", None),
            api_name=api_name,
            path_arg_index=FILE_API_PATH_ARG[api_name],
            requested_path=path_value,
            path_value=path_value,
            path_kind=path_kind,  # type: ignore[arg-type]
            resolution_source=resolution_source,  # type: ignore[arg-type]
            resolution_evidence=resolution_evidence or [],
            resource_class=FileResourceClass.MISSING_NON_PSEUDO_FS,
        )

    # ------------------------------------------------------------------
    # Node 5 (LLM)
    # ------------------------------------------------------------------

    async def _node5_analyze_resources(
        self,
        view: AnalysisView,
        resources: dict[str, FileResource],
        *,
        phase: str,
    ) -> dict[str, FileResourceAnalysis]:
        """Analyze each exact resource without inferring resource families.

        Concurrency: this orchestrator does NOT acquire the LLM-concurrency
        semaphore. It lets resources dispatch in parallel and relies on
        FileResourceAnalysisAgent's per-LLM-call gating (small / map /
        reduce each acquire ``self._llm_concurrency_sem`` around their
        actual provider request).
        """
        if phase != "full":
            logger.info(
                "[FileResolver] Node 5 gated: phase is not full; zero LLM calls"
            )
            return {}
        if not resources:
            logger.info(
                "[FileResolver] Node 5: no resources — skipping "
                "FileResourceAnalysisAgent"
            )
            return {}

        from .resource_analysis_agent import FileResourceAnalysisAgent

        trace_dir = (
            self.global_config.target_agent_debug_dir() / "file_resolver"
        )
        agent = FileResourceAnalysisAgent(
            self.global_config,
            concurrency_sem=self._llm_concurrency_sem,
        )

        async def _one(resource_id: str, resource):
            return resource_id, await self.execution.call(
                "resource", resource_id, lambda: agent.analyze_resource(
                    view=view, resource=resource, trace_dir=trace_dir, phase=phase,
                ),
            )

        items = sorted(resources.items())
        outcomes = await gather_agent_tasks(
            *(_one(resource_id, resource) for resource_id, resource in items)
        )

        analyses = {}
        for resource_id, outcome in outcomes:
            if outcome is None:
                continue
            analyses[resource_id] = outcome

        logger.info(
            f"[FileResolver] Node 5: {len(analyses)}/{len(items)} exact resources "
            "produced reports"
        )

        return analyses

    # ------------------------------------------------------------------
    # Node 6 (persist)
    # ------------------------------------------------------------------

    def publish_reports(
        self,
        result: FileResolverResult,
        *,
        persist_json: bool = True,
    ) -> FileResolverResult:
        """Write the index markdown, per-resource agent-report markdowns
        (when present), and the structured JSON snapshot. Rendering lives
        in ``reports.py``. Static phase writes the index + JSON only —
        per-resource ``.md`` are emitted only for resources that have a
        ``FileResourceReport`` in ``result.resource_reports``.
        """
        from . import reports  # local import; reports.py is sibling module

        out_dir = (
            self.global_config.target_diagnostic_reports_dir() / "file_reports"
        )
        out_dir.mkdir(parents=True, exist_ok=True)

        # Remove only per-resource pages named by the previous controller
        # JSON. A static run after a full run must not leave stale generated
        # reports, while unrelated human notes in this directory stay intact.
        prior_result_path = out_dir / "file_resolver_result.json"
        if prior_result_path.exists():
            try:
                prior_payload = json.loads(
                    prior_result_path.read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                prior_payload = {}
            prior_ids: Set[str] = set()
            for field in ("resource_reports",):
                value = prior_payload.get(field, {})
                if isinstance(value, dict):
                    prior_ids.update(str(item) for item in value)
            for resource_id in prior_ids:
                safe_name = _safe_filename(resource_id)
                suffixes = (".md", "_result.json") if persist_json else (".md",)
                for suffix in suffixes:
                    path = out_dir / f"{safe_name}{suffix}"
                    if path.is_file():
                        path.unlink()

        if persist_json:
            json_path = out_dir / "file_resolver_result.json"
            write_model_json(json_path, result)
            result = load_model_json(json_path, FileResolverResult)

        for resource_id, report in result.resource_reports.items():
            safe_name = _safe_filename(resource_id)
            report_json_path = out_dir / f"{safe_name}_result.json"
            if persist_json:
                write_model_json(report_json_path, report)
                report = load_model_json(report_json_path, type(report))
            write_text(
                out_dir / f"{safe_name}.md",
                reports.render_per_resource_report(report),
            )

        write_text(out_dir / "index.md", reports.render_index(result))
        logger.info(f"[FileResolver] persisted output at {out_dir}")
        return result


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------



def _safe_filename(profile_key: str) -> str:
    """Translate a profile_key (``bin::func::Lnn::api#idx``) into a
    filesystem-safe filename."""
    return profile_key.replace("::", "__").replace("#", "_")
