"""Pydantic schema for FileResolver.

The persisted model has one resource layer: callsites with the same typed
path ``(path_kind, path_value)`` form one :class:`FileResource`.  No resource
family is inferred here.  A full-phase :class:`FileResourceReport` describes
that exact resource through the existing ``CallSiteReport -> UsageReport``
hierarchy.
"""
from __future__ import annotations

from fmst_analyzer.analysis.base.execution import AnalysisExecution

from enum import Enum
from typing import Dict, List, Literal, Optional, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator
from fmst_analyzer.analysis.base.analysis_finding import (
    FileFindingDomain, FindingAnchor, PlanningFindings, validate_finding_references,
)
from fmst_analyzer.analysis.base.finding_binding import FindingSemantics, FindingTarget, pointer, validate_bound_finding

from fmst_analyzer.analysis.base.coverage_flow import CoverageFlow
from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICall
from fmst_analyzer.analysis.base.report_schema import CallSiteAnalysis, CallSiteReport, UsageReport

FILE_RESOLVER_SCHEMA_VERSION = 12


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FileResourceClass(str, Enum):
    """Classification of a resolved path candidate by ordered rule
    (first match wins):

    1. ``PSEUDO_FS_DEV``          — absolute path ``/dev`` / ``/dev/...``.
    2. ``PSEUDO_FS_PROC``         — absolute path ``/proc`` / ``/proc/...``.
    3. ``PSEUDO_FS_SYS``          — absolute path ``/sys`` / ``/sys/...``.
    4. ``IN_ROOTFS``              — concrete path that resolves to an
       existing entry under the extracted rootfs.
    5. ``MISSING_NON_PSEUDO_FS``  — concrete or pattern path that is
       neither pseudo-fs nor in rootfs.

    The classifier implementation in ``classifier.py`` honours this exact
    order. This docstring is the authoritative rule statement.
    """

    IN_ROOTFS = "in_rootfs"
    PSEUDO_FS_DEV = "pseudo_fs_dev"
    PSEUDO_FS_PROC = "pseudo_fs_proc"
    PSEUDO_FS_SYS = "pseudo_fs_sys"
    MISSING_NON_PSEUDO_FS = "missing_non_pseudo_fs"


# The three pseudo-fs classes as a tuple (preserves docstring rule order)
# and a frozenset for O(1) membership checks.
PSEUDO_FS_CLASSES: "tuple[FileResourceClass, ...]" = (
    FileResourceClass.PSEUDO_FS_DEV,
    FileResourceClass.PSEUDO_FS_PROC,
    FileResourceClass.PSEUDO_FS_SYS,
)
PSEUDO_FS_CLASS_SET: "frozenset[FileResourceClass]" = frozenset(PSEUDO_FS_CLASSES)


# ---------------------------------------------------------------------------
# Hierarchical report: UsageReport → CallSiteReport → FileResourceReport
# ---------------------------------------------------------------------------


class FileResourceReport(BaseModel):
    """Descriptive analysis of one exact typed filesystem resource.

    Descriptive-only — no intervention prescription. Written only for
    resources whose path class is ``PSEUDO_FS_*``
    (always), or ``MISSING_NON_PSEUDO_FS`` when
    ``file_resolver_scope == "with_allowlist"`` AND the path's extension
    is in ``file_resolver_normal_fs_ext_allowlist``, or any
    ``MISSING_NON_PSEUDO_FS`` when ``file_resolver_scope == "full"``.

    Field responsibilities (no overlap enforced by agent prompt):
      * containing_function_purpose / setup_details / usage_reports live in
        each CallSiteReport — per-site detail.
      * coverage_flows / summary — resource-level analysis across CallSiteReports.
        Conditional semantic claims live in the same analysis's finding.
      * observed_apis — Python-derived dedup of api_name values across
        usage_reports; not agent-filled.
    """

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="before")
    @classmethod
    def discard_computed_fields(cls, value):
        if isinstance(value, dict):
            value = {key: item for key, item in value.items() if key != "observed_apis"}
        return value

    resource_group_id: str = Field(
        description=(
            "Stable identifier of the exact FileResource. The historical "
            "field name is retained for downstream JSON compatibility."
        )
    )
    primary_path: str = Field(
        description=(
            "The exact resource path or stable format pattern. It always "
            "equals the owning FileResource.path_value."
        )
    )
    resource_class: FileResourceClass = Field(
        description="Static classification of this exact filesystem resource."
    )

    callsite_reports: List[CallSiteReport] = Field(
        description=(
            "One entry per creating callsite for this exact resource. "
            "Length equals the number of creating-API callsites "
            "(query-only callsites like stat/access on the same path are "
            "excluded from agent analysis and listed only in the index)."
        )
    )

    coverage_flows: List[CoverageFlow] = Field(
        default_factory=list,
        description=(
            "One CoverageFlow per distinct lifecycle usage of this "
            "resource. Example: a resource touched only by "
            "fopen(r)+fread+fclose with an exit-on-NULL guard produces "
            "ONE flow with setup=[fopen], use=[fread,fclose], "
            "termination=[exit]. A rendezvous file with both read-first "
            "and create-fallback paths produces TWO flows. MAY be empty "
            "only when the agent cannot produce a coherent flow "
            "structure; each flow's callsites are flattened into "
            "FileResolverResult.covered_api_calls for cross-analyzer "
            "overlap observation, not context exclusion."
        )
    )

    summary: str = Field(
        description=(
            "Resource-level prose covering: (1) program's internal model of "
            "the resource (format, device semantics, data shape); "
            "(2) behaviour under each resource state — present / absent / "
            "malformed / call-failure — and how those outcomes propagate; "
            "(3) distinct per-site conditions and outcomes without selecting a "
            "dominant expectation or failure effect.\n"
            "Must NOT duplicate single-site detail already in "
            "callsite_reports[i].setup_details / usage_reports[j].details. "
            "Must NOT prescribe intervention (no 'should', 'intervention', "
            "'emulation', 'stub', 'create' as imperatives)."
        )
    )

    @computed_field
    @property
    def observed_apis(self) -> List[str]:
        """De-duplicated list of api_name values across all usage_reports.

        Consumers use this for quick filtering (e.g., 'every resource
        that is ioctl'd'). Sorted for stable output.
        """
        seen: Set[str] = set()
        for cr in self.callsite_reports:
            for ur in cr.usage_reports:
                seen.add(ur.api_name)
        return sorted(seen)


# ---------------------------------------------------------------------------
# FileCallsite (unchanged from B1 except for agent_report removal)
# ---------------------------------------------------------------------------


class FileResourceMapResult(BaseModel):
    """Map-worker output for a resource with many creating callsites.

    One worker sees a chunk of open callsites from one exact resource and
    emits per-callsite reports for that chunk only.
    Python concatenates the lists from every worker losslessly before
    the reduce stage.
    """

    model_config = ConfigDict(extra="forbid")

    callsite_reports: List[CallSiteAnalysis] = Field(
        description=(
            "One CallSiteReport per open callsite in this chunk. Length "
            "MUST equal the number of callsites the worker received — "
            "never skip, summarize away, or merge callsites. If two "
            "callsites look identical, still emit two entries."
        )
    )


class FileResourceReduceResult(BaseModel):
    """Reduce-agent output for a resource with many creating callsites.

    Reduce sees the full concatenated ``callsite_reports`` plus the
    exact-resource metadata and synthesizes the top-level fields. It
    does NOT re-emit ``callsite_reports`` — that list comes from the
    map stage. ``observed_apis`` is Python-derived from the map output
    on ``FileResourceReport`` assembly, so reduce does not emit it.
    """

    model_config = ConfigDict(extra="forbid")

    coverage_flows: List[CoverageFlow] = Field(
        default_factory=list,
        description=(
            "Same shape and semantics as "
            "FileResourceReport.coverage_flows. Reduce aggregates the "
            "per-site lifecycle structure observed in the concatenated "
            "callsite_reports into resource-level flows. MAY be empty "
            "only when the resource has no coherent flow structure."
        )
    )
    summary: str = Field(
        description=(
            "Resource-level cross-site / cross-state prose. Same content "
            "contract as FileResourceReport.summary. Must NOT duplicate "
            "single-site detail already in callsite_reports[i]. Describe "
            "observed behavior without selecting an intervention strategy."
        )
    )
    finding: FindingSemantics = Field(
        description=(
            "Semantic finding from this resource analysis. Reference /callsite_reports/N "
            "and its setup/usage evidence, or /coverage_flows/N. Describe caller checks, "
            "return/error/output requirements, file or device state and lifecycle, "
            "native fallback and explicit unknown instance data or effects. Mere path "
            "existence or API presence proves no runtime behavior. The Controller attaches "
            "the supplied resource_usage_sites and total_usage_sites to each report by "
            "callsite_id before validating these references. Cite that provided evidence "
            "as /callsite_reports/N/resource_usage_sites/M without generating it again."
        )
    )


class FileResourceAnalysisOutput(FileResourceReduceResult):
    """One full resource analysis; static identity is supplied by the Controller."""
    model_config = ConfigDict(extra="forbid")
    callsite_reports: List[CallSiteAnalysis] = Field(
        description="Exactly one complete source-backed report per supplied creating callsite."
    )


class FilePathCandidate(BaseModel):
    """One concrete or patterned path recovered by the fallback agent."""

    value: str = Field(
        min_length=1,
        description=(
            "Exact path literal or format pattern only, without annotations."
        ),
    )
    kind: Literal["concrete", "pattern"] = Field(
        description=(
            "concrete for an exact compile-time path; pattern when a stable "
            "format is known but contains runtime substitutions."
        ),
    )
    evidence: List[str] = Field(
        min_length=1,
        description=(
            "Exact binary/function/line evidence that derives this value. "
            "Include caller or wrapper locations when they determine it."
        ),
    )


class FilePathResolution(BaseModel):
    """Structured output of FileResolver's path-only fallback agent."""

    candidates: List[FilePathCandidate] = Field(
        default_factory=list,
        description=(
            "All distinct concrete paths and stable format patterns proven "
            "for the target argument. Do not emit an unresolved sentinel."
        ),
    )
    missing_evidence: List[str] = Field(
        default_factory=list,
        description=(
            "Specific dynamic sources or missing code relationships that "
            "prevent complete resolution. Required when candidates is empty."
        ),
    )

    @model_validator(mode="after")
    def _require_result_or_gap(self):
        if not self.candidates and not self.missing_evidence:
            raise ValueError(
                "path resolution without candidates must name missing_evidence"
            )
        merged = {}
        for candidate in self.candidates:
            key = (candidate.kind, candidate.value)
            if key in merged:
                previous = merged[key]
                merged[key] = previous.model_copy(update={
                    "evidence": list(dict.fromkeys([*previous.evidence, *candidate.evidence])),
                })
            else:
                merged[key] = candidate
        self.candidates = list(merged.values())
        return self


class FileCallsite(BaseModel):
    """Callsite metadata — one record per resolved path candidate.

    When the same callsite resolves to multiple candidate paths (dataflow
    branching or the path fallback agent returning multiple candidates),
    each candidate becomes a separate FileCallsite keyed by
    ``profile_key = "{callsite_id}#{candidate_idx}"``. ``callsite_id``
    includes the CTree index (or an EA/column fallback), so two calls
    rendered on the same source line remain distinct.

    ``resource_group_id`` links eligible callsites to their exact
    :class:`FileResource`. The historical name is retained for persisted
    output compatibility; no family grouping is performed.
    """

    callsite_id: str = Field(
        description=(
            '"{binary}::{func}::L{line}::{api}@ctree{index}". '
            "The suffix is a stable semantic identity, not display text; "
            "legacy CallSite objects use an EA/column suffix instead."
        )
    )
    candidate_idx: int = Field(
        description="0-based index when a callsite resolves to multiple candidates"
    )
    profile_key: str = Field(
        description='"{callsite_id}#{candidate_idx}" — the FileResolverResult.callsites dict key'
    )

    binary_name: str
    function_name: str
    function_ea: Optional[int] = Field(
        default=None,
        description="Function entry EA in the owning IDA database.",
    )
    snapshot_hash: Optional[str] = Field(
        default=None,
        description="Immutable FunctionSemanticSnapshot identity.",
    )
    line_number: int
    column_number: int = Field(
        default=0,
        description="Rendered C column of the call expression.",
    )
    callsite_ea: int = Field(
        default=0,
        description="Instruction address associated with the CTree call.",
    )
    ctree_index: Optional[int] = Field(
        default=None,
        description="CTree object identity within the function snapshot.",
    )
    api_name: str
    path_arg_index: int

    requested_path: str = Field(
        description=(
            "Path recovered from the API argument before guest-root symlink "
            "resolution. It equals path_value unless the frozen rootfs "
            "contains a symlink alias."
        )
    )
    path_value: str = Field(
        description=(
            "Effective guest path after lexical rootfs symlink resolution, "
            "or an absolute stable format pattern."
        )
    )
    path_kind: Literal["concrete", "pattern"]
    resolution_source: Literal[
        "literal_static",
        "global_static",
        "dataflow_static",
        "file_path_agent",
    ]

    resolution_evidence: List[str] = Field(
        default_factory=list,
        description=(
            "Agent-provided code evidence for file_path_agent candidates; "
            "empty for controller-resolved static candidates."
        ),
    )

    resource_class: FileResourceClass

    resource_group_id: Optional[str] = Field(
        default=None,
        description=(
            "Stable exact-resource id for callsites eligible for "
            "per-resource analysis. Back-links into FileResolverResult.resources "
            "and resource_reports."
        ),
    )


# ---------------------------------------------------------------------------
# Exact resources
# ---------------------------------------------------------------------------


class FileResource(BaseModel):
    """One exact typed path and all eligible creating callsites using it."""

    resource_group_id: str = Field(
        description=(
            "Stable readable identifier derived from path_kind and path_value. "
            "The historical suffix 'group_id' is retained for compatibility."
        )
    )
    path_value: str
    path_kind: Literal["concrete", "pattern"]
    resource_class: FileResourceClass
    callsites: List[FileCallsite] = Field(
        description=(
            "All eligible FileCallsites sharing this exact typed path. "
            "'Eligible' means: scope+allowlist admit them AND api_name "
            "is in the creating set (open/open64, openat variants, "
            "creat variants, fopen/freopen variants, opendir, or "
            "mkstemp variants)."
        )
    )


# ---------------------------------------------------------------------------
# Top-level result
# ---------------------------------------------------------------------------


def _derive_file_reason_from_callsite(cs: "FileCallsite") -> str:
    """Coverage reason for a path-based FileCallsite.

    Format: ``filesystem {api} on {resource_class}``. Pure function,
    zero LLM cost. Lives here (not in base/coverage.py) because the
    rule is FileResolver-specific — IPC has its own agent-driven
    reason-string logic.
    """
    return f"filesystem {cs.api_name} on {cs.resource_class.value}"


class FileResolverResult(BaseModel):
    """Top-level FileResolver output. Persisted as ``file_resolver_result.json``.

    Contents across phases:
      * phase="static" — ``callsites`` +
        ``queued_for_path_agent`` + ``resources``. ``resource_reports`` empty.
      * phase="full"   — all of the above, plus ``resource_reports``;
        ``queued_for_path_agent`` empty.
    """

    model_config = ConfigDict(extra="forbid")
    execution: AnalysisExecution = Field(description="Task completion and execution failures, independent of firmware semantic gaps.")
    schema_version: Literal[12] = Field(
        description=(
            "FileResolver persisted schema version. It is required so old "
            "path, fallback eligibility, and usage-location semantics fail "
            "validation instead of being reused."
        )
    )
    phase: Literal["static", "full"] = Field(
        description="Analyzer phase that produced this persisted result.",
    )
    root_binary: str
    finding_target: FindingTarget = Field(description="Verified target executable path and digest used for finding identity.")
    planning_findings: PlanningFindings = Field(description="Semantic findings from this exact resource analysis, or explicit static/failed-analysis gaps.")
    callsites: Dict[str, FileCallsite] = Field(
        default_factory=dict,
        description="profile_key → FileCallsite; one entry per resolved candidate",
    )
    path_resolution_gaps: Dict[str, List[str]] = Field(
        default_factory=dict,
        description=(
            "callsite_id to explicit missing evidence from relative paths, "
            "guest symlink failures, intentionally unexpanded query-only "
            "paths, or failed/partial fallback analysis."
        ),
    )
    queued_for_path_agent: List[str] = Field(
        default_factory=list,
        description=(
            "Unresolved creating-API callsite_ids that would be handed to "
            "the file path fallback agent in full phase. Unresolved "
            "query-only APIs are recorded in path_resolution_gaps instead. "
            "Populated only in phase='static' runs."
        ),
    )

    resources: Dict[str, FileResource] = Field(
        default_factory=dict,
        description=(
            "resource_group_id to exact typed FileResource. Covers only "
            "agent-eligible creating callsites and is present in both phases."
        ),
    )
    resource_reports: Dict[str, FileResourceReport] = Field(
        default_factory=dict,
        description="resource_group_id to full-phase FileResourceReport.",
    )
    @model_validator(mode="before")
    @classmethod
    def discard_computed_fields(cls, value):
        if isinstance(value, dict):
            value = dict(value)
            for field in ("covered_api_calls", "counts_by_resolution_source", "counts_by_resource_class"):
                value.pop(field, None)
        return value

    @model_validator(mode="after")
    def validate_findings(self):
        self.execution.validate_phase(self.phase)
        if set(self.resource_reports) & self.execution.unsuccessful_subjects("resource"):
            raise ValueError("failed resources cannot publish successful reports")
        if any(key != site.profile_key for key, site in self.callsites.items()):
            raise ValueError("file callsite key must equal profile_key")
        if self.phase == "static":
            if self.resource_reports:
                raise ValueError("static file results cannot contain Agent resource analyses")
            if any(site.resolution_source == "file_path_agent" for site in self.callsites.values()):
                raise ValueError("static file results cannot contain Agent path resolutions")
        elif set(self.resource_reports) | self.execution.unsuccessful_subjects("resource") != set(self.resources):
            raise ValueError("full resource reports and execution failures must exactly cover file resources")
        expected = {self.finding_target.ref("file", key): key for key in self.resources
                    if key not in self.execution.unsuccessful_subjects("resource")}
        if set(self.planning_findings) != set(expected):
            raise ValueError("planning_findings must exactly cover file resources")
        for ref, finding in self.planning_findings.items():
            key = expected[ref]
            resource = self.resources[key]
            if resource.resource_group_id != key:
                raise ValueError("resource key must equal resource_group_id")
            if any(self.callsites.get(site.profile_key) != site for site in resource.callsites):
                raise ValueError("resource callsite disagrees with source callsites")
            if finding.domain != FileFindingDomain(
                kind="file", resource_id=key, path=resource.path_value,
                resource_class=resource.resource_class.value,
                callsite_ids=sorted({site.callsite_id for site in resource.callsites}),
            ):
                raise ValueError("file finding domain disagrees with its source resource")
            if finding.boundary.kind != "resource" or finding.boundary.anchors != [
                FindingAnchor(kind="path", ref=pointer("resources", key, "path_value"))
            ]:
                raise ValueError("file finding must anchor its source resource path")
            report = self.resource_reports.get(key)
            if report is not None:
                if (report.resource_group_id, report.primary_path, report.resource_class) != (
                    key, resource.path_value, resource.resource_class,
                ):
                    raise ValueError("file report identity disagrees with source resource")
                validate_bound_finding(
                    finding, record_ref=pointer("resource_reports", key),
                    document=report.model_dump(mode="json"),
                    allowed_roots={"callsite_reports", "coverage_flows"},
                )
            else:
                if any(claim.kind != "unknown" for claim in finding.claims):
                    raise ValueError("unassessed file resource cannot claim known semantics")
                if finding.boundary.reachability_refs or finding.boundary.coverage_refs:
                    raise ValueError("unassessed file resource cannot claim semantic coverage")
                allowed = {pointer("resources", key)}
                if any(evidence not in allowed for claim in finding.claims for evidence in claim.evidence_refs):
                    raise ValueError("static file gap must cite its own source resource")
        validate_finding_references(self.planning_findings, self.model_dump(mode="json"))
        return self

    @computed_field
    @property
    def counts_by_resolution_source(self) -> Dict[str, int]:
        """Per-source candidate count. Useful to report static vs LLM coverage."""
        buckets = {
            "literal_static": 0,
            "global_static": 0,
            "dataflow_static": 0,
            "file_path_agent": 0,
        }
        for c in self.callsites.values():
            buckets[c.resolution_source] = buckets.get(c.resolution_source, 0) + 1
        return buckets

    @computed_field
    @property
    def counts_by_resource_class(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for c in self.callsites.values():
            out[c.resource_class.value] = out.get(c.resource_class.value, 0) + 1
        return out

    @computed_field
    @property
    def covered_api_calls(self) -> List[CoveredAPICall]:
        """APIs FileResolver declares as filesystem-resource related.

        Merges three sources, deduped by immutable CTree identity when
        available and display coordinates only for legacy/agent-authored facts:

          * Source A: ``self.callsites`` — path-based creating /
            query-only callsites (open / stat / access / ...).
          * Source B: ``resource_reports[*].callsite_reports[*]
            .usage_reports[*]`` — fd-based use sites discovered by
            FileResourceAnalysisAgent (read / ioctl / mmap / close / ...).
          * Source C: ``resource_reports[*].coverage_flows[*].
            (setup / use / termination)`` — agent-authored lifecycle
            flow entries (added in the resource-contract refactor).

        Coverage is an observation index; it does not assign intervention ownership.
        """
        seen: Set[Tuple] = set()
        authoritative_display: Set[Tuple[str, str, str, int]] = set()
        out: List[CoveredAPICall] = []

        for cs in self.callsites.values():
            claim = CoveredAPICall(
                binary_name=cs.binary_name,
                function_name=cs.function_name,
                api_name=cs.api_name,
                line_number=cs.line_number,
                column_number=cs.column_number,
                function_ea=cs.function_ea,
                snapshot_hash=cs.snapshot_hash,
                ctree_index=cs.ctree_index,
                source_ea=cs.callsite_ea or None,
                reason=_derive_file_reason_from_callsite(cs),
            )
            if claim.identity_key in seen:
                continue
            seen.add(claim.identity_key)
            authoritative_display.add(claim.display_key)
            out.append(claim)

        for report in self.resource_reports.values():
            rc_value = report.resource_class.value
            for cr in report.callsite_reports:
                for ur in cr.usage_reports:
                    claim = CoveredAPICall(
                        binary_name=ur.binary_name,
                        function_name=ur.function_name,
                        api_name=ur.api_name,
                        line_number=ur.line_number,
                        reason=f"filesystem {ur.api_name} on {rc_value}",
                    )
                    if claim.display_key in authoritative_display:
                        continue
                    if claim.identity_key in seen:
                        continue
                    seen.add(claim.identity_key)
                    out.append(claim)

        # Source C: coverage_flows (added in the resource-contract refactor).
        # Agents emit structured CoverageFlow objects on every resource_report;
        # flattening their setup/use/termination lists gives the synthesis
        # layer access to the same dedup key that IPC's covered_api_calls
        # provides, so ProcessLifecycleAnalyzer can skip exits that File's
        # flows already claim.
        for report in self.resource_reports.values():
            for flow in report.coverage_flows:
                for rac in (*flow.setup, *flow.use, *flow.termination):
                    if (
                        rac.ctree_index is None
                        and rac.display_key in authoritative_display
                    ):
                        continue
                    if rac.identity_key in seen:
                        continue
                    seen.add(rac.identity_key)
                    out.append(rac)

        return out
