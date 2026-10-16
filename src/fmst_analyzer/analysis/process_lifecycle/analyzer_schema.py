"""Structured output for ProcessLifecycleAnalyzer.

The persisted result assigns one assessment or explicit execution failure to
each stable process-event callsite. Other analyzers do not suppress events.
Agent-only draft types live here as well so their field
descriptions are visible through the structured-output schema.
"""
from __future__ import annotations

from fmst_analyzer.analysis.base.execution import AnalysisExecution

from enum import Enum
from typing import Literal
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator
from fmst_analyzer.analysis.base.analysis_finding import (
    FindingAnchor, PlanningFindings, ProcessFindingDomain, validate_finding_references,
)
from fmst_analyzer.analysis.base.finding_binding import FindingSemantics, FindingTarget, pointer, validate_bound_finding


PROCESS_LIFECYCLE_SCHEMA_VERSION = 5


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProcessEventKind(str, Enum):
    TERMINATION = "termination"
    PROCESS_TRANSITION = "process_transition"


class ProcessEventDisposition(str, Enum):
    STARTUP_BLOCKER = "startup_blocker"
    EXPECTED_LIFECYCLE = "expected_lifecycle"
    RUNTIME_ONLY = "runtime_only"
    UNRESOLVED = "unresolved"


class ProcessEventCallsite(StrictModel):
    """Controller-owned identity for one reachable process event."""

    callsite_id: str = Field(
        description="Opaque stable identity for this exact CTree call."
    )
    binary_name: str = Field(description="LibDepGraph module containing the call.")
    function_name: str = Field(description="Persisted decompiler artifact name.")
    function_ea: int = Field(description="Function entry EA in its IDA database.")
    snapshot_hash: str = Field(description="FunctionSemanticSnapshot identity.")
    ctree_index: int = Field(description="CTree object identity within snapshot_hash.")
    source_ea: int | None = Field(
        default=None,
        description="Guest instruction EA associated with the CTree call, or null for BADADDR.",
    )
    line_number: int = Field(description="One-based line in the persisted C artifact.")
    column_number: int = Field(description="Zero-based column in the persisted C artifact.")
    api_name: str = Field(
        description=(
            "Normalized API symbol. Exactly one of exit, _exit, _Exit, "
            "quick_exit, abort, __assert_fail, daemon, fork, vfork, "
            "clone, or setsid."
        )
    )
    event_kind: ProcessEventKind = Field(
        description="Mechanical API-family classification; never Agent-authored."
    )


class ProcessCodeEvidence(StrictModel):
    claim: str = Field(description="Exact fact supported by this code citation.")
    binary_name: str = Field(description="Module containing the cited code.")
    function_name: str = Field(description="Function containing the cited line.")
    line_number: int = Field(description="One-based line in the persisted C artifact.")
    api_name: str | None = Field(
        default=None,
        description="Verbatim API called at the cited line, or null for branch/control-flow evidence.",
    )


class ProcessTriggerInput(StrictModel):
    kind: Literal["path", "environment_variable", "argv", "global", "other"] = Field(
        description="Kind of non-callsite input that directly controls the process event."
    )
    value: str = Field(
        description="Verbatim path, environment name, argv expression, global name, or other input."
    )
    summary: str = Field(description="How this input admits or prevents the event path.")


class ProcessTriggerCallsiteDraft(StrictModel):
    """Agent citation for a direct triggering API before identity resolution."""

    binary_name: str = Field(description="Module containing the triggering API call.")
    function_name: str = Field(description="Function containing the triggering API call.")
    line_number: int = Field(description="One-based line of the triggering API call.")
    column_number: int | None = Field(
        default=None,
        description="Zero-based column when needed to distinguish same-line calls.",
    )
    api_name: str = Field(description="Verbatim direct triggering API symbol.")


class ProcessTriggerCallsite(StrictModel):
    """Controller-resolved stable identity for a direct trigger API."""

    callsite_id: str = Field(description="Stable identity of the triggering CTree call.")
    binary_name: str
    function_name: str
    function_ea: int
    snapshot_hash: str
    ctree_index: int
    source_ea: int | None = None
    line_number: int
    column_number: int
    api_name: str


class ProcessLifecycleAgentResult(StrictModel):
    """Agent-owned semantic draft for one controller-supplied event."""

    disposition: ProcessEventDisposition = Field(
        description=(
            "startup_blocker when an unmet runtime dependency causes a complete target startup failure witness; "
            "expected_lifecycle for a normal termination or process transition, even after "
            "startup, including deliberate usage/help and invalid-command rejection; "
            "runtime_only only for an abnormal failure termination whose every "
            "reachable context occurs after startup; unresolved when the caller/guard or "
            "cross-process failure-propagation evidence is insufficient."
        )
    )
    trigger_callsites: list[ProcessTriggerCallsiteDraft] = Field(
        default_factory=list,
        description=(
            "Direct API calls whose specific result predicate reaches this exact event. "
            "Each trigger needs its actual guard and branch destination in evidence; "
            "neighboring or nested allocation checks are not interchangeable. "
            "A failure that reaches cleanup and returns is not an abort trigger. A trigger may be absent when only the event and condition are known. "
            "Do not invent a preceding API to satisfy this field."
        ),
    )
    trigger_inputs: list[ProcessTriggerInput] = Field(
        default_factory=list,
        description="Non-callsite inputs such as paths, environment variables, argv, or globals.",
    )
    summary: str = Field(description="Concise startup/runtime reachability and effect conclusion.")
    evidence: list[ProcessCodeEvidence] = Field(
        default_factory=list,
        description=(
            "Code citations proving caller context, guards, and resulting process behavior. "
            "A child/helper startup-blocker claim must also cite the parent's observation "
            "and propagation to root-target or service-readiness failure. A custom-library "
            "or indirect-callback claim must cite the root startup caller and exact binding."
        ),
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific facts that could not be established; required for unresolved.",
    )
    finding: FindingSemantics = Field(
        description=(
            "Semantic finding for this exact event, consistent with its disposition. "
            "Claims state concrete caller-visible return/error/output requirements, "
            "process state, lifecycle and native fallback constraints. Cite /evidence/N "
            "for known claims and reachability; unknowns may cite /missing_evidence/N. "
            "Coverage is not inferred from a nearby call. Do not choose an intervention."
        )
    )

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        self.finding.validate_references(
            self.model_dump(mode="json"), allowed_roots={"evidence", "missing_evidence"},
        )
        for claim in self.finding.claims:
            if claim.kind != "unknown" and any(
                not ref.startswith("/evidence/") for ref in claim.evidence_refs
            ):
                raise ValueError("known process claims must cite code evidence")
        if self.disposition is ProcessEventDisposition.UNRESOLVED:
            if not self.missing_evidence:
                raise ValueError("unresolved disposition requires missing_evidence")
        else:
            if not self.evidence:
                raise ValueError(f"{self.disposition.value} disposition requires code evidence")

        return self


class ProcessEventAssessment(StrictModel):
    callsite_id: str = Field(description="Controller-owned ProcessEventCallsite identity.")
    disposition: ProcessEventDisposition
    trigger_callsites: list[ProcessTriggerCallsite | ProcessTriggerCallsiteDraft] = Field(default_factory=list)
    trigger_inputs: list[ProcessTriggerInput] = Field(default_factory=list)
    summary: str
    evidence: list[ProcessCodeEvidence] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if self.disposition is ProcessEventDisposition.UNRESOLVED:
            if not self.missing_evidence:
                raise ValueError("unresolved disposition requires missing_evidence")
        else:
            if not self.evidence:
                raise ValueError(f"{self.disposition.value} disposition requires code evidence")

        return self


class ProcessEventAssessmentReport(StrictModel):
    """Self-contained JSON source for one per-assessment Markdown page."""

    schema_version: int = PROCESS_LIFECYCLE_SCHEMA_VERSION
    root_binary: str
    callsite: ProcessEventCallsite
    assessment: ProcessEventAssessment

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.schema_version != PROCESS_LIFECYCLE_SCHEMA_VERSION:
            raise ValueError("unsupported process lifecycle report schema")
        if self.callsite.callsite_id != self.assessment.callsite_id:
            raise ValueError("assessment report callsite identities disagree")
        return self


class ProcessLifecycleAnalysisResult(StrictModel):
    execution: AnalysisExecution = Field(description="Task completion and execution failures, independent of semantic unknowns.")
    schema_version: int = Field(
        description="Persisted ProcessLifecycleAnalyzer schema version.",
    )
    phase: Literal["static", "full"] = Field(
        description="Analyzer phase that produced this result.",
    )
    root_binary: str
    finding_target: FindingTarget = Field(description="Controller-verified target identity used for stable findings.")
    planning_findings: PlanningFindings = Field(description="Same-analysis semantic findings keyed by controller-owned identity.")
    callsites: dict[str, ProcessEventCallsite] = Field(default_factory=dict)
    assessments: dict[str, ProcessEventAssessment] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_accounting(self) -> Self:
        self.execution.validate_phase(self.phase)
        if self.schema_version != PROCESS_LIFECYCLE_SCHEMA_VERSION:
            raise ValueError(
                f"expected schema_version={PROCESS_LIFECYCLE_SCHEMA_VERSION}, "
                f"got {self.schema_version}"
            )
        if any(key != item.callsite_id for key, item in self.callsites.items()):
            raise ValueError("callsites mapping key must equal ProcessEventCallsite.callsite_id")
        if any(key != item.callsite_id for key, item in self.assessments.items()):
            raise ValueError("assessments mapping key must equal ProcessEventAssessment.callsite_id")
        all_ids = set(self.callsites)
        assessment_ids = set(self.assessments)
        if assessment_ids & self.execution.unsuccessful_subjects("process"):
            raise ValueError("failed process tasks cannot publish assessments")
        if self.phase == "static":
            if self.assessments:
                raise ValueError("static phase must not contain Agent assessments")
        elif assessment_ids | self.execution.unsuccessful_subjects("process") != all_ids:
            raise ValueError(
                "full assessments and execution failures must exactly cover all callsites"
            )
        expected = {
            self.finding_target.ref("process", key): key
            for key in all_ids - self.execution.unsuccessful_subjects("process")
        }
        if set(self.planning_findings) != set(expected):
            raise ValueError("planning_findings must exactly cover assessed or statically collected process callsites")
        for ref, finding in self.planning_findings.items():
            key = expected[ref]
            callsite = self.callsites[key]
            if finding.domain != ProcessFindingDomain(
                kind="process", callsite_id=key, event_kind=callsite.event_kind.value,
            ):
                raise ValueError("process finding domain disagrees with its source callsite")
            if finding.boundary.kind != "callsite" or finding.boundary.anchors != [
                FindingAnchor(kind="callsite", ref=pointer("callsites", key))
            ]:
                raise ValueError("process finding must anchor its exact source callsite")
            if self.phase == "static" and any(claim.kind != "unknown" for claim in finding.claims):
                raise ValueError("static process collection cannot claim Agent semantics")
            if self.phase == "static":
                if finding.boundary.reachability_refs or finding.boundary.coverage_refs:
                    raise ValueError("static process findings cannot claim semantic reachability or coverage")
                if any(ref != pointer("callsites", key)
                       for claim in finding.claims for ref in claim.evidence_refs):
                    raise ValueError("static process finding must cite its own callsite")
            else:
                validate_bound_finding(
                    finding, record_ref=pointer("assessments", key),
                    document=self.assessments[key].model_dump(mode="json"),
                    allowed_roots={"evidence", "missing_evidence"},
                )
            for claim in finding.claims:
                if claim.kind != "unknown" and any(
                    not evidence.startswith(pointer("assessments", key, "evidence") + "/")
                    for evidence in claim.evidence_refs
                ):
                    raise ValueError("process claim must cite its own assessment code evidence")
        validate_finding_references(self.planning_findings, self.model_dump(mode="json"))
        return self


__all__ = [
    "PROCESS_LIFECYCLE_SCHEMA_VERSION",
    "ProcessCodeEvidence",
    "ProcessEventAssessment",
    "ProcessEventAssessmentReport",
    "ProcessEventCallsite",
    "ProcessEventDisposition",
    "ProcessEventKind",
    "ProcessLifecycleAgentResult",
    "ProcessLifecycleAnalysisResult",
    "ProcessTriggerCallsite",
    "ProcessTriggerCallsiteDraft",
    "ProcessTriggerInput",
]
