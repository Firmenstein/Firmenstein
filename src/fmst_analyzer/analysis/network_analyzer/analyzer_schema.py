"""Persisted and agent-output schemas for NetworkAnalyzer v11."""
from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError

from fmst_analyzer.analysis.base.execution import AnalysisExecution

from enum import Enum
from typing import Literal
from typing_extensions import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from fmst_analyzer.analysis.base.coverage_flow import CoverageFlow
from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICall
from fmst_analyzer.analysis.base.analysis_finding import (
    FindingAnchor, NetworkFindingDomain, PlanningFindings, validate_finding_references,
)
from fmst_analyzer.analysis.base.finding_binding import (
    FindingSemantics, FindingTarget, pointer, validate_bound_finding,
)


NETWORK_ANALYSIS_SCHEMA_VERSION = 11
NETWORK_EVIDENCE_ROOTS = {"evidence", "context_anchor", "api_effects", "coverage_flows", "identity", "missing_evidence"}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NetworkDisposition(str, Enum):
    NETWORK = "network"
    INTERNAL_IPC = "internal_ipc"
    FILE_RESOURCE = "file_resource"
    NOT_NETWORK = "not_network"
    UNRESOLVED = "unresolved"


class NetworkInteractionKind(str, Enum):
    LISTENER = "listener"
    OUTBOUND_CONNECTION = "outbound_connection"
    DATAGRAM = "datagram"
    RESOLVER = "resolver"
    INTERFACE_QUERY = "interface_query"
    INTERFACE_CONFIG = "interface_config"
    NETLINK = "netlink"
    OTHER = "other"


class IdentityResolution(str, Enum):
    EXACT = "exact"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"


class NetworkRawArgument(StrictModel):
    index: int = Field(description="One-based CTree argument index.")
    expression: str = Field(description="Unmodified IDA CTree argument expression.")


class NetworkCodeLocation(StrictModel):
    binary_name: str = Field(description="LibDepGraph module name used by code tools.")
    binary_path: str = Field(description="Canonical rootfs-relative ELF path.")
    binary_sha256: str = Field(description="SHA-256 of binary_path.")
    function_name: str = Field(description="Decompiler artifact name containing the call.")
    function_ea: int = Field(description="Function entry EA in its IDA database.")
    snapshot_hash: str = Field(description="FunctionSemanticSnapshot hash.")
    ctree_index: int = Field(description="CTree object identity within snapshot_hash.")
    source_ea: int | None = Field(
        default=None,
        description="Instruction EA associated with the CTree call, or null for BADADDR.",
    )
    line_number: int = Field(description="One-based line in the persisted decompiled C file.")
    column_number: int = Field(description="Zero-based column in the persisted C file.")


class NetworkAPIBinding(StrictModel):
    symbol: str = Field(description="Normalized terminal API symbol selected by the registry.")
    call_kind: str = Field(description="IDA CTree call kind: direct, helper, indirect, or other.")
    verified: bool = Field(
        description=(
            "True only when the CTree call is a direct reachable call to the selected "
            "external API symbol; false keeps the binding visible but unresolved."
        )
    )


class NetworkCallsite(StrictModel):
    callsite_id: str = Field(description="Stable controller-owned CTree callsite identity.")
    location: NetworkCodeLocation = Field(description="Immutable code and CTree location.")
    api_name: str = Field(description="Normalized network registry API name.")
    api_family: str = Field(description="Registry family used only for candidate accounting.")
    api_binding: NetworkAPIBinding = Field(description="Deterministic call-target binding fact.")
    expression_text: str = Field(description="Complete unmodified IDA call expression.")
    arguments: list[NetworkRawArgument] = Field(
        description="Call arguments in original one-based CTree order."
    )
    return_expression: str | None = Field(
        default=None,
        description="Receiving expression for the API return value, or null when unused.",
    )


class NetworkIdentity(StrictModel):
    resolution: IdentityResolution = Field(
        description="Whether the network identity is exact, partial, or unresolved."
    )
    family: str | None = Field(default=None, description="Socket family when known.")
    socket_type: str | None = Field(default=None, description="Socket type when known.")
    protocol: str | None = Field(default=None, description="Transport or socket protocol.")
    local_address: str | None = Field(default=None, description="Local bind address.")
    local_port: int | None = Field(default=None, description="Local host-order port.")
    remote_address: str | None = Field(default=None, description="Remote destination address.")
    remote_port: int | None = Field(default=None, description="Remote host-order port.")
    hostname: str | None = Field(default=None, description="Resolver hostname when known.")
    service: str | None = Field(default=None, description="Resolver service name when known.")
    interface: str | None = Field(default=None, description="Interface name or index expression.")
    operation: str | None = Field(
        default=None,
        description="ioctl request or socket-option operation when known.",
    )
    netlink_protocol: str | None = Field(
        default=None,
        description="Netlink protocol number or symbolic name when known.",
    )


class NetworkEvidence(StrictModel):
    claim: str = Field(description="Exact fact supported by this code citation.")
    binary_name: str = Field(description="LibDepGraph module containing the cited code.")
    function_name: str = Field(description="Enclosing caller's decompiler artifact name containing the cited line; not the callee/import stub.")
    line_number: int = Field(description="One-based line in the persisted C file.")
    api_name: str | None = Field(
        default=None,
        description="Verbatim callee at the cited line for an actual call; null for a branch, return statement or other non-call evidence.",
    )
    callsite_id: str | None = Field(
        default=None,
        description="Input callsite identity when this citation points to a supplied candidate.",
    )

    def validate_callsite(self, fact: NetworkCallsite) -> None:
        """A catalog ID and explicit code coordinates must name the same call."""
        location = fact.location
        if (
            (self.binary_name, self.function_name, self.line_number)
            != (location.binary_name, location.function_name, location.line_number)
        ):
            raise OutputValidationError(
                f"evidence callsite {self.callsite_id} disagrees with its catalog location: "
                f"expected {location.binary_name}::{location.function_name}:L{location.line_number} "
                f"{fact.api_name}, got {self.binary_name}::{self.function_name}:L{self.line_number} "
                f"{self.api_name}"
            )


class NetworkAPIEffect(StrictModel):
    binary_name: str = Field(description="Module containing the API operation.")
    function_name: str = Field(description="Enclosing caller's decompiler artifact containing the API call; not the callee/import stub.")
    line_number: int = Field(description="One-based line of the call in the complete persisted C artifact.")
    api_name: str = Field(description="Verbatim callee symbol of an actual API call. Branches and return statements belong in NetworkEvidence and effect descriptions.")
    role: str = Field(
        description="Short factual role such as setup, use, query, configuration, or failure check."
    )
    return_or_output_use: str = Field(
        description=("Exact data consumed from the return value or output memory, including relevant "
                     "field/byte offsets and branch comparisons. Preserve the value actually passed "
                     "to the caller, including the source expression and concrete numeric cases, and "
                     "to later operations, even when unusual or apparently buggy. Say unused only "
                     "when the inspected callers establish that; missing dataflow is an explicit gap.")
    )
    side_effect: str = Field(
        description=("Program-visible memory, descriptor/object or state change, including initialization "
                     "before later errors and conditional cleanup. Do not infer output behavior solely "
                     "from an API name or normalize firmware behavior into the usual API pattern. "
                     "For pointed memory, state the byte range passed to the API and the offsets of "
                     "relevant fields. The actual argument length, not a decompiler local's declared "
                     "size, determines whether adjacent storage is included; an adjacent scalar can "
                     "be part of the same input/output object.")
    )
    failure_effect: str = Field(
        description=("Actual conditional failure propagation to the observing caller or target entry. "
                     "Describe the state at that observation after all writes on the failing path; "
                     "an error does not undo earlier initialization, clearing or partial output. "
                     "Separate failures before and after a write when the caller observes different "
                     "values, including zero-length and short transfers. "
                     "Returning from main terminates the target; a helper error alone does not. "
                     "Distinguish cleanup/continuation, local operation failure, child exit, normal "
                     "daemon-parent exit, and target termination. Cite the specific branch; if the "
                     "caller path cannot be established, state that precise gap.")
    )


class NetworkContextAnchor(StrictModel):
    binary_name: str = Field(description="Module containing the source position distinguishing this invocation.")
    function_name: str = Field(description="Function containing the distinguishing caller, branch or resource origin.")
    line_number: int = Field(ge=1, description="Verified one-based position in the persisted decompiled source, not a list offset.")
    column_number: int = Field(ge=0, default=0, description="Zero-based start column of the cited C token, excluding line-number display prefixes. Indentation or the middle of an identifier is not a valid position. Distinguishes expressions on one source line.")

    def identity_key(self) -> tuple[str, str, int, int]:
        return self.binary_name, self.function_name, self.line_number, self.column_number


class NetworkInteractionDraft(StrictModel):
    """Agent-owned semantic delta. Python supplies the final interaction_id."""

    callsite_ids: list[str] = Field(
        min_length=1,
        description=(
            "Controller-provided callsite identities proven relevant to this "
            "environment interaction. The same shared helper callsite may appear "
            "in another interaction. Do not include a callsite merely because it "
            "is in the same function or uses a similarly named descriptor."
        ),
    )
    context_anchor: NetworkContextAnchor | None = Field(
        description=(
            "Minimal verified source position distinguishing this invocation context, such "
            "as a branch, caller or resource constructor. Additional evidence belongs in "
            "evidence, not in this identity. Null only when context is unresolved. Different "
            "contexts may share all callsite_ids; natural-language labels do not distinguish identities."
        ),
    )
    applicability: str = Field(
        pattern=r"\S",
        description="Conditions enabling this interaction, including argument/branch polarity and unknown applicability. Preserve every conditional effect in the finding; do not select a dominant outcome.",
    )
    disposition: NetworkDisposition = Field(
        description=(
            "Final target-relative classification. network/internal_ipc/"
            "file_resource require a target-reachable invocation that can execute "
            "the claimed callsites. not_network also covers a registered API in a "
            "branch proven infeasible for every target-reachable invocation."
        )
    )
    interaction_kind: NetworkInteractionKind | None = Field(
        default=None,
        description=(
            "Network interaction kind. Required when disposition is network; "
            "MUST be null for internal_ipc, file_resource, not_network, and unresolved. "
            "Socket roles describe the evidenced lifecycle context, including inherited "
            "listeners and accepted connections; setup calls need not occur in that context."
        ),
    )
    identity: NetworkIdentity | None = Field(
        default=None,
        description="Partially or exactly recovered endpoint, interface, resolver, or Netlink identity.",
    )
    coverage_flows: list[CoverageFlow] = Field(
        default_factory=list,
        description="Setup/use/failure flows backed by cited calls. May be empty when unresolved.",
    )
    api_effects: list[NetworkAPIEffect] = Field(
        default_factory=list,
        description="Return-value, output-buffer, side-effect, and failure behavior facts.",
    )
    summary: str = Field(description="Concise factual description of the interaction and its effect.")
    evidence: list[NetworkEvidence] = Field(
        default_factory=list,
        description=(
            "Code citations supporting classification, target-path applicability, "
            "and recovered semantics. Reusable library behavior must cite the "
            "target-reachable caller path that enables or excludes the claimed branch."
        ),
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific facts that could not be established. Required for unresolved.",
    )

    @field_validator("callsite_ids", mode="after")
    @classmethod
    def stable_deduplicate_callsite_ids(cls, value):
        """Deduplicate only after Pydantic has validated every string element."""
        return list(dict.fromkeys(value))

    @model_validator(mode="after")
    def validate_semantics(self) -> Self:
        if self.disposition is NetworkDisposition.UNRESOLVED and not self.missing_evidence:
            raise ValueError("unresolved disposition requires missing_evidence")
        return self


class NetworkInteractionOutput(NetworkInteractionDraft):
    finding: FindingSemantics = Field(description=(
        "Semantic claims from this interaction analysis: caller-visible return/error/output "
        "requirements, socket or interface state, native fallback and unknowns. Cite local "
        "JSON pointers into /evidence, /api_effects, /coverage_flows, /identity or /missing_evidence. "
        "Claims must preserve the same conditional outcomes as their cited API effects; a fallback "
        "claim cannot restore an earlier value that those effects already overwrote. "
        "API presence alone is not a behavioral guarantee. This field is bound into the "
        "Result's planning_findings by the Controller, not copied into persisted analyses."
    ))

    @model_validator(mode="after")
    def validate_finding(self) -> Self:
        self.finding.validate_references(self.model_dump(mode="json"), allowed_roots=NETWORK_EVIDENCE_ROOTS)
        return self


class NetworkResourceAgentResult(StrictModel):
    analyses: list[NetworkInteractionOutput] = Field(
        min_length=1,
        description=(
            "One or more environment interactions discovered from the supplied seed. "
            "Each item describes one source-backed invocation context with all its conditional "
            "effects. The seed must occur in at least one item and may occur in several "
            "distinct contexts. Other controller-provided callsites require evidence of "
            "participation. Identical callsite sets are valid for distinct context anchors; "
            "duplicate records for the same context are invalid."
        )
    )


class NetworkInteractionAnalysis(NetworkInteractionDraft):
    interaction_id: str = Field(description="Stable controller-owned interaction identity.")
    anchor_callsite_id: str = Field(
        description=(
            "Controller-owned seed whose Agent invocation produced this analysis. "
            "The seed may occur in multiple distinct invocation contexts, and an "
            "invocation may also return a separate interaction that does not contain "
            "the seed."
        )
    )


class NetworkInteractionReport(StrictModel):
    """Self-contained source for one per-interaction Markdown page."""

    schema_version: int = Field(
        default=NETWORK_ANALYSIS_SCHEMA_VERSION,
        description="Persisted NetworkAnalyzer schema version.",
    )
    root_binary: str = Field(description="Target binary that roots reachability.")
    analysis: NetworkInteractionAnalysis = Field(
        description="Controller-validated network interaction."
    )
    callsites: dict[str, NetworkCallsite] = Field(
        description="Complete callsite facts referenced by analysis.callsite_ids."
    )

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.schema_version != NETWORK_ANALYSIS_SCHEMA_VERSION:
            raise ValueError(
                f"expected schema_version={NETWORK_ANALYSIS_SCHEMA_VERSION}, "
                f"got {self.schema_version}"
            )
        expected = set(self.analysis.callsite_ids)
        if set(self.callsites) != expected:
            raise ValueError(
                "per-interaction callsites must exactly match analysis.callsite_ids"
            )
        if any(key != fact.callsite_id for key, fact in self.callsites.items()):
            raise ValueError(
                "per-interaction callsite key must equal NetworkCallsite.callsite_id"
            )
        return self


class NetworkAnalysisResult(StrictModel):
    execution: AnalysisExecution = Field(description="Task completion and execution failures, independent of phase and semantic unknowns.")
    schema_version: int = Field(
        description="Persisted NetworkAnalyzer schema version.",
    )
    phase: Literal["static", "full"] = Field(
        description="Analyzer phase that produced this persisted result.",
    )
    root_binary: str = Field(description="Target binary that roots reachability.")
    finding_target: FindingTarget = Field(description="Verified target guest path and executable digest.")
    planning_findings: PlanningFindings = Field(description="Findings from the same interaction analysis; static results explicitly leave this empty.")
    callsites: dict[str, NetworkCallsite] = Field(
        default_factory=dict,
        description="All reachable registry callsites; other analyzers' observations never exclude these candidates.",
    )
    analyses: list[NetworkInteractionAnalysis] = Field(
        default_factory=list,
        description=(
            "Controller-validated resource reports. Reports may share callsites "
            "when one static helper participates in multiple runtime resources."
        ),
    )
    pending_callsite_ids: list[str] = Field(
        default_factory=list,
        description="Static-phase callsites awaiting resource-seeded Agent analysis.",
    )

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_computed_fields(cls, value):
        # Pydantic includes computed fields in model_dump_json(). They are
        # derived from persisted facts and must never become a second source
        # of truth when that JSON is loaded again.
        if isinstance(value, dict) and "covered_api_calls" in value:
            value = dict(value)
            value.pop("covered_api_calls", None)
        return value

    @computed_field
    @property
    def covered_api_calls(self) -> list[CoveredAPICall]:
        by_key: dict[tuple, CoveredAPICall] = {}
        authoritative_display: set[tuple[str, str, str, int]] = set()
        for analysis in self.analyses:
            if analysis.disposition is not NetworkDisposition.NETWORK:
                continue
            for callsite_id in analysis.callsite_ids:
                fact = self.callsites[callsite_id]
                location = fact.location
                claim = CoveredAPICall(
                    binary_name=location.binary_name,
                    function_name=location.function_name,
                    api_name=fact.api_name,
                    line_number=location.line_number,
                    column_number=location.column_number,
                    function_ea=location.function_ea,
                    snapshot_hash=location.snapshot_hash,
                    ctree_index=location.ctree_index,
                    source_ea=location.source_ea,
                    reason=(f"network {analysis.interaction_kind.value}"
                            if analysis.interaction_kind is not None else "network"),
                )
                by_key[claim.identity_key] = claim
                authoritative_display.add(claim.display_key)
        for analysis in self.analyses:
            if analysis.disposition is not NetworkDisposition.NETWORK:
                continue
            for flow in analysis.coverage_flows:
                for item in (*flow.setup, *flow.use, *flow.termination):
                    if (
                        item.ctree_index is None
                        and item.display_key in authoritative_display
                    ):
                        continue
                    by_key[item.identity_key] = item
        return [by_key[key] for key in sorted(
            by_key, key=lambda key: tuple((part is not None, part) for part in key)
        )]

    @model_validator(mode="after")
    def validate_accounting(self) -> Self:
        self.execution.validate_phase(self.phase)
        if self.schema_version != NETWORK_ANALYSIS_SCHEMA_VERSION:
            raise ValueError(
                f"expected schema_version={NETWORK_ANALYSIS_SCHEMA_VERSION}, "
                f"got {self.schema_version}"
            )
        if self.phase not in {"static", "full"}:
            raise ValueError("phase must be static or full")
        if any(key != fact.callsite_id for key, fact in self.callsites.items()):
            raise ValueError("callsites mapping key must equal NetworkCallsite.callsite_id")
        all_ids = set(self.callsites)
        covered: set[str] = set()
        interaction_ids: set[str] = set()
        for analysis in self.analyses:
            if analysis.interaction_id in interaction_ids:
                raise ValueError(f"duplicate interaction_id {analysis.interaction_id}")
            interaction_ids.add(analysis.interaction_id)
            if analysis.anchor_callsite_id not in all_ids:
                raise ValueError("analysis anchor references unknown callsite")
            covered.update(analysis.callsite_ids)
        if not covered.issubset(all_ids):
            raise ValueError("analyses reference unknown callsite")
        for analysis in self.analyses:
            for evidence in analysis.evidence:
                if evidence.callsite_id is not None:
                    if evidence.callsite_id not in analysis.callsite_ids:
                        raise ValueError("evidence callsite_id must belong to its interaction")
                    evidence.validate_callsite(self.callsites[evidence.callsite_id])
        if len(self.pending_callsite_ids) != len(set(self.pending_callsite_ids)):
            raise ValueError("pending_callsite_ids contains duplicates")
        if not set(self.pending_callsite_ids).issubset(all_ids):
            raise ValueError("pending_callsite_ids references unknown callsite")
        if self.phase == "static":
            if self.analyses:
                raise ValueError("static phase must not contain Agent analyses")
            expected = all_ids
            if set(self.pending_callsite_ids) != expected:
                raise ValueError("static pending_callsite_ids must cover every callsite")
        else:
            if self.pending_callsite_ids:
                raise ValueError("full phase must not retain pending_callsite_ids")
            failed = self.execution.unsuccessful_subjects("network")
            if any(item.anchor_callsite_id in failed for item in self.analyses):
                raise ValueError("failed network tasks cannot publish anchor analyses")
            if not failed.issubset(all_ids) or covered | failed != all_ids:
                raise ValueError("full analyses and execution failures must account for every callsite")
        expected = {self.finding_target.ref("network", item.interaction_id): (index, item)
                    for index, item in enumerate(self.analyses)}
        if set(self.planning_findings) != set(expected):
            raise ValueError("planning_findings must exactly cover network analyses")
        for ref, finding in self.planning_findings.items():
            index, analysis = expected[ref]
            if finding.domain != NetworkFindingDomain(
                kind="network", interaction_id=analysis.interaction_id,
                interaction_kind=analysis.interaction_kind.value if analysis.interaction_kind else None,
                callsite_ids=sorted(analysis.callsite_ids),
            ):
                raise ValueError("network finding domain disagrees with its interaction")
            if finding.boundary.kind != "resource" or finding.boundary.anchors != [
                FindingAnchor(kind="callsite", ref=pointer("callsites", key))
                for key in sorted(analysis.callsite_ids)
            ] + ([FindingAnchor(kind="function", ref=pointer("analyses", index, "context_anchor"))]
                 if analysis.context_anchor else []):
                raise ValueError("network finding must anchor its interaction callsites")
            validate_bound_finding(
                finding, record_ref=pointer("analyses", index),
                document=analysis.model_dump(mode="json"), allowed_roots=NETWORK_EVIDENCE_ROOTS,
            )
        validate_finding_references(self.planning_findings, self.model_dump(mode="json"))
        return self


__all__ = [
    "NETWORK_ANALYSIS_SCHEMA_VERSION",
    "IdentityResolution",
    "NetworkAnalysisResult",
    "NetworkAPIBinding",
    "NetworkAPIEffect",
    "NetworkCallsite",
    "NetworkCodeLocation",
    "NetworkDisposition",
    "NetworkEvidence",
    "NetworkResourceAgentResult",
    "NetworkIdentity",
    "NetworkInteractionAnalysis",
    "NetworkInteractionDraft",
    "NetworkInteractionKind",
    "NetworkInteractionReport",
    "NetworkRawArgument",
]
