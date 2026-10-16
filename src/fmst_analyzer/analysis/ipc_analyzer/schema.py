"""Evidence-backed product schema for IPCAnalyzer.

The persisted result is assembled by the deterministic controller.  Agents
only return the delta models from :mod:`agent_schema`; they never manufacture
firmware, process, binary, CTree, endpoint, or channel identities.
"""

from __future__ import annotations

from fmst_analyzer.analysis.base.execution import AnalysisExecution

from enum import Enum
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICall
from fmst_analyzer.analysis.base.analysis_finding import (
    FindingAnchor, IPCFindingDomain, PlanningFindings, validate_finding_references,
)
from fmst_analyzer.analysis.base.finding_binding import FindingTarget, pointer


IPC_ANALYSIS_SCHEMA_VERSION = 30


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AnalysisPhase(str, Enum):
    STATIC = "static"
    FULL = "full"


class VerificationStatus(str, Enum):
    VERIFIED_STATIC = "verified_static"
    VERIFIED_AGENT = "verified_agent"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


class CandidateSource(str, Enum):
    """Deterministic evidence class that authorized structural inspection."""

    CONSTANT_INTERSECTION = "constant_intersection"
    MECHANISM_FALLBACK = "mechanism_fallback"


class IdentifierRelation(str, Enum):
    EXACT = "exact"
    CALLER_SUPPLIED = "caller_supplied"
    UNRESOLVED = "unresolved"


class IPCMechanism(str, Enum):
    SYSV_SHM = "sysv_shm"
    SYSV_MSG = "sysv_msg"
    SYSV_SEM = "sysv_sem"
    POSIX_SHM = "posix_shm"
    POSIX_MQ = "posix_mq"
    POSIX_SEM = "posix_sem"
    UDS = "uds"
    LOOPBACK_SOCKET = "loopback_socket"
    FIFO = "fifo"
    KERNEL_CHANNEL = "kernel_channel"
    EXTERNAL_NETWORK = "external_network"
    UNKNOWN = "unknown"


_FIRMWARE_IPC_MECHANISMS = frozenset({
    IPCMechanism.SYSV_SHM,
    IPCMechanism.SYSV_MSG,
    IPCMechanism.SYSV_SEM,
    IPCMechanism.POSIX_SHM,
    IPCMechanism.POSIX_MQ,
    IPCMechanism.POSIX_SEM,
    IPCMechanism.UDS,
    IPCMechanism.LOOPBACK_SOCKET,
    IPCMechanism.FIFO,
})


class EndpointRole(str, Enum):
    SERVER = "server"
    CLIENT = "client"
    CREATOR = "creator"
    ACCESSOR = "accessor"
    SENDER = "sender"
    RECEIVER = "receiver"
    PEER = "peer"
    UNKNOWN = "unknown"


class APIBindingKind(str, Enum):
    IN_BINARY = "in_binary"
    DYNAMIC_IMPORT = "dynamic_import"
    RAW_SYSCALL = "raw_syscall"
    UNRESOLVED = "unresolved"


class CallsiteDisposition(str, Enum):
    MIXED = "mixed"
    EXECUTION_FAILED = "execution_failed"
    CHANNEL_ENDPOINT = "channel_endpoint"
    NOT_FIRMWARE_IPC = "not_firmware_ipc"
    UNRESOLVED = "unresolved"


class PeerRequirement(str, Enum):
    NONE = "none"
    AVAILABILITY = "availability"
    DATA = "data"
    UNKNOWN = "unknown"


class LocalImpact(str, Enum):
    PROCESS_BLOCKED = "process_blocked"
    OPERATION_AFFECTED = "operation_affected"
    NONE = "none"
    UNKNOWN = "unknown"


class RawArgument(StrictModel):
    index: int = Field(description="One-based argument index at the CTree call.")
    expression: str = Field(description="Unmodified IDA expression text for this argument.")


class CodeLocation(StrictModel):
    binary_path: str = Field(description="Canonical rootfs-relative ELF path containing the object.")
    binary_sha256: str = Field(description="SHA-256 of binary_path.")
    function_name: str = Field(description="Decompiler-visible function artifact name.")
    function_ea: int = Field(description="Function entry EA in its IDA database.")
    snapshot_hash: str = Field(description="FunctionSemanticSnapshot hash.")
    ctree_index: int = Field(description="CTree object identity within snapshot_hash.")
    source_ea: int | None = Field(
        description="Instruction EA associated with the object, or null for BADADDR."
    )
    line_number: int = Field(description="One-based line in the rendered decompiled C artifact.")
    column_number: int = Field(description="Zero-based column in the rendered decompiled C artifact.")


class EvidenceCitation(StrictModel):
    claim: str = Field(description="Exact fact supported or contradicted by this citation.")
    binary_path: str = Field(
        description=(
            "Canonical rootfs-relative binary, library, script, or configuration "
            "artifact path. The historical field name is retained for cache compatibility."
        )
    )
    function_name: str = Field(
        description="Decompiler-visible function name, or <config>/<script> for text artifacts."
    )
    function_ea: int | None = Field(
        default=None,
        description=(
            "Exact enclosing function entry EA from the inspected native source, not the cited "
            "instruction address or a guessed value. Use null when that entry EA is unavailable."
        ),
    )
    line_number: int | None = Field(
        default=None,
        description="One-based rendered C/text line, or null for structural evidence.",
    )
    callsite_id: str | None = Field(
        default=None,
        description="Controller-owned callsite identity when the cited line is a known candidate.",
    )


class APISymbolBinding(StrictModel):
    kind: APIBindingKind = Field(
        description=(
            "Mechanically proven call-target category. dynamic_import means the "
            "source ELF declares an undefined dynamic symbol; it does not assert "
            "which runtime library will provide that symbol."
        )
    )
    symbol: str = Field(description="Terminal symbol or raw syscall name.")
    binary_path: str | None = Field(
        default=None,
        description=(
            "Canonical rootfs-relative definition ELF only for an in_binary "
            "definition; null for dynamic imports whose runtime provider is not inferred."
        ),
    )
    binary_sha256: str | None = Field(
        default=None,
        description="Implementing ELF SHA-256 when binary_path is known.",
    )
    status: VerificationStatus = Field(
        description="verified_static for a unique loader fact, otherwise unresolved."
    )
    reason: str = Field(
        description="Deterministic ELF fact establishing or limiting this classification."
    )

    @model_validator(mode="after")
    def validate_static_binding(self) -> Self:
        if (self.binary_path is None) != (self.binary_sha256 is None):
            raise ValueError("API binding path and SHA-256 must be present together")
        if self.status is VerificationStatus.VERIFIED_STATIC:
            if self.kind is APIBindingKind.UNRESOLVED:
                raise ValueError("verified static API binding cannot have unresolved kind")
        elif self.status is VerificationStatus.UNRESOLVED:
            if self.kind is not APIBindingKind.UNRESOLVED:
                raise ValueError("unresolved API binding must have unresolved kind")
        else:
            raise ValueError("API binding status must be verified_static or unresolved")
        return self


class CallsiteFact(StrictModel):
    callsite_id: str = Field(description="Stable controller-owned CTree callsite identity.")
    location: CodeLocation = Field(description="Exact CTree/code identity.")
    api_family: str = Field(description="Versioned interaction-registry family.")
    mechanism_hint: IPCMechanism = Field(
        description="Mechanism implied by the primitive, or unknown when arguments decide it."
    )
    callee_name: str = Field(description="Verbatim CTree callee name.")
    call_kind: str = Field(description="direct, helper, indirect, or other CTree call kind.")
    expression_text: str = Field(description="Unmodified complete call expression from IDA.")
    arguments: list[RawArgument] = Field(description="Arguments in original CTree order.")
    return_expression: str | None = Field(
        default=None,
        description="Receiving identifier/expression, or null when the return is not assigned.",
    )
    api_binding: APISymbolBinding = Field(
        description=(
            "Deterministic call-target classification. It never infers a runtime "
            "library provider, wrapper semantics, or the opposite IPC process."
        )
    )


class TargetProcess(StrictModel):
    """The single executable invocation analyzed by this product."""

    executable_path: str = Field(description="Canonical rootfs-relative executable path.")
    executable_sha256: str = Field(description="SHA-256 of executable_path.")
    argv0: str = Field(description="Observed or canonical argv[0], preserving multicall identity.")

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        FindingTarget(path=self.executable_path, sha256=self.executable_sha256)
        return self


class ResourceIdentity(StrictModel):
    resource_key: str = Field(description="Stable key local to the containing channel.")
    kind: str = Field(description="Mechanism-specific resource kind such as uds_path or sysv_key.")
    canonical_value: str | None = Field(
        default=None,
        description="Kernel-visible or exact symbolic identity; null when unresolved.",
    )
    expressions: list[str] = Field(
        description="All unmodified endpoint expressions/provenance that produced the identity."
    )
    status: VerificationStatus = Field(description="How the resource identity was established.")
    evidence: list[EvidenceCitation] = Field(description="Evidence supporting the identity.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific missing facts when status is unresolved.",
    )


class WrapperHop(StrictModel):
    binary_path: str = Field(description="Canonical rootfs-relative binary or custom library path.")
    function_name: str = Field(description="Decompiler-visible wrapper function.")
    line_number: int = Field(description="Line that calls the next hop.")


class PeerEndpointLocation(StrictModel):
    binary_path: str = Field(
        description="Rootfs-relative executable or custom library containing the endpoint."
    )
    function_name: str = Field(description="Decompiler-visible function containing the endpoint.")
    function_ea: int | None = Field(
        default=None,
        description="Function entry EA when supplied by structural analysis.",
    )
    line_number: int | None = Field(
        default=None,
        description="One-based decompiled line, or null before semantic onboarding.",
    )
    primitive: str = Field(description="Verbatim endpoint API/syscall name at that line.")


class StructuralFunctionRef(StrictModel):
    binary_path: str = Field(description="Canonical rootfs-relative ELF path.")
    function_name: str = Field(description="IDA structural function name.")
    function_ea: int = Field(description="Function entry EA in that ELF's IDB.")


class EndpointCallPath(StrictModel):
    """Typed executable-to-provider-to-endpoint witness without Hex-Rays."""

    entry: StructuralFunctionRef = Field(
        description="Executable-owned function where this witness begins."
    )
    call_path: list[StructuralFunctionRef] = Field(
        description=(
            "Stable direct-call witness from entry through zero or more custom "
            "providers to the endpoint function."
        )
    )
    endpoint: PeerEndpointLocation = Field(
        description="Function and primitive implementing the candidate endpoint."
    )
    identifier_relation: IdentifierRelation = Field(
        description=(
            "exact when the Channel identifier is present on this path, "
            "caller_supplied when it enters as a wrapper argument, or unresolved."
        )
    )
    identifier: str | None = Field(
        default=None,
        description="Exact canonical Channel identifier when statically visible.",
    )
    identifier_xref_ea: int | None = Field(
        default=None,
        description=(
            "Code xref EA for a statically visible identifier. It may be in the "
            "endpoint function for exact or in an upstream wrapper for caller_supplied; "
            "null when no xref is available."
        ),
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific missing evidence for non-exact identifier relations.",
    )

    @model_validator(mode="after")
    def validate_path(self) -> Self:
        if not self.call_path or self.call_path[0] != self.entry:
            raise ValueError("endpoint call path must begin with entry")
        last = self.call_path[-1]
        if (
            last.binary_path != self.endpoint.binary_path
            or last.function_name != self.endpoint.function_name
            or last.function_ea != self.endpoint.function_ea
        ):
            raise ValueError("endpoint call path must end at endpoint function")
        if self.identifier_relation is IdentifierRelation.EXACT:
            if self.identifier is None or self.identifier_xref_ea is None:
                raise ValueError("exact identifier relation requires value and xref EA")
        elif not self.missing_evidence:
            raise ValueError(
                "caller-supplied/unresolved identifier relation requires missing_evidence"
            )
        return self


class Endpoint(StrictModel):
    identity_resource_keys: list[str] = Field(description="Channel resource keys proving this endpoint's minimal kernel-object identity; other resources are associated observations.")
    context_anchor: WrapperHop | None = Field(default=None, description="Minimal caller/branch position distinguishing this source invocation, independent of wrapper evidence growth.")
    endpoint_id: str = Field(description="Stable controller-owned channel endpoint identity.")
    callsite_id: str = Field(description="Terminal CallsiteFact identity.")
    role: EndpointRole = Field(description="Role played on this channel.")
    api_binding: APISymbolBinding = Field(
        description=(
            "Verified or unresolved terminal API symbol binding. This does not identify "
            "the firmware process at the opposite IPC endpoint."
        )
    )
    wrapper_path: list[WrapperHop] = Field(
        default_factory=list,
        description="Operation-relevant process-to-terminal custom wrapper path.",
    )
    coverage_claims: list[CoveredAPICall] = Field(
        default_factory=list,
        description="Callsites owned by this IPC protocol for cross-analyzer deduplication.",
    )
    status: VerificationStatus = Field(description="Endpoint verification status.")
    evidence: list[EvidenceCitation] = Field(description="Evidence for endpoint membership and role.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific missing facts when status is unresolved.",
    )


class PeerCandidateAssessment(StrictModel):
    executable_path: str = Field(description="Canonical rootfs-relative candidate executable path.")
    executable_sha256: str = Field(description="SHA-256 of executable_path.")
    argv0: str | None = Field(
        description=(
            "Exact invocation argv[0] when established, including multicall applet "
            "identity; null when only the executable identity is verified."
        )
    )
    role: EndpointRole = Field(description="Candidate's role on this channel.")
    endpoint_locations: list[PeerEndpointLocation] = Field(
        description="Inspected endpoint code locations supporting the candidate verdict."
    )
    status: VerificationStatus = Field(description="Verified, rejected, or unresolved candidate verdict.")
    reason: str = Field(description="Evidence-backed reason for the candidate verdict.")
    evidence: list[EvidenceCitation] = Field(description="Code/config evidence inspected for this candidate.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Concrete missing facts when the candidate remains unresolved.",
    )

    @model_validator(mode="after")
    def validate_verdict_evidence(self) -> Self:
        if self.status in {
            VerificationStatus.VERIFIED_AGENT,
            VerificationStatus.VERIFIED_STATIC,
        }:
            if not self.endpoint_locations:
                raise ValueError(
                    "verified peer candidate requires endpoint_locations"
                )
        return self


class PeerCandidateEvidence(StrictModel):
    executable_path: str = Field(
        description=(
            "Canonical rootfs-relative executable selected by deterministic "
            "LIEF capability and named-constant indexing. This is a candidate "
            "lead, not a peer verdict; only call_paths authorize "
            "assembly-only Peer Verification inspection."
        )
    )
    source: CandidateSource = Field(
        description=(
            "Deterministic LIEF/constant evidence class. constant_intersection "
            "has both compatible endpoint capability and an exact named "
            "identifier in one executable dependency closure; mechanism_fallback "
            "is reserved for channels without a stable named identifier."
        )
    )
    reasons: list[str] = Field(
        description=(
            "Complete deterministic reasons, such as endpoint imports, an exact "
            "named resource occurrence, or unique DT_NEEDED provider ownership."
        )
    )
    call_paths: list[EndpointCallPath] = Field(
        default_factory=list,
        description=(
            "Typed executable-to-endpoint structural witnesses. They bound the "
            "assembly shown to the Agent but do not prove runtime branch execution."
        ),
    )


class IPCChannel(StrictModel):
    channel_id: str = Field(description="Stable controller-owned logical channel identity.")
    mechanism: IPCMechanism = Field(description="Communication mechanism shared by its endpoints.")
    resources: list[ResourceIdentity] = Field(description="Simple or composite resource identity.")
    endpoints: list[Endpoint] = Field(description="All known channel participants.")
    retrieval_candidates: list[PeerCandidateEvidence] = Field(
        default_factory=list,
        description=(
            "Executable candidate universe selected by deterministic LIEF and "
            "constant indexing, with structural IDA evidence when available. "
            "They are not peer verdicts."
        ),
    )
    peer_candidates: list[PeerCandidateAssessment] = Field(
        default_factory=list,
        description="Executable candidates actually inspected by the Peer Verification Agent.",
    )
    status: VerificationStatus = Field(description="Channel membership verification status.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific missing facts when the channel remains provisional.",
    )



class DependencyAssessment(StrictModel):
    dependency_id: str = Field(description="Stable controller-owned dependency identity.")
    channel_id: str = Field(description="Channel whose local use is assessed.")
    consumer_endpoint_ids: list[str] = Field(description="Consumer endpoints covered by this assessment.")
    peer_requirement: PeerRequirement = Field(
        description=(
            "Minimum peer-supplied semantics observed by target-local code: none when "
            "no success/data/state is consumed, availability when only interaction "
            "success is checked, data when a response/shared state/handle is consumed, "
            "or unknown when static evidence cannot decide."
        )
    )
    local_impact: LocalImpact = Field(
        description=(
            "Target-local consequence when the peer is absent or incompatible: "
            "process_blocked for failure to start/stay ready, operation_affected for "
            "a failed or degraded request/feature/output/state, none for no observable "
            "local change, or unknown when evidence is insufficient."
        )
    )
    summary: str = Field(description="Evidence-backed description of the affected operation.")
    status: VerificationStatus = Field(description="Assessment verification status.")
    evidence: list[EvidenceCitation] = Field(description="Control/data-flow evidence for the assessment.")
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Concrete missing facts when status is unresolved.",
    )

    @model_validator(mode="after")
    def validate_dependency_judgment(self) -> Self:
        if not self.consumer_endpoint_ids:
            raise ValueError("dependency requires at least one consumer endpoint")
        if len(self.consumer_endpoint_ids) != len(set(self.consumer_endpoint_ids)):
            raise ValueError("dependency consumer_endpoint_ids must be unique")
        return self


class UnresolvedItem(StrictModel):
    unresolved_item_id: str = Field(
        description="Stable controller-owned unresolved-item identity."
    )
    subject_kind: str = Field(
        description="callsite, resource, channel, peer, dependency, or analysis_scope."
    )
    subject_id: str = Field(description="Identity of the object at which analysis stopped.")
    affected_channel_ids: list[str] = Field(
        default_factory=list,
        description=(
            "Stable Channel identities whose peer analysis is affected by this "
            "missing evidence. Empty when the item precedes Channel formation."
        ),
    )
    reason: str = Field(description="Why static and Agent analysis cannot currently continue.")
    missing_evidence: list[str] = Field(description="Concrete missing evidence.")
    runtime_evidence_requests: list[str] = Field(
        default_factory=list,
        description="Concrete runtime observations that would resolve this item.",
    )

    @model_validator(mode="after")
    def validate_affected_channels(self) -> Self:
        if self.affected_channel_ids != sorted(set(self.affected_channel_ids)):
            raise ValueError("affected_channel_ids must be sorted and unique")
        return self


class CallsiteContext(StrictModel):
    context_id: str = Field(description="Controller-owned source observation identity.")
    disposition: CallsiteDisposition = Field(description="Classification of this context, never the aggregate mixed/failed state.")
    mechanism: IPCMechanism = Field(description="Mechanism observed in this source context.")
    context_anchor: WrapperHop | None = Field(description="Minimal source anchor or null when unresolved/direct.")
    wrapper_path: list[WrapperHop] = Field(description="Source navigation path supporting this context.")
    endpoint_role: EndpointRole = Field(description="Target's observed role in this invocation.")
    resources: list[ResourceIdentity] = Field(description="All resource observations, including excluded and unknown resources.")
    endpoint_ids: list[str] = Field(description="IPC endpoints created from this context only.")
    unresolved_item_ids: list[str] = Field(description="Unknowns from this context only.")
    summary: str = Field(description="Agent's original factual context summary.")
    evidence: list[EvidenceCitation] = Field(description="Original source citations for this context.")
    missing_evidence: list[str] = Field(description="Specific missing facts for this source observation.")

    @model_validator(mode="after")
    def validate_context(self) -> Self:
        if self.disposition in {CallsiteDisposition.MIXED, CallsiteDisposition.EXECUTION_FAILED}:
            raise ValueError("source contexts cannot be mixed or execution_failed")
        if self.context_anchor is not None and self.context_anchor not in self.wrapper_path:
            raise ValueError("context_anchor must belong to wrapper_path")
        if (self.disposition is CallsiteDisposition.CHANNEL_ENDPOINT) != bool(self.endpoint_ids):
            raise ValueError("only endpoint contexts reference endpoint_ids")
        if self.disposition is CallsiteDisposition.UNRESOLVED and not self.unresolved_item_ids:
            raise ValueError("unresolved context requires unresolved_item_ids")
        if self.disposition is CallsiteDisposition.NOT_FIRMWARE_IPC and self.unresolved_item_ids:
            raise ValueError("excluded context cannot reference unresolved items")
        return self


class CallsiteAccounting(StrictModel):
    callsite_id: str = Field(description="Candidate CallsiteFact identity.")
    disposition: CallsiteDisposition = Field(description="Order-independent aggregate; mixed when source contexts have different classifications.")
    contexts: list[CallsiteContext] = Field(default_factory=list, description="All source observations, retaining excluded and unresolved contexts alongside endpoints. Empty only for static/failed accounting.")
    endpoint_ids: list[str] = Field(
        default_factory=list,
        description="Endpoint identities when disposition is channel_endpoint.",
    )
    unresolved_item_ids: list[str] = Field(
        default_factory=list,
        description="Unresolved-item identities when disposition is unresolved.",
    )
    reason: str = Field(description="Auditable reason for this terminal disposition.")

    @model_validator(mode="after")
    def validate_references_for_disposition(self) -> Self:
        if self.contexts:
            identities = [context.context_id for context in self.contexts]
            if len(identities) != len(set(identities)):
                raise ValueError("duplicate source context identity")
            dispositions = {context.disposition for context in self.contexts}
            expected = next(iter(dispositions)) if len(dispositions) == 1 else CallsiteDisposition.MIXED
            if self.disposition is not expected:
                raise ValueError("aggregate disposition disagrees with source contexts")
            if set(self.endpoint_ids) != {key for context in self.contexts for key in context.endpoint_ids} or set(self.unresolved_item_ids) != {key for context in self.contexts for key in context.unresolved_item_ids}:
                raise ValueError("aggregate references must exactly cover source contexts")
            return self
        if self.disposition is CallsiteDisposition.MIXED:
            raise ValueError("mixed accounting requires source contexts")
        if self.disposition is CallsiteDisposition.CHANNEL_ENDPOINT:
            if not self.endpoint_ids or self.unresolved_item_ids:
                raise ValueError("channel_endpoint accounting requires endpoint_ids only")
        elif self.disposition is CallsiteDisposition.UNRESOLVED:
            if not self.unresolved_item_ids or self.endpoint_ids:
                raise ValueError(
                    "unresolved accounting requires unresolved_item_ids only"
                )
        elif self.endpoint_ids or self.unresolved_item_ids:
            raise ValueError(
                "not_firmware_ipc accounting cannot reference endpoints/unresolved items"
            )
        return self


class IPCCallsiteReport(StrictModel):
    """Self-contained JSON source for one IPC callsite Markdown page."""

    schema_version: int = IPC_ANALYSIS_SCHEMA_VERSION
    phase: AnalysisPhase
    firmware_sha256: str
    target_process: TargetProcess
    callsite: CallsiteFact
    callsite_accounting: CallsiteAccounting

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.schema_version != IPC_ANALYSIS_SCHEMA_VERSION:
            raise ValueError("unsupported IPC callsite report schema")
        if self.callsite.callsite_id != self.callsite_accounting.callsite_id:
            raise ValueError("IPC callsite report identities disagree")
        return self


class IPCChannelReport(StrictModel):
    """Self-contained JSON source for one IPC channel Markdown page."""

    schema_version: int = IPC_ANALYSIS_SCHEMA_VERSION
    phase: AnalysisPhase
    firmware_sha256: str
    target_process: TargetProcess
    channel: IPCChannel
    dependency_assessments: list[DependencyAssessment] = Field(
        default_factory=list,
        description="Target-local dependency judgments for this exact channel.",
    )
    unresolved_items: list[UnresolvedItem] = Field(
        default_factory=list,
        description="Unresolved analysis boundaries that affect this exact channel.",
    )

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if self.schema_version != IPC_ANALYSIS_SCHEMA_VERSION:
            raise ValueError("unsupported IPC channel report schema")
        channel_id = self.channel.channel_id
        if any(
            item.channel_id != channel_id
            for item in self.dependency_assessments
        ):
            raise ValueError("IPC channel report contains another channel's dependency")
        if any(
            channel_id not in item.affected_channel_ids
            for item in self.unresolved_items
        ):
            raise ValueError("IPC channel report contains an unrelated unresolved item")
        return self


class IPCAnalysisResult(StrictModel):
    execution: AnalysisExecution = Field(description="Site and peer task outcomes, distinct from firmware uncertainty.")
    schema_version: int = Field(description="IPC product schema version.")
    phase: AnalysisPhase = Field(description="static has zero LLM calls; full includes Agent findings.")
    firmware_sha256: str = Field(description="FirmProbe firmware artifact identity.")
    target_process: TargetProcess = Field(
        description="The one target executable invocation whose direct IPC is analyzed."
    )
    planning_findings: PlanningFindings = Field(description="Channel semantic findings produced by the same Site Resolution analysis; static phase explicitly leaves this empty.")
    callsites: list[CallsiteFact] = Field(
        description=(
            "Complete resource-anchor candidate universe. FD-only send/receive, "
            "listen/accept, constructor, and control operations are auxiliary code "
            "context and may appear in endpoint coverage_claims, not as independent "
            "resource candidates."
        )
    )
    channels: list[IPCChannel] = Field(description="Verified and provisional logical IPC channels.")
    dependency_assessments: list[DependencyAssessment] = Field(
        description="Directed semantic dependencies, separate from channel topology."
    )
    unresolved_items: list[UnresolvedItem] = Field(
        description="Explicit unresolved analysis items."
    )
    callsite_accounting: list[CallsiteAccounting] = Field(
        description="One aggregate and its complete source contexts for every CallsiteFact."
    )

    @model_validator(mode="before")
    @classmethod
    def discard_serialized_computed_fields(cls, value):
        """Allow JSON replay while keeping every non-computed extra forbidden."""
        if isinstance(value, dict) and "covered_api_calls" in value:
            value = dict(value)
            value.pop("covered_api_calls")
        return value

    @computed_field
    @property
    def covered_api_calls(self) -> list[CoveredAPICall]:
        """Stable callsite observations for established firmware IPC endpoints.

        These are overlap hints, not proof of complete semantic coverage or
        exclusive ownership. Other Analyzers retain their independent scope.
        """
        by_key: dict[tuple, CoveredAPICall] = {}
        for channel in self.channels:
            if channel.mechanism not in _FIRMWARE_IPC_MECHANISMS:
                continue
            for endpoint in channel.endpoints:
                for claim in endpoint.coverage_claims:
                    key = claim.identity_key
                    by_key[key] = claim
        return [by_key[key] for key in sorted(
            by_key, key=lambda key: tuple((part is not None, part) for part in key)
        )]

    @model_validator(mode="after")
    def validate_identity_graph(self) -> Self:
        self.execution.validate_phase(self.phase)
        if self.schema_version != IPC_ANALYSIS_SCHEMA_VERSION:
            raise ValueError(
                f"expected schema_version={IPC_ANALYSIS_SCHEMA_VERSION}, got {self.schema_version}"
            )

        callsites = _unique(self.callsites, "callsite_id")
        channels = _unique(self.channels, "channel_id")
        dependencies = _unique(self.dependency_assessments, "dependency_id")
        unresolved_items = _unique(
            self.unresolved_items, "unresolved_item_id",
        )
        accounting = _unique(self.callsite_accounting, "callsite_id")
        del dependencies

        endpoint_by_id: dict[str, Endpoint] = {}
        for channel in self.channels:
            resource_keys = [resource.resource_key for resource in channel.resources]
            if len(resource_keys) != len(set(resource_keys)):
                raise ValueError(f"duplicate resource_key in channel {channel.channel_id}")
            for endpoint in channel.endpoints:
                keys = endpoint.identity_resource_keys
                if not keys or len(keys) != len(set(keys)) or not set(keys) <= set(resource_keys):
                    raise ValueError("endpoint identity_resource_keys must name unique resources in its channel")
                if endpoint.context_anchor is not None and endpoint.context_anchor not in endpoint.wrapper_path:
                    raise ValueError("endpoint context_anchor must be a source position in wrapper_path")
            retrieval_paths = [
                candidate.executable_path
                for candidate in channel.retrieval_candidates
            ]
            if len(retrieval_paths) != len(set(retrieval_paths)):
                raise ValueError(
                    f"duplicate retrieval candidate in channel {channel.channel_id}"
                )
            inspected_identities = [
                (candidate.executable_path, candidate.argv0)
                for candidate in channel.peer_candidates
            ]
            if len(inspected_identities) != len(set(inspected_identities)):
                raise ValueError(
                    f"duplicate inspected process identity in channel {channel.channel_id}"
                )
            for endpoint in channel.endpoints:
                if endpoint.endpoint_id in endpoint_by_id:
                    raise ValueError(f"duplicate endpoint_id: {endpoint.endpoint_id}")
                endpoint_by_id[endpoint.endpoint_id] = endpoint
                if endpoint.callsite_id not in callsites:
                    raise ValueError(f"endpoint {endpoint.endpoint_id} references unknown callsite")

        failed_callsites = self.execution.unsuccessful_subjects("site")
        if set(accounting) != set(callsites):
            missing = sorted(set(callsites) - set(accounting))
            extra = sorted(set(accounting) - set(callsites))
            raise ValueError(f"callsite accounting mismatch: missing={missing}, extra={extra}")
        if failed_callsites != {key for key, item in accounting.items()
                              if item.disposition is CallsiteDisposition.EXECUTION_FAILED}:
            raise ValueError("execution_failed accounting must match failed site tasks")

        for item in self.callsite_accounting:
            unknown_endpoints = set(item.endpoint_ids) - endpoint_by_id.keys()
            unknown_unresolved = (
                set(item.unresolved_item_ids) - unresolved_items.keys()
            )
            if unknown_endpoints or unknown_unresolved:
                raise ValueError(
                    f"accounting {item.callsite_id} has unknown refs: "
                    f"endpoints={sorted(unknown_endpoints)}, "
                    f"unresolved_items={sorted(unknown_unresolved)}"
                )
            if any(endpoint_by_id[key].callsite_id != item.callsite_id for key in item.endpoint_ids):
                raise ValueError("accounting endpoint belongs to a different callsite")
            for context in item.contexts:
                if any(unresolved_items[key].subject_kind != "callsite" or unresolved_items[key].subject_id != item.callsite_id
                       for key in context.unresolved_item_ids):
                    raise ValueError("context unresolved item belongs to a different callsite")
                if any(endpoint_by_id[key].context_anchor != context.context_anchor for key in context.endpoint_ids):
                    raise ValueError("context endpoint source anchor mismatch")

        for item in self.unresolved_items:
            unknown_channels = set(item.affected_channel_ids) - channels.keys()
            if unknown_channels:
                raise ValueError(
                    f"unresolved item {item.unresolved_item_id} references "
                    f"unknown channels {sorted(unknown_channels)}"
                )

        for dependency in self.dependency_assessments:
            if dependency.channel_id not in channels:
                raise ValueError(f"dependency {dependency.dependency_id} has unknown channel")
            unknown_endpoints = set(dependency.consumer_endpoint_ids) - endpoint_by_id.keys()
            if unknown_endpoints:
                raise ValueError(
                    f"dependency {dependency.dependency_id} references unknown endpoints "
                    f"{sorted(unknown_endpoints)}"
                )

        from .findings import channel_finding_ref
        if self.phase is AnalysisPhase.STATIC and (self.channels or self.dependency_assessments):
            raise ValueError("static IPC results cannot contain Agent channel or dependency analyses")
        expected = {channel_finding_ref(self.target_process, item.channel_id): (index, item)
                    for index, item in enumerate(self.channels)}
        if set(self.planning_findings) != set(expected):
            raise ValueError("planning_findings must exactly cover IPC channels")
        for ref, finding in self.planning_findings.items():
            index, channel = expected[ref]
            if finding.domain != IPCFindingDomain(
                kind="ipc", channel_id=channel.channel_id, mechanism=channel.mechanism.value,
                endpoint_ids=sorted(endpoint.endpoint_id for endpoint in channel.endpoints),
            ):
                raise ValueError("IPC finding domain disagrees with its source channel")
            channel_ref = pointer("channels", index)
            if finding.boundary.kind != "resource" or finding.boundary.anchors != [
                FindingAnchor(kind="ipc_channel", ref=channel_ref)
            ]:
                raise ValueError("IPC finding must anchor its source channel")
            allowed = [channel_ref, *(
                pointer("dependency_assessments", i)
                for i, dependency in enumerate(self.dependency_assessments)
                if dependency.channel_id == channel.channel_id
            )]
            refs = [*finding.boundary.reachability_refs, *finding.boundary.coverage_refs,
                    *(item for claim in finding.claims for item in claim.evidence_refs)]
            if any(not any(item == prefix or item.startswith(prefix + "/") for prefix in allowed) for item in refs):
                raise ValueError("IPC finding evidence must belong to its channel or target-local dependencies")
        validate_finding_references(self.planning_findings, self.model_dump(mode="json"))

        return self


def _unique(items: list[BaseModel], field_name: str) -> dict[str, BaseModel]:
    result: dict[str, BaseModel] = {}
    for item in items:
        identity = getattr(item, field_name)
        if identity in result:
            raise ValueError(f"duplicate {field_name}: {identity}")
        result[identity] = item
    return result


__all__ = [
    "APIBindingKind",
    "APISymbolBinding",
    "AnalysisPhase",
    "CandidateSource",
    "CallsiteAccounting",
    "CallsiteDisposition",
    "CallsiteFact",
    "CodeLocation",
    "DependencyAssessment",
    "Endpoint",
    "EndpointCallPath",
    "EndpointRole",
    "EvidenceCitation",
    "IPCAnalysisResult",
    "IPCCallsiteReport",
    "IPCChannel",
    "IPCChannelReport",
    "IPCMechanism",
    "IPC_ANALYSIS_SCHEMA_VERSION",
    "IdentifierRelation",
    "PeerCandidateEvidence",
    "PeerCandidateAssessment",
    "PeerEndpointLocation",
    "LocalImpact",
    "PeerRequirement",
    "TargetProcess",
    "RawArgument",
    "ResourceIdentity",
    "StructuralFunctionRef",
    "UnresolvedItem",
    "VerificationStatus",
    "WrapperHop",
]
