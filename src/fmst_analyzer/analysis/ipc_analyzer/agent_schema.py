"""Structured deltas returned by IPCAnalyzer task agents.

These models deliberately contain no controller-owned hashes or final object
identities.  The controller validates every echoed input ID and every path
before merging a delta into :class:`IPCAnalysisResult`.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal
from typing_extensions import Self

from pydantic import Field, model_validator
from fmst_analyzer.analysis.base.finding_binding import FindingSemantics

from .schema import (
    CallsiteDisposition,
    EndpointRole,
    EvidenceCitation,
    IPCMechanism,
    LocalImpact,
    PeerRequirement,
    PeerEndpointLocation,
    StrictModel,
    WrapperHop,
)


class CandidateVerdict(str, Enum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    UNRESOLVED = "unresolved"


_LOOPBACK_IDENTITY_KINDS = frozenset({
    "socket_family", "socket_type", "socket_protocol", "loopback_address", "socket_port",
})


class AgentResourceFinding(StrictModel):
    kind: str = Field(
        description=(
            "Mechanism-specific resource kind such as uds_path, loopback_address, "
            "sysv_key, posix_name, or fifo_path. A loopback identity uses five separate "
            "resources: socket_family (AF_INET/AF_INET6), socket_type (SOCK_STREAM/"
            "SOCK_DGRAM), socket_protocol (0/IPPROTO_TCP/IPPROTO_UDP), loopback_address "
            "(IP literal), and socket_port (decimal host-order port)."
        )
    )
    canonical_value: str | None = Field(
        description=(
            "Exact kernel-visible value or exact symbolic identity. Use null when "
            "the value depends on runtime state and cannot be proved."
        )
    )
    expression: str = Field(
        description="Unmodified expression/provenance chain producing the resource."
    )
    evidence: list[EvidenceCitation] = Field(
        description="Code citations proving the value or deepest known provenance."
    )
    missing_evidence: list[str] = Field(
        description="Concrete missing facts; empty only when resolved is true."
    )

    @model_validator(mode="after")
    def validate_resolution(self) -> Self:
        if self.canonical_value is None and not self.missing_evidence:
            raise ValueError(
                "resource without canonical_value must name missing_evidence"
            )
        return self


class TerminationCallsiteDraft(StrictModel):
    """Agent citation for a process event owned by this IPC dependency."""

    binary_name: str = Field(description="Module containing the termination call.")
    function_name: str = Field(description="Persisted decompiler function name.")
    line_number: int = Field(description="One-based persisted C line.")
    column_number: int | None = Field(
        default=None,
        description="Zero-based column when needed to distinguish same-line calls.",
    )
    api_name: str = Field(
        description=(
            "Exact exit, _exit, _Exit, quick_exit, abort, or "
            "__assert_fail symbol."
        )
    )
    reason: str = Field(
        description="How failure of this IPC interaction reaches the termination call."
    )



class SiteDependencyFinding(StrictModel):
    finding: FindingSemantics = Field(description=(
        "Semantic finding from this same target-local dependency analysis. Capture "
        "caller-visible message, return/output, state, lifecycle and fallback constraints, "
        "with explicit unknown data or external effects. State each claim's applicable "
        "operation/caller context. Every pointer is relative to this SiteDependencyFinding object: "
        "use /evidence/0 or /missing_evidence/0, with no /dependency or /finding prefix. "
        "Do not decide whether to launch a peer, emulate a resource or install a hook."
    ))
    peer_requirement: PeerRequirement = Field(
        description=(
            "Minimum opposite-endpoint semantics consumed by target-local code: "
            "none, availability, data, or unknown. This does not choose a "
            "rehosting intervention."
        )
    )
    local_impact: LocalImpact = Field(
        description=(
            "Target-local consequence when the opposite endpoint is absent or "
            "incompatible: process_blocked, operation_affected, none, or unknown. "
            "Main returning terminates the target process; a helper's error return "
            "requires caller tracing. Distinguish local failure, child exit, normal "
            "daemon-parent exit, and target-service termination. Preserve buffer "
            "initialization and every output/state value actually consumed, even on errors."
        )
    )
    summary: str = Field(
        description="Affected target operation and its evidence-backed consequence."
    )
    evidence: list[EvidenceCitation] = Field(
        description="Target-local control/data-flow citations supporting the judgment."
    )
    termination_callsites: list[TerminationCallsiteDraft] = Field(
        default_factory=list,
        description=(
            "Exact termination calls reached because the opposite endpoint is absent "
            "or incompatible. Empty for operation-only failure, permanent retry, or "
            "when no unique termination call is proved."
        ),
    )
    missing_evidence: list[str] = Field(
        description="Concrete missing facts; required when either judgment is unknown."
    )

    @model_validator(mode="after")
    def validate_unknowns(self) -> Self:
        self.finding.validate_references(
            self.model_dump(mode="json"), allowed_roots={"evidence", "missing_evidence"},
        )
        return self


class SiteCallsiteFinding(StrictModel):
    callsite_id: str = Field(
        description="Echo exactly one controller-supplied callsite ID; never invent an ID."
    )
    disposition: Literal[CallsiteDisposition.CHANNEL_ENDPOINT, CallsiteDisposition.NOT_FIRMWARE_IPC, CallsiteDisposition.UNRESOLVED] = Field(
        description=(
            "Confirmed IPC endpoint, non-firmware IPC, or unresolved interaction "
            "classification. A confirmed endpoint may "
            "still carry an unresolved resource identity."
        )
    )
    mechanism: IPCMechanism = Field(
        description="Resolved interaction mechanism, including external/kernel when excluded."
    )
    endpoint_role: EndpointRole = Field(description="Role of this process at the callsite.")
    resources: list[AgentResourceFinding] = Field(
        description="Resource observations, including related IPC objects and runtime handles; only identity_resource_indices defines the kernel object at this endpoint."
    )
    identity_resource_indices: list[int] = Field(default_factory=list, description=(
        "Indices of the minimal kernel-object discriminators in resources. Required for channel_endpoint. "
        "A SysV endpoint uses its own key, not an associated semaphore/shared-memory key or returned ID. "
        "UDS uses pathname/abstract name, POSIX IPC uses its name, FIFO its path, and loopback uses "
        "exactly one each of socket_family, socket_type, socket_protocol, loopback_address, "
        "and socket_port. Include all five even when a value is unknown: use null canonical_value "
        "and explain missing_evidence. Extra evidence or related objects cannot redefine the identity."
    ))
    context_anchor: WrapperHop | None = Field(default=None, description=(
        "Minimal verified caller/branch source position distinguishing an invocation of a shared terminal. "
        "Must be in wrapper_path; null for a direct or single established context. More evidence or a longer "
        "wrapper path must not change this source anchor. Distinct contexts need distinct source anchors."
    ))
    wrapper_path: list[WrapperHop] = Field(
        description="Operation-relevant process-to-terminal wrapper path; empty if direct or unresolved."
    )
    covered_callsite_ids: list[str] = Field(
        description=(
            "Controller-supplied auxiliary callsite IDs semantically owned by this "
            "IPC interaction. The controller restores their immutable code identities."
        )
    )
    dependency: SiteDependencyFinding | None = Field(
        description=(
            "Target-local semantics consumed from the opposite endpoint and the "
            "effect of its absence. Required only for channel_endpoint findings."
        )
    )
    summary: str = Field(description="One factual sentence describing this callsite's interaction.")
    evidence: list[EvidenceCitation] = Field(description=(
        "Evidence for this callsite's disposition and role. Non-empty for channel_endpoint "
        "and not_firmware_ipc; resource/dependency citations do not replace this evidence. "
        "May be empty for unresolved."
    ))
    missing_evidence: list[str] = Field(
        description="Concrete missing facts; non-empty for unresolved disposition."
    )

    @model_validator(mode="after")
    def validate_disposition(self) -> Self:
        if self.disposition is not CallsiteDisposition.UNRESOLVED and not self.evidence:
            raise ValueError(
                f"{self.disposition.value} requires non-empty evidence for the disposition "
                "and role; resource/dependency citations do not replace it"
            )
        if len(self.covered_callsite_ids) != len(set(self.covered_callsite_ids)):
            raise ValueError("covered_callsite_ids must not contain duplicates")
        if self.context_anchor is not None and self.context_anchor not in self.wrapper_path:
            raise ValueError("IPC context_anchor must be a verified wrapper_path source position")
        if self.disposition is CallsiteDisposition.CHANNEL_ENDPOINT:
            if not self.resources:
                raise ValueError("channel endpoint requires at least one resource identity")
            if self.dependency is None:
                raise ValueError("channel endpoint requires a target-local dependency judgment")
            self.resource_identity()
        elif self.disposition is CallsiteDisposition.UNRESOLVED:
            if self.dependency is not None:
                raise ValueError("unresolved callsite cannot carry a dependency judgment")
            if not self.missing_evidence:
                raise ValueError("unresolved callsite must name missing_evidence")
        else:
            if self.dependency is not None:
                raise ValueError("not_firmware_ipc cannot carry a dependency judgment")
        return self

    def source_context(self) -> tuple | None:
        anchor = self.context_anchor
        return (anchor.binary_path, anchor.function_name, anchor.line_number) if anchor is not None else None

    def context_identity(self) -> tuple:
        """Typed observation identity; prose never merges source contexts."""
        return (
            self.disposition.value, self.mechanism.value,
            self.resource_identity() if self.disposition is CallsiteDisposition.CHANNEL_ENDPOINT else (),
            self.source_context(),
        )

    def resource_identity(self) -> tuple:
        indices = self.identity_resource_indices
        if not indices or len(set(indices)) != len(indices) or any(i < 0 or i >= len(self.resources) for i in indices):
            raise ValueError("channel endpoint requires valid unique identity_resource_indices")
        selected = [self.resources[i] for i in indices]
        if self.mechanism.value.startswith("sysv_"):
            allowed = {"sysv_key", self.mechanism.value + "_key"}
            if len(selected) != 1 or selected[0].kind not in allowed:
                raise ValueError("SysV identity must select this mechanism's key, not related objects or returned handles")
            from .identity import canonical_sysv_key
            return (("key", canonical_sysv_key(selected[0].canonical_value)),)
        if self.mechanism.value.startswith("posix_"):
            if len(selected) != 1 or selected[0].kind not in {"posix_name", self.mechanism.value + "_name"}:
                raise ValueError("POSIX IPC identity must select this object's name")
            return (("name", selected[0].canonical_value),)
        if self.mechanism is IPCMechanism.UDS:
            if len(selected) != 1 or selected[0].kind not in {"uds_path", "uds_abstract_name"}:
                raise ValueError("UDS identity requires one pathname or abstract name")
        elif self.mechanism is IPCMechanism.FIFO:
            if len(selected) != 1 or selected[0].kind != "fifo_path":
                raise ValueError("FIFO identity requires its path")
        elif self.mechanism is IPCMechanism.LOOPBACK_SOCKET:
            actual = [r.kind for r in selected]
            if set(actual) != _LOOPBACK_IDENTITY_KINDS or len(actual) != len(_LOOPBACK_IDENTITY_KINDS):
                raise ValueError(
                    "loopback identity_resource_indices must select exactly one resource of each kind: "
                    f"{sorted(_LOOPBACK_IDENTITY_KINDS)}; selected={actual}; "
                    f"missing={sorted(_LOOPBACK_IDENTITY_KINDS - set(actual))}. "
                    "Unknown values use null canonical_value with missing_evidence."
                )
        return tuple(sorted(((r.kind, r.canonical_value) for r in selected), key=repr))



class SiteResolutionOutput(StrictModel):
    callsite_findings: list[SiteCallsiteFinding] = Field(
        description=(
            "At least one finding for every supplied callsite ID. Repeat a callsite ID "
            "for distinct source contexts, including IPC endpoints, excluded external "
            "interactions and unresolved observations of a reused terminal wrapper callsite."
        )
    )
    @model_validator(mode="after")
    def validate_context_variants(self) -> Self:
        by_callsite: dict[str, list[SiteCallsiteFinding]] = {}
        for finding in self.callsite_findings:
            by_callsite.setdefault(finding.callsite_id, []).append(finding)
        for identity, findings in by_callsite.items():
            if len(findings) == 1:
                continue
            contexts = [finding.context_identity() for finding in findings]
            if len(contexts) != len(set(contexts)):
                raise ValueError(f"duplicate endpoint context for callsite_id {identity}")
        return self


class PeerFinding(StrictModel):
    executable_path: str = Field(
        description="Echo one controller-supplied rootfs-relative candidate executable path."
    )
    argv0: str | None = Field(
        description="Exact invocation argv[0], including multicall applet identity, or null if unresolved."
    )
    verdict: CandidateVerdict = Field(description="Verified, rejected, or unresolved peer verdict.")
    role: EndpointRole = Field(description="Candidate's role on this channel.")
    endpoint_locations: list[PeerEndpointLocation] = Field(
        description=(
            "Inspected endpoint operations selected from this candidate's "
            "controller-supplied call_paths[].endpoint. Echo its binary path, "
            "function name, EA and primitive. Upstream wrappers in call_path "
            "are supporting evidence, not additional endpoint operations."
        )
    )
    summary: str = Field(description="Factual verdict reason without speculation.")
    evidence: list[EvidenceCitation] = Field(description="Evidence inspected for this candidate.")
    missing_evidence: list[str] = Field(
        description="Concrete missing facts; required only for unresolved verdict."
    )

    @model_validator(mode="after")
    def validate_verdict(self) -> Self:
        if self.verdict is CandidateVerdict.VERIFIED:
            if (
                not self.endpoint_locations
                or not self.evidence
            ):
                raise ValueError(
                    "verified peer requires endpoint locations, evidence, "
                    "with source references"
                )
        elif self.verdict is CandidateVerdict.UNRESOLVED:
            if not self.missing_evidence:
                raise ValueError("unresolved peer must name missing_evidence")
        elif not self.evidence:
            raise ValueError("rejected peer requires evidence")
        return self


class PeerVerificationOutput(StrictModel):
    peer_findings: list[PeerFinding] = Field(
        description=(
            "Verdicts only for executable candidates actually inspected. The deterministic "
            "retrieval pool is persisted separately on the controller-owned channel."
        )
    )
    @model_validator(mode="after")
    def validate_unique_candidates(self) -> Self:
        paths = [finding.executable_path for finding in self.peer_findings]
        if len(paths) != len(set(paths)):
            raise ValueError("duplicate executable path in peer_findings")
        return self


__all__ = [
    "AgentResourceFinding",
    "CandidateVerdict",
    "PeerFinding",
    "PeerVerificationOutput",
    "SiteCallsiteFinding",
    "SiteDependencyFinding",
    "SiteResolutionOutput",
    "TerminationCallsiteDraft",
]
