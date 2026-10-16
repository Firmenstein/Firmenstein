"""Shared analysis facts; domain Result models own their evidence and provenance."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Annotated, Literal
from typing_extensions import Self

from pydantic import (
    AfterValidator, BaseModel, ConfigDict, Field, StringConstraints,
    TypeAdapter, model_validator,
)


FindingSource = Literal["file", "network", "ipc", "process", "init_launch"]
_source_adapter = TypeAdapter(FindingSource)
NonBlank = Annotated[str, StringConstraints(strict=True, pattern=r"\S")]


def _validate_pointer(value: str) -> str:
    if not value.startswith("/") or re.search(r"~(?![01])", value):
        raise ValueError("evidence ref must be an RFC 6901 JSON pointer beginning with /")
    if value.split("/", 2)[1] == "planning_findings":
        raise ValueError("a finding cannot cite planning_findings as its own evidence")
    return value


EvidenceRef = Annotated[NonBlank, AfterValidator(_validate_pointer)]
FindingRef = Annotated[str, StringConstraints(
    strict=True,
    pattern=r"^finding:(file|network|ipc|process|init_launch):v1:[0-9a-f]{64}$",
)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FindingAnchor(_StrictModel):
    kind: Literal["function", "callsite", "path", "fd", "device", "ipc_channel", "environment"] = Field(
        description="Kind of source object locating the analyzed behavior, without selecting an intervention."
    )
    ref: EvidenceRef = Field(
        description="JSON pointer to that object or value in the owning Result; details remain in that source record."
    )


class FindingBoundary(_StrictModel):
    kind: Literal["function", "resource", "callsite", "environment"] = Field(
        description="Scope over which the finding's claims apply; not a hook or execution strategy."
    )
    anchors: list[FindingAnchor] = Field(
        min_length=1, description="Source objects that locate this one coherent analysis subject."
    )
    reachability_refs: list[EvidenceRef] = Field(
        description="Pointers to target-to-subject call paths or launch evidence; empty means none established."
    )
    coverage_refs: list[EvidenceRef] = Field(
        description="Pointers to covered API calls or usage flows; an empty list makes no coverage claim."
    )


class FindingClaim(_StrictModel):
    kind: Literal["guarantee", "state", "fallback", "unknown"] = Field(
        description="Caller-visible return/error/output effects, cross-call state, fallback behavior, or an explicit knowledge gap."
    )
    statement: NonBlank = Field(
        description="Complete semantic assertion or precise missing knowledge, including its applicability conditions."
    )
    evidence_refs: list[EvidenceRef] = Field(
        description="Pointers to supporting Result records, including persisted code/script citations; only unknown may have no evidence."
    )
    unknown_kind: Literal["instance_data", "applicability", "semantics", "external_effects"] | None = Field(
        description="Required category for unknown claims, otherwise null; unknown instance values do not imply unknown behavior."
    )

    @model_validator(mode="after")
    def validate_knowledge(self) -> Self:
        if (self.kind == "unknown") != (self.unknown_kind is not None):
            raise ValueError("unknown_kind is required exactly when kind is unknown")
        if self.kind != "unknown" and not self.evidence_refs:
            raise ValueError("a known semantic claim requires evidence_refs")
        return self


class FileFindingDomain(_StrictModel):
    kind: Literal["file"] = Field(description="FileResolver domain discriminator.")
    resource_id: NonBlank = Field(description="Stable controller-owned resource identity in the File Result.")
    path: NonBlank | None = Field(description="Guest path or path expression from the source resource, null when unresolved; never a host path.")
    resource_class: NonBlank | None = Field(description="File Result's resource classification, null when unresolved; its vocabulary is owned by the File Analyzer.")
    callsite_ids: list[NonBlank] = Field(description="Stable File callsite identities associated with this resource.")


class NetworkFindingDomain(_StrictModel):
    kind: Literal["network"] = Field(description="NetworkAnalyzer domain discriminator.")
    interaction_id: NonBlank = Field(description="Stable controller-owned network interaction identity.")
    interaction_kind: NonBlank | None = Field(description="Network Result's interaction classification, null when unresolved.")
    callsite_ids: list[NonBlank] = Field(description="Stable network callsite identities belonging to this interaction.")


class IPCFindingDomain(_StrictModel):
    kind: Literal["ipc"] = Field(description="IPCAnalyzer domain discriminator.")
    channel_id: NonBlank = Field(description="Stable controller-owned channel identity in the IPC Result.")
    mechanism: NonBlank = Field(description="IPC Result's mechanism classification, without a peer execution decision.")
    endpoint_ids: list[NonBlank] = Field(description="Stable endpoint identities in the referenced channel.")


class ProcessFindingDomain(_StrictModel):
    kind: Literal["process"] = Field(description="ProcessLifecycleAnalyzer domain discriminator.")
    callsite_id: NonBlank = Field(description="Stable process lifecycle callsite identity in the Process Result.")
    event_kind: NonBlank = Field(description="Process Result's event classification; not a decision to change lifecycle behavior.")


class InitLaunchFindingDomain(_StrictModel):
    kind: Literal["init_launch"] = Field(description="InitLaunchAnalyzer domain discriminator.")
    recipe_id: NonBlank = Field(description="Existing launch recipe identity; the full recipe remains in the InitLaunch Result.")
    preparation_refs: list[EvidenceRef] = Field(description="Pointers to the recipe's source-backed preparation records.")


FindingDomain = Annotated[
    FileFindingDomain | NetworkFindingDomain | IPCFindingDomain | ProcessFindingDomain | InitLaunchFindingDomain,
    Field(discriminator="kind"),
]


class AnalysisFinding(_StrictModel):
    finding_ref: FindingRef = Field(
        description="Controller-assigned identity from make_finding_ref; never generated from summary, phase, array order, or an Agent-chosen label."
    )
    summary: NonBlank = Field(description="Analyzer-authored summary for planning; preserved verbatim without truncation or downstream rewriting.")
    boundary: FindingBoundary = Field(description="Evidence-backed scope of this analysis subject.")
    claims: list[FindingClaim] = Field(min_length=1, description="Supported semantic facts and explicit unknowns; no strategy, Unit, or capability decisions.")
    domain: FindingDomain | None = Field(description="Small typed domain identity, or null when common anchors suffice; never a duplicate evidence payload.")

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.domain is not None and self.finding_ref.split(":")[1] != self.domain.kind:
            raise ValueError("domain kind must match the finding_ref source")
        return self


def validate_finding_map(findings: dict[str, AnalysisFinding]) -> dict[str, AnalysisFinding]:
    """Validate the identity keys of an already parsed finding map."""
    for key, finding in findings.items():
        if key != finding.finding_ref:
            raise ValueError(f"planning_findings key must equal finding_ref: {key!r}")
    return findings


# G2 Result fields use this type with Field(description=...), without a default.
PlanningFindings = Annotated[dict[str, AnalysisFinding], AfterValidator(validate_finding_map)]


def make_finding_ref(
    *, source: FindingSource, target_path: str, target_sha256: str, source_id: str,
) -> str:
    """Bind a subject collected by a controller to an exact target executable.

    source_id is a stable domain object identity, including invocation context
    when it distinguishes subjects. It must survive static/full enrichment;
    display lines, list offsets, summaries and resolved runtime values are not IDs.
    target_path is rootfs-relative POSIX data, independent of the host/workdir.
    """
    source = _source_adapter.validate_python(source)
    if not isinstance(target_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", target_sha256):
        raise ValueError("target_sha256 must be a lowercase SHA-256 digest")
    if (
        not isinstance(target_path, str) or not target_path
        or "\\" in target_path or "\0" in target_path
    ):
        raise ValueError("target_path must be a canonical rootfs-relative POSIX path")
    path = PurePosixPath(target_path)
    if (
        path.is_absolute() or ".." in path.parts or not path.parts
        or path.as_posix() != target_path or re.match(r"^[A-Za-z]:", target_path)
    ):
        raise ValueError("target_path must be a canonical rootfs-relative POSIX path")
    if (
        not isinstance(source_id, str) or not source_id.strip()
        or source_id != source_id.strip() or "\0" in source_id
    ):
        raise ValueError("source_id must be a nonblank canonical domain identity")
    payload = json.dumps(
        [source, target_path, target_sha256, source_id],
        ensure_ascii=False, separators=(",", ":"),
    )
    return f"finding:{source}:v1:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def resolve_evidence_ref(result: dict, ref: str) -> object:
    """Resolve an RFC 6901 pointer within one already-loaded Result; no I/O.

    Array offsets locate evidence in this artifact, never define finding identity.
    Code/script evidence must itself be persisted in the Result before citation.
    """
    _validate_pointer(ref)
    value = result
    for part in ref.split("/")[1:]:
        token = part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and token in value:
            value = value[token]
        elif (
            isinstance(value, list) and re.fullmatch(r"0|[1-9][0-9]*", token)
            and int(token) < len(value)
        ):
            value = value[int(token)]
        else:
            raise ValueError(f"unresolved evidence ref: {ref!r}")
    return value


def validate_finding_references(findings: dict[str, AnalysisFinding], result: dict) -> None:
    """Check the finding map and every citation at a Result persistence boundary."""
    validate_finding_map(findings)
    refs: set[str] = set()
    for finding in findings.values():
        refs.update(anchor.ref for anchor in finding.boundary.anchors)
        refs.update(finding.boundary.reachability_refs)
        refs.update(finding.boundary.coverage_refs)
        for claim in finding.claims:
            refs.update(claim.evidence_refs)
        if isinstance(finding.domain, InitLaunchFindingDomain):
            refs.update(finding.domain.preparation_refs)
    for ref in sorted(refs):
        resolve_evidence_ref(result, ref)
