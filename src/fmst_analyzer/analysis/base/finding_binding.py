"""Bind same-analysis semantic drafts to controller-owned source records."""
from __future__ import annotations

import hashlib
from .output_validation import OutputValidationError
from pathlib import Path
from typing import Literal
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .analysis_finding import (
    AnalysisFinding, EvidenceRef, FindingAnchor, FindingBoundary, FindingClaim,
    FindingDomain, FindingSource, NonBlank, make_finding_ref, resolve_evidence_ref,
)


class FindingTarget(BaseModel):
    """Exact executable identity; no host/workdir coordinates enter findings."""

    model_config = ConfigDict(extra="forbid")
    path: str = Field(description="Canonical rootfs-relative POSIX path of the selected target.")
    sha256: str = Field(description="Lowercase SHA-256 of the selected target executable bytes.")

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        self.ref("process", "identity-validation")
        return self

    def ref(self, source: FindingSource, source_id: str) -> str:
        return make_finding_ref(
            source=source, target_path=self.path,
            target_sha256=self.sha256, source_id=source_id,
        )

    @classmethod
    def from_file(cls, rootfs: Path, target: Path) -> Self:
        rootfs = rootfs.resolve()
        target = target.resolve()
        relative = target.relative_to(rootfs).as_posix()
        digest = hashlib.sha256()
        with target.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return cls(path=relative, sha256=digest.hexdigest())


class FindingSemantics(BaseModel):
    """Transient part of the existing domain Agent output, never a second report."""

    model_config = ConfigDict(extra="forbid")
    summary: NonBlank = Field(description="Concise factual summary of this subject's caller-visible behavior and remaining gaps.")
    claims: list[FindingClaim] = Field(
        min_length=1,
        description="Supported guarantees, state transitions, native fallback boundaries and explicit unknowns. References are JSON pointers in the enclosing domain record, not in this semantics object.",
    )
    reachability_refs: list[EvidenceRef] = Field(description="Pointers in the enclosing domain record proving target-to-subject applicability; empty when unproved.")
    coverage_refs: list[EvidenceRef] = Field(description="Pointers in the enclosing domain record to supported call coverage; empty makes no coverage claim.")

    def validate_references(self, document: dict, *, allowed_roots: set[str]) -> None:
        refs = [*self.reachability_refs, *self.coverage_refs]
        for claim in self.claims:
            refs.extend(claim.evidence_refs)
        for ref in refs:
            if ref.split("/", 2)[1] not in allowed_roots:
                raise OutputValidationError(f"semantic evidence {ref!r} must cite {sorted(allowed_roots)}")
            # Null and empty values are valid evidence of an unknown or absent
            # value. Existence and ownership are structural checks; whether a
            # value supports a semantic claim is not a generic truthiness rule.
            try:
                resolve_evidence_ref(document, ref)
            except ValueError as error:
                raise OutputValidationError(str(error)) from error


def pointer(*parts: str | int) -> str:
    """Build a JSON pointer without interpreting slashes inside source IDs."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in parts)


def bind_finding(
    *, target: FindingTarget, source: FindingSource, source_id: str,
    semantics: FindingSemantics, record_ref: str,
    boundary_kind: Literal["function", "resource", "callsite", "environment"],
    anchors: list[FindingAnchor], domain: FindingDomain | None,
) -> AnalysisFinding:
    """Rebase evidence locators once, after domain normalization is complete."""
    return AnalysisFinding(
        finding_ref=target.ref(source, source_id), summary=semantics.summary,
        boundary=FindingBoundary(
            kind=boundary_kind, anchors=anchors,
            reachability_refs=[record_ref + ref for ref in semantics.reachability_refs],
            coverage_refs=[record_ref + ref for ref in semantics.coverage_refs],
        ),
        claims=[claim.model_copy(update={
            "evidence_refs": [record_ref + ref for ref in claim.evidence_refs],
        }) for claim in semantics.claims],
        domain=domain,
    )


def validate_bound_finding(
    finding: AnalysisFinding, *, record_ref: str, document: dict, allowed_roots: set[str],
) -> None:
    """Reject citations borrowed from another subject, even when they resolve."""
    def local(ref: str) -> str:
        if not ref.startswith(record_ref + "/"):
            raise ValueError(f"finding evidence {ref!r} does not belong to {record_ref}")
        return ref[len(record_ref):]

    FindingSemantics(
        summary=finding.summary,
        claims=[claim.model_copy(update={"evidence_refs": [local(ref) for ref in claim.evidence_refs]})
                for claim in finding.claims],
        reachability_refs=[local(ref) for ref in finding.boundary.reachability_refs],
        coverage_refs=[local(ref) for ref in finding.boundary.coverage_refs],
    ).validate_references(document, allowed_roots=allowed_roots)
