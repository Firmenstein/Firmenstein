"""Persisted schema for the deterministic intervention planning catalog."""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fmst_analyzer.analysis.init_launch.analyzer_schema import LaunchRecipe
from fmst_analyzer.analysis.base.finding_binding import pointer


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceKind(str, Enum):
    IPC = "ipc"
    FILE = "file"
    NETWORK = "network"
    PROCESS = "process"
    INIT_LAUNCH = "init_launch"


class PlanningTargetIdentity(StrictModel):
    target_basename: str
    selected_rootfs_path: str
    executable_sha256: str
    argv0: str
    target_aliases: list[str] = Field(default_factory=list)
    firmware_sha256: str


class SourceArtifact(StrictModel):
    source_kind: SourceKind
    relative_path: str
    schema_version: int
    phase: Literal["static", "full"]
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the exact source JSON bytes read when building this index.")
    provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$", description="SHA-256 of the input receipt binding this Result to its producing attempt.")


class FindingIndexEntry(StrictModel):
    finding_ref: str = Field(description="Exact Analyzer-owned finding_ref; the index never invents semantic identities.")
    source_kind: SourceKind
    source_id: str
    summary: str
    boundary_kind: Literal["function", "resource", "callsite", "environment"]
    anchor_keys: list[str] = Field(description="Mechanical source-object overlap hints, never semantic ownership decisions.")
    evidence_refs: list[str] = Field(description="Exact evidence pointers from the source finding; no semantic projection.")
    source_locator: str = Field(description="JSON pointer to this finding in its digest-pinned Analyzer Result.")

    @model_validator(mode="after")
    def validate_locator(self):
        if self.source_locator != pointer("planning_findings", self.finding_ref):
            raise ValueError("source_locator must name the exact source finding")
        return self


class PlanningEvidenceGap(StrictModel):
    gap_ref: str
    source_kind: SourceKind
    source_id: str | None = None
    subject: str
    reasons: list[str] = Field(min_length=1)
    related_source_ids: list[str] = Field(default_factory=list)


class PlanningEvidenceCatalog(StrictModel):
    """Materialized index over the five analyzer JSON sources.

    This model is not an intervention plan. It preserves only compact indices,
    source identities, launch candidates, and explicit gaps. The referenced
    analyzer JSON files remain the immutable analysis records, not certified semantic truth.
    """

    schema_version: Literal[5] = 5
    target_identity: PlanningTargetIdentity
    source_artifacts: dict[SourceKind, SourceArtifact]
    finding_index: dict[str, FindingIndexEntry]
    launch_candidates: dict[str, LaunchRecipe] = Field(default_factory=dict)
    gaps: dict[str, PlanningEvidenceGap] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_identity_maps(self):
        if set(self.source_artifacts) != set(SourceKind):
            raise ValueError("source_artifacts must contain all five analyzer sources")
        for key, artifact in self.source_artifacts.items():
            if key is not artifact.source_kind:
                raise ValueError("source_artifact key must equal source_kind")
        if any(
            key != item.finding_ref
            for key, item in self.finding_index.items()
        ):
            raise ValueError("finding index key must equal finding_ref")
        if any(key != item.recipe_id for key, item in self.launch_candidates.items()):
            raise ValueError("launch candidate key must equal recipe_id")
        if any(key != item.gap_ref for key, item in self.gaps.items()):
            raise ValueError("gap key must equal gap_ref")
        return self


__all__ = [
    "PlanningEvidenceCatalog",
    "PlanningEvidenceGap",
    "FindingIndexEntry",
    "PlanningTargetIdentity",
    "SourceArtifact",
    "SourceKind",
]
