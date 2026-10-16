"""Runtime-derived ownership, separate from immutable Catalog claim ownership."""
from __future__ import annotations

from typing import Literal, Self
from pydantic import BaseModel, ConfigDict, Field, model_validator
from fmst_analyzer.intervention_contracts import (
    InterventionAnchor, InterventionContract,
)


class RuntimeUnitDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    unit_id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$", description="Unique runtime Unit ID; existing IDs may revise only their Contract, retaining anchors and strategy.")
    strategy: Literal["function_stub", "callsite_hook", "pseudo_file", "environment_setup"] = Field(description="Execution owner supported by GuestWeave, or Contract revision of an existing static environment owner. Environment admission does not generate Rust adapters.")
    anchors: list[InterventionAnchor] = Field(min_length=1, description="Exact resolved owner. New resource source_ref must be evidence:N, where N is the zero-based index in proposal.evidence. Function/callsite addresses are resolved against the current analysis view.")
    summary: str = Field(min_length=1, description="Runtime-derived behavior and applicability, without inventing Catalog findings or claiming upstream coverage.")
    contract: InterventionContract = Field(description="Caller-visible behavior, state sources, native fallback and verification; does not alter the service scenario.")


class AdaptationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(description="Absolute existing read-only source or Controller attempt evidence file.")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$", description="Digest of the exact existing source bytes.")
    excerpt: str = Field(min_length=1, description="Exact UTF-8 source excerpt; its presence is verified, its interpretation remains a hypothesis.")


class RuntimeUnitProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: Literal["upsert", "rollback"] = Field(description="Propose a new owner or a Contract replacement; rollback restores the authored file contents and ownership state immediately before the most recent still-active admission.")
    unit: RuntimeUnitDefinition | None = Field(default=None, description="Complete proposed definition for upsert; null for rollback.")
    parent_adaptation_id: str | None = Field(default=None, description="Latest active adaptation ID, or null before the first admission. Prevents applying stale proposals.")
    evidence: list[AdaptationEvidence] = Field(min_length=1, description="Existing sources supporting the revision; include runtime evidence from the current attempt, partial execution, or native client. Sources establish observations and identity, not a proven repair hypothesis.")
    rationale: str = Field(min_length=1, description="Observed blocker, why this owner and Contract address it, and behavior preserved.")
    limitations: list[str] = Field(description="Unproved assumptions and missing physical data. Logical emulation state may be initialized explicitly and maintained coherently; do not present it as captured device data.")

    @model_validator(mode="after")
    def check_operation(self) -> Self:
        if (self.operation == "upsert") != (self.unit is not None):
            raise ValueError("upsert requires unit; rollback must omit unit")
        return self


class RuntimeAdaptation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    adaptation_id: str = Field(description="Controller content identity of this admitted proposal and parent workspace.")
    proposal: RuntimeUnitProposal
    source_attempt_path: str
    parent_workspace_sha256: str
    result_workspace_sha256: str
    before: RuntimeUnitDefinition | None
    after: RuntimeUnitDefinition | None
    evidence_snapshots: dict[str, str] = Field(description="Original evidence path to a content-verified snapshot path relative to runtime_adaptations; retained with success publications.")
    rollback_snapshot_path: str = Field(description="Pre-admission authored file contents relative to runtime_adaptations; immutable upstream Plan and Generator remain separate.")
