"""Persisted Unit-based InterventionGenerator result schema."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from fmst_analyzer.synthesizer.intervention_generator.environment import (
    EnvironmentGenerationResult,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionUnit,
)
from .architecture import GeneratorArch
from .review_schema import ContractReview, UnitReviewOutcome


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FailureSignal(StrictModel):
    code: Literal[
        "provider_error",
        "structured_output_error",
        "tool_timeout",
        "tool_step_limit",
        "turn_timeout",
        "cancelled",
        "no_candidate",
        "input_validation",
        "build",
        "test",
        "environment_generation",
    ] = Field(
        default="input_validation",
        description="Stable machine-readable failure category.",
    )
    phase: Literal[
        "input_validation",
        "review",
        "environment_generation",
        "build",
        "test_compile",
        "test_runtime",
    ] = Field(description="Generator boundary that produced the failure.")
    file_path: str | None = Field(
        default=None,
        description="Generated source path associated with the failure.",
    )
    message: str = Field(description="Complete provider, validator, or Cargo error.")


class UnitGenerationResult(StrictModel):
    unit_id: str
    contract_digest: str = Field(
        default="",
        description="SHA-256 digest of the persisted Intervention Unit contract.",
    )
    report_stem: str = Field(
        min_length=1,
        pattern=r"^[A-Za-z0-9._-]+$",
        description="Stable readable stem for this Unit's JSON/Markdown report pair.",
    )
    strategy: Literal[
        "environment_setup", "function_stub", "pseudo_file", "callsite_hook"
    ]
    status: Literal[
        "pending",
        "ok",
        "generation_failed",
        "build_failed",
        "test_failed",
        "skipped",
    ]
    failure_reason: str | None = None
    failure_code: str | None = Field(
        default=None,
        description="Stable failure category, when this Unit is not ready.",
    )
    last_failure_signal: FailureSignal | None = None
    generated_files: list[str] = Field(
        default_factory=list,
        description="Complete generated files attributable to this Unit.",
    )
    round_traces: list["UnitRoundTrace"] = Field(
        default_factory=list,
        description="One trace path for every Generator Agent turn.",
    )
    revision_count: int = Field(
        default=0,
        ge=0,
        description="Number of additional self-correction turns, if any.",
    )
    review_history: list[UnitReviewOutcome] = Field(
        default_factory=list,
        description="Legacy replay field; v1 Generator runs leave this empty.",
    )


class ImplementationContextChange(StrictModel):
    planned_sha256: str | None = Field(description="Implementation source hash recorded by the frozen Plan, or null for a newly exposed source.")
    observed_sha256: str | None = Field(description="Implementation source hash at Generation publication, or null for a removed source.")


class GenerationPublication(StrictModel):
    baseline_id: str = Field(pattern=r"^[0-9a-f]{64}$", description="Content identity of the immutable candidate snapshot and its consumed input.")
    baseline_path: str = Field(description="Absolute immutable snapshot directory; never a mutable current pointer.")
    artifact_hashes: dict[str, str] = Field(description="Exact published authored file paths mapped to SHA-256 of mode and bytes, including source, tests, manifests and Environment.")
    missing_files: list[str] = Field(default_factory=list, description="Declared candidate files absent at publication; failure evidence, not executable delivery.")


class InterventionGenerationResult(StrictModel):
    schema_version: Literal[17] = 17
    plan_digest: str = Field(pattern=r"^[0-9a-f]{64}$", description="Canonical content SHA-256 of the complete Plan actually consumed, including its Catalog input digest.")
    completion_status: Literal["partial", "complete"] = "complete"
    target_binary: str
    arch: GeneratorArch
    total_units: int
    ok_count: int
    not_ready_count: int
    skipped_count: int
    units: list[UnitGenerationResult] = Field(default_factory=list)
    cargo_build_status: Literal["ok", "failed", "not_run"]
    cargo_test_status: Literal["ok", "failed", "not_run"]
    cargo_build_failure: FailureSignal | None = None
    cargo_test_failure: FailureSignal | None = None
    intervention_crate_path: str | None = None
    test_crate_path: str | None = None
    environment: EnvironmentGenerationResult
    implementation_context_changes: dict[str, ImplementationContextChange] = Field(default_factory=dict, description="Historical Plan implementation assumptions that differ from this Generation's framework; evidence for downstream review, not altered Plan contents.")
    publication: GenerationPublication | None = Field(default=None, description="Immutable publication receipt. Null only for an in-progress checkpoint, never executable input.")


class UnitGenerationReport(StrictModel):
    schema_version: Literal[17] = 17
    unit: InterventionUnit
    generation: UnitGenerationResult
    environment_script_path: str | None = None


class UnitRoundTrace(StrictModel):
    round_index: int = Field(
        ge=1,
        description="One-based Generator Agent turn number.",
    )
    generator_trace_path: str | None = Field(
        default=None,
        description="Atomic Markdown trajectory for the implementation turn.",
    )
    reviewer_trace_path: str | None = Field(
        default=None,
        description="Legacy field retained for replay of pre-v1 artifacts; new runs leave it empty.",
    )


UnitGenerationResult.model_rebuild()
UnitGenerationReport.model_rebuild()


__all__ = [
    "ContractReview",
    "FailureSignal",
    "InterventionGenerationResult",
    "UnitReviewOutcome",
    "UnitGenerationReport",
    "UnitRoundTrace",
    "UnitGenerationResult",
]
