"""Structured Agent drafts and normalized intervention-plan artifacts."""

from __future__ import annotations

from typing import Annotated, Literal
from typing_extensions import Self

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from fmst_analyzer.analysis.init_launch.analyzer_schema import LaunchRecipe
from .planning_context import PlanningContext
from fmst_analyzer.intervention_contracts import (
    ResourceKind, ResourceAnchor, ResolvedFunctionAnchor, ResolvedCallsiteAnchor,
    InterventionAnchor, InterventionContract,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    FindingIndexEntry,
    SourceArtifact,
    SourceKind,
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


DecisionId = Annotated[str, Field(
    min_length=1, pattern=r"\S",
    description="Exact nonblank logical decision handle. Preserve spelling, case and spacing; unique across outcomes. It is not an implementation name.",
)]
UnitId = Annotated[str, Field(
    pattern=r"^[a-z][a-z0-9_-]{0,79}$",
    description="Stable implementation Unit name used by build artifacts; lowercase letter followed by up to 79 lowercase letters, digits, underscores or hyphens.",
)]


class LaunchChoice(StrictModel):
    recipe_id: str | None = Field(
        default=None,
        description=(
            "Existing launch recipe selected for the required service behavior under "
            "the supplied rehosting baseline, or null "
            "when none is applicable or applicability remains unresolved."
        ),
    )
    reason: str = Field(
        min_length=1,
        description=(
            "Checked launch conditions, supporting baseline/source facts and "
            "material alternatives. For null identify the incompatible or "
            "unresolved conditions; candidate count is not applicability evidence."
        ),
    )

    @model_validator(mode="after")
    def normalize(self) -> Self:
        self.reason = self.reason.strip()
        if not self.reason:
            raise ValueError("launch choice reason must not be blank")
        if self.recipe_id is not None:
            self.recipe_id = self.recipe_id.strip()
            if not self.recipe_id:
                raise ValueError("recipe_id must not be blank")
        return self


class BehaviorScope(StrictModel):
    finding_ref: str = Field(min_length=1, description="Exact source finding whose conditional behavior is addressed.")
    claim_indices: list[int] = Field(min_length=1, description="Zero-based indices of the source finding claims addressed, within the digest-pinned Catalog. These are content locators, not stable identities.")
    applicability: str = Field(min_length=1, description="Source-supported conditions for these behaviors. Preserve all material branches of the cited claims; do not silently narrow a claim to an easier case.")

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if len(self.claim_indices) != len(set(self.claim_indices)) or any(index < 0 for index in self.claim_indices):
            raise ValueError("claim_indices must be unique and nonnegative")
        self.finding_ref = _nonblank(self.finding_ref, "finding_ref")
        self.applicability = _nonblank(self.applicability, "applicability")
        return self

    def keys(self) -> set[tuple[str, int]]:
        return {(self.finding_ref, index) for index in self.claim_indices}


class ScopedOutcome(StrictModel):
    behavior_scopes: list[BehaviorScope] = Field(min_length=1, description="Exact source claims and applicability owned or investigated by this outcome. Several findings may share one Unit.")

    @model_validator(mode="before")
    @classmethod
    def discard_computed_refs(cls, value):
        if isinstance(value, dict):
            value = dict(value)
            value.pop("finding_refs", None)
        return value

    @computed_field
    @property
    def finding_refs(self) -> list[str]:
        return sorted({scope.finding_ref for scope in self.behavior_scopes})


class NoIntervention(BehaviorScope):
    finding_ref: str = Field(
        min_length=1,
        description=(
            "Source finding whose cited behavior is native, immaterial to the service "
            "goal, or refuted without a remaining intervention need."
        ),
    )
    reason: str = Field(
        min_length=1,
        description=(
            "Concrete native compatibility, target-goal impact, or refutation evidence "
            "supporting this decision. Process survival alone is insufficient."
        ),
    )

    @model_validator(mode="after")
    def normalize(self) -> Self:
        self.finding_ref = _nonblank(self.finding_ref, "finding_ref")
        self.reason = _nonblank(self.reason, "reason")
        return self


InterventionStrategy = Literal[
    "environment_setup",
    "function_stub",
    "pseudo_file",
    "callsite_hook",
]

# ``environment_setup`` is executed before the firmware image is imported.
# It can therefore only materialize static filesystem state. Runtime
# resources (peers, live endpoints and process/environment state) belong to a
# RunnerTask and must never be routed to the Environment Agent.
STATIC_ENVIRONMENT_RESOURCE_KINDS = frozenset({"path", "path_pattern"})


class FunctionAnchorDraft(StrictModel):
    kind: Literal["function"] = Field(
        default="function",
        description="Discriminator for a function-level intervention owner.",
    )
    binary_name: str = Field(
        min_length=1,
        description="Binary containing the function to mock.",
    )
    function_ea: int = Field(
        ge=0,
        description="Function entry address in the named binary.",
    )


class CallsiteAnchorDraft(StrictModel):
    kind: Literal["callsite"] = Field(
        default="callsite",
        description="Discriminator for a callsite-specific intervention owner.",
    )
    callsite_id: str = Field(
        min_length=1,
        description="Stable callsite identity from the supplied analyzer evidence.",
    )


InterventionAnchorDraft = (
    FunctionAnchorDraft | ResourceAnchor | CallsiteAnchorDraft
)


class InterventionUnitDraft(ScopedOutcome):
    strategy: InterventionStrategy = Field(
        description="Mock boundary selected for this unit."
    )
    anchors: list[InterventionAnchorDraft] = Field(
        min_length=1,
        description=(
            "Actual intervention registration points: function_stub uses function "
            "anchors; callsite_hook uses callsite anchors; pseudo_file uses exact "
            "path resources; environment_setup uses path/path_pattern resources. "
            "Functions only cited as evidence or preserved wholly native are not "
            "registration points."
        ),
    )
    contract: InterventionContract = Field(
        description=(
            "Independently testable caller-visible guarantees must describe "
            "applicability, native fallback, return values and output effects, "
            "state and lifecycle, and the factual basis or explicitly "
            "falsifiable assumptions for caller-visible values. Unknown exact "
            "instance data does not block a coherent candidate."
        ),
    )
    summary: str = Field(
        min_length=1,
        description="Concise explanation of the planned intervention boundary.",
    )

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        self.summary = _nonblank(self.summary, "summary")
        kinds = {anchor.kind for anchor in self.anchors}
        expected = {
            "function_stub": "function",
            "pseudo_file": "resource",
            "environment_setup": "resource",
            "callsite_hook": "callsite",
        }[self.strategy]
        if kinds != {expected}:
            invalid = ", ".join(
                f"anchors[{index}].kind={anchor.kind!r}"
                for index, anchor in enumerate(self.anchors) if anchor.kind != expected
            )
            raise ValueError(f"{self.strategy} requires only {expected} anchors; got {invalid}")
        if self.strategy == "pseudo_file" and any(
            not isinstance(anchor, ResourceAnchor)
            or anchor.resource_kind != "path"
            for anchor in self.anchors
        ):
            raise ValueError("pseudo_file requires exact path resources")
        if self.strategy == "environment_setup" and any(
            not isinstance(anchor, ResourceAnchor)
            or anchor.resource_kind not in STATIC_ENVIRONMENT_RESOURCE_KINDS
            for anchor in self.anchors
        ):
            raise ValueError(
                "environment_setup requires only path/path_pattern resources; "
                "runtime peers, endpoints, and environment values belong to runner_tasks"
            )
        return self


class RunnerTask(ScopedOutcome):
    objective: str = Field(
        min_length=1,
        description=(
            "A specific missing runtime fact or dependency that prevents defining "
            "useful behavior from available evidence. Explain why a Unit cannot "
            "supply it now, the concrete observation or action needed, its "
            "completion evidence and the affected decision. Routine tests, "
            "trace collection and Unit refinement are not separate tasks. "
            "A task neither owns behavior nor resolves a recorded gap."
        ),
    )

    @model_validator(mode="after")
    def normalize(self) -> Self:
        self.objective = _nonblank(self.objective, "objective")
        return self


class UnresolvedBehavior(BehaviorScope):
    reason: str = Field(min_length=1, description="Specific contradiction or missing fact that prevents a justified decision for these behaviors.")
    return_to: Literal["analyzer", "launch", "runtime_capability"] = Field(description="Boundary that must supply the missing evidence; provider failures are execution failures, never semantic gaps.")


class InterventionUnit(ScopedOutcome):
    unit_id: UnitId
    strategy: InterventionStrategy
    anchors: list[InterventionAnchor]
    summary: str
    contract: InterventionContract

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        expected = {
            "function_stub": "function",
            "pseudo_file": "resource",
            "environment_setup": "resource",
            "callsite_hook": "callsite",
        }[self.strategy]
        kinds = {anchor.kind for anchor in self.anchors}
        if kinds != {expected}:
            invalid = ", ".join(
                f"anchors[{index}].kind={anchor.kind!r}"
                for index, anchor in enumerate(self.anchors) if anchor.kind != expected
            )
            raise ValueError(f"{self.strategy} requires only {expected} anchors; got {invalid or 'no anchors'}")
        if self.strategy == "pseudo_file" and any(
            not isinstance(anchor, ResourceAnchor)
            or anchor.resource_kind != "path"
            for anchor in self.anchors
        ):
            raise ValueError("pseudo_file requires exact path resources")
        if self.strategy == "environment_setup" and any(
            not isinstance(anchor, ResourceAnchor)
            or anchor.resource_kind not in STATIC_ENVIRONMENT_RESOURCE_KINDS
            for anchor in self.anchors
        ):
            raise ValueError(
                "environment_setup requires only path/path_pattern resources; "
                "runtime peers, endpoints, and environment values belong to runner_tasks"
            )
        return self


class PlanContents(StrictModel):
    """Global decisions; logical handles and implementation Unit names differ."""

    units: dict[UnitId, InterventionUnit] = Field(default_factory=dict)
    no_interventions: dict[DecisionId, NoIntervention] = Field(default_factory=dict)
    unresolved: dict[DecisionId, UnresolvedBehavior] = Field(default_factory=dict)
    runner_tasks: dict[DecisionId, RunnerTask] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_decision_ids(self) -> Self:
        seen: set[str] = set()
        for field in DECISION_FIELDS:
            mapping = getattr(self, field)
            if seen.intersection(mapping):
                raise ValueError(f"decision IDs must be unique across outcomes: {sorted(seen.intersection(mapping))}")
            seen.update(mapping)
        if any(key != unit.unit_id for key, unit in self.units.items()):
            raise ValueError("unit key must equal unit_id")
        return self


DECISION_FIELDS = ("units", "no_interventions", "unresolved", "runner_tasks")


class PlannerExecution(StrictModel):
    model: str
    reasoning_effort: str | None
    provider: str
    model_provider: str
    session_id: str
    turn_id: str


class InterventionPlanResult(PlanContents):
    schema_version: Literal[13] = 13
    catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$", description="Content SHA-256 of the exact Catalog consumed, including every source JSON digest.")
    planning_context: PlanningContext
    service_goal: str | None = None
    launch_choice: LaunchChoice
    claim_counts: dict[str, Annotated[int, Field(ge=0)]]
    draft_revision: int = Field(ge=0)
    producer: PlannerExecution | None = None

    @model_validator(mode="after")
    def validate_coverage(self) -> Self:
        expected = {(ref, index) for ref, count in self.claim_counts.items() for index in range(count)}
        covered = []
        for unit in self.units.values():
            covered.extend(key for scope in unit.behavior_scopes for key in scope.keys())
        covered.extend(key for item in self.no_interventions.values() for key in item.keys())
        covered.extend(key for item in self.unresolved.values() for key in item.keys())
        if len(covered) != len(set(covered)):
            raise ValueError("a source claim must have exactly one current decision")
        if set(covered) != expected:
            raise ValueError(f"published Plan claim coverage differs: missing={sorted(expected - set(covered))!r}; unexpected={sorted(set(covered) - expected)!r}")
        return self


class UnitPlanReport(StrictModel):
    schema_version: Literal[13] = 13
    catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    service_goal: str | None
    launch_choice: LaunchChoice
    selected_launch_recipe: LaunchRecipe | None = None
    finding_index: dict[str, FindingIndexEntry]
    source_artifacts: dict[SourceKind, SourceArtifact]
    unit: InterventionUnit


def _nonblank(value: str, field: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{field} must not be blank")
    return value


def _nonblank_unique(values: list[str], field: str) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _nonblank(value, field)
        if item not in seen:
            seen.add(item)
            normalized.append(item)
    return normalized


__all__ = [
    "BehaviorScope", "CallsiteAnchorDraft", "DECISION_FIELDS", "DecisionId",
    "FunctionAnchorDraft", "InterventionAnchor", "InterventionAnchorDraft",
    "InterventionContract", "InterventionPlanResult", "InterventionStrategy",
    "InterventionUnit", "InterventionUnitDraft", "LaunchChoice", "NoIntervention",
    "PlanContents", "PlannerExecution", "ResolvedCallsiteAnchor",
    "ResolvedFunctionAnchor", "ResourceAnchor", "ResourceKind", "RunnerTask",
    "UnitId", "UnitPlanReport", "UnresolvedBehavior",
]
