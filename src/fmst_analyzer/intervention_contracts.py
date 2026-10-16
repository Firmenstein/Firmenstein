"""Portable intervention ownership and behavior contracts, without analyzers."""
from __future__ import annotations
from typing import Literal
from typing_extensions import Self
from pydantic import BaseModel, ConfigDict, Field, field_validator

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

ResourceKind = Literal[
    "path",
    "path_pattern",
    "ipc_peer",
    "ipc_channel",
    "network_endpoint",
    "environment_value",
]

class ResourceAnchor(StrictModel):
    kind: Literal["resource"] = Field(
        default="resource",
        description="Discriminator for an environment or pseudo-resource owner.",
    )
    resource_kind: ResourceKind = Field(
        description="Typed firmware-visible resource owned by the intervention."
    )
    value: str = Field(
        min_length=1,
        description="Concrete resource value represented by this anchor.",
    )
    source_ref: str = Field(
        min_length=1,
        description="Exact finding_ref owned by this Unit, selected launch recipe_id, or source object ID supplied by its finding records. Do not use a JSON pointer, prose citation or file path.",
    )

class ResolvedFunctionAnchor(StrictModel):
    kind: Literal["function"] = "function"
    binary_name: str
    function_name: str
    function_ea: int

class ResolvedCallsiteAnchor(StrictModel):
    kind: Literal["callsite"] = "callsite"
    callsite_id: str
    binary_name: str
    function_name: str
    function_ea: int
    snapshot_hash: str
    ctree_index: int
    source_ea: int | None = None
    line_number: int
    column_number: int
    api_name: str

InterventionAnchor = (
    ResolvedFunctionAnchor | ResourceAnchor | ResolvedCallsiteAnchor
)

class InterventionContract(StrictModel):
    """The semantic contract a Unit owns across planning and execution.

    The lists intentionally contain declarative statements rather than source
    code.  A generated implementation may change within this boundary, while
    changing the boundary itself requires a new planning result.
    """

    applicability: list[str] = Field(
        min_length=1,
        description="Conditions under which the Unit claims the interaction.",
    )
    owned_resources: list[str] = Field(
        min_length=1,
        description="Exact paths, functions, or callsites owned by the Unit.",
    )
    operations: list[str] = Field(
        min_length=1,
        description="Guest-visible operations and guarantees implemented by the Unit.",
    )
    state: list[str] = Field(
        default_factory=list,
        description=(
            "State shape, initial values or source, initialization before first "
            "consumer, isolation, and lifetime. An existing native initializer "
            "only supplies state if the selected execution actually reaches it."
        ),
    )
    native_fallback: list[str] = Field(
        default_factory=list,
        description="Conditions under which an unclaimed interaction reaches native guest execution.",
    )
    required_iib_capabilities: list[str] = Field(
        default_factory=list,
        description=(
            "Required runtime manifest JSON capability IDs, e.g. "
            "invocation_native_call or guest_memory_read_write. Use serialized "
            "snake_case identifiers, not Rust enum variants such as "
            "InvocationNativeCall. A declaration does not prove target conformance."
        ),
    )
    verification: list[str] = Field(
        min_length=1,
        description=(
            "Generator checks and runtime observations that test the Unit's "
            "guarantees and guide permitted refinement. Routine validation "
            "belongs here, not in separate RunnerTasks."
        ),
    )
    allowed_refinement_scope: list[str] = Field(
        description=(
            "Implementation details RunnerAgent may refine without replanning. "
            "Supply an explicit empty list to permit no runtime Unit edits; "
            "initial generation of the Contract remains authorized."
        ),
    )

    @field_validator("applicability", "owned_resources", "operations", "state",
                     "native_fallback", "required_iib_capabilities", "verification",
                     "allowed_refinement_scope")
    @classmethod
    def normalize_entries(cls, values: list[str], info) -> list[str]:
        return _nonblank_unique(values, info.field_name) if values else []

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
