"""Legacy review schema retained only for replaying pre-v1 artifacts.

The v1 Generator has no Reviewer Agent or review control flow. Keeping this
decoder lets historical G0/G2 evidence remain inspectable without making it a
runtime decision in new Generation runs.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ContractReview(_StrictModel):
    contract_index: int = Field(
        ge=0,
        description=(
            "Zero-based index of the exact contract.operations item being reviewed."
        ),
    )
    status: Literal[
        "satisfied",
        "implementation_gap",
        "test_gap",
        "iib_capability_required",
        "plan_mismatch",
    ] = Field(
        description=(
            "Whether the generated implementation and test satisfy this "
            "contract item, omit implementation or test behavior, require "
            "an unavailable IIB capability, or expose an invalid Plan premise."
        )
    )
    evidence: str = Field(
        min_length=1,
        description=(
            "Concrete code, test, Analyzer, or IIB-runtime evidence supporting "
            "the review status."
        ),
    )
    required_change: str | None = Field(
        default=None,
        description=(
            "Specific change required from the implementation Agent. This is "
            "null only when the item is satisfied; IIB capability and Plan "
            "mismatch statuses instead state the external change required."
        ),
    )


class UnitReviewOutcome(_StrictModel):
    verdict: Literal[
        "approved",
        "revision_required",
        "iib_capability_required",
        "plan_mismatch",
    ] = Field(
        description=(
            "approved only when every contract item is implemented and tested; "
            "revision_required for fixable Unit-source or test gaps; "
            "iib_capability_required when a valid contract needs a concrete "
            "capability absent from the inspected IIB API/runtime; plan_mismatch "
            "when the selected owner, strategy, anchor, or contract is invalid."
        )
    )
    contract_reviews: list[ContractReview] = Field(
        description=(
            "Exactly one review for every contract.operations item, ordered by its "
            "zero-based contract_index."
        )
    )
    summary: str = Field(
        min_length=1,
        description="Concise independent review conclusion and stopping reason.",
    )


def normalize_unit_review(
    review: UnitReviewOutcome,
    contract_count: int,
) -> tuple[UnitReviewOutcome, str | None]:
    """Validate exact contract accounting and verdict/status consistency."""
    ordered = sorted(
        review.contract_reviews,
        key=lambda item: item.contract_index,
    )
    indexes = [item.contract_index for item in ordered]
    expected = list(range(contract_count))
    if indexes != expected:
        return review, (
            "independent review must cover each contract.operations item exactly "
            f"once; expected indexes {expected}, received {indexes}"
        )
    for item in ordered:
        if item.status != "satisfied" and not (
            item.required_change and item.required_change.strip()
        ):
            return review, (
                "independent review item "
                f"{item.contract_index} status {item.status!r} is missing "
                "required_change"
            )

    statuses = {item.status for item in ordered}
    valid = False
    if review.verdict == "approved":
        valid = statuses <= {"satisfied"}
    elif review.verdict == "revision_required":
        valid = bool(statuses & {"implementation_gap", "test_gap"}) and not (
            statuses & {"iib_capability_required", "plan_mismatch"}
        )
    elif review.verdict == "iib_capability_required":
        valid = (
            "iib_capability_required" in statuses
            and "plan_mismatch" not in statuses
        )
    elif review.verdict == "plan_mismatch":
        valid = "plan_mismatch" in statuses
    if not valid:
        return review, (
            f"independent review verdict {review.verdict!r} contradicts "
            f"contract statuses {sorted(statuses)}"
        )
    return review.model_copy(update={"contract_reviews": ordered}), None


__all__ = [
    "ContractReview",
    "normalize_unit_review",
    "UnitReviewOutcome",
]
