"""One atomic, revisable Plan draft and deterministic source-claim progress.

This layer neither calls an Agent nor decides whether a claim is true. Unit
anchor resolution is supplied by the production boundary or an offline fixture.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from fmst_analyzer.analysis.base.report_io import load_model_json, model_content_sha256, write_model_json

from .behavior_validation import claim_keys, validate_scope
from .planning_context import PlanningContext
from .schema import (
    DECISION_FIELDS, DecisionId, InterventionUnit, InterventionUnitDraft,
    LaunchChoice, NoIntervention, PlanContents, RunnerTask,
    StrictModel, UnresolvedBehavior, UnitId,
)


class PlanBatch(StrictModel):
    expected_revision: int = Field(ge=0, description="Revision returned by the latest draft read or accepted update. A stale revision is rejected.")
    reason: str = Field(min_length=1, description="Concise evidence or engineering reason for this batch, including any reconsidered decisions.")
    launch_choice: LaunchChoice | None = Field(default=None, description="Replace the launch decision when supplied. Omission preserves it; recipe_id=null explicitly records no applicable launch.")
    units: dict[UnitId, InterventionUnitDraft] = Field(default_factory=dict, description="Add or replace complete Units by stable implementation Unit name. Several findings can share one Unit; logical decisions in other outcomes need not use Unit naming.")
    no_interventions: dict[DecisionId, NoIntervention] = Field(default_factory=dict, description="Add or replace decisions supported by native behavior, immaterial failure, or refuted claims without a remaining intervention need.")
    unresolved: dict[DecisionId, UnresolvedBehavior] = Field(default_factory=dict, description="Add or replace explicit blocking semantic gaps. Execution failures and unprocessed claims are not semantic gaps.")
    runner_tasks: dict[DecisionId, RunnerTask] = Field(default_factory=dict, description="Add or replace concrete runtime follow-up. A task may accompany any decision but does not itself account for a claim.")
    withdraw: list[DecisionId] = Field(default_factory=list, description="Remove existing decision IDs, including Units being merged or replaced. Removal and additions are atomic.")
    reconfirm: list[DecisionId] = Field(default_factory=list, description="Existing decisions rechecked against a changed launch and still valid. Explain the review in reason; updating a decision also rechecks it.")

    @model_validator(mode="after")
    def validate_batch(self):
        self.reason = self.reason.strip()
        if not self.reason:
            raise ValueError("reason must not be blank")
        for field in ("withdraw", "reconfirm"):
            values = getattr(self, field)
            if len(values) != len(set(values)):
                raise ValueError(f"{field} must contain unique IDs")
        if set(self.withdraw) & set(self.reconfirm):
            raise ValueError("a withdrawn decision cannot also be reconfirmed")
        return self


class PlanDraft(PlanContents):
    schema_version: Literal[2] = 2
    catalog_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    planning_context: PlanningContext
    service_goal: str | None
    launch_choice: LaunchChoice | None = None
    revision: int = Field(default=0, ge=0)
    review_pending: list[DecisionId] = Field(default_factory=list)
    history: list[PlanBatch] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_history(self):
        if self.revision != len(self.history):
            raise ValueError("draft revision must match its accepted history")
        if any(item.expected_revision != index for index, item in enumerate(self.history)):
            raise ValueError("draft history must have consecutive revisions")
        known = decision_ids(self)
        if len(set(self.review_pending)) != len(self.review_pending) or set(self.review_pending) - known:
            raise ValueError("review_pending must name unique existing decisions")
        return self


def decision_ids(contents: PlanContents) -> set[str]:
    return {key for field in DECISION_FIELDS for key in getattr(contents, field)}


def validate_contents(contents: PlanContents, catalog, resolver, *, complete: bool = False) -> None:
    """Check references, claim accounting and concrete owners; never judge prose."""
    allowed = set(catalog.finding_index)
    expected = claim_keys(resolver, allowed)
    owners: dict[tuple[str, int], str] = {}
    errors = []
    for field in ("units", "no_interventions", "unresolved", "runner_tasks"):
        for decision_id, item in getattr(contents, field).items():
            scopes = item.behavior_scopes if field in {"units", "runner_tasks"} else [item]
            for index, scope in enumerate(scopes):
                location = f"{field}/{decision_id}/scopes/{index}"
                try:
                    validate_scope(scope, resolver, allowed)
                except ValueError as error:
                    errors.append(f"{location}: {error}")
                if field == "runner_tasks":
                    continue
                for key in scope.keys():
                    if key in owners:
                        errors.append(f"{location}: claim {key!r} already has decision {owners[key]!r}")
                    owners[key] = decision_id
    if complete and expected - owners.keys():
        errors.append(f"unprocessed claims: {sorted(expected - owners.keys())!r}")

    # Source evidence overlap is a hint, not a mandatory Cartesian checklist.
    # Concrete intervention anchors, however, must have one execution owner.
    anchor_owners = {}
    for unit_id, unit in contents.units.items():
        for anchor in unit.anchors:
            if anchor.kind == "resource":
                key = (anchor.kind, anchor.resource_kind, anchor.value)
            elif anchor.kind == "function":
                key = (anchor.kind, anchor.binary_name, anchor.function_ea)
            else:
                key = (anchor.kind, anchor.binary_name, anchor.function_ea, anchor.snapshot_hash, anchor.ctree_index)
            previous = anchor_owners.setdefault(key, unit_id)
            if previous != unit_id:
                errors.append(f"units/{unit_id}: concrete anchor {key!r} already belongs to Unit {previous!r}; use one coherent owner")
    if errors:
        raise ValueError("\n".join(errors))


class PlanDraftStore:
    """A single writer publishes each validated batch with one atomic replace."""

    def __init__(self, path: Path, catalog, resolver, planning_context: PlanningContext,
                 *, service_goal: str | None = None,
                 resolve_unit: Callable[[str, InterventionUnitDraft, LaunchChoice | None], InterventionUnit] | None = None):
        self.path = Path(path)
        self.catalog = catalog
        self.resolver = resolver
        self.resolve_unit = resolve_unit
        goal = service_goal.strip() if service_goal else None
        identity = dict(catalog_digest=model_content_sha256(catalog), planning_context=planning_context, service_goal=goal or None)
        if self.path.exists():
            state = load_model_json(self.path, PlanDraft)
            if any(getattr(state, field) != value for field, value in identity.items()):
                raise ValueError("draft Catalog, PlanningContext or service goal changed; start a new attempt")
            validate_contents(state, catalog, resolver)
        else:
            state = PlanDraft(**identity)
            write_model_json(self.path, state)
        self._state = state

    @property
    def state(self) -> PlanDraft:
        """Return a copy so callers cannot bypass validation or persistence."""
        return self._state.model_copy(deep=True)

    def apply(self, batch: PlanBatch) -> PlanDraft:
        before = self._state
        if batch.expected_revision != before.revision:
            raise ValueError(f"stale expected_revision={batch.expected_revision}; current revision={before.revision}")
        known = decision_ids(before)
        if unknown := (set(batch.withdraw) | set(batch.reconfirm)) - known:
            raise ValueError(f"unknown decision IDs: {sorted(unknown)!r}")
        if self.path.exists() and load_model_json(self.path, PlanDraft) != before:
            raise ValueError("draft changed on disk; reload before editing")
        candidate = before.model_copy(deep=True)
        pending = set(candidate.review_pending)
        if batch.launch_choice is not None:
            if batch.launch_choice.recipe_id is not None and batch.launch_choice.recipe_id not in self.catalog.launch_candidates:
                raise ValueError(f"unknown launch recipe_id: {batch.launch_choice.recipe_id!r}")
            if candidate.launch_choice is None or batch.launch_choice.recipe_id != candidate.launch_choice.recipe_id:
                pending.update(known)
            candidate.launch_choice = batch.launch_choice
        for field in DECISION_FIELDS:
            mapping = getattr(candidate, field)
            for key in batch.withdraw:
                mapping.pop(key, None)
            updates = getattr(batch, field)
            for key, value in updates.items():
                if field == "units":
                    if self.resolve_unit is None:
                        raise ValueError("Unit anchor resolution is unavailable")
                    value = self.resolve_unit(key, value, candidate.launch_choice)
                mapping[key] = value
            pending.difference_update(updates)
        pending.difference_update(batch.withdraw)
        pending.difference_update(batch.reconfirm)
        candidate.review_pending = sorted(pending)
        candidate.revision += 1
        candidate.history.append(batch.model_copy(deep=True))
        # model_copy/update does not validate nested mutations.
        candidate = PlanDraft.model_validate(candidate.model_dump(mode="json"))
        validate_contents(candidate, self.catalog, self.resolver)
        write_model_json(self.path, candidate)
        self._state = candidate
        return self.state

    def progress(self) -> dict:
        state = self._state
        decided = set()
        for field in ("units", "no_interventions", "unresolved"):
            for key, item in getattr(state, field).items():
                if key in state.review_pending:
                    continue
                scopes = item.behavior_scopes if field == "units" else [item]
                decided.update(claim for scope in scopes for claim in scope.keys())
        findings = {}
        expected = claim_keys(self.resolver, self.catalog.finding_index)
        for ref in sorted(self.catalog.finding_index):
            claims = {index for finding, index in expected if finding == ref}
            done = {index for finding, index in decided if finding == ref}
            findings[ref] = {"status": "processed" if done == claims else "partial" if done else "unprocessed",
                             "claim_count": len(claims), "decided_claim_indices": sorted(done),
                             "remaining_claim_indices": sorted(claims - done)}
        return {"revision": state.revision, "finding_count": len(findings),
                "processed_findings": sum(item["status"] == "processed" for item in findings.values()),
                "claim_count": len(expected), "decided_claims": len(decided),
                "unresolved_ids": sorted(state.unresolved), "review_pending": state.review_pending,
                "launch_choice": state.launch_choice.model_dump(mode="json") if state.launch_choice else None,
                "findings": findings}

    def validate_complete(self) -> PlanDraft:
        """Complete accounting may still contain explicit semantic blockers."""
        state = self.state
        validate_contents(state, self.catalog, self.resolver, complete=True)
        if state.review_pending:
            raise ValueError(f"decisions require review after launch change: {state.review_pending!r}")
        if state.launch_choice is None:
            raise ValueError("launch selection has not been assessed")
        return state
