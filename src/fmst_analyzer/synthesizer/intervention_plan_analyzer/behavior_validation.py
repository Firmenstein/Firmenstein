"""Mechanical finding references and overlap hints, without semantic inference."""
from collections import defaultdict
from itertools import combinations


def overlap_pairs(catalog, refs):
    by_anchor = defaultdict(set)
    for ref in refs:
        for anchor in catalog.finding_index[ref].anchor_keys:
            by_anchor[anchor].add(ref)
    return {pair for group in by_anchor.values() for pair in combinations(sorted(group), 2)}


def claim_keys(resolver, refs):
    return {(ref, index) for ref in refs
            for index, _ in enumerate(resolver.finding_evidence(ref)["finding"]["claims"])}


def claim_counts(resolver, refs):
    return {ref: len(resolver.finding_evidence(ref)["finding"]["claims"]) for ref in sorted(refs)}


def validate_scope(scope, resolver, allowed_refs):
    if scope.finding_ref not in allowed_refs:
        raise ValueError(f"behavior scope references an unknown finding: {scope.finding_ref}")
    expected = claim_keys(resolver, [scope.finding_ref])
    if not scope.keys() <= expected:
        raise ValueError(f"behavior scope references nonexistent source claims: {sorted(scope.keys() - expected)!r}")


def validate_plan_behaviors(plan, catalog, resolver):
    from .draft import validate_contents
    if plan.claim_counts != claim_counts(resolver, catalog.finding_index):
        raise ValueError("Plan claim counts differ from the exact source Catalog")
    if plan.launch_choice.recipe_id is not None and plan.launch_choice.recipe_id not in catalog.launch_candidates:
        raise ValueError("Plan references an unknown launch recipe")
    validate_contents(plan, catalog, resolver, complete=True)
