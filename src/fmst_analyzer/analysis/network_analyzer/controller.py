"""Deterministic validation and identity assignment for NetworkAnalyzer."""
from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError, validate_code_reference

import hashlib
import json
from collections.abc import Iterable

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView

from .analyzer_schema import (
    NetworkCallsite,
    NetworkResourceAgentResult,
    NetworkInteractionAnalysis,
    NetworkInteractionDraft,
)
from .findings import NetworkInteractionResult


def stable_interaction_id(
    root_binary: str,
    anchor_callsite_id: str,
    draft: NetworkInteractionDraft,
) -> str:
    payload = json.dumps(
        [
            root_binary,
            anchor_callsite_id,
            draft.context_anchor.identity_key() if draft.context_anchor else None,
        ],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return f"network:{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:24]}"


def _validate_code_reference(view, *, binary_name, function_name, line_number, api_name=None):
    validate_code_reference(view, binary_name=binary_name, function_name=function_name, line_number=line_number)
    # C text does not prove callee identity: casts, indirect calls, and wrappers
    # need not spell the API name. Callsite citations are bound to static facts
    # separately; supporting references only promise a resolvable source location.


def _iter_flow_calls(draft: NetworkInteractionDraft) -> Iterable:
    for flow in draft.coverage_flows:
        yield from flow.setup
        yield from flow.use
        yield from flow.termination


def validate_resource_result(
    output: NetworkResourceAgentResult,
    seed_callsite_id: str,
    available_facts: list[NetworkCallsite],
    view: AnalysisView,
) -> None:
    output = normalize_resource_result(output, available_facts, view=view)
    errors = []

    def check(label, validate, *args, **kwargs):
        try:
            validate(*args, **kwargs)
        except OutputValidationError as error:
            errors.append(f"{label}: {error}")
            return False
        return True

    available = {fact.callsite_id for fact in available_facts}
    actual = [
        callsite_id
        for draft in output.analyses
        for callsite_id in draft.callsite_ids
    ]
    extra = sorted(set(actual) - available)
    seed_count = sum(
        seed_callsite_id in draft.callsite_ids
        for draft in output.analyses
    )
    if seed_count < 1 or extra:
        errors.append(
            "resource callsite claim mismatch: "
            f"required seed_callsite_id={seed_callsite_id!r} must occur in at least one "
            f"analyses[*].callsite_ids; seed_count={seed_count}, extra={extra}; "
            f"legal callsite_ids={sorted(available)}. "
            "Use the supplied Callsite catalog and Seed callsite for exact source identities."
        )
    by_id = {fact.callsite_id: fact for fact in available_facts}
    for index, draft in enumerate(output.analyses):
        label = f"analyses[{index}]"
        claimed = set(draft.callsite_ids)
        if draft.context_anchor is not None:
            anchor = draft.context_anchor
            if check(label + ".context_anchor", _validate_code_reference,
                     view, binary_name=anchor.binary_name, function_name=anchor.function_name,
                     line_number=anchor.line_number):
                line = view.get_full_code(anchor.binary_name, anchor.function_name).splitlines()[anchor.line_number - 1]
                if anchor.column_number < 0 or anchor.column_number > len(line):
                    errors.append(f"{label}.context_anchor.column_number={anchor.column_number} is outside 0..{len(line)}")
        for evidence_index, evidence in enumerate(draft.evidence):
            evidence_label = f"{label}.evidence[{evidence_index}]"
            if (
                evidence.callsite_id is not None
                and evidence.callsite_id not in claimed
            ):
                errors.append(
                    evidence_label + ": "
                    "evidence callsite_id must belong to the interaction that "
                    f"claims it: {evidence.callsite_id}"
                )
            if evidence.callsite_id is not None:
                if evidence.callsite_id in by_id:
                    check(evidence_label, evidence.validate_callsite, by_id[evidence.callsite_id])
                else:
                    errors.append(f"{evidence_label}: unknown callsite_id {evidence.callsite_id}")
            check(
                evidence_label, _validate_code_reference,
                view,
                binary_name=evidence.binary_name,
                function_name=evidence.function_name,
                line_number=evidence.line_number,
            )
        for effect_index, effect in enumerate(draft.api_effects):
            check(
                f"{label}.api_effects[{effect_index}]", _validate_code_reference,
                view,
                binary_name=effect.binary_name,
                function_name=effect.function_name,
                line_number=effect.line_number,
            )
        for item_index, item in enumerate(_iter_flow_calls(draft)):
            check(
                f"{label}.coverage_flows call[{item_index}]", _validate_code_reference,
                view,
                binary_name=item.binary_name,
                function_name=item.function_name,
                line_number=item.line_number,
            )
    if errors:
        raise OutputValidationError("Network result validation failed:\n" + "\n".join(errors))


def normalize_resource_result(
    output: NetworkResourceAgentResult,
    available_facts: list[NetworkCallsite],
    *, view: AnalysisView | None = None,
) -> NetworkResourceAgentResult:
    """Canonicalize callsite identities without changing Agent semantics."""
    catalog_order = {
        fact.callsite_id: index
        for index, fact in enumerate(available_facts)
    }
    fallback_index = len(catalog_order)
    analyses = []
    for draft in output.analyses:
        callsite_ids = sorted(
            set(draft.callsite_ids),
            key=lambda callsite_id: (
                catalog_order.get(callsite_id, fallback_index),
                callsite_id,
            ),
        )
        evidence = list(draft.evidence)
        if view is not None:
            by_id = {fact.callsite_id: fact for fact in available_facts}
            evidence = []
            for item in draft.evidence:
                fact = by_id.get(item.callsite_id)
                if fact is not None and item.binary_name == fact.location.binary_name:
                    actual_ea = view.get_function_ea(item.binary_name, item.function_name)
                    expected_ea = view.get_function_ea(fact.location.binary_name, fact.location.function_name)
                    if actual_ea is not None and actual_ea == expected_ea:
                        item = item.model_copy(update={"function_name": fact.location.function_name})
                evidence.append(item)
        analyses.append(draft.model_copy(update={"callsite_ids": callsite_ids, "evidence": evidence}))
    return output.model_copy(update={"analyses": analyses})


def finalize_resource_result(
    root_binary: str,
    anchor_callsite_id: str,
    output: NetworkResourceAgentResult,
) -> list[NetworkInteractionResult]:
    from collections import Counter
    from uuid import uuid4

    drafts = list({draft.model_dump_json(): draft for draft in output.analyses}.values())
    ids = [stable_interaction_id(root_binary, anchor_callsite_id, draft) for draft in drafts]
    counts = Counter(ids)
    return [
        NetworkInteractionResult(NetworkInteractionAnalysis(
            **draft.model_dump(exclude={"finding"}),
            anchor_callsite_id=anchor_callsite_id,
            # A source anchor is not necessarily an observation identity. Assign
            # separate persisted IDs to collisions, without judging their content.
            interaction_id=identity if counts[identity] == 1 else f"{identity}:{uuid4().hex}",
        ), draft.finding)
        for draft, identity in zip(drafts, ids, strict=True)
    ]




__all__ = [
    "finalize_resource_result",
    "normalize_resource_result",
    "stable_interaction_id",
    "validate_resource_result",
]
