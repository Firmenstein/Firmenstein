"""Deterministic validation and identity resolution for process events."""
from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError, validate_code_reference

import hashlib
import json

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView

from .analyzer_schema import (
    ProcessEventAssessment,
    ProcessEventCallsite,
    ProcessLifecycleAgentResult,
    ProcessTriggerCallsite,
    ProcessTriggerCallsiteDraft,
)
from .findings import ProcessEventAnalysis


def normalize_api_name(api_name: str) -> str:
    return api_name.removeprefix("__imp_")


def _rendered_api_aliases(api_name: str) -> tuple[str, ...]:
    """Names that Hex-Rays may render for the same termination call.

    The authoritative identity remains the CTree call.  Some IDBs preserve
    ``_exit`` as the callee while the persisted pseudocode prints ``exit``.
    Keep that renderer quirk local to code-reference matching instead of
    globally conflating the two APIs in coverage or event collection.
    """
    normalized = normalize_api_name(api_name)
    if normalized in {"exit", "_exit"}:
        return ("exit", "_exit")
    return (normalized,)


def stable_ctree_id(
    prefix: str,
    binary_name: str,
    function_ea: int,
    snapshot_hash: str,
    ctree_index: int,
) -> str:
    payload = json.dumps(
        [binary_name, function_ea, snapshot_hash, ctree_index],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}:{digest}"


def _validate_code_reference(view, *, binary_name, function_name, line_number, api_name=None):
    validate_code_reference(view, binary_name=binary_name, function_name=function_name, line_number=line_number)


def validate_agent_result(
    output: ProcessLifecycleAgentResult,
    view: AnalysisView,
    source: ProcessEventCallsite,
) -> None:
    """Validate Agent-authored locations before accepting semantics."""
    errors = []
    for field in ("evidence", "trigger_callsites"):
        for index, reference in enumerate(getattr(output, field)):
            try:
                _validate_code_reference(view, binary_name=reference.binary_name,
                    function_name=reference.function_name, line_number=reference.line_number)
            except OutputValidationError as error:
                errors.append(f"/{field}/{index}: {error}")
    if errors:
        raise OutputValidationError("Process source validation failed:\n" + "\n".join(errors))


def _resolve_trigger(
    view: AnalysisView,
    draft: ProcessTriggerCallsiteDraft,
) -> tuple[ProcessTriggerCallsite | None, str | None]:
    normalized = normalize_api_name(draft.api_name)
    aliases = _rendered_api_aliases(normalized)
    function_ea = view.get_function_ea(draft.binary_name, draft.function_name)
    if function_ea is None:
        return None, (
            f"trigger function not found: "
            f"{draft.binary_name}::{draft.function_name}"
        )
    try:
        candidates = []
        for alias in aliases:
            candidates.extend(view.collect_api_callsites(alias))
    except Exception as error:
        return None, (
            f"trigger API {normalized!r} could not be enumerated at "
            f"{draft.binary_name}::{draft.function_name}:L{draft.line_number}: "
            f"{error!r}"
        )
    matches = []
    for callsite in candidates:
        if callsite.binary_name != draft.binary_name:
            continue
        if callsite.caller_ea != function_ea:
            continue
        if callsite.line_number != draft.line_number:
            continue
        if (
            draft.column_number is not None
            and callsite.column_number != draft.column_number
        ):
            continue
        if normalize_api_name(callsite.callee_name) not in aliases:
            continue
        matches.append(callsite)
    matches = list(dict.fromkeys(matches))
    if len(matches) != 1:
        return None, (
            f"trigger API {normalized!r} at "
            f"{draft.binary_name}::{draft.function_name}:L{draft.line_number} "
            f"resolved to {len(matches)} CTree calls"
        )
    callsite = matches[0]
    if callsite.snapshot_hash is None or callsite.ctree_index is None:
        return None, (
            f"trigger API {normalized!r} at "
            f"{draft.binary_name}::{draft.function_name}:L{draft.line_number} "
            "lacks stable CTree identity"
        )
    return ProcessTriggerCallsite(
        callsite_id=stable_ctree_id(
            "process-trigger",
            draft.binary_name,
            callsite.caller_ea,
            callsite.snapshot_hash,
            callsite.ctree_index,
        ),
        binary_name=draft.binary_name,
        function_name=draft.function_name,
        function_ea=callsite.caller_ea,
        snapshot_hash=callsite.snapshot_hash,
        ctree_index=callsite.ctree_index,
        source_ea=callsite.source_ea,
        line_number=callsite.line_number,
        column_number=callsite.column_number,
        api_name=normalize_api_name(callsite.callee_name),
    ), None


def finalize_analysis(
    source: ProcessEventCallsite,
    output: ProcessLifecycleAgentResult,
    view: AnalysisView,
) -> ProcessEventAnalysis:
    """Stamp source identity and resolve trigger references when unique."""
    triggers = []
    missing = list(dict.fromkeys(output.missing_evidence))
    for draft in output.trigger_callsites:
        trigger, problem = _resolve_trigger(view, draft)
        if trigger is None:
            if problem is not None and problem not in missing:
                missing.append(problem)
            triggers.append(draft)
        else:
            triggers.append(trigger)
    trigger_inputs = []
    seen_inputs: set[str] = set()
    for item in output.trigger_inputs:
        identity = item.model_dump_json()
        if identity not in seen_inputs:
            seen_inputs.add(identity)
            trigger_inputs.append(item)
    # Preserve evidence indices: the same output's semantic claims cite them.
    evidence = list(output.evidence)
    assessment = ProcessEventAssessment(
        callsite_id=source.callsite_id,
        disposition=output.disposition,
        trigger_callsites=triggers,
        trigger_inputs=trigger_inputs,
        summary=output.summary,
        evidence=evidence,
        missing_evidence=list(output.missing_evidence) + [
            reason for reason in missing if reason not in output.missing_evidence
        ],
    )
    output.finding.validate_references(
        assessment.model_dump(mode="json"), allowed_roots={"evidence", "missing_evidence"},
    )
    return ProcessEventAnalysis(assessment, output.finding)



__all__ = [
    "finalize_analysis",
    "normalize_api_name",
    "stable_ctree_id",
    "validate_agent_result",
]
