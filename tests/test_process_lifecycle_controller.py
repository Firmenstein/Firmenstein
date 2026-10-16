"""Controller validation and trigger-callsite identity resolution."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.process_lifecycle import (
    ProcessCodeEvidence,
    ProcessEventCallsite,
    ProcessEventDisposition,
    ProcessEventKind,
    ProcessLifecycleAgentResult,
    ProcessTriggerCallsiteDraft,
    ProcessTriggerInput,
)
from fmst_analyzer.analysis.process_lifecycle.controller import (
    finalize_analysis,
    validate_agent_result,
)


@dataclass(frozen=True)
class FakeCallsite:
    binary_name: str = "httpd"
    caller_ea: int = 0x1000
    snapshot_hash: str | None = "snap-trigger"
    ctree_index: int | None = 11
    source_ea: int | None = 0x1080
    line_number: int = 2
    column_number: int = 8
    callee_name: str = "access"


class FakeView:
    def __init__(self, callsites=None):
        self.lib_dep_graph = SimpleNamespace(
            get_node_by_name=lambda name: object() if name == "httpd" else None
        )
        self.callsites = list(callsites or [FakeCallsite()])

    def get_function_ea(self, binary_name, function_name):
        if (binary_name, function_name) == ("httpd", "main"):
            return 0x1000
        return None

    def get_full_code(self, binary_name, function_name):
        if self.get_function_ea(binary_name, function_name) is None:
            raise FileNotFoundError
        return "int main() {\n  if (access(\"/etc/config\", 0) < 0) exit(1);\n}"

    def collect_api_callsites(self, api_name):
        return [
            callsite for callsite in self.callsites
            if callsite.callee_name == api_name
        ]


def _source():
    return ProcessEventCallsite(
        callsite_id="process-event:source",
        binary_name="httpd",
        function_name="main",
        function_ea=0x1000,
        snapshot_hash="snap-source",
        ctree_index=12,
        source_ea=0x1088,
        line_number=2,
        column_number=42,
        api_name="exit",
        event_kind=ProcessEventKind.TERMINATION,
    )


def _draft():
    return ProcessLifecycleAgentResult(
        finding={
            "summary": "Missing configuration admits the startup exit branch.",
            "claims": [{"kind": "guarantee", "statement": "access failure reaches exit.",
                        "evidence_refs": ["/evidence/0"], "unknown_kind": None}],
            "reachability_refs": ["/evidence/0"], "coverage_refs": [],
        },
        disposition=ProcessEventDisposition.STARTUP_BLOCKER,
        trigger_callsites=[ProcessTriggerCallsiteDraft(
            binary_name="httpd",
            function_name="main",
            line_number=2,
            column_number=8,
            api_name="access",
        )],
        summary="missing config admits startup exit",
        evidence=[ProcessCodeEvidence(
            claim="access failure reaches exit",
            binary_name="httpd",
            function_name="main",
            line_number=2,
            api_name="access",
        )],
    )


def test_unique_trigger_is_resolved_to_ctree_identity():
    output = _draft()
    view = FakeView()
    validate_agent_result(output, view, _source())
    assessment = finalize_analysis(_source(), output, view).assessment
    assert len(assessment.trigger_callsites) == 1
    trigger = assessment.trigger_callsites[0]
    assert trigger.ctree_index == 11
    assert trigger.column_number == 8
    assert trigger.callsite_id.startswith("process-trigger:")


def test_ambiguous_trigger_is_not_fabricated_and_becomes_missing_evidence():
    output = _draft()
    view = FakeView([FakeCallsite(), FakeCallsite(ctree_index=13)])
    assessment = finalize_analysis(_source(), output, view).assessment
    assert assessment.trigger_callsites == output.trigger_callsites
    assert assessment.disposition is output.disposition
    assert any("resolved to 2 CTree calls" in item for item in assessment.missing_evidence)


def test_unresolved_trigger_draft_cannot_be_bypassed_by_key_input():
    output = _draft().model_copy(deep=True)
    output.trigger_inputs = [ProcessTriggerInput(
        kind="global",
        value="GVar_modules",
        summary="selects an indirect callback",
    )]
    view = FakeView([FakeCallsite(ctree_index=13)])
    # Both callsites share the same source coordinates, so the trigger draft is
    # ambiguous even though a key input was also supplied.
    view.callsites.append(FakeCallsite(ctree_index=14))
    validate_agent_result(output, view, _source())
    assessment = finalize_analysis(_source(), output, view).assessment
    assert assessment.disposition is output.disposition


def test_invalid_agent_code_location_is_rejected():
    output = _draft().model_copy(deep=True)
    output.evidence[0].line_number = 99
    with pytest.raises(ValueError, match="outside"):
        validate_agent_result(output, FakeView(), _source())


def test_termination_event_cannot_cite_itself_as_trigger():
    source_call = FakeCallsite(
        snapshot_hash="snap-source",
        ctree_index=12,
        line_number=2,
        column_number=42,
        callee_name="exit",
    )
    output = _draft().model_copy(update={
        "trigger_callsites": [ProcessTriggerCallsiteDraft(
            binary_name="httpd",
            function_name="main",
            line_number=2,
            column_number=42,
            api_name="exit",
        )],
    })
    validate_agent_result(output, FakeView([source_call]), _source())


def test_renderer_exit_alias_resolves_to_authoritative_underscore_exit():
    source = _source().model_copy(update={
        "ctree_index": 99,
        "column_number": 50,
    })
    rendered_alias = FakeCallsite(
        snapshot_hash="snap-trigger",
        ctree_index=11,
        line_number=2,
        column_number=8,
        callee_name="_exit",
    )
    output = _draft().model_copy(update={
        "trigger_callsites": [ProcessTriggerCallsiteDraft(
            binary_name="httpd",
            function_name="main",
            line_number=2,
            column_number=8,
            api_name="exit",
        )],
    })
    view = FakeView([rendered_alias])
    validate_agent_result(output, view, source)
    assessment = finalize_analysis(source, output, view).assessment
    assert assessment.trigger_callsites[0].api_name == "_exit"


def test_startup_blocker_requires_a_trigger_or_key_input():
    output = _draft().model_copy(update={"trigger_callsites": []})
    validate_agent_result(output, FakeView(), _source())
