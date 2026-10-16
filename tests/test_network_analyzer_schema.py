"""NetworkAnalyzer v8 schema/accounting/report invariants."""
from pathlib import Path

import pytest
from dotenv import load_dotenv
from pydantic import ValidationError

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    IdentityResolution,
    NetworkAPIBinding,
    NetworkAnalysisResult,
    NetworkAPIEffect,
    NetworkCallsite,
    NetworkCodeLocation,
    NetworkDisposition,
    NetworkEvidence,
    NetworkIdentity,
    NetworkInteractionAnalysis,
    NetworkInteractionKind,
    NetworkInteractionReport,
)
from fmst_analyzer.analysis.network_analyzer.reports import (
    interaction_report_stem,
    render_index,
    render_interaction,
)



def _result(**fields):
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget, FindingSemantics
    from fmst_analyzer.analysis.network_analyzer.findings import NetworkInteractionResult, build_findings
    target = FindingTarget(path="usr/sbin/" + fields["root_binary"], sha256="a" * 64)
    outcomes = [NetworkInteractionResult(item, FindingSemantics(**dict(summary="Synthetic fixture; behavior unassessed.",
        claims=[dict(kind="unknown", statement="No semantic analysis in this fixture.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[])))
                for item in fields.get("analyses", [])]
    return NetworkAnalysisResult(execution={"tasks": {}},
        schema_version=fields.pop("schema_version", 11), finding_target=target,
        planning_findings=build_findings(target, outcomes), **fields,
    )

def _fact(identity: str = "cs1", api: str = "bind", line: int = 3):
    return NetworkCallsite(
        callsite_id=identity,
        location=NetworkCodeLocation(
            binary_name="httpd",
            binary_path="usr/sbin/httpd",
            binary_sha256="a" * 64,
            function_name="main",
            function_ea=0x1000,
            snapshot_hash="b" * 64,
            ctree_index=line,
            source_ea=0x1100 + line,
            line_number=line,
            column_number=2,
        ),
        api_name=api,
        api_family="endpoint",
        api_binding=NetworkAPIBinding(
            symbol=api, call_kind="direct", verified=True,
        ),
        expression_text=f"{api}(fd, addr, 16)",
        arguments=[],
        return_expression="v1",
    )


def _network_analysis(callsite_ids: list[str]):
    return NetworkInteractionAnalysis(
        context_anchor=dict(binary_name="httpd", function_name="main", line_number=1, column_number=0),
        applicability="Synthetic source context for this structural test.",
        interaction_id="network:" + "c" * 24,
        anchor_callsite_id=callsite_ids[0],
        callsite_ids=callsite_ids,
        disposition=NetworkDisposition.NETWORK,
        interaction_kind=NetworkInteractionKind.LISTENER,
        identity=NetworkIdentity(
            resolution=IdentityResolution.EXACT,
            family="AF_INET",
            local_address="0.0.0.0",
            local_port=80,
        ),

        summary="The service binds port 80 and exits if bind fails.",
    )


def test_static_phase_is_zero_agent_and_accounts_pending():
    fact = _fact()
    result = _result(
        phase="static",
        root_binary="httpd",
        callsites={fact.callsite_id: fact},
        pending_callsite_ids=[fact.callsite_id],
    )
    assert result.analyses == []
    assert result.covered_api_calls == []
    index = render_index(result)
    assert "`httpd::main:L3`" in index
    assert "`bind(fd, addr, 16)`" in index
    assert "`cs1`" in index


def test_old_network_schema_is_rejected():
    with pytest.raises(ValidationError, match="schema_version"):
        _result(
            schema_version=2,
            phase="full",
            root_binary="httpd",
        )


def test_full_phase_requires_exact_partition():
    first = _fact("cs1", "bind", 3)
    second = _fact("cs2", "listen", 4)
    with pytest.raises(ValidationError, match="full analyses"):
        _result(
            phase="full",
            root_binary="httpd",
            callsites={"cs1": first, "cs2": second},
            analyses=[_network_analysis(["cs1"])],
        )


def test_full_round_trip_and_computed_coverage():
    first = _fact("cs1", "bind", 3)
    second = _fact("cs2", "listen", 4)
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={"cs1": first, "cs2": second},
        analyses=[_network_analysis(["cs1", "cs2"])],
    )
    loaded = NetworkAnalysisResult.model_validate_json(result.model_dump_json())
    assert loaded == result
    assert [
        (item.function_name, item.line_number, item.api_name)
        for item in loaded.covered_api_calls
    ] == [("main", 3, "bind"), ("main", 4, "listen")]


def test_network_with_null_interaction_kind_round_trips_without_inventing_kind():
    fact = _fact(api="gethostbyname")
    fields = _network_analysis([fact.callsite_id]).model_dump()
    fields["interaction_kind"] = None
    analysis = NetworkInteractionAnalysis.model_validate(fields)
    result = _result(
        phase="full", root_binary="httpd",
        callsites={fact.callsite_id: fact}, analyses=[analysis],
    )
    loaded = NetworkAnalysisResult.model_validate_json(result.model_dump_json())
    assert loaded.analyses[0].interaction_kind is None
    assert loaded.planning_findings == result.planning_findings
    assert len(loaded.covered_api_calls) == 1
    assert loaded.covered_api_calls[0].api_name == "gethostbyname"
    assert loaded.covered_api_calls[0].reason == "network"
    assert "interaction_kind" in render_index(loaded)


def test_covered_api_calls_keep_same_line_ctree_objects_distinct():
    first = _fact("cs1", "bind", 3)
    second = _fact("cs2", "bind", 3)
    second = second.model_copy(update={
        "location": second.location.model_copy(update={
            "ctree_index": 99,
            "source_ea": 0x1199,
            "column_number": 20,
        })
    })
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={"cs1": first, "cs2": second},
        analyses=[_network_analysis(["cs1", "cs2"])],
    )
    assert {
        (item.ctree_index, item.column_number, item.source_ea)
        for item in result.covered_api_calls
    } == {(3, 2, 0x1103), (99, 20, 0x1199)}


def test_coverage_round_trip_preserves_unknown_and_known_display_columns():
    from fmst_analyzer.analysis.base.coverage_flow import CoverageFlow
    from fmst_analyzer.analysis.base.covered_api_call import CoveredAPICall

    fact = _fact()
    observations = [CoveredAPICall(
        binary_name="httpd", function_name="helper", api_name="recv",
        line_number=8, column_number=column, reason="Receive response bytes.",
    ) for column in (None, 12)]
    analysis = _network_analysis([fact.callsite_id])
    analysis.coverage_flows = [CoverageFlow(
        flow_id="receive_response", description="Receive after endpoint setup.",
        setup=[], use=observations, termination=[],
    )]
    result = _result(phase="full", root_binary="httpd",
                     callsites={fact.callsite_id: fact}, analyses=[analysis])
    loaded = NetworkAnalysisResult.model_validate_json(result.model_dump_json())
    assert loaded == result
    assert {item.column_number for item in loaded.covered_api_calls
            if item.function_name == "helper"} == {None, 12}
    assert len(loaded.covered_api_calls) == 3
    analysis.coverage_flows[0].use.reverse()
    assert result.covered_api_calls == loaded.covered_api_calls


def test_independent_anchor_reports_can_share_callsites():
    socket = _fact("socket", "socket", 2)
    bind = _fact("bind", "bind", 3)
    first = _network_analysis(["bind", "socket"])
    first.anchor_callsite_id = "bind"
    first.interaction_id = "network:" + "a" * 24
    second = NetworkInteractionAnalysis(
        context_anchor=None,
        applicability="Synthetic source context for this structural test.",
        interaction_id="network:" + "b" * 24,
        anchor_callsite_id="socket",
        callsite_ids=["socket"],
        disposition=NetworkDisposition.UNRESOLVED,
        summary="socket fallback anchor",
        missing_evidence=["endpoint relation unavailable"],
    )
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={"socket": socket, "bind": bind},
        analyses=[first, second],
    )
    assert sum(
        "socket" in analysis.callsite_ids
        for analysis in result.analyses
    ) == 2


def test_shared_network_callsite_has_one_covered_api_fact():
    socket = _fact("socket", "socket", 2)
    first = _network_analysis(["socket"])
    first.interaction_id = "network:" + "a" * 24
    second = _network_analysis(["socket"])
    second.interaction_id = "network:" + "b" * 24
    second.context_anchor = second.context_anchor.model_copy(update={"line_number": 2})
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={"socket": socket},
        analyses=[first, second],
    )
    assert len(result.covered_api_calls) == 1


def test_non_network_analysis_cannot_carry_network_contract():
    NetworkInteractionAnalysis(
        context_anchor=dict(binary_name="httpd", function_name="main", line_number=1, column_number=0),
        applicability="Synthetic source context for this structural test.",
        interaction_id="network:" + "d" * 24,
        anchor_callsite_id="cs1",
        callsite_ids=["cs1"],
        disposition="not_network",
        interaction_kind="other",

        summary="not network",
    )


def test_unresolved_requires_specific_missing_evidence():
    with pytest.raises(ValidationError, match="missing_evidence"):
        NetworkInteractionAnalysis(
            context_anchor=dict(binary_name="httpd", function_name="main", line_number=1, column_number=0),
            applicability="Synthetic source context for this structural test.",
            interaction_id="network:" + "e" * 24,
            anchor_callsite_id="cs1",
            callsite_ids=["cs1"],
            disposition="unresolved",
            summary="could not classify",
        )


def test_json_and_markdown_are_symmetric_for_network_interaction():
    fact = _fact()
    analysis = _network_analysis([fact.callsite_id])
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={fact.callsite_id: fact},
        analyses=[analysis],
    )
    stem = interaction_report_stem(analysis)
    index = render_index(result)
    report = NetworkInteractionReport(
        root_binary=result.root_binary,
        analysis=analysis,
        callsites={fact.callsite_id: fact},
    )
    loaded_report = NetworkInteractionReport.model_validate_json(
        report.model_dump_json()
    )
    page = render_interaction(loaded_report)
    assert f"{stem}.json" in index
    assert f"{stem}.md" in index
    assert "`httpd::main:L3`" in index
    assert "`bind(fd, addr, 16)`" in index
    assert "#### callsite_ids\n\n| location" in index
    assert "- callsite_ids:\n\n| location" not in index
    assert "| `httpd::main:L3` | `bind` | `bind(fd, addr, 16)` | `cs1` |" in index
    assert "bind(fd, addr, 16)" in page
    assert "return_expression" in page
    assert '"v1"' in page
    for label in (
        "disposition", "interaction_kind", "callsite_ids", "identity",
        "context_anchor", "applicability", "api_effects", "coverage_flows", "evidence",
        "missing_evidence",
    ):
        assert label in page


def test_non_network_report_preserves_effects_evidence_and_missing_facts():
    fact = _fact(api="ioctl")
    analysis = NetworkInteractionAnalysis(
        context_anchor=None,
        applicability="Synthetic source context for this structural test.",
        interaction_id="network:" + "f" * 24,
        anchor_callsite_id=fact.callsite_id,
        callsite_ids=[fact.callsite_id],
        disposition=NetworkDisposition.UNRESOLVED,
        api_effects=[NetworkAPIEffect(
            binary_name="httpd",
            function_name="main",
            line_number=3,
            api_name="ioctl",
            role="query",
            return_or_output_use="the caller checks the return value",
            side_effect="the output buffer may be updated",
            failure_effect="the caller takes a degraded path",
        )],
        summary="The descriptor owner could not be proven.",
        evidence=[NetworkEvidence(
            claim="ioctl operates on a caller-supplied descriptor",
            binary_name="httpd",
            function_name="main",
            line_number=3,
            api_name="ioctl",
            callsite_id=fact.callsite_id,
        )],
        missing_evidence=["descriptor creation site"],
    )
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={fact.callsite_id: fact},
        analyses=[analysis],
    )
    report = NetworkInteractionReport(
        root_binary=result.root_binary,
        analysis=analysis,
        callsites={fact.callsite_id: fact},
    )

    index = render_index(result)
    page = render_interaction(report)

    stem = interaction_report_stem(analysis)
    assert f"[md]({stem}.md) / [json]({stem}.json)" in index
    assert "interaction_kind: ` null `" in page
    assert "identity: ` null `" in page
    assert "context_anchor: ` null `" in page
    assert analysis.applicability in page
    assert "the caller checks the return value" in page
    assert "ioctl operates on a caller-supplied descriptor" in page
    assert "descriptor creation site" in page
    assert "ctree_index: ` 3 `" in page
    assert "column_number: ` 2 `" in page


def test_interaction_report_requires_exact_callsite_facts():
    fact = _fact()
    analysis = _network_analysis([fact.callsite_id])
    with pytest.raises(ValidationError, match="exactly match"):
        NetworkInteractionReport(
            root_binary="httpd",
            analysis=analysis,
            callsites={},
        )
