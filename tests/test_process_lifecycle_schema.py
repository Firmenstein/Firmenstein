"""ProcessLifecycle persisted-schema and report invariants."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from dotenv import load_dotenv
from pydantic import ValidationError

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.process_lifecycle import (
    ProcessCodeEvidence,
    ProcessEventAssessment,
    ProcessEventAssessmentReport,
    ProcessEventCallsite,
    ProcessEventDisposition,
    ProcessEventKind,
    ProcessLifecycleAnalysisResult,
    ProcessLifecycleAnalyzer,
    ProcessTriggerInput,
)
from fmst_analyzer.analysis.process_lifecycle.reports import (
    assessment_report_stem,
    render_assessment_report,
    render_index,
)


def _callsite(callsite_id: str = "process-event:abc") -> ProcessEventCallsite:
    return ProcessEventCallsite(
        callsite_id=callsite_id,
        binary_name="httpd",
        function_name="main",
        function_ea=0x1000,
        snapshot_hash="snap",
        ctree_index=7,
        source_ea=0x1040,
        line_number=10,
        column_number=6,
        api_name="exit",
        event_kind=ProcessEventKind.TERMINATION,
    )


def _assessment(
    disposition: ProcessEventDisposition = ProcessEventDisposition.STARTUP_BLOCKER,
) -> ProcessEventAssessment:
    kwargs = {}
    if disposition is ProcessEventDisposition.UNRESOLVED:
        kwargs["missing_evidence"] = ["dynamic caller"]
    else:
        kwargs["evidence"] = [ProcessCodeEvidence(
            claim="failure branch reaches exit",
            binary_name="httpd",
            function_name="main",
            line_number=10,
            api_name="exit",
        )]
    return ProcessEventAssessment(
        callsite_id="process-event:abc",
        disposition=disposition,
        trigger_inputs=[ProcessTriggerInput(
            kind="path",
            value="/etc/config",
            summary="missing path admits the failure branch",
        )] if disposition is ProcessEventDisposition.STARTUP_BLOCKER else [],
        summary="classified process event",
        **kwargs,
    )


def _result(**kwargs):
    from fmst_analyzer.analysis.base.finding_binding import FindingTarget, FindingSemantics
    from fmst_analyzer.analysis.process_lifecycle.findings import ProcessEventAnalysis, build_findings, unresolved_semantics
    target = FindingTarget(path="usr/sbin/httpd", sha256="a" * 64)
    analyses = {}
    for key, assessment in kwargs.get("assessments", {}).items():
        if assessment.disposition is ProcessEventDisposition.UNRESOLVED:
            semantics = unresolved_semantics(assessment)
        else:
            semantics = FindingSemantics.model_validate({
                "summary": "Configuration failure reaches exit.",
                "claims": [{"kind": "guarantee", "statement": "The failure branch terminates the process.",
                            "evidence_refs": ["/evidence/0"], "unknown_kind": None}],
                "reachability_refs": ["/evidence/0"], "coverage_refs": [],
            })
        analyses[key] = ProcessEventAnalysis(assessment, semantics)
    return ProcessLifecycleAnalysisResult(execution={"tasks": {}},
        schema_version=5, finding_target=target,
        planning_findings=build_findings(target, kwargs.get("callsites", {}), kwargs.get("skipped", {}), analyses),
        **kwargs,
    )


def test_callsite_keeps_line_column_ctree_and_source_ea_together():
    callsite = _callsite()
    assert (
        callsite.line_number,
        callsite.column_number,
        callsite.ctree_index,
        callsite.source_ea,
    ) == (10, 6, 7, 0x1040)


def test_static_result_has_no_assessments_and_no_covered_api_surface():
    callsite = _callsite()
    result = _result(
        phase="static",
        root_binary="httpd",
        callsites={callsite.callsite_id: callsite},
    )
    assert result.assessments == {}
    assert not hasattr(result, "covered_api_calls")


def test_full_result_requires_exact_accounting():
    callsite = _callsite()
    with pytest.raises(ValidationError, match="exactly cover"):
        _result(
            phase="full",
            root_binary="httpd",
            callsites={callsite.callsite_id: callsite},
        )
    assessment = _assessment()
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={callsite.callsite_id: callsite},
        assessments={assessment.callsite_id: assessment},
    )
    assert set(result.assessments) == set(result.callsites)


def test_upstream_skip_field_cannot_satisfy_process_accounting():
    callsite = _callsite()
    with pytest.raises(ValidationError, match="skipped"):
        _result(phase="full", root_binary="httpd", callsites={callsite.callsite_id: callsite},
                skipped={callsite.callsite_id: "network_callsite_covered"})


def test_unresolved_requires_specific_missing_evidence():
    with pytest.raises(ValidationError, match="requires missing_evidence"):
        ProcessEventAssessment(
            callsite_id="process-event:abc",
            disposition=ProcessEventDisposition.UNRESOLVED,
            summary="unknown",
        )


def test_json_round_trip_and_markdown_are_pure_views():
    callsite = _callsite()
    assessment = _assessment()
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={callsite.callsite_id: callsite},
        assessments={assessment.callsite_id: assessment},
    )
    restored = ProcessLifecycleAnalysisResult.model_validate_json(
        result.model_dump_json()
    )
    assert restored == result
    index = render_index(restored)
    assert "startup_blocker" in index
    assert "L10:C6" in index
    per = ProcessEventAssessmentReport(
        root_binary="httpd",
        callsite=callsite,
        assessment=assessment,
    )
    markdown = render_assessment_report(per)
    for label in (
        "callsite_id", "disposition", "trigger_callsites", "trigger_inputs",
        "evidence", "missing_evidence", "line_number", "column_number",
    ):
        assert label in markdown
    assert assessment_report_stem(assessment).startswith(
        "startup_blocker__process-event_"
    )


def test_legacy_process_event_payload_is_not_accepted():
    with pytest.raises(ValidationError):
        ProcessLifecycleAnalysisResult.model_validate({
            "phase": "full",
            "root_binary": "httpd",
            "candidates": {},
            "issues": {},
        })


def test_persistence_writes_symmetric_pages_and_removes_stale_pages(tmp_path):
    reports_root = tmp_path / "diagnostic_reports" / "httpd"
    config = SimpleNamespace(
        workdir=tmp_path,
        agent_concurrency_limit=1,
        target_diagnostic_reports_dir=lambda: reports_root,
    )
    analyzer = ProcessLifecycleAnalyzer(config)
    callsite = _callsite()
    assessment = _assessment()
    result = _result(
        phase="full",
        root_binary="httpd",
        callsites={callsite.callsite_id: callsite},
        assessments={assessment.callsite_id: assessment},
    )
    out_dir = reports_root / "process_lifecycle_reports"
    out_dir.mkdir(parents=True)
    (out_dir / "stale.md").write_text("stale")
    (out_dir / "stale.json").write_text("{}")
    published = analyzer.publish_reports(result)
    loaded = ProcessLifecycleAnalysisResult.model_validate_json(
        (out_dir / "process_lifecycle_analysis_result.json").read_text()
    )
    assert published == loaded
    assert published is not result
    assert not (out_dir / "stale.md").exists()
    assert not (out_dir / "stale.json").exists()
    stem = assessment_report_stem(assessment)
    assert (out_dir / f"{stem}.md").exists()
    assert (out_dir / f"{stem}.json").exists()
    assert (out_dir / "index.md").exists()
    assert (out_dir / "process_lifecycle_analysis_result.json").exists()
