"""Process findings from the same event analysis, with deterministic identity."""
from dataclasses import dataclass

from fmst_analyzer.analysis.base.analysis_finding import (
    AnalysisFinding, FindingAnchor, FindingBoundary, FindingClaim, ProcessFindingDomain,
)
from fmst_analyzer.analysis.base.finding_binding import (
    FindingSemantics, FindingTarget, bind_finding, pointer,
)
from .analyzer_schema import ProcessEventAssessment, ProcessEventCallsite


@dataclass(frozen=True)
class ProcessEventAnalysis:
    assessment: ProcessEventAssessment
    semantics: FindingSemantics


def unresolved_semantics(assessment: ProcessEventAssessment) -> FindingSemantics:
    return FindingSemantics(
        summary=assessment.summary,
        claims=[FindingClaim(
            kind="unknown", statement=reason, unknown_kind="semantics",
            evidence_refs=[pointer("missing_evidence", index)],
        ) for index, reason in enumerate(assessment.missing_evidence)],
        reachability_refs=[], coverage_refs=[],
    )


def build_findings(
    target: FindingTarget, callsites: dict[str, ProcessEventCallsite],
    uncompleted: set[str] | dict[str, str], analyses: dict[str, ProcessEventAnalysis],
) -> dict[str, AnalysisFinding]:
    findings = {}
    for key, callsite in sorted(callsites.items()):
        if key in uncompleted:
            continue
        anchor = FindingAnchor(kind="callsite", ref=pointer("callsites", key))
        domain = ProcessFindingDomain(
            kind="process", callsite_id=key, event_kind=callsite.event_kind.value,
        )
        if key in analyses:
            finding = bind_finding(
                target=target, source="process", source_id=key,
                semantics=analyses[key].semantics, record_ref=pointer("assessments", key),
                boundary_kind="callsite", anchors=[anchor], domain=domain,
            )
        else:
            finding = AnalysisFinding(
                finding_ref=target.ref("process", key),
                summary=f"{callsite.api_name} at {callsite.binary_name}::{callsite.function_name}; lifecycle semantics unassessed.",
                boundary=FindingBoundary(
                    kind="callsite", anchors=[anchor], reachability_refs=[], coverage_refs=[],
                ),
                claims=[FindingClaim(
                    kind="unknown", unknown_kind="semantics",
                    statement="Static call-graph reachability does not establish invocation guards, lifecycle effects or target startup impact.",
                    evidence_refs=[anchor.ref],
                )],
                domain=domain,
            )
        findings[finding.finding_ref] = finding
    return findings
