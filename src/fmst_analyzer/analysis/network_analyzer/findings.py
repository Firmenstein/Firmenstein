"""Bind Network's same-analysis semantic output after interaction ordering."""
from dataclasses import dataclass

from fmst_analyzer.analysis.base.analysis_finding import FindingAnchor, NetworkFindingDomain
from fmst_analyzer.analysis.base.finding_binding import FindingSemantics, FindingTarget, bind_finding, pointer
from .analyzer_schema import NetworkInteractionAnalysis


@dataclass(frozen=True)
class NetworkInteractionResult:
    analysis: NetworkInteractionAnalysis
    semantics: FindingSemantics


def build_findings(target: FindingTarget, results: list[NetworkInteractionResult]):
    findings = {}
    for index, result in enumerate(results):
        analysis = result.analysis
        finding = bind_finding(
            target=target, source="network", source_id=analysis.interaction_id,
            semantics=result.semantics, record_ref=pointer("analyses", index),
            boundary_kind="resource",
            anchors=[FindingAnchor(kind="callsite", ref=pointer("callsites", key))
                     for key in sorted(analysis.callsite_ids)] + (
                         [FindingAnchor(kind="function", ref=pointer("analyses", index, "context_anchor"))]
                         if analysis.context_anchor else []),
            domain=NetworkFindingDomain(
                kind="network", interaction_id=analysis.interaction_id,
                interaction_kind=analysis.interaction_kind.value if analysis.interaction_kind else None,
                callsite_ids=sorted(analysis.callsite_ids),
            ),
        )
        findings[finding.finding_ref] = finding
    return findings
