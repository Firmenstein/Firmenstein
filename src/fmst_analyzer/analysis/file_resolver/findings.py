"""File findings retain exact-resource identity across static/full analysis."""
from dataclasses import dataclass

from fmst_analyzer.analysis.base.analysis_finding import (
    AnalysisFinding, FileFindingDomain, FindingAnchor, FindingBoundary, FindingClaim,
)
from fmst_analyzer.analysis.base.finding_binding import FindingSemantics, FindingTarget, bind_finding, pointer
from .analyzer_schema import FileResource, FileResourceReport


@dataclass(frozen=True)
class FileResourceAnalysis:
    report: FileResourceReport
    semantics: FindingSemantics


def build_findings(
    target: FindingTarget, resources: dict[str, FileResource],
    analyses: dict[str, FileResourceAnalysis],
    *, failed_resources: set[str] | None = None,
) -> dict[str, AnalysisFinding]:
    findings = {}
    for key, resource in sorted(resources.items()):
        if key in (failed_resources or set()):
            continue
        anchor = FindingAnchor(kind="path", ref=pointer("resources", key, "path_value"))
        domain = FileFindingDomain(
            kind="file", resource_id=key, path=resource.path_value,
            resource_class=resource.resource_class.value,
            callsite_ids=sorted({site.callsite_id for site in resource.callsites}),
        )
        if key in analyses:
            finding = bind_finding(
                target=target, source="file", source_id=key,
                semantics=analyses[key].semantics, record_ref=pointer("resource_reports", key),
                boundary_kind="resource", anchors=[anchor], domain=domain,
            )
        else:
            claims = [FindingClaim(
                kind="unknown", unknown_kind="semantics",
                statement="The recovered path and static classification do not establish caller-visible read/write behavior, state, failure handling or native fallback.",
                evidence_refs=[pointer("resources", key)],
            )]
            finding = AnalysisFinding(
                finding_ref=target.ref("file", key),
                summary=f"{resource.path_value}: resource semantics unassessed.",
                boundary=FindingBoundary(
                    kind="resource", anchors=[anchor], reachability_refs=[], coverage_refs=[],
                ),
                claims=claims, domain=domain,
            )
        findings[finding.finding_ref] = finding
    return findings
