"""Assemble channel findings from the existing Site Resolution analysis."""
import json

from fmst_analyzer.analysis.base.analysis_finding import (
    AnalysisFinding, FindingAnchor, FindingBoundary, IPCFindingDomain,
)
from fmst_analyzer.analysis.base.finding_binding import FindingTarget, pointer


def channel_finding_ref(target_process, channel_id: str) -> str:
    target = FindingTarget(
        path=target_process.executable_path, sha256=target_process.executable_sha256,
    )
    return target.ref("ipc", json.dumps([target_process.argv0, channel_id], separators=(",", ":"), ensure_ascii=False))


def build_findings(target_process, channels, dependencies, semantics_by_dependency):
    if set(semantics_by_dependency) != {item.dependency_id for item in dependencies}:
        raise ValueError("IPC semantic drafts must exactly cover dependency assessments")
    findings = {}
    for channel_index, channel in enumerate(channels):
        summaries, claims, reachability, coverage = [], [], [], []
        for index, dependency in enumerate(dependencies):
            if dependency.channel_id != channel.channel_id:
                continue
            semantics = semantics_by_dependency[dependency.dependency_id]
            semantics.validate_references(
                dependency.model_dump(mode="json"), allowed_roots={"evidence", "missing_evidence"},
            )
            prefix = pointer("dependency_assessments", index)
            summaries.append(semantics.summary)
            claims.extend(claim.model_copy(update={
                "evidence_refs": [prefix + ref for ref in claim.evidence_refs],
            }) for claim in semantics.claims)
            reachability.extend(prefix + ref for ref in semantics.reachability_refs)
            coverage.extend(prefix + ref for ref in semantics.coverage_refs)
        if not claims:
            raise ValueError(f"IPC channel {channel.channel_id} has no target-local semantic assessment")
        ref = channel_finding_ref(target_process, channel.channel_id)
        findings[ref] = AnalysisFinding(
            finding_ref=ref, summary="\n\n".join(dict.fromkeys(summaries)),
            boundary=FindingBoundary(
                kind="resource", anchors=[FindingAnchor(kind="ipc_channel", ref=pointer("channels", channel_index))],
                reachability_refs=list(dict.fromkeys(reachability)), coverage_refs=list(dict.fromkeys(coverage)),
            ),
            claims=claims,
            domain=IPCFindingDomain(
                kind="ipc", channel_id=channel.channel_id, mechanism=channel.mechanism.value,
                endpoint_ids=sorted(endpoint.endpoint_id for endpoint in channel.endpoints),
            ),
        )
    return findings
