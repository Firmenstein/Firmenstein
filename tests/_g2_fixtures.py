"""Explicit unknown semantic data for tests of topology and orchestration."""
from fmst_analyzer.analysis.base.finding_binding import FindingSemantics
from fmst_analyzer.analysis.ipc_analyzer.findings import channel_finding_ref


def unknown_semantics():
    return FindingSemantics(
        summary="Synthetic fixture; semantic behavior is unassessed.",
        claims=[dict(kind="unknown", statement="This fixture tests structure, not semantic behavior.",
                     unknown_kind="semantics", evidence_refs=[])],
        reachability_refs=[], coverage_refs=[],
    )


def ipc_topology_findings(target, channels):
    findings = {}
    for index, channel in enumerate(channels):
        ref = channel_finding_ref(target, channel.channel_id)
        semantics = unknown_semantics()
        findings[ref] = dict(
            finding_ref=ref, summary=semantics.summary, claims=semantics.claims,
            boundary=dict(kind="resource", anchors=[dict(kind="ipc_channel", ref=f"/channels/{index}")],
                          reachability_refs=[], coverage_refs=[]),
            domain=dict(kind="ipc", channel_id=channel.channel_id, mechanism=channel.mechanism.value,
                        endpoint_ids=sorted(item.endpoint_id for item in channel.endpoints)),
        )
    return findings
