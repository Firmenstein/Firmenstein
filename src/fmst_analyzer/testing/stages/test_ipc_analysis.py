"""Pipeline stages for IPCAnalyzer static and full phases."""

from __future__ import annotations

from typing import TYPE_CHECKING, Tuple

from fmst_analyzer.analysis.ipc_analyzer.schema import (
    AnalysisPhase,
    CallsiteDisposition,
    IPCAnalysisResult,
)

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


def _validate_common(
    tester: "PipelineTester",
    result: IPCAnalysisResult,
) -> list[str]:
    issues: list[str] = []
    callsite_ids = {fact.callsite_id for fact in result.callsites}
    accounting_ids = {item.callsite_id for item in result.callsite_accounting}
    if accounting_ids != callsite_ids:
        issues.append(
            f"callsite accounting mismatch: callsites={len(callsite_ids)}, "
            f"accounting={len(accounting_ids)}"
        )

    report_dir = (
        tester.global_config.target_diagnostic_reports_dir() / "ipc_reports"
    )
    json_path = report_dir / "ipc_analysis_result.json"
    if not json_path.is_file():
        issues.append(f"missing JSON SoT: {json_path}")
    else:
        replay = IPCAnalysisResult.model_validate_json(
            json_path.read_text(encoding="utf-8")
        )
        if replay != result:
            issues.append("persisted JSON does not round-trip to the in-memory result")
    if not (report_dir / "index.md").is_file():
        issues.append("missing index.md")
    callsite_pages = [
        path for path in (report_dir / "callsites").glob("*.md")
        if path.name != "index.md"
    ]
    channel_pages = [
        path for path in (report_dir / "channels").glob("*.md")
        if path.name != "index.md"
    ]
    if len(callsite_pages) != len(result.callsites):
        issues.append("per-callsite Markdown count does not match JSON")
    if len(channel_pages) != len(result.channels):
        issues.append("per-channel Markdown count does not match JSON")
    if result.phase is AnalysisPhase.FULL:
        callsite_jsons = list((report_dir / "callsites").glob("*_result.json"))
        channel_jsons = list((report_dir / "channels").glob("*_result.json"))
        if len(callsite_jsons) != len(result.callsites):
            issues.append("per-callsite JSON count does not match aggregate JSON")
        if len(channel_jsons) != len(result.channels):
            issues.append("per-channel JSON count does not match aggregate JSON")
    return issues


async def test_ipc_analysis_static(
    tester: "PipelineTester",
) -> Tuple[bool, str]:
    result = await tester.ensure_ipc_result(phase="static")
    issues = _validate_common(tester, result)
    if result.phase is not AnalysisPhase.STATIC:
        issues.append(f"phase is {result.phase.value}, expected static")
    if result.channels or result.dependency_assessments:
        issues.append("static phase produced interpreted semantic objects")
    if any(
        item.disposition is not CallsiteDisposition.UNRESOLVED
        for item in result.callsite_accounting
    ):
        issues.append("static phase semantically classified a callsite")
    detail = (
        f"{len(result.callsites)} immutable callsites, "
        f"{len(result.unresolved_items)} unresolved items"
    )
    if issues:
        detail += "; " + "; ".join(issues)
    return not issues, detail


async def test_ipc_analysis(tester: "PipelineTester") -> Tuple[bool, str]:
    result = await tester.ensure_ipc_result(phase="full")
    if result.execution.status != "complete":
        return False, "Analyzer execution incomplete: " + result.execution.model_dump_json()
    issues = _validate_common(tester, result)
    if result.phase is not AnalysisPhase.FULL:
        issues.append(f"phase is {result.phase.value}, expected full")
    channel_endpoint_ids = {
        endpoint.endpoint_id
        for channel in result.channels
        for endpoint in channel.endpoints
    }
    accounted_endpoint_ids = {
        endpoint_id
        for item in result.callsite_accounting
        for endpoint_id in item.endpoint_ids
    }
    if channel_endpoint_ids != accounted_endpoint_ids:
        issues.append("endpoint set and callsite accounting differ")
    dependency_endpoint_ids = [
        endpoint_id
        for assessment in result.dependency_assessments
        for endpoint_id in assessment.consumer_endpoint_ids
    ]
    if (
        set(dependency_endpoint_ids) != channel_endpoint_ids
        or len(dependency_endpoint_ids) != len(set(dependency_endpoint_ids))
    ):
        issues.append(
            "site dependency assessments do not cover every endpoint exactly once"
        )
    detail = (
        f"target={result.target_process.executable_path}, "
        f"{len(result.callsites)} callsites, {len(result.channels)} channels, "
        f"{len(result.dependency_assessments)} dependency assessments, "
        f"{len(result.unresolved_items)} unresolved items"
    )
    if issues:
        detail += "; " + "; ".join(issues)
    return not issues, detail


__all__ = ["test_ipc_analysis", "test_ipc_analysis_static"]
