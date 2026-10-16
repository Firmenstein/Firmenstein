"""Full-phase FileResolver pipeline stage.

Validates exact-resource construction, complete per-resource callsite
accounting, execution status, and persisted JSON/Markdown.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Tuple

from loguru import logger
from fmst_analyzer.analysis.file_resolver.analyzer_schema import FILE_RESOLVER_SCHEMA_VERSION

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_file_resolver(
    tester: "PipelineTester",
) -> Tuple[bool, str]:
    result = await tester.ensure_file_resolver_result(phase="full")
    if result.execution.status != "complete":
        return False, "Analyzer execution incomplete: " + result.execution.model_dump_json()
    issues: List[str] = []

    if result.schema_version != FILE_RESOLVER_SCHEMA_VERSION:
        issues.append(
            f"unexpected FileResolver schema_version={result.schema_version}"
        )

    missing_accounting = [
        resource_id
        for resource_id in result.resources
        if resource_id not in result.resource_reports
    ]
    if missing_accounting:
        issues.append(
            "resources have no validated report: "
            f"{missing_accounting}"
        )


    for resource_id, resource in result.resources.items():
        for callsite in resource.callsites:
            if callsite.resource_group_id != resource_id:
                issues.append(
                    f"{callsite.profile_key}: resource back-link "
                    f"{callsite.resource_group_id!r} != {resource_id!r}"
                )

    for resource_id, report in result.resource_reports.items():
        resource = result.resources.get(resource_id)
        if resource is None:
            issues.append(
                f"{resource_id}: resource_report without matching resource"
            )
            continue
        if report.primary_path != resource.path_value:
            issues.append(
                f"{resource_id}: primary_path {report.primary_path!r} != "
                f"resource path {resource.path_value!r}"
            )

        expected_ids = sorted(cs.callsite_id for cs in resource.callsites)
        actual_ids = sorted(cr.callsite_id for cr in report.callsite_reports)
        if actual_ids != expected_ids:
            issues.append(
                f"{resource_id}: callsite accounting mismatch: "
                f"expected={expected_ids}, actual={actual_ids}"
            )

        for callsite_report in report.callsite_reports:
            if not isinstance(callsite_report.resource_usage_sites, list):
                issues.append(
                    f"{resource_id}/{callsite_report.callsite_id}: "
                    "resource_usage_sites is not a list"
                )
            if not isinstance(callsite_report.total_usage_sites, int):
                issues.append(
                    f"{resource_id}/{callsite_report.callsite_id}: "
                    "total_usage_sites is not an int"
                )

        for flow in report.coverage_flows:
            if not re.match(r"^[a-z][a-z0-9_]*$", flow.flow_id):
                issues.append(
                    f"{resource_id}: bad flow_id {flow.flow_id!r}"
                )

    workdir = tester.global_config.workdir
    if workdir:
        out_dir = (
            tester.global_config.target_diagnostic_reports_dir()
            / "file_reports"
        )
        for required in ("index.md", "file_resolver_result.json"):
            if not (out_dir / required).exists():
                issues.append(f"artifact missing: {out_dir / required}")
        for resource_id in result.resource_reports:
            safe = resource_id.replace("::", "__").replace("#", "_")
            md_path = out_dir / f"{safe}.md"
            result_path = out_dir / f"{safe}_result.json"
            if not md_path.exists():
                issues.append(f"per-resource markdown missing: {md_path}")
            if not result_path.exists():
                issues.append(f"per-resource JSON missing: {result_path}")
    else:
        logger.warning("[TEST] workdir is None; skipping disk verification")

    print(
        f"\n=== FileResolver full phase: {len(result.callsites)} candidates / "
        f"{len(result.resources)} exact resources / "
        f"{len(result.resource_reports)} reports / "
        f"execution={result.execution.status} ===",
        flush=True,
    )
    if issues:
        print(f"\n  Issues ({len(issues)}):", flush=True)
        for issue in issues:
            print(f"    - {issue}", flush=True)

    summary = (
        f"{len(result.resources)} resources; "
        f"{len(result.resource_reports)} reports; "
        f"execution={result.execution.status}"
    )
    if issues:
        summary += f"; {len(issues)} issues"
    return not issues, summary
