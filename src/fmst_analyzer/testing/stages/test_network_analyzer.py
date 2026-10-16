"""Full NetworkAnalyzer stage."""
from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    NetworkDisposition,
    NetworkInteractionReport,
)
from fmst_analyzer.analysis.network_analyzer.reports import (
    interaction_report_stem,
)

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_network_analyzer(
    tester: "PipelineTester",
) -> tuple[bool, str]:
    result = await tester.ensure_network_analyzer_result(phase="full")
    if result.execution.status != "complete":
        return False, "Analyzer execution incomplete: " + result.execution.model_dump_json()
    issues: list[str] = []
    if result.pending_callsite_ids:
        issues.append("full phase retained pending_callsite_ids")
    accounted = set()
    for analysis in result.analyses:
        accounted.update(analysis.callsite_ids)
    if accounted != set(result.callsites):
        issues.append("analyses do not cover every callsite")

    out_dir = (
        tester.global_config.target_diagnostic_reports_dir()
        / "network_reports"
    )
    for name in ("index.md", "network_analysis_result.json"):
        if not (out_dir / name).exists():
            issues.append(f"missing persisted artifact: {out_dir / name}")
    for analysis in result.analyses:
        if analysis.disposition is not NetworkDisposition.NETWORK:
            continue
        stem = interaction_report_stem(analysis)
        for suffix in (".json", ".md"):
            if not (out_dir / f"{stem}{suffix}").exists():
                issues.append(f"missing per-interaction artifact: {stem}{suffix}")
        report_path = out_dir / f"{stem}.json"
        if report_path.exists():
            try:
                report = NetworkInteractionReport.model_validate_json(
                    report_path.read_text(encoding="utf-8")
                )
            except Exception as error:
                issues.append(f"invalid per-interaction JSON {stem}: {error}")
            else:
                if report.analysis != analysis:
                    issues.append(
                        f"per-interaction JSON does not match top-level result: {stem}"
                    )

    dispositions = Counter(item.disposition.value for item in result.analyses)
    print(
        "\n=== NetworkAnalyzer full ===\n"
        f"  callsites: {len(result.callsites)}\n"
        f"  interaction analyses: {len(result.analyses)}\n"
        f"  dispositions: {dict(sorted(dispositions.items()))}",
        flush=True,
    )
    summary = (
        f"{len(result.callsites)} callsites, "
        f"{len(result.analyses)} analyses, "
        f"{dispositions.get('network', 0)} network"
    )
    if issues:
        summary += f"; issues={issues}"
    return not issues, summary
