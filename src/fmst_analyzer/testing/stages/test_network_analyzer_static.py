"""Pure-static NetworkAnalyzer stage: collection, disk dedup, persistence."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_network_analyzer_static(
    tester: "PipelineTester",
) -> tuple[bool, str]:
    result = await tester.ensure_network_analyzer_result(phase="static")
    issues: list[str] = []
    if result.analyses:
        issues.append(
            f"static phase produced {len(result.analyses)} Agent analyses"
        )
    expected_pending = set(result.callsites)
    if set(result.pending_callsite_ids) != expected_pending:
        issues.append("pending_callsite_ids is not the complete callsite set")
    out_dir = (
        tester.global_config.target_diagnostic_reports_dir()
        / "network_reports"
    )
    for name in ("index.md", "network_analysis_result.json"):
        if not (out_dir / name).exists():
            issues.append(f"missing persisted artifact: {out_dir / name}")
    pending_callsites = [
        result.callsites[callsite_id]
        for callsite_id in result.pending_callsite_ids
    ]
    pending_binary_count = len({
        callsite.location.binary_name for callsite in pending_callsites
    })
    print(
        "\n=== NetworkAnalyzer static ===\n"
        f"  callsites: {len(result.callsites)}\n"
        f"  pending callsites: {len(result.pending_callsite_ids)}\n"
        f"  pending resource seeds: {len(result.pending_callsite_ids)}\n"
        f"  binaries represented: {pending_binary_count}",
        flush=True,
    )
    summary = (
        f"{len(result.callsites)} callsites, "
        f"{len(result.pending_callsite_ids)} pending resource seeds across "
        f"{pending_binary_count} binaries"
    )
    if issues:
        summary += f"; issues={issues}"
    return not issues, summary
