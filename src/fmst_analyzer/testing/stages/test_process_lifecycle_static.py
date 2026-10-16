"""Test stage: process-lifecycle-static (zero Agent calls)."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_process_lifecycle_static(
    tester: "PipelineTester",
) -> tuple[bool, str]:
    result = await tester.ensure_process_lifecycle_result(phase="static")
    problems: list[str] = []
    if result.assessments:
        problems.append("static phase contains Agent assessments")
    out_dir = (
        tester.global_config.target_diagnostic_reports_dir()
        / "process_lifecycle_reports"
    )
    for required in ("index.md", "process_lifecycle_analysis_result.json"):
        if not (out_dir / required).exists():
            problems.append(f"missing persisted artifact: {out_dir / required}")
    summary = (
        f"{len(result.callsites)} callsites, "
        "0 Agent assessments"
    )
    if problems:
        summary += "; " + "; ".join(problems)
    return not problems, summary


__all__ = ["test_process_lifecycle_static"]
