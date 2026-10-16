"""Test stage: process-lifecycle full phase."""
from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_process_lifecycle(
    tester: "PipelineTester",
) -> tuple[bool, str]:
    result = await tester.ensure_process_lifecycle_result(phase="full")
    if result.execution.status != "complete":
        return False, "Analyzer execution incomplete: " + result.execution.model_dump_json()
    problems: list[str] = []
    expected = set(result.callsites)
    if set(result.assessments) != expected:
        problems.append("assessments do not exactly cover callsites")
    out_dir = (
        tester.global_config.target_diagnostic_reports_dir()
        / "process_lifecycle_reports"
    )
    for required in ("index.md", "process_lifecycle_analysis_result.json"):
        if not (out_dir / required).exists():
            problems.append(f"missing persisted artifact: {out_dir / required}")
    per_json = [
        path for path in out_dir.glob("*.json")
        if path.name not in {"process_lifecycle_analysis_result.json", "input_provenance.json"}
    ]
    per_md = [path for path in out_dir.glob("*.md")
              if path.name not in {"index.md", "input_provenance.md"}]
    if len(per_json) != len(result.assessments):
        problems.append("per-assessment JSON count does not match assessments")
    if len(per_md) != len(result.assessments):
        problems.append("per-assessment Markdown count does not match assessments")
    counts = Counter(item.disposition.value for item in result.assessments.values())
    summary = (
        f"{len(result.callsites)} callsites, {len(result.assessments)} assessments, "
        + ", ".join(f"{key}={counts[key]}" for key in sorted(counts))
    )
    if problems:
        summary += "; " + "; ".join(problems)
    return not problems, summary


__all__ = ["test_process_lifecycle"]
