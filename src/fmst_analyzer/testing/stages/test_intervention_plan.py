"""Stage: production InterventionPlanAnalyzer and report replay."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fmst_analyzer.synthesizer.intervention_plan_analyzer import (
    UnitPlanReport,
    InterventionPlanAnalyzer,
    InterventionPlanResult,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.reports import (
    render_unit_report,
    render_index,
)

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_intervention_plan(tester: "PipelineTester") -> tuple[bool, str]:
    await tester.ensure_analysis_view()
    catalog, plan = await InterventionPlanAnalyzer(
        tester.global_config
    ).run(tester.view)
    out_dir = (
        tester.global_config.target_diagnostic_reports_dir()
        / "intervention_plan_reports"
    )
    persisted = InterventionPlanResult.model_validate_json(
        (out_dir / "intervention_plan_result.json").read_text(encoding="utf-8")
    )
    issues: list[str] = []
    if persisted != plan:
        issues.append("persisted plan differs from in-memory plan")
    if (out_dir / "index.md").read_text(encoding="utf-8") != render_index(
        catalog, persisted
    ):
        issues.append("index.md is not a pure rendering of plan JSON")
    unit_reports: dict[str, UnitPlanReport] = {}
    for json_path in sorted((out_dir / "units").glob("*.json")):
        try:
            report = UnitPlanReport.model_validate_json(
                json_path.read_text(encoding="utf-8")
            )
        except Exception as error:
            issues.append(f"invalid Unit report {json_path.name}: {error}")
            continue
        unit_reports[report.unit.unit_id] = report
        md_path = json_path.with_suffix(".md")
        if not md_path.is_file():
            issues.append(f"missing Unit Markdown: {md_path.name}")
        elif md_path.read_text(encoding="utf-8") != render_unit_report(report):
            issues.append(f"Unit Markdown is not a pure rendering: {md_path.name}")
    if set(unit_reports) != set(plan.units):
        issues.append("per-Unit report set differs from intervention plan")
    detail = (
        f"launch={plan.launch_choice.recipe_id or '(none)'}, "
        f"units={len(plan.units)}, runner_tasks={len(plan.runner_tasks)}, "
        f"no_interventions={len(plan.no_interventions)}, unresolved={len(plan.unresolved)}, "
        f"claims={sum(plan.claim_counts.values())}, revision={plan.draft_revision}"
    )
    if issues:
        detail += "; " + "; ".join(issues)
    return not issues, detail


__all__ = ["test_intervention_plan"]
