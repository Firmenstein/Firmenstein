"""Stage: generate and verify artifacts from the production Unit plan."""

from __future__ import annotations

from pathlib import Path
from fmst_analyzer.framework import runtime_workspace
from typing import TYPE_CHECKING

from fmst_analyzer.synthesizer.intervention_generator import (
    InterventionGenerationResult,
    InterventionGenerator,
    UnitGenerationReport,
)
from fmst_analyzer.synthesizer.intervention_generator.reports import (
    render_index,
    render_unit,
)
from fmst_analyzer.synthesizer.intervention_generator.architecture import (
    detect_generator_arch,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer import load_persisted_intervention_plan

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_intervention_generate(
    tester: "PipelineTester",
) -> tuple[bool, str]:
    await tester.ensure_analysis_view()
    reports_root = tester.global_config.target_diagnostic_reports_dir()
    try:
        _catalog, plan = load_persisted_intervention_plan(
            reports_root, global_config=tester.global_config, require_current_implementation=False,
        )
    except Exception as error:
        return False, str(error)
    result = await InterventionGenerator(tester.global_config).run(
        view=tester.view,
        image_name=tester.image_name,
        arch=detect_generator_arch(tester.view.root.binary_path),
        diagnostic_reports_root=reports_root,
        trace_root=(
            tester.global_config.target_agent_debug_dir()
            / "intervention_generator"
        ),
        interventions_root=tester.global_config.workdir / "interventions",
        test_harnesses_root=tester.global_config.workdir / "test_harnesses",
        env_scripts_root=tester.global_config.workdir / "env_scripts",
        iib_api_abspath=runtime_workspace(tester.global_config) / "fmst-iib-api",
    )
    out_dir = reports_root / "intervention_generation_reports"
    persisted = InterventionGenerationResult.model_validate_json(
        (out_dir / "intervention_generation_result.json").read_text(
            encoding="utf-8"
        )
    )
    issues: list[str] = []
    if persisted != result:
        issues.append("persisted generation result differs from memory")
    if (out_dir / "index.md").read_text(encoding="utf-8") != render_index(
        persisted
    ):
        issues.append("index.md is not a pure rendering of generation JSON")
    planned_units = {
        unit_id: unit
        for unit_id, unit in plan.units.items()
    }
    unit_reports: dict[str, UnitGenerationReport] = {}
    for json_path in sorted((out_dir / "units").glob("*.json")):
        try:
            report = UnitGenerationReport.model_validate_json(
                json_path.read_text(encoding="utf-8")
            )
        except Exception as error:
            issues.append(f"invalid Unit report {json_path.name}: {error}")
            continue
        unit_reports[report.generation.unit_id] = report
        if planned_units.get(report.generation.unit_id) != report.unit:
            issues.append(
                f"Unit report differs from consumed plan: {report.generation.unit_id}"
            )
        md_path = json_path.with_suffix(".md")
        if not md_path.is_file():
            issues.append(f"missing Unit Markdown: {md_path.name}")
        elif md_path.read_text(encoding="utf-8") != render_unit(report):
            issues.append(f"Unit Markdown is not a pure rendering: {md_path.name}")
    if set(unit_reports) != {item.unit_id for item in persisted.units}:
        issues.append("per-Unit report set differs from generation result")
    if result.not_ready_count:
        issues.append(f"{result.not_ready_count} Unit(s) not ready")
    detail = (
        f"units={result.total_units}, ok={result.ok_count}, "
        f"not_ready={result.not_ready_count}, skipped={result.skipped_count}"
    )
    if issues:
        detail += "; " + "; ".join(issues)
    return not issues, detail

__all__ = ["test_intervention_generate"]
