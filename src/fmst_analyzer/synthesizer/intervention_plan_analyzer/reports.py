"""Pure JSON-backed Plan and Unit reports; the result JSON publishes last."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath

from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json, write_text
from .catalog import PlanningEvidenceCatalog
from .schema import InterventionPlanResult, UnitPlanReport


def _json_block(value) -> list[str]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return ["```json", json.dumps(value, ensure_ascii=False, indent=2), "```", ""]


def _render_unit(unit) -> list[str]:
    lines = [f"- unit_id: `{unit.unit_id}`", f"- strategy: `{unit.strategy}`", f"- summary: {unit.summary}", ""]
    for field in ("behavior_scopes", "anchors", "contract"):
        lines.extend([f"### {field}", ""])
        value = getattr(unit, field)
        lines.extend(_json_block([item.model_dump(mode="json") for item in value] if isinstance(value, list) else value))
    return lines


def render_index(catalog: PlanningEvidenceCatalog, result: InterventionPlanResult) -> str:
    lines = ["# Intervention Plan", "", f"- schema_version: {result.schema_version}",
             f"- catalog_digest: `{result.catalog_digest}`", f"- draft_revision: {result.draft_revision}",
             f"- service_goal: {result.service_goal or '(unspecified)'}",
             f"- target_basename: `{catalog.target_identity.target_basename}`",
             f"- claim_counts: {sum(result.claim_counts.values())} claims / {len(result.claim_counts)} findings",
             f"- units: {len(result.units)}", f"- no_interventions: {len(result.no_interventions)}",
             f"- runner_tasks: {len(result.runner_tasks)}", f"- unresolved: {len(result.unresolved)}", "",
             "Claim accounting does not establish semantic correctness or runtime readiness.", "",
             "## producer", ""]
    lines.extend(_json_block(result.producer))
    lines.extend(["## launch_choice", ""])
    lines.extend(_json_block(result.launch_choice))
    if result.launch_choice.recipe_id is not None:
        lines.extend(["## selected_launch_recipe", ""])
        lines.extend(_json_block(catalog.launch_candidates[result.launch_choice.recipe_id]))
    lines.extend(["## units", ""])
    for key, unit in result.units.items():
        lines.extend([f"- [{key}](units/{key}.md) / [JSON](units/{key}.json): `{unit.strategy}` — {unit.summary}"])
    for field in ("no_interventions", "runner_tasks", "unresolved"):
        lines.extend(["", f"## {field}", ""])
        for key, item in getattr(result, field).items():
            lines.extend([f"### {key}", "", *_json_block(item)])
    lines.extend(["## claim_counts", "", *_json_block(result.claim_counts), "## source_artifacts", ""])
    for kind, item in catalog.source_artifacts.items():
        source = PurePosixPath("..") / item.relative_path
        lines.append(f"- {kind.value}: [source JSON]({source.as_posix()}) / [Analyzer index]({(source.parent / 'index.md').as_posix()})")
    lines.extend(["", *_json_block({key.value: item.model_dump(mode="json") for key, item in catalog.source_artifacts.items()})])
    return "\n".join(lines).rstrip() + "\n"


def render_unit_report(report: UnitPlanReport) -> str:
    lines = [f"# Intervention Unit {report.unit.unit_id}", "",
             f"- schema_version: {report.schema_version}", f"- catalog_digest: `{report.catalog_digest}`",
             f"- service_goal: {report.service_goal or '(unspecified)'}", "", "## unit", ""]
    lines.extend(_render_unit(report.unit))
    lines.extend(["## launch_choice", "", *_json_block(report.launch_choice), "## selected_launch_recipe", "", *_json_block(report.selected_launch_recipe)])
    for field in ("finding_index", "source_artifacts"):
        lines.extend([f"## {field}", ""])
        lines.extend(_json_block({str(key.value if hasattr(key, "value") else key): item.model_dump(mode="json") for key, item in getattr(report, field).items()}))
    return "\n".join(lines).rstrip() + "\n"


def unit_reports(catalog: PlanningEvidenceCatalog, result: InterventionPlanResult) -> list[UnitPlanReport]:
    return [UnitPlanReport(catalog_digest=result.catalog_digest, service_goal=result.service_goal,
                launch_choice=result.launch_choice, selected_launch_recipe=catalog.launch_candidates.get(result.launch_choice.recipe_id),
                finding_index={ref: catalog.finding_index[ref] for ref in unit.finding_refs},
                source_artifacts=catalog.source_artifacts, unit=unit)
            for unit in result.units.values()]


def persist_intervention_plan(reports_root: Path, catalog: PlanningEvidenceCatalog,
                              result: InterventionPlanResult) -> None:
    root = Path(reports_root) / "intervention_plan_reports"
    (root / "intervention_plan_result.json").unlink(missing_ok=True)
    units_root = root / "units"
    if units_root.is_dir():
        for path in units_root.iterdir():
            if path.is_file() and path.suffix in {".json", ".md"}:
                path.unlink()
    for report in unit_reports(catalog, result):
        path = root / "units" / f"{report.unit.unit_id}.json"
        write_model_json(path, report)
        write_text(path.with_suffix(".md"), render_unit_report(load_model_json(path, UnitPlanReport)))
    write_text(root / "index.md", render_index(catalog, result))
    write_model_json(root / "intervention_plan_result.json", result)


def render_intervention_plan_markdown(reports_root: Path, catalog: PlanningEvidenceCatalog,
                                     result: InterventionPlanResult) -> None:
    root = Path(reports_root) / "intervention_plan_reports"
    for expected in unit_reports(catalog, result):
        path = root / "units" / f"{expected.unit.unit_id}.json"
        report = load_model_json(path, UnitPlanReport)
        if report != expected:
            raise ValueError(f"Unit report differs from the published Plan: {path}")
        write_text(path.with_suffix(".md"), render_unit_report(report))
    write_text(root / "index.md", render_index(catalog, result))


def replay_saved_reports(plan_root: Path) -> None:
    root = Path(plan_root)
    result = load_model_json(root / "intervention_plan_result.json", InterventionPlanResult)
    catalog = load_model_json(root.parent / "intervention_planner_inputs/planner_input_catalog.json", PlanningEvidenceCatalog)
    render_intervention_plan_markdown(root.parent, catalog, result)
