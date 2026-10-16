"""Pipeline stage for single-Agent InitLaunch discovery."""
from __future__ import annotations

from fmst_analyzer.analysis.init_launch.analyzer_schema import INIT_LAUNCH_SCHEMA_VERSION

from typing import TYPE_CHECKING, List, Tuple

from fmst_analyzer.analysis.init_launch.analyzer_schema import LaunchRecipe
from fmst_analyzer.analysis.init_launch.reports import (
    recipe_report_stem,
    render_index,
    render_recipe,
)

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_init_launch(
    tester: "PipelineTester",
    phase: str = "full",
) -> Tuple[bool, str]:
    result = await tester.ensure_init_launch_result(phase=phase)
    if result.execution.status != "complete":
        return False, "Analyzer execution incomplete: " + result.execution.model_dump_json()
    issues: List[str] = []

    if result.schema_version != INIT_LAUNCH_SCHEMA_VERSION:
        issues.append(f"unexpected schema_version={result.schema_version}")
    if result.phase != phase:
        issues.append(f"unexpected phase={result.phase}")
    if phase == "static" and result.launch_recipes:
        issues.append("static result contains Agent launch recipes")
    if not result.target_identity.selected_rootfs_path:
        issues.append("selected_rootfs_path is empty")
    if not result.launch_recipes and not result.analysis_gaps:
        issues.append("no launch recipes and no analysis gaps")

    for recipe_id, recipe in result.launch_recipes.items():
        if recipe_id != recipe.recipe_id:
            issues.append(
                f"recipe key {recipe_id!r} != recipe_id {recipe.recipe_id!r}"
            )
        if not recipe.command_template:
            issues.append(
                f"recipe {recipe_id!r} has empty command_template"
            )
        if not recipe.initialization_chain:
            issues.append(
                f"recipe {recipe_id!r} has empty initialization_chain"
            )
        elif recipe.initialization_chain[-1] != recipe.launch_site:
            issues.append(
                f"recipe {recipe_id!r} initialization_chain does not end "
                "at launch_site"
            )

    workdir = tester.global_config.workdir
    if workdir is not None:
        out_dir = (
            tester.global_config.target_diagnostic_reports_dir()
            / "init_launch_reports"
        )
        for name in ("init_launch_analysis_result.json", "index.md"):
            if not (out_dir / name).is_file():
                issues.append(f"missing artifact: {out_dir / name}")
        index_path = out_dir / "index.md"
        if index_path.is_file() and index_path.read_text() != render_index(result):
            issues.append("index.md is not a pure rendering of result JSON")

        expected_json = set()
        expected_md = set()
        for recipe in result.launch_recipes.values():
            stem = recipe_report_stem(recipe)
            json_path = out_dir / f"{stem}.json"
            md_path = out_dir / f"{stem}.md"
            expected_json.add(json_path.name)
            expected_md.add(md_path.name)
            if not json_path.is_file() or not md_path.is_file():
                issues.append(f"missing per-recipe artifacts for {recipe.recipe_id}")
                continue
            try:
                persisted = LaunchRecipe.model_validate_json(
                    json_path.read_text()
                )
            except Exception as exc:
                issues.append(f"invalid {json_path.name}: {exc}")
                continue
            if persisted != recipe:
                issues.append(f"{json_path.name} differs from top-level JSON")
            if md_path.read_text() != render_recipe(recipe):
                issues.append(f"{md_path.name} is not a pure JSON rendering")

        actual_json = {
            path.name for path in out_dir.glob("*.json")
            if path.name not in {"init_launch_analysis_result.json", "input_provenance.json"}
        }
        actual_md = {
            path.name for path in out_dir.glob("*.md")
            if path.name not in {"index.md", "input_provenance.md"}
        }
        if actual_json != expected_json:
            issues.append(
                f"per-recipe JSON set mismatch: expected={sorted(expected_json)}, "
                f"actual={sorted(actual_json)}"
            )
        if actual_md != expected_md:
            issues.append(
                f"per-recipe Markdown set mismatch: expected={sorted(expected_md)}, "
                f"actual={sorted(actual_md)}"
            )

    summary = (
        f"{len(result.launch_recipes)} recipes, "
        f"{len(result.analysis_gaps)} analysis gaps"
    )
    if issues:
        summary += f"; {len(issues)} problems: " + "; ".join(issues)
    return not issues, summary


async def test_init_launch_static(tester: "PipelineTester") -> Tuple[bool, str]:
    return await test_init_launch(tester, phase="static")
