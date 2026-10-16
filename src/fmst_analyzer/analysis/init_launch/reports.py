"""Pure Markdown renderers for InitLaunch JSON artifacts."""
from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import List
from fmst_analyzer.analysis.base.finding_reports import render_fields, render_planning_findings

from .analyzer_schema import InitLaunchAnalysisResult, LaunchRecipe, SourceSnippet


def recipe_report_stem(recipe: LaunchRecipe) -> str:
    source = PurePosixPath(recipe.launch_site.path).name or "launch"
    readable = re.sub(r"[^A-Za-z0-9_.-]+", "_", source).strip("._") or "launch"
    location = re.sub(
        r"[^A-Za-z0-9_.-]+", "_", recipe.launch_site.location
    ).strip("._")
    prefix = f"{readable}_{location}" if location else readable
    return f"recipe_{prefix}__{recipe.recipe_id}"


def _snippet_lines(snippet: SourceSnippet) -> List[str]:
    lines = [
        f"- path: `{snippet.path}`",
        f"- location: `{snippet.location}`",
        "- text:",
        "",
        "  ```text",
    ]
    lines.extend(f"  {line}" for line in snippet.text.splitlines())
    lines.append("  ```")
    return lines


def render_recipe(recipe: LaunchRecipe) -> str:
    lines = [
        f"# Launch recipe `{recipe.recipe_id}`",
        "",
        f"- recipe_id: `{recipe.recipe_id}`",
        f"- executable_path: `{recipe.executable_path}`",
        "- command_template:",
    ]
    lines.extend(f"  - `{item}`" for item in recipe.command_template)
    lines.extend(["", "## launch_site", ""])
    lines.extend(_snippet_lines(recipe.launch_site))
    lines.extend(["", "## context_anchor", ""])
    lines.extend(_snippet_lines(recipe.context_anchor))
    lines.extend(["", "## applicability", "", recipe.applicability])
    lines.extend(["", "## initialization_chain", ""])
    for index, source in enumerate(recipe.initialization_chain, start=1):
        lines.extend([f"### initialization_chain[{index}]", ""])
        lines.extend(_snippet_lines(source))
        lines.append("")
    lines.extend(["", "## preparation_actions", ""])
    if not recipe.preparation_actions:
        lines.append("_(none)_")
    for index, action in enumerate(recipe.preparation_actions, start=1):
        lines.extend([f"### preparation_actions[{index}]", ""])
        lines.extend(_snippet_lines(action))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_index(result: InitLaunchAnalysisResult) -> str:
    identity = result.target_identity
    incomplete_reachability = any(
        not finding.boundary.reachability_refs
        for finding in result.planning_findings.values()
    )
    introduction = (
        "This report includes source-backed launch commands with unresolved "
        "initialization applicability. Consult applicability, planning_findings "
        "and analysis_gaps before selecting a candidate."
        if incomplete_reachability else
        "This report lists rootfs-backed commands with a complete firmware "
        "initialization chain to the selected target. It does not rank "
        "candidates or prescribe how to launch them."
    )
    lines = [
        f"# InitLaunchAnalyzer — `{identity.target_basename}`",
        "",
        introduction,
        "",
        "- Structured source of truth: "
        "[`init_launch_analysis_result.json`](init_launch_analysis_result.json)",
        "",
        f"- schema_version: `{result.schema_version}`",
        f"- phase: `{result.phase}`",
        "",
        "## target_identity",
        "",
        f"- target_basename: `{identity.target_basename}`",
        f"- selected_rootfs_path: `{identity.selected_rootfs_path}`",
        "- target_aliases:",
    ]
    if identity.target_aliases:
        lines.extend(f"  - `{path}`" for path in identity.target_aliases)
    else:
        lines.append("  - _(none)_")

    lines.extend(["", "## launch_recipes", ""])
    if not result.launch_recipes:
        lines.append("_(none)_")
    else:
        for recipe_id, recipe in result.launch_recipes.items():
            stem = recipe_report_stem(recipe)
            lines.extend([
                f"### launch_recipes.{recipe_id}",
                "",
                f"- recipe_id: `{recipe.recipe_id}`",
                f"- executable_path: `{recipe.executable_path}`",
                "- command_template:",
                *[f"  - `{item}`" for item in recipe.command_template],
                "",
                "#### launch_site",
                "",
            ])
            lines.extend(_snippet_lines(recipe.launch_site))
            lines.extend(["", "#### context_anchor", ""])
            lines.extend(_snippet_lines(recipe.context_anchor))
            lines.extend(["", "#### applicability", "", recipe.applicability])
            lines.extend(["", "#### initialization_chain", ""])
            for index, source in enumerate(
                recipe.initialization_chain,
                start=1,
            ):
                lines.extend([
                    f"##### initialization_chain[{index}]",
                    "",
                ])
                lines.extend(_snippet_lines(source))
                lines.append("")
            lines.extend(["#### preparation_actions", ""])
            if not recipe.preparation_actions:
                lines.append("_(none)_")
            for index, action in enumerate(
                recipe.preparation_actions,
                start=1,
            ):
                lines.extend([
                    f"##### preparation_actions[{index}]",
                    "",
                ])
                lines.extend(_snippet_lines(action))
                lines.append("")
            lines.extend([
                "",
                "#### report",
                "",
                f"- report: [json]({stem}.json) / [md]({stem}.md)",
                "",
            ])

    lines.extend(["", "## analysis_gaps", ""])
    if not result.analysis_gaps:
        lines.append("_(none)_")
    for index, gap in enumerate(result.analysis_gaps, start=1):
        lines.extend([
            f"### analysis_gaps[{index}]",
            "",
            f"- kind: `{gap.kind}`",
            f"- reason: {gap.reason}",
            "",
            "#### source",
            "",
        ])
        if gap.source is None:
            lines.append("_(none)_")
        else:
            lines.extend(_snippet_lines(gap.source))
            lines.append("")
    lines.extend([
        "", "## finding_target", "", render_fields(result.finding_target.model_dump(mode="json")),
        "", "## initialization_roots", "", render_fields({"initialization_roots": result.initialization_roots}),
        "", render_planning_findings(result.planning_findings),
    ])
    lines.extend(["", "## execution", "", render_fields(result.execution.model_dump(mode="json"))])
    lines.extend(["", "## correction_history", "", render_fields([item.model_dump(mode="json") for item in result.correction_history])])
    return "\n".join(lines).rstrip() + "\n"


__all__ = ["recipe_report_stem", "render_index", "render_recipe"]
