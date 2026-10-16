"""Pure Markdown rendering for ProcessLifecycleAnalyzer JSON models."""
from __future__ import annotations

from collections import Counter
from fmst_analyzer.analysis.base.finding_reports import render_fields, render_planning_findings

from .analyzer_schema import (
    ProcessEventAssessment,
    ProcessEventAssessmentReport,
    ProcessLifecycleAnalysisResult,
)


def _escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def assessment_report_stem(assessment: ProcessEventAssessment) -> str:
    stable_id = assessment.callsite_id.replace(":", "_").replace("/", "_")
    return f"{assessment.disposition.value}__{stable_id}"


def render_index(result: ProcessLifecycleAnalysisResult) -> str:
    counts = Counter(item.disposition.value for item in result.assessments.values())
    lines = [
        f"# Process Lifecycle Analysis — `{result.root_binary}`",
        "",
        "This report classifies reachable termination and process-transition "
        "calls by whether they can block target startup. JSON is the source of truth; "
        "the pages linked below are deterministic views of the same data.",
        "",
        "- Structured source of truth: "
        "[`process_lifecycle_analysis_result.json`](process_lifecycle_analysis_result.json)",
        "",
        "## Summary",
        "",
        f"- schema_version: `{result.schema_version}`",
        f"- phase: `{result.phase}`",
        f"- root_binary: `{result.root_binary}`",
        f"- callsites: {len(result.callsites)}",
        f"- assessments: {len(result.assessments)}",
    ]
    for disposition in (
        "startup_blocker",
        "expected_lifecycle",
        "runtime_only",
        "unresolved",
    ):
        lines.append(f"- {disposition}: {counts[disposition]}")

    lines.extend(["", "## assessments", ""])
    if not result.assessments:
        lines.append("_None._")
    else:
        lines.extend([
            "| disposition | event | location | summary | report |",
            "|---|---|---|---|---|",
        ])
        for callsite_id, assessment in sorted(
            result.assessments.items(),
            key=lambda item: (item[1].disposition.value, item[0]),
        ):
            callsite = result.callsites[callsite_id]
            stem = assessment_report_stem(assessment)
            location = (
                f"`{callsite.binary_name}::{callsite.function_name}:"
                f"L{callsite.line_number}:C{callsite.column_number}`"
            )
            lines.append(
                f"| `{assessment.disposition.value}` | `{callsite.api_name}` | "
                f"{location} | {_escape(assessment.summary)} | "
                f"[md]({stem}.md) / [json]({stem}.json) |"
            )

    lines.extend([
        "", "## finding_target", "", render_fields(result.finding_target.model_dump(mode="json")),
        "", "## callsites", "", render_fields({
            key: value.model_dump(mode="json") for key, value in sorted(result.callsites.items())
        }),
        "", render_planning_findings(result.planning_findings),
    ])
    lines.extend(["", "## execution", "", render_fields(result.execution.model_dump(mode="json"))])
    return "\n".join(lines).rstrip() + "\n"


def render_assessment_report(report: ProcessEventAssessmentReport) -> str:
    return "# Process event assessment\n\n" + render_fields(report.model_dump(mode="json"))



__all__ = [
    "assessment_report_stem",
    "render_assessment_report",
    "render_index",
]
