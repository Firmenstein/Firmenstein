"""Complete pure Markdown views of FileResolver's persisted schema."""
from .analyzer_schema import FileResolverResult, FileResourceReport
from fmst_analyzer.analysis.base.finding_reports import render_fields, render_planning_findings


def render_index(result: FileResolverResult) -> str:
    lines = [
        f"# File Resolver Report — `{result.root_binary}`", "",
        "- Structured source of truth: [file_resolver_result.json](file_resolver_result.json)",
        f"- schema_version: `{result.schema_version}`",
        f"- phase: `{result.phase}`", "",
    ]
    document = result.model_dump(mode="json", exclude={
        "schema_version", "phase", "resource_reports", "planning_findings",
    })
    for field, value in document.items():
        lines.extend([f"## {field}", "", render_fields({field: value})])
    lines.extend(["## resource_reports", ""])
    if not result.resource_reports:
        lines.append("`{}`")
    for key in sorted(result.resource_reports):
        stem = key.replace("::", "__").replace("#", "_")
        lines.append(f"- {key}: [md]({stem}.md) / [json]({stem}_result.json)")
    lines.extend(["", render_planning_findings(result.planning_findings)])
    return "\n".join(lines).rstrip() + "\n"


def render_per_resource_report(report: FileResourceReport) -> str:
    return f"# File Resource Report — `{report.primary_path}`\n\n" + render_fields(report.model_dump(mode="json"))
