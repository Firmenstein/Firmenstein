"""Pure Markdown rendering for NetworkAnalyzer v8 JSON models."""
from __future__ import annotations

from collections import Counter
from fmst_analyzer.analysis.base.finding_reports import render_fields, render_planning_findings

from .analyzer_schema import (
    NetworkAnalysisResult,
    NetworkCallsite,
    NetworkDisposition,
    NetworkInteractionAnalysis,
    NetworkInteractionReport,
)


def interaction_report_stem(analysis: NetworkInteractionAnalysis) -> str:
    kind = (
        analysis.interaction_kind.value
        if analysis.interaction_kind is not None
        else analysis.disposition.value
    )
    digest = analysis.interaction_id.split(":", 1)[-1]
    return f"{kind}__{digest}"


def _identity_summary(analysis: NetworkInteractionAnalysis) -> str:
    identity = analysis.identity
    if identity is None:
        return "—"
    values: list[str] = []
    for label, value in (
        ("family", identity.family),
        ("socket_type", identity.socket_type),
        ("protocol", identity.protocol),
        ("local_address", identity.local_address),
        ("local_port", identity.local_port),
        ("remote_address", identity.remote_address),
        ("remote_port", identity.remote_port),
        ("hostname", identity.hostname),
        ("service", identity.service),
        ("interface", identity.interface),
        ("operation", identity.operation),
        ("netlink_protocol", identity.netlink_protocol),
    ):
        if value is not None:
            values.append(f"{label}={value}")
    values.append(f"resolution={identity.resolution.value}")
    return ", ".join(values)


def _table_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def _code_location(fact: NetworkCallsite) -> str:
    location = fact.location
    return (
        f"{location.binary_name}::{location.function_name}:"
        f"L{location.line_number}"
    )


def _analysis_locations(
    analysis: NetworkInteractionAnalysis,
    callsites: dict[str, NetworkCallsite],
) -> str:
    locations = sorted({
        (
            callsites[callsite_id].location.binary_name,
            callsites[callsite_id].location.function_name,
        )
        for callsite_id in analysis.callsite_ids
    })
    return "<br>".join(
        f"`{binary_name}::{function_name}`"
        for binary_name, function_name in locations
    )


def _analysis_heading(
    analysis: NetworkInteractionAnalysis,
    callsites: dict[str, NetworkCallsite],
) -> str:
    label = (
        analysis.interaction_kind.value
        if analysis.interaction_kind is not None
        else analysis.disposition.value
    )
    first = callsites[analysis.callsite_ids[0]]
    return f"{label} — {_code_location(first).rsplit(':L', 1)[0]}"


def _callsite_table(
    callsite_ids: list[str],
    callsites: dict[str, NetworkCallsite],
    reasons: dict[str, str] | None = None,
) -> list[str]:
    headers = ["location", "api_name", "expression_text", "callsite_id"]
    if reasons is not None:
        headers.append("reason")
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "---|" * len(headers),
    ]
    for callsite_id in callsite_ids:
        fact = callsites[callsite_id]
        row = [
            f"`{_table_text(_code_location(fact))}`",
            f"`{_table_text(fact.api_name)}`",
            f"`{_table_text(fact.expression_text)}`",
            f"`{callsite_id}`",
        ]
        if reasons is not None:
            row.append(_table_text(reasons[callsite_id]))
        lines.append("| " + " | ".join(row) + " |")
    return lines


def render_index(result: NetworkAnalysisResult) -> str:
    dispositions = Counter(item.disposition.value for item in result.analyses)
    analyzed_counts = Counter(
        callsite_id
        for analysis in result.analyses
        for callsite_id in analysis.callsite_ids
    )
    lines = [
        f"# NetworkAnalyzer — {result.root_binary}",
        "",
        (
            "This report accounts for reachable calls that establish, identify, "
            "query, or configure network resources. `network` entries describe "
            "external network-stack dependencies. `internal_ipc` and "
            "`file_resource` describe domain observations; `not_network` is a proven "
            "non-network use or target-infeasible API branch; `unresolved` records "
            "the exact missing evidence. "
            "Each analysis is rooted at one resource anchor. A shared helper "
            "callsite may be referenced by more than one analysis."
        ),
        "",
        "- Structured source of truth: "
        "[`network_analysis_result.json`](network_analysis_result.json)",
        "",
        "## Summary",
        "",
        f"- schema_version: `{result.schema_version}`",
        f"- phase: `{result.phase}`",
        f"- root_binary: `{result.root_binary}`",
        f"- callsites: {len(result.callsites)}",
        f"- analyses: {len(result.analyses)}",
        f"- analysis_callsite_references: {sum(analyzed_counts.values())}",
        f"- analyzed_unique_callsites: {len(analyzed_counts)}",
        f"- shared_callsite_ids: {sum(count > 1 for count in analyzed_counts.values())}",
        f"- pending_callsite_ids: {len(result.pending_callsite_ids)}",
    ]
    for disposition in NetworkDisposition:
        lines.append(
            f"- disposition `{disposition.value}`: "
            f"{dispositions.get(disposition.value, 0)}"
        )

    lines.extend(["", "## Analyses", ""])
    if not result.analyses:
        lines.append("_No full-phase analyses are present._")
    else:
        lines.extend([
            "| disposition | interaction_kind | anchor_callsite_id | code_locations | identity | callsites | report | interaction_id |",
            "|---|---|---|---|---|---:|---|---|",
        ])
        for analysis in sorted(
            result.analyses,
            key=lambda item: (item.disposition.value, item.interaction_id),
        ):
            kind = (
                f"`{analysis.interaction_kind.value}`"
                if analysis.interaction_kind
                else "—"
            )
            stem = interaction_report_stem(analysis)
            report = f"[md]({stem}.md) / [json]({stem}.json)"
            lines.append(
                f"| `{analysis.disposition.value}` "
                f"| {kind} "
                f"| `{analysis.anchor_callsite_id}` "
                f"| {_analysis_locations(analysis, result.callsites)} "
                f"| {_table_text(_identity_summary(analysis))} "
                f"| {len(analysis.callsite_ids)} "
                f"| {report} "
                f"| `{analysis.interaction_id}` |"
            )
        lines.extend(["", "## Analysis details", ""])
        for analysis in sorted(
            result.analyses,
            key=lambda item: (item.disposition.value, item.interaction_id),
        ):
            lines.extend([
                f"### {_analysis_heading(analysis, result.callsites)}",
                "",
                f"- interaction_id: `{analysis.interaction_id}`",
                f"- anchor_callsite_id: `{analysis.anchor_callsite_id}`",
                f"- disposition: `{analysis.disposition.value}`",
                (
                    f"- interaction_kind: `{analysis.interaction_kind.value}`"
                    if analysis.interaction_kind
                    else "- interaction_kind: null"
                ),
                f"- summary: {analysis.summary}",
                f"- applicability: {analysis.applicability}",
                render_fields({"context_anchor": analysis.context_anchor.model_dump(mode="json") if analysis.context_anchor else None}),
                "",
                "#### callsite_ids",
                "",
            ])
            lines.extend(
                _callsite_table(
                    analysis.callsite_ids,
                    result.callsites,
                )
            )
            lines.extend(["", "#### missing_evidence", ""])
            if analysis.missing_evidence:
                lines.extend(f"- {item}" for item in analysis.missing_evidence)
            else:
                lines.append("_None._")
            lines.append("")

    lines.extend(["", "## pending_callsite_ids", ""])
    if result.pending_callsite_ids:
        lines.extend(
            _callsite_table(
                result.pending_callsite_ids,
                result.callsites,
            )
        )
    else:
        lines.append("_None._")
    lines.extend(["", "## finding_target", "", render_fields({"finding_target": result.finding_target.model_dump(mode="json")}),
                  "## callsites", "", render_fields({"callsites": {key: value.model_dump(mode="json") for key, value in result.callsites.items()}}),
                  "## covered_api_calls", "", render_fields({"covered_api_calls": [item.model_dump(mode="json") for item in result.covered_api_calls]}),
                  render_planning_findings(result.planning_findings)])
    lines.extend(["", "## execution", "", render_fields(result.execution.model_dump(mode="json"))])
    return "\n".join(lines).rstrip() + "\n"


def render_interaction(report: NetworkInteractionReport) -> str:
    return (
        f"# {_analysis_heading(report.analysis, report.callsites)}\n\n"
        + render_fields(report.model_dump(mode="json"))
    )


__all__ = ["interaction_report_stem", "render_index", "render_interaction"]
