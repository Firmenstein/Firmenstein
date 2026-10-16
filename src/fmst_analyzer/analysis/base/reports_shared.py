"""Shared renderers for resource-usage-site evidence.

Produces two outputs from the same ``List[EffectiveCallsite]`` data:
 - ``format_resource_usage_sites_for_agent`` — the ``<resource_usage_sites>``
   block injected into the agent's first user message.
 - ``format_resource_usage_sites_md`` — the ``## Resource Usage Sites``
   section (with ``<details>`` collapse) for per-callsite drill-down MDs.

Both are pure functions of the sites list plus the full-set total so
consumers can surface ``N of M`` truncation.
"""
from typing import List

from .report_schema import EffectiveCallsite


def format_resource_usage_sites_for_agent(
    sites: List[EffectiveCallsite],
    total: int,
) -> str:
    """Render the agent-input block. Empty sites → a single-line note
    inside the tag so the agent knows the field was populated but
    yielded no decision points."""
    header = (
        f'<resource_usage_sites count="{len(sites)}" total="{total}" '
        f'note="top-K non-thunk call sites in view.root that reach '
        f'this resource, lex-sorted by (binary, function, line).">'
    )
    if not sites:
        return (
            header
            + "\nNo call sites found (target unreachable or all "
            "intermediate frames thunks).\n</resource_usage_sites>"
        )
    parts = [header, ""]
    for i, s in enumerate(sites, start=1):
        parts.append(
            f"[{i}] {s.binary}::{s.function}::L{s.representative_line} "
            f"(reached via {s.reached_via}):"
        )
        for snippet_line in s.context_snippet.splitlines():
            parts.append(f"    {snippet_line}")
        parts.append("")
    parts.append("</resource_usage_sites>")
    return "\n".join(parts)


def format_resource_usage_sites_md(
    sites: List[EffectiveCallsite],
    total: int,
    *,
    heading_level: int = 2,
    title: str = "Resource Usage Sites",
    empty_message: str = (
        "_(no call sites — target unreachable or all intermediate frames thunks)_"
    ),
) -> str:
    """Render a collapsible resource-usage section at the requested depth."""
    heading = "#" * heading_level
    item_heading = "#" * (heading_level + 1)
    if not sites:
        return f"{heading} {title}\n\n{empty_message}\n"
    lines = [
        f"{heading} {title}",
        "",
        f"**{len(sites)} of {total}** non-thunk call sites in `view.root` "
        "that reach this resource.",
        "",
        "<details>",
        "<summary>Click to expand</summary>",
        "",
    ]
    for s in sites:
        lines += [
            f"{item_heading} `{s.binary}::{s.function}::L{s.representative_line}`",
            f"*reached via {s.reached_via}*",
            "",
            "```c",
            s.context_snippet,
            "```",
            "",
        ]
    lines.append("</details>")
    lines.append("")
    return "\n".join(lines)
