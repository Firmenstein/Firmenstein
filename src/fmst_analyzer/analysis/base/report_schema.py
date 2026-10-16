"""Shared per-callsite report schema across analyzers.

``UsageReport`` and ``CallSiteReport`` describe how an anchor's output is
produced at a call site and how the downstream program consumes it. They
are domain-neutral. FileResolver uses them directly; NetworkAnalyzer v7 uses
its own resource-level API-effect schema.

Field-level contracts live in each ``Field(description=...)`` so the LLM
tool schema surface stays identical whichever analyzer imports these
types. Domain-specific guidance (what to put into ``setup_details`` for a
socket vs a file anchor) belongs in the analyzer's prompt, not here.

When another consumer emerges these types
stay here; extract only if a consumer needs a differently-shaped
equivalent. Meanwhile, ``post_use_constraint`` semantics are intentionally
verbatim shared — partial tracing is encoded as free text, not as a
structured status enum.
"""
from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

class EffectiveCallsite(BaseModel):
    """A single decision point in ``view.root`` code that reaches a
    target resource. Produced by
    :meth:`AnalysisView.collect_effective_callsites`."""
    binary: str = Field(
        description="Binary containing this call site (almost always "
        "view.root)."
    )
    function: str = Field(
        description="Containing function's decompiled name."
    )
    representative_line: int = Field(
        description="Line within ``function`` where it calls the next "
        "hop toward the target resource. If the function has multiple "
        "such lines, the numerically smallest one is kept."
    )
    reached_via: str = Field(
        description="Arrow-joined short chain from this function toward "
        "the target, with thunk frames omitted. Example: "
        "'nvram_get → nvram_init'."
    )
    context_snippet: str = Field(
        description="±5 lines around ``representative_line`` of the "
        "function body, preserving original line-number prefix."
    )


class UsageReport(BaseModel):
    """A single downstream use of the value produced by an anchor
    (fd returned by ``open`` / ``socket`` / ``getaddrinfo`` / ...).

    The structured record lets the synthesizer iterate programmatically
    (e.g. ``[u for cr in report.callsite_reports for u in cr.usage_reports
    if u.api_name == "ioctl"]``).
    """

    binary_name: str = Field(
        pattern=r"\S",
        description="Binary containing this use; required to locate cross-binary evidence unambiguously.",
    )
    function_name: str = Field(description="Function containing the use")
    line_number: int = Field(description="Line number of the use")
    api_name: str = Field(
        description=(
            "External API symbol at this use site, copied verbatim from "
            "the call expression. Examples: 'ioctl', 'read', 'pread', "
            "'fread', 'readv', 'mmap', 'fcntl', 'close', 'bind', "
            "'connect', 'sendto', 'recvmsg'. Use the exact identifier "
            "that appears in the decompiled code — do NOT normalize "
            "variants (pread != read, fread != read, sendto != send)."
        ),
    )
    details: str = Field(
        description=(
            "Factual description of this single call site. Cover the "
            "dimensions that apply to this API call:\n"
            "- parameters: arguments passed at this call (cmd constants, "
            "  flags, buffer / struct pointers, sizes, offsets, "
            "  sockaddr fields)\n"
            "- data source: if this call writes data, where does the "
            "  data come from (literal, global, caller arg, prior "
            "  computation)\n"
            "- output destination: if this call produces data (retval "
            "  or out buffer), where is it stored (local, struct field, "
            "  global)\n"
            "- condition: if this is a conditional call (close on an "
            "  error path, read in a loop, connect inside a retry "
            "  block), state the condition.\n"
            "Do NOT describe how the output is checked / branched on "
            "downstream — that belongs in post_use_constraint."
        ),
    )
    post_use_constraint: Optional[str] = Field(
        default=None,
        description=(
            "Natural-language description of how this op's output "
            "(retval, out buffer, or values derived from them) is "
            "later checked, compared, or branched on, including the "
            "consequence when the check fails. "
            "Examples: 'ioctl retval != 0 -> exit(1) at L125'; "
            "'buffer[0..6] compared via strcmp to global lan_ip at "
            "L203; mismatch triggers return -1'; "
            "'read retval checked > 0; < 0 branch closes fd and "
            "returns -1'; 'connect retval == -1 -> goto retry loop'. "
            "Trace relevant callers and state until the observed constraint or a "
            "specific missing relationship is established. Distinguish main returning "
            "(target process termination) from a local error return or child exit. "
            "For a numerical return mapping, retain the source expression and its "
            "concrete input/result cases as well as the qualitative effect. "
            "Set None only when no use is established, and retain any tracing gap "
            "in the finding. Do NOT fill with ungrounded boilerplate."
        ),
    )


class CallSiteAnalysis(BaseModel):
    """Analysis of one anchor callsite's full lifecycle (setup + uses).

    Per-anchor container. One exact resource/problem may have several
    anchors (several file opens of the same typed path, or several sockets
    serving the same endpoint); each anchor becomes its own
    ``CallSiteReport`` inside the top-level report.
    """

    model_config = ConfigDict(extra="forbid")

    callsite_id: str = Field(
        description=(
            'Back-link to the anchor\'s callsite identity; the '
            '"{binary}::{function}::L{line}::{api}" form shared with '
            'IPC / File / Network analyzers. Pass through verbatim '
            'from the input — do not invent, normalize, or reformat.'
        )
    )
    containing_function_purpose: str = Field(
        description=(
            "One-sentence header describing what the containing "
            "function does. Example: 'init_cpu_count initializes "
            "global cpu_count from /proc/cpuinfo'. Must NOT duplicate "
            "content from setup_details, usage_reports, or the "
            "resource/problem top-level summary."
        )
    )
    setup_details: str = Field(
        description=(
            "Anchor setup facts at THIS call site. Domain-specific "
            "content:\n"
            "- File anchors (open / fopen / opendir / ...): flags "
            "  (O_RDONLY / O_CREAT / ...) + mode + how the returned "
            "  fd / FILE* is stored (local / global / struct field) + "
            "  close site.\n"
            "- Socket anchors (socket / socketpair): family / type / "
            "  protocol + where the fd is stored + close site. Do NOT "
            "  describe downstream bind / listen / connect / send / "
            "  recv / ioctl here — those are UsageReport entries.\n"
            "- Non-fd query anchors (gethostbyname / getaddrinfo / "
            "  getifaddrs / if_nametoindex / ...): the query args "
            "  (hostname / ifname / ...) and where the output buffer "
            "  / linked-list / retval is stored."
        )
    )
    usage_reports: List[UsageReport] = Field(
        description=(
            "Every downstream use of the value returned by this anchor. "
            "For fd-producing anchors, follow the fd across function "
            "boundaries: callee arguments, global variables, struct "
            "fields (best-effort). When the trail goes dark, note the "
            "limit in the resource/problem top-level summary rather "
            "than fabricating sites. Do not replace a long list with "
            "representative samples or silently omit distinct API calls."
        )
    )

class CallSiteReport(CallSiteAnalysis):
    """Analysis plus Controller-verified reachability, assembled before binding."""

    resource_usage_sites: List[EffectiveCallsite] = Field(
        default_factory=list,
        description=(
            "Up to 10 non-thunk call sites in view.root that reach "
            "this callsite's target, lex-sorted by (binary, function, "
            "line). Each entry carries ±5 lines of local code around "
            "the call — the agent uses these as primary evidence for "
            "caller effects; these excerpts do not prove every invocation feasible."
        ),
    )
    total_usage_sites: int = Field(
        default=0,
        description=(
            "Full set size before the K-cap."
        ),
    )


__all__ = ["UsageReport", "CallSiteAnalysis", "CallSiteReport"]
