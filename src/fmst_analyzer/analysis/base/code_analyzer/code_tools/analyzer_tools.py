"""
Standard tools for CodeAnalyzer Agent.

Nine code access tools:
- view_function:     read a function's full decompiled code
- view_disassembly:  read one function's address-annotated assembly
- view_callers:      list callers with callsite context code
- view_callees:      list callees with annotations
- trace_variable:    cross-function variable dataflow tracing with code context
- view_code_range:   read a specific line range from a function
- view_global:       resolve a global variable's value
- find_string_xref:      find functions that reference a given string literal
- find_global_var_xref:  find functions that reference a given global variable

evaluate_integer_cases checks source-derived arithmetic without executing code.

All decompiled code access goes through these tools. When an agent also has
provider-native filesystem tools, those tools are rooted at a report directory
and cannot access the decompiled-code tree.

Each tool returns formatted code directly in its response, with L{num}: line
prefixes and ... gap markers for consistent rendering.

Tools are created via ``make_analyzer_tools(view)`` and share one
``AnalysisView`` facade. All code tools require an explicit binary name.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from fmst_basic.agent.tool import AgentTool, tool

from .format_utils import (
    format_code_snippet,
    merge_line_ranges,
    extract_merged_snippet,
)
from .integer_evaluation import evaluate_integer_cases
from fmst_analyzer.nodes.common import FunctionAttr
from fmst_analyzer.graphs.api_dep_graph import ImplStatus
from ..analysis_view import AnalysisView

if TYPE_CHECKING:
    from fmst_analyzer.nodes.binary import BinaryNode


# ---------------------------------------------------------------------------
# Module-level helpers
#
# View resolution lives on `LibDepGraph.resolve_view(name, *, prefer=...)`
# and on `AnalysisView.resolve_view(name)` which wraps it with the current
# view as the anchor. The tool helpers below just compose those plus the
# structural fallback against `LibDepGraph.find_implementation_by_name`.
# ---------------------------------------------------------------------------

def _callee_impl_binary(
    func_node, view: AnalysisView,
) -> Optional["BinaryNode"]:
    """Return the implementer BinaryNode for an EXTERNAL `func_node`, or
    None if it can't be resolved.

    Uses ``view.resolve_view(func_node.module)`` to pick the right ADG,
    then asks that ADG for its ``get_impl_binary`` answer. Falls back to
    a global ``LibDepGraph.find_implementation_by_name`` lookup when no
    ADG covers the owner (the .so-only edge case).
    """
    target_adg = view.resolve_view(func_node.module)
    if target_adg is not None and func_node in target_adg:
        return target_adg.get_impl_binary(func_node)
    impl_lib, _ = view.lib_dep_graph.find_implementation_by_name(func_node.name)
    return impl_lib


def _callee_annotation(func_node, view: AnalysisView) -> str:
    """Produce the ``[external: ...]`` or ``[cross-binary -> ...]`` annotation.

    Picks the right ADG for `func_node` via ``view.resolve_view(func.module)``.
    Rule 1 prefers ``view.adg`` when it covers ``func_node.module``; rule 2
    falls back to the ADG rooted at the owner binary; rule 3 degrades to a
    global LibDepGraph lookup + DEFAULT_LIB classification. This keeps the
    annotation meaningful even for functions outside the current analyzer's
    view (e.g. ad-hoc onboarded peers).
    """
    if not func_node.has_attr(FunctionAttr.EXTERNAL):
        return ""

    target_adg = view.resolve_view(func_node.module)
    if target_adg is not None and func_node in target_adg:
        status = target_adg.get_impl_status(func_node)
        impl_bin = target_adg.get_impl_binary(func_node)
        if status is ImplStatus.DEFAULT_LIB:
            lib_name = impl_bin.name if impl_bin else "libc"
            return f"[external: {lib_name}]"
        if status is ImplStatus.NO_IMPL:
            return "[external: unresolved]"
        if status is ImplStatus.RESOLVED_IN_SCOPE:
            return f"[cross-binary -> {impl_bin.name}]" if impl_bin else ""
        return ""

    # Fallback: no ADG covers the function. Use global LibDepGraph lookup
    # and classify against DEFAULT_LIB to produce a meaningful annotation.
    impl_lib, _ = view.lib_dep_graph.find_implementation_by_name(func_node.name)
    if impl_lib is None:
        return "[external: unresolved]"
    default_libs = view.global_config.DEFAULT_LIB
    if any(dl in impl_lib.name for dl in default_libs):
        return f"[external: {impl_lib.name}]"
    return f"[cross-binary -> {impl_lib.name}]"


def _callee_annotation_by_name(
    func_name: str, binary_name: str, view: AnalysisView,
) -> str:
    """Produce annotation by looking up the function node from name + binary.

    Fetches the CallGraph via ``LibDepGraph.get_callgraph_by_name`` (the
    structural path), so ad-hoc onboarded peers that live outside the
    current analyzer's ADG scope are still reachable.
    """
    cg = view.lib_dep_graph.get_callgraph_by_name(binary_name)
    if cg is None:
        return "[external: unknown binary]"
    try:
        func_node = cg.get_node_by_name(func_name)
    except ValueError:
        return "[external: unresolved]"
    return _callee_annotation(func_node, view)


# Process-level caches shared across make_analyzer_tools() calls.  The resolved
# JSON path identifies the image/workdir; the stat signature invalidates cached
# content when onboarding republishes an index at the same path.
_STRING_XREF_CACHE: Dict[
    Path,
    tuple[tuple[int, int, int, int], Dict[str, List[Dict[str, Any]]]],
] = {}
_GLOBAL_VAR_XREF_CACHE: Dict[
    Path,
    tuple[tuple[int, int, int, int], Dict[str, List[Dict[str, Any]]]],
] = {}


def _binary_basename(binary_name: str) -> str:
    """Map a canonical guest path to the current basename identity.

    Callsite records expose guest paths such as ``lib/libubox.so`` while
    LibDepGraph currently keys binaries by basename. Code tools accept both
    forms so an agent does not need to know that storage detail. LibDepGraph
    already rejects distinct binaries with the same basename, so this does
    not hide an ambiguous identity.
    """
    return Path(binary_name).name


def _load_xref_index(
    json_path: Path,
    cache: Dict[
        Path,
        tuple[tuple[int, int, int, int], Dict[str, List[Dict[str, Any]]]],
    ],
) -> Optional[Dict[str, List[Dict[str, Any]]]]:
    """Load one xref index without sharing it across images or stale files."""
    json_path = json_path.resolve()
    try:
        stat_before = json_path.stat()
    except OSError:
        return None
    signature = (
        stat_before.st_dev,
        stat_before.st_ino,
        stat_before.st_size,
        stat_before.st_mtime_ns,
    )
    cached = cache.get(json_path)
    if cached is not None and cached[0] == signature:
        return cached[1]

    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None

    try:
        stat_after = json_path.stat()
    except OSError:
        return data
    signature_after = (
        stat_after.st_dev,
        stat_after.st_ino,
        stat_after.st_size,
        stat_after.st_mtime_ns,
    )
    if signature_after == signature:
        cache[json_path] = (signature, data)
    return data


def _render_string_xref_hits(
    binary_name: str,
    needle: str,
    hits: List[tuple],
    kind: str = "exact",
    max_strings: int = 20,
    max_refs_per_string: int = 20,
) -> str:
    """Format find_string_xref results for agent consumption.

    ``hits`` is a list of ``(matched_string, [{"func": ..., "ea": ...}, ...])``.
    Caller chooses `kind` ("exact" or "substring") for the header.
    Truncation limits guard against pathological sweeps (e.g. needle=`"a"`
    substring-matching half the binary); when a cap is hit the output
    includes an explicit ``(showing N of M)`` marker per AGENTS.md section 5.
    """
    lines: List[str] = []
    header_total = sum(len(refs) for _, refs in hits)
    lines.append(
        f"{len(hits)} string literal(s) in '{binary_name}' {kind}-match "
        f"'{needle}' across {header_total} xref(s):"
    )

    shown_strings = hits[:max_strings]
    for matched_str, refs in shown_strings:
        shown_refs = refs[:max_refs_per_string]
        truncated = len(refs) > len(shown_refs)
        if len(matched_str) > 200:
            display = (
                f"{matched_str[:200]}... "
                f"(truncated, showing 200 of {len(matched_str)} chars)"
            )
        else:
            display = matched_str
        if matched_str == needle:
            lines.append(f"  - '{display}':")
        else:
            lines.append(f"  - '{display}' (contains needle):")
        for ref in shown_refs:
            lines.append(f"      · {ref.get('func', '?')} @ {ref.get('ea', '?')}")
        if truncated:
            lines.append(
                f"      (showing {len(shown_refs)} of {len(refs)} xref(s))"
            )

    if len(hits) > len(shown_strings):
        lines.append(
            f"  (showing {len(shown_strings)} of {len(hits)} matching strings)"
        )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tool factory
# ---------------------------------------------------------------------------

def make_analyzer_tools(view: AnalysisView) -> List[AgentTool]:
    """Create analyzer tools bound to a single ``AnalysisView``.

    `view` is the view-bound query handle owned by the analyzer that's
    creating these tools — per-analyzer-invocation, NOT session-wide.
    Individual tool calls may dynamically pick a different ADG via
    ``view.resolve_view(binary_name)`` based on
    ``binary_name``; the anchor is the "default containing view" used
    by rule 1 of the resolution.

    All returned tools capture ``view`` from this scope. They require
    an explicit binary_name on every call — no automatic resolution.

    Args:
        view: the analyzer's code-analysis facade.

    Returns:
        List of 9 tools: [view_function, view_disassembly, view_callers,
        view_callees, trace_variable, view_code_range, view_global,
        find_string_xref, find_global_var_xref]
    """
    # -------------------------------------------------------------------
    # Tool 1: view_function
    # -------------------------------------------------------------------

    @tool
    def view_function(
        function_name: str,
        binary_name: str,
    ) -> str:
        """View the full decompiled code of a function.

        Returns the complete function code with line numbers.

        Args:
            function_name: Name of the function to view
            binary_name: Binary containing the function
        """
        binary_name = _binary_basename(binary_name)
        try:
            code = view.get_full_code(binary_name, function_name)
        except FileNotFoundError:
            return f'Decompiled code for "{function_name}" in {binary_name} not found on disk.'

        total_lines = len(code.splitlines())
        return format_code_snippet(
            binary_name, function_name, code,
            header_suffix=f"({total_lines} lines)",
        )

    # -------------------------------------------------------------------
    # Tool 2: view_disassembly
    # -------------------------------------------------------------------

    @tool
    def view_disassembly(
        binary_name: str,
        function_ea: int | None = None,
        function_name: str | None = None,
    ) -> str:
        """View the exact persisted assembly listing for one function.

        Use this when decompiled output is missing, contradictory, or
        ambiguous.  The listing is resolved from the binary and function EA,
        so callers do not need to guess IDA's sanitized artifact filename.
        A function name is accepted as a convenience when the model has not
        yet copied the EA from a controller-owned finding.
        It contains instruction addresses and bytes where IDA exposes them.

        Args:
            function_ea: IDA effective address of the function to inspect.
            binary_name: Binary containing the function.
            function_name: Optional function name used to resolve the EA.

        Returns:
            The complete assembly listing and its authoritative filesystem
            path, or an explicit message when the artifact is unavailable.
        """
        binary_name = _binary_basename(binary_name)
        if function_ea is None:
            if not function_name:
                return "Assembly unavailable: provide function_ea or function_name."
            try:
                function_ea = view.get_function_ea(binary_name, function_name)
            except (FileNotFoundError, ValueError, RuntimeError) as error:
                return (
                    f"Assembly unavailable for {binary_name}::{function_name}: "
                    f"{error}"
                )
            if function_ea is None:
                return (
                    f"Assembly unavailable for {binary_name}::{function_name}: "
                    "function not found."
                )
        try:
            path, listing = view.get_disassembly(binary_name, function_ea)
        except (
            FileNotFoundError,
            ValueError,
            RuntimeError,
        ) as error:
            return (
                f"Assembly unavailable for {binary_name}@{function_ea:#x}: "
                f"{error}"
            )
        return (
            f"=== Assembly: {path} ===\n"
            f"=== {binary_name} function EA {function_ea:#x} ===\n"
            f"{listing}"
        )

    # -------------------------------------------------------------------
    # Tool 3: view_callers
    # -------------------------------------------------------------------

    @tool
    def view_callers(
        function_name: str,
        binary_name: str,
    ) -> str:
        """View all callers of a function within the selected view, with callsite code context.

        Searches every binary in the ADG view selected by `binary_name`
        (NOT every onboarded binary) for callers. The view is chosen
        dynamically: if `binary_name` is in the current analyzer's
        anchor ADG scope, that anchor is used; otherwise the ADG rooted
        at `binary_name` is used (for ad-hoc onboarded peers). Returns
        each caller's function prototype and 5 lines of code context
        around the callsite. Cross-binary callers are tagged with
        [cross-binary].

        Use this to trace how a function is invoked and what arguments
        callers pass.

        Args:
            function_name: Name of the function to find callers of
            binary_name: Binary where the function is defined (drives view selection + cross-binary tagging)
        """
        binary_name = _binary_basename(binary_name)
        view_adg = view.resolve_view(binary_name)
        if view_adg is None:
            return (
                f'Binary "{binary_name}" is not onboarded as an analysis root '
                f'and is not in the current analyzer\'s view. Onboard it first.'
            )

        defined_in = binary_name

        caller_entries: List[dict] = []

        for binary_node, callgraph in view_adg.binary_callgraphs.items():
            bin_name = binary_node.name
            if not callgraph.has_node_by_name(function_name):
                continue
            try:
                func_node = callgraph.get_node_by_name(function_name)
            except ValueError:
                continue

            # Match callsites by both symbol name and decompiled name,
            # since CallSite.callee_name stores the original symbol name
            # which may differ from the decompiled name passed by the agent.
            match_names = {func_node.name, func_node.decompiled_name}

            callers = callgraph.get_callers_of(func_node)
            for caller in callers:
                caller_display = caller.decompiled_name
                cross_tag = " [cross-binary]" if bin_name != defined_in else ""
                caller_ea = getattr(caller, "ea", None)
                caller_assembly = None
                if isinstance(caller_ea, int):
                    try:
                        caller_assembly = view.get_disassembly_path(
                            bin_name, caller_ea,
                        )
                    except (
                        AttributeError,
                        FileNotFoundError,
                        RuntimeError,
                        ValueError,
                    ):
                        caller_assembly = None

                callsites: List[dict] = []
                try:
                    for cs in caller.get_callsites().values():
                        if cs.callee_name in match_names:
                            source_ea = getattr(cs, "source_ea", None)
                            if source_ea is None:
                                source_ea = getattr(cs, "callsite_ea", None)
                            callsites.append({
                                "line": getattr(cs, "line_number", None),
                                "column": getattr(cs, "column_number", None),
                                "ctree_index": getattr(cs, "ctree_index", None),
                                "source_ea": source_ea,
                            })
                except Exception:
                    pass
                callsites.sort(key=lambda cs: (
                    cs["line"] if isinstance(cs["line"], int) else -1,
                    cs["column"] if isinstance(cs["column"], int) else -1,
                    cs["ctree_index"]
                    if isinstance(cs["ctree_index"], int) else -1,
                    cs["source_ea"]
                    if isinstance(cs["source_ea"], int) else -1,
                ))

                caller_entries.append({
                    "bin_name": bin_name,
                    "caller_display": caller_display,
                    "caller_ea": caller_ea,
                    "caller_assembly": caller_assembly,
                    "callsites": callsites,
                    "cross_tag": cross_tag,
                })

        # Determinism: sort callers lexically; each caller's callsites are
        # independently sorted above by their CTree/source coordinates.
        caller_entries.sort(key=lambda e: (
            e["bin_name"],
            e["caller_display"],
        ))

        if not caller_entries:
            return f'No callers found for "{function_name}".'

        callsite_count = sum(len(entry["callsites"]) for entry in caller_entries)
        parts: List[str] = [
            f"Found {len(caller_entries)} callers of {function_name} "
            f"(defined in {defined_in}); located {callsite_count} matching "
            f"callsites:"
        ]

        for entry in caller_entries:
            bin_name = entry["bin_name"]
            caller_display = entry["caller_display"]
            caller_ea = entry["caller_ea"]
            caller_assembly = entry["caller_assembly"]
            callsites = entry["callsites"]
            cross_tag = entry["cross_tag"]
            function_ea_label = (
                f", function EA=0x{caller_ea:x}"
                if isinstance(caller_ea, int) else ""
            )

            if not callsites:
                assembly_label = (
                    f", assembly: {caller_assembly}"
                    if caller_assembly is not None else ""
                )
                parts.append(
                    f"\n--- {bin_name}::{caller_display} "
                    f"(line unknown{function_ea_label}{assembly_label})"
                    f"{cross_tag} ---"
                )
                parts.append("  (callsite line not available)")
                continue

            locations: List[str] = []
            call_lines: List[int] = []
            for callsite in callsites:
                call_line = callsite["line"]
                call_column = callsite["column"]
                ctree_index = callsite["ctree_index"]
                source_ea = callsite["source_ea"]
                location = f"L{call_line}" if isinstance(call_line, int) else "line unknown"
                if isinstance(call_column, int):
                    location += f":C{call_column}"
                if isinstance(ctree_index, int):
                    location += f", ctree={ctree_index}"
                if isinstance(source_ea, int):
                    location += f", EA=0x{source_ea:x}"
                locations.append(location)
                if isinstance(call_line, int) and call_line > 0:
                    call_lines.append(call_line)

            location_label = "; ".join(locations)
            if not call_lines:
                assembly_label = (
                    f", assembly: {caller_assembly}"
                    if caller_assembly is not None else ""
                )
                parts.append(
                    f"\n--- {bin_name}::{caller_display} "
                    f"(callsites: {location_label}"
                    f"{function_ea_label}{assembly_label}){cross_tag} ---"
                )
                parts.append("  (callsite code position not available)")
                continue

            try:
                full_code = view.get_full_code(bin_name, caller_display)
                all_lines = full_code.splitlines()
                total_lines = len(all_lines)

                proto_end = 0
                for idx, line in enumerate(all_lines):
                    if "{" in line:
                        proto_end = idx + 1
                        break

                ranges = merge_line_ranges(
                    sorted(set(call_lines)), context=5, total_lines=total_lines,
                )
                if proto_end > 0 and ranges and ranges[0][0] > proto_end + 1:
                    ranges = [(1, proto_end)] + ranges

                snippet = extract_merged_snippet(all_lines, ranges)
                label = "callsite" if len(callsites) == 1 else "callsites"
                assembly_label = (
                    f", assembly: {caller_assembly}"
                    if caller_assembly is not None else ""
                )
                suffix = (
                    f"({label}: {location_label}{function_ea_label}"
                    f"{assembly_label}){cross_tag}"
                )
                parts.append(f"\n--- {bin_name}::{caller_display} {suffix} ---")
                parts.append(snippet)
                if total_lines and ranges[-1][1] < total_lines:
                    parts.append("  ...")
            except FileNotFoundError:
                if view.lib_dep_graph.get_callgraph_by_name(bin_name) is None:
                    reason = "binary not onboarded"
                else:
                    reason = "decompiled code not exported"
                parts.append(
                    f"\n--- {bin_name}::{caller_display} "
                    f"(callsites: {location_label}, code unavailable: "
                    f"{reason}){cross_tag} ---"
                )

        return "\n".join(parts)

    # -------------------------------------------------------------------
    # Tool 4: view_callees
    # -------------------------------------------------------------------

    @tool
    def view_callees(
        function_name: str,
        binary_name: str,
    ) -> str:
        """View all functions called by a given function.

        Returns a list of callees with type annotations:
        - [external: libc] — system library functions, usually no need to inspect
        - [cross-binary -> lib] — cross-binary functions, use view_function to read
        - No annotation — same-binary internal functions, use view_function to read

        Args:
            function_name: Name of the function to list callees of
            binary_name: Binary containing the function
        """
        binary_name = _binary_basename(binary_name)
        cg = view.lib_dep_graph.get_callgraph_by_name(binary_name)
        if cg is None:
            return (
                f'CallGraph for "{binary_name}" not available. '
                f'Is the binary onboarded?'
            )

        try:
            func_node = cg.get_node_by_name(function_name)
        except ValueError:
            return f'Function "{function_name}" not found in {binary_name}.'

        from fmst_analyzer.graphs.base_graph import EdgeType
        callees = list(cg.get_successors_by_type(func_node, EdgeType.CALL))

        if not callees:
            return f'No callees found for "{function_name}".'

        lines: List[str] = [f"Callees of {function_name} ({binary_name}):"]
        for callee in sorted(callees, key=lambda n: n.name):
            callee_display = callee.decompiled_name
            annotation = _callee_annotation(callee, view)
            callee_ea = getattr(callee, "ea", None)

            if annotation and "external" in annotation:
                lines.append(f"  {callee_display:<50s} {annotation}")
            else:
                callee_binary = binary_name
                if annotation and "cross-binary" in annotation:
                    impl_bin = _callee_impl_binary(callee, view)
                    if impl_bin:
                        callee_binary = impl_bin.name
                location = (
                    f", EA=0x{callee_ea:x}"
                    if isinstance(callee_ea, int) else ""
                )
                assembly = None
                if isinstance(callee_ea, int):
                    try:
                        assembly = view.get_disassembly_path(
                            callee_binary, callee_ea,
                        )
                    except (
                        AttributeError,
                        FileNotFoundError,
                        RuntimeError,
                        ValueError,
                    ):
                        assembly = None
                assembly_label = (
                    f", assembly: {assembly}"
                    if assembly is not None else ""
                )
                entry = (
                    f"  {callee_display} ({callee_binary}{location}"
                    f"{assembly_label})"
                )
                if annotation:
                    entry = f"{entry}  {annotation}"
                lines.append(entry)

        lines.append(f"Total: {len(callees)} callees")
        lines.append(
            "Use view_function(name, binary_name) for C or "
            "view_disassembly(function_ea, binary_name) for assembly."
        )
        return "\n".join(lines)

    # -------------------------------------------------------------------
    # Tool 5: trace_variable
    # -------------------------------------------------------------------

    @tool
    async def trace_variable(
        variable_name: str,
        function_name: str,
        direction: str,
        binary_name: str,
        max_depth: int = 4,
    ) -> str:
        """Trace variable dataflow propagation across functions.

        Follows a variable across function boundaries via the `direction` parameter:
        "forward" traces downstream usage, "backward" traces upstream origin, "both"
        does both. Returns code context (5 lines around each usage site, merged when
        close together) and reports boundary functions where tracing stops.

        Does NOT work across binary boundaries — for cross-binary callers
        (marked [cross-binary] by view_callers), use view_function to manually
        inspect the caller's code in the other binary.

        Args:
            variable_name: Variable name to trace (e.g. 'v5', 'fd', 'result')
            function_name: Function where the variable resides
            direction: "forward" (downstream), "backward" (upstream), or "both"
            binary_name: Binary containing the function
            max_depth: Max cross-function trace depth, default 4
        """
        binary_name = _binary_basename(binary_name)
        selected_adg = view.resolve_view(binary_name)
        if selected_adg is None:
            return (
                f'Binary "{binary_name}" is not onboarded as an analysis root '
                "and is not in the current analyzer's view. Onboard it first."
            )
        selected_view = (
            view if selected_adg is view.adg else AnalysisView(selected_adg)
        )
        try:
            graph = selected_view.trace_variables(
                binary_name=binary_name,
                func_name=function_name,
                var_name=variable_name,
                direction=direction,
                max_sink_depth=max_depth,
                max_rise_depth=max_depth,
            )
        except Exception as e:
            return f"DataFlow tracing failed: {e}"

        if graph.node_count == 0:
            return f"No dataflow found for variable '{variable_name}' in function '{function_name}'"

        func_usage: dict[tuple[str, str], list[int]] = {}
        for node in graph.nodes:
            representative_lines = []
            if node.usage_lines:
                representative_lines = node.usage_lines
            elif node.declaration_line > 0:
                representative_lines = [node.declaration_line]
            if not representative_lines:
                continue

            key = (node.binary_name, node.func_name)
            if key not in func_usage:
                func_usage[key] = []
            for line in representative_lines:
                if line not in func_usage[key]:
                    func_usage[key].append(line)

        if not func_usage:
            return (
                f"Traced {graph.node_count} nodes for '{variable_name}' "
                f"but no code locations found."
            )

        total_sites = sum(len(lines) for lines in func_usage.values())
        parts: List[str] = [
            f"Traced '{variable_name}' {direction} from {function_name}: "
            f"{total_sites} usage sites in {len(func_usage)} functions"
        ]

        func_items = list(func_usage.items())

        for (node_binary, node_func), usage_lines in func_items:
            function_ea = None
            assembly_path = None
            try:
                function_ea = view.get_function_ea(node_binary, node_func)
                if function_ea is not None:
                    assembly_path = view.get_disassembly_path(
                        node_binary, function_ea,
                    )
            except (
                AttributeError,
                FileNotFoundError,
                RuntimeError,
                ValueError,
            ):
                function_ea = None
                assembly_path = None
            assembly_label = (
                f", function EA=0x{function_ea:x}"
                if isinstance(function_ea, int) else ""
            )
            if assembly_path is not None:
                assembly_label += f", assembly: {assembly_path}"
            try:
                full_code = view.get_full_code(node_binary, node_func)
                all_lines = full_code.splitlines()
                total_lines = len(all_lines)

                ranges = merge_line_ranges(usage_lines, context=5, total_lines=total_lines)

                proto_end = 0
                for idx, ln in enumerate(all_lines):
                    if "{" in ln:
                        proto_end = idx + 1
                        break
                if proto_end > 0 and ranges and ranges[0][0] > proto_end + 1:
                    ranges = [(1, proto_end)] + ranges

                snippet = extract_merged_snippet(all_lines, ranges)
                lines_label = ", ".join(f"L{ln}" for ln in sorted(usage_lines))
                parts.append(
                    f"\n--- {node_binary}::{node_func} "
                    f"(usage: {lines_label}{assembly_label}) ---"
                )
                parts.append(snippet)
                if total_lines and ranges[-1][1] < total_lines:
                    parts.append("  ...")
            except FileNotFoundError:
                lines_str = ", ".join(f"L{ln}" for ln in sorted(usage_lines))
                parts.append(
                    f"\n--- {node_binary}::{node_func} "
                    f"({lines_str}{assembly_label}, code unavailable) ---"
                )

        # --- Boundary report: detect external functions in the graph ---
        boundary_funcs: dict[str, str] = {}  # func_name -> annotation
        for node in graph.nodes:
            fn = node.func_name
            bn = node.binary_name
            if fn in boundary_funcs:
                continue
            if view.is_external_function(bn, fn, resolve_thunk=True):
                annotation = _callee_annotation_by_name(fn, bn, view)
                boundary_funcs[fn] = annotation

        if boundary_funcs:
            parts.append("\nNote: tracing stopped at binary boundaries:")
            for fn, ann in boundary_funcs.items():
                parts.append(f"  - {fn} {ann}")
            parts.append("Cross-binary dataflow tracing is not yet supported.")

        return "\n".join(parts)

    # -------------------------------------------------------------------
    # Tool 6: view_code_range
    # -------------------------------------------------------------------

    @tool
    def view_code_range(
        function_name: str,
        start_line: int,
        end_line: int,
        binary_name: str,
    ) -> str:
        """View a specific line range from a function's decompiled code.

        Returns the requested code range with line numbers.
        Line numbers start at 1, both start_line and end_line are inclusive.

        Args:
            function_name: Name of the function
            start_line: First line to show (1-indexed, inclusive)
            end_line: Last line to show (1-indexed, inclusive)
            binary_name: Binary containing the function
        """
        binary_name = _binary_basename(binary_name)
        try:
            code_slice = view.get_code_lines(
                binary_name, function_name, start_line, end_line,
            )
        except (FileNotFoundError, ValueError) as e:
            return f'Error reading {function_name} L{start_line}-L{end_line}: {e}'

        if not code_slice:
            return f'No code found at {function_name} L{start_line}-L{end_line}.'

        try:
            full_code = view.get_full_code(binary_name, function_name)
            total_lines = len(full_code.splitlines())
        except FileNotFoundError:
            total_lines = None

        return format_code_snippet(
            binary_name, function_name, code_slice,
            start_line=start_line, total_lines=total_lines,
            header_suffix=f"L{start_line}-L{end_line}" + (f" (total {total_lines} lines)" if total_lines else ""),
        )

    # -------------------------------------------------------------------
    # Tool 7: view_global
    # -------------------------------------------------------------------

    @tool
    def view_global(
        variable_name: str,
        binary_name: str,
    ) -> str:
        """Resolve the actual value of a global variable (e.g. GVar_XXXXXXXX).

        Use this when decompiled code references GVar_ prefixed names.
        Accepts both GVar_-prefixed names (from decompiled code) and raw IDA names
        (e.g., target names returned by address-type results).

        Supports four result types:
        - string: e.g., GVar_X = "some_path" (string)
        - integer: e.g., GVar_X = 12345 (integer)
        - address: e.g., GVar_X = 0xABCD -> target_name (.data) (address)
        - bss: runtime variable, no static value

        For address type, the target name can be passed directly to view_global
        to recursively resolve pointer chains.

        Args:
            variable_name: Global variable name (e.g. 'GVar_0804A000' or 'aDoFile2')
            binary_name: Binary containing the global variable
        """
        binary_name = _binary_basename(binary_name)
        try:
            result = view.get_global_variable_value(
                variable_name, binary_name
            )
        except (ValueError, RuntimeError) as e:
            return f'Global variable "{variable_name}" not found in {binary_name}: {e}'

        if result is None:
            return f'Global variable "{variable_name}" not found or has no resolved value in {binary_name}.'

        value_type, value_repr = result
        if value_type == "string":
            return f'{variable_name} = "{value_repr}" (string)'
        elif value_type == "integer":
            return f'{variable_name} = {value_repr} (integer)'
        elif value_type == "address":
            return f'{variable_name} = {value_repr} (address — use view_global on the target if needed)'
        elif value_type == "bss":
            return f'{variable_name}: {value_repr} (runtime variable, no static value)'
        else:
            return f'{variable_name} = {value_repr} ({value_type})'

    # -------------------------------------------------------------------
    # Tool 8: find_string_xref
    # -------------------------------------------------------------------

    def _load_string_xref_index(
        binary_name: str,
    ) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        code_dir = view.global_config.decompiled_code_dir
        json_path = code_dir / binary_name / "string_xrefs.json"
        return _load_xref_index(json_path, _STRING_XREF_CACHE)

    @tool
    def find_string_xref(binary_name: str, needle: str) -> str:
        """Find functions in `binary_name` that reference the string
        literal `needle`.

        Backed by a per-binary string→xref index extracted from IDA at
        onboarding time (``<decompiled_code>/<binary>/string_xrefs.json``).
        Much stronger signal than byte-search: proves the string is
        actually used from code, not just sitting as dead metadata.

        Lookup order:
        1. Exact match on the full string literal.
        2. Substring match — any indexed string that contains `needle`.
           Useful when the IDA-recognised literal has surrounding
           characters (NUL padding, wrapping, etc.) the caller didn't
           include.

        Args:
            binary_name: Binary containing the code. The index must
                have been built during onboarding — if missing, the
                tool tells the caller to onboard first.
            needle: Raw string content. Do NOT include surrounding
                quotes. Literal match — no regex.

        Returns a human-readable listing of hits (matched string +
        function name + xref EA), or an informative message when no
        reference is found or the index is missing."""
        binary_name = _binary_basename(binary_name)
        data = _load_string_xref_index(binary_name)
        if data is None:
            return (
                f"No string xref index for '{binary_name}'. "
                f"Onboard the binary first so the index gets built."
            )

        exact = data.get(needle)
        if exact:
            return _render_string_xref_hits(binary_name, needle, [(needle, exact)])

        substring_hits: List[tuple] = []
        for key, refs in data.items():
            if needle in key:
                substring_hits.append((key, refs))
        if substring_hits:
            return _render_string_xref_hits(
                binary_name, needle, substring_hits, kind="substring"
            )

        return (
            f"No functions in '{binary_name}' reference '{needle}' "
            f"(neither as an exact literal nor as a substring)."
        )

    # -------------------------------------------------------------------
    # Tool 9: find_global_var_xref
    # -------------------------------------------------------------------

    def _load_global_var_xref_index(
        binary_name: str,
    ) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        code_dir = view.global_config.decompiled_code_dir
        json_path = code_dir / binary_name / "global_var_xrefs.json"
        return _load_xref_index(json_path, _GLOBAL_VAR_XREF_CACHE)

    @tool
    def find_global_var_xref(binary_name: str, var_name: str) -> str:
        """Find functions in `binary_name` that reference the global
        variable `var_name`.

        Backed by a per-binary global-var → xref index built at onboarding
        time (``<decompiled_code>/<binary>/global_var_xrefs.json``). Use
        this to discover every callsite that reads or writes a named
        global — critical for following fd/handle propagation when the
        opener stores it in a global variable that later callers consume.

        Args:
            binary_name: Binary containing the code. The index is built
                during onboarding — if missing, this tool tells the
                caller to onboard first.
            var_name: The global variable name. If the decompiled code
                shows a ``GVar_`` prefix, that prefix is stripped
                automatically before lookup; pass either form.

        Returns a human-readable listing of hits (function name + xref
        EA), or an informative message when no reference is found or the
        index is missing.
        """
        binary_name = _binary_basename(binary_name)
        data = _load_global_var_xref_index(binary_name)
        if data is None:
            return (
                f"No global var xref index for '{binary_name}'. "
                f"Onboard the binary first so the index gets built."
            )

        # Agents see decompiled code with the analyzer's GVar_ prefix;
        # the on-disk index keys on the canonical IDA symbol name.
        lookup = var_name[5:] if var_name.startswith("GVar_") else var_name
        refs = data.get(lookup)
        if not refs:
            return (
                f"No functions in '{binary_name}' reference global var "
                f"'{var_name}' (looked up as '{lookup}')."
            )

        shown = refs[:20]
        lines = [
            f"{len(refs)} xref(s) to global var '{lookup}' in '{binary_name}':"
        ]
        for ref in shown:
            lines.append(f"  · {ref.get('func', '?')} @ {ref.get('ea', '?')}")
        if len(refs) > len(shown):
            lines.append(f"  (showing {len(shown)} of {len(refs)} xref(s))")
        return "\n".join(lines)

    # -------------------------------------------------------------------
    # Return all tools
    # -------------------------------------------------------------------

    return [view_function, view_disassembly, view_callers, view_callees,
            trace_variable, view_code_range, view_global,
            find_string_xref, find_global_var_xref, evaluate_integer_cases]
