"""The single query handle for one target-rooted analysis view."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from loguru import logger
from ..report_schema import EffectiveCallsite

from fmst_analyzer.graphs.api_dep_graph import ApiDepGraph
from fmst_analyzer.graphs.base_graph import EdgeType
from fmst_analyzer.nodes.common import FunctionAttr
from fmst_analyzer.nodes.semantic import VariablePropResult
from .dataflow.types import TraceDirection

if TYPE_CHECKING:
    from .dataflow.graph import DataFlowGraph
    from fmst_analyzer.global_config import GlobalConfig
    from fmst_analyzer.graphs.call_graph import CallGraph
    from fmst_analyzer.graphs.lib_dep_graph import LibDepGraph
    from fmst_analyzer.nodes.binary import BinaryNode
    from fmst_analyzer.nodes.function import FunctionNode
    from fmst_analyzer.nodes.callsite import CallSite


@dataclass
class SemanticCheckResult:
    """Semantic snapshot and artifact integrity for one binary."""

    total_decompiled: int
    total_snapshots: int
    missing_funcs: List[str]
    extra_funcs: List[str]

    @property
    def missing_count(self) -> int:
        return len(self.missing_funcs)

    @property
    def extra_count(self) -> int:
        return len(self.extra_funcs)




@dataclass
class AnalysisView:
    """Query structural and reachable code facts for one ADG root."""

    adg: ApiDepGraph

    def __post_init__(self) -> None:
        if self.adg.analysis_level != "semantic":
            raise ValueError(
                "AnalysisView requires a semantic ApiDepGraph; call "
                "decompile_analysis() before constructing code-analysis tools"
            )

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def lib_dep_graph(self) -> "LibDepGraph":
        return self.adg.lib_dep_graph

    @property
    def global_config(self) -> "GlobalConfig":
        return self.adg.global_config

    @property
    def root(self) -> "BinaryNode":
        return self.adg.root

    def _get_callgraph_for_binary(
        self, binary_name: str,
    ) -> Optional["CallGraph"]:
        return self.lib_dep_graph.get_callgraph_by_name(binary_name)

    def get_binary_elf_identity(self, binary_name: str) -> dict[str, str]:
        """Read the guest ELF identity independently of the analysis host ABI."""
        import lief

        binary = self.lib_dep_graph.get_node_by_name(binary_name)
        if binary is None:
            raise ValueError(f"Binary {binary_name!r} not found")
        parsed = lief.parse(str(binary.binary_path))
        if not isinstance(parsed, lief.ELF.Binary):
            raise ValueError(f"Cannot parse ELF identity: {binary.binary_path}")
        header = parsed.header
        return {
            "machine": header.machine_type.name,
            "class": header.identity_class.name,
            "byte_order": header.identity_data.name,
            "processor_flags": hex(header.processor_flag),
        }

    def get_global_variable_value(
        self, gvar_name: str, binary_name: str,
    ) -> Optional[Tuple[str, str]]:
        original_name = (
            gvar_name[len("GVar_"):]
            if gvar_name.startswith("GVar_")
            else gvar_name
        )
        callgraph = self._get_callgraph_for_binary(binary_name)
        if callgraph is None:
            raise ValueError(f"CallGraph for binary {binary_name} not found")
        return callgraph.binary_node.get_global_var_value(original_name)

    def get_function_ea(
        self, binary_name: str, function_name: str,
    ) -> Optional[int]:
        # Persisted C/S locations use CallGraph.artifact_stem, which may be a
        # sanitized or EA-suffixed name rather than the ELF/IDA symbol.  The
        # CallGraph name map is the canonical inverse of get_decompiled_name;
        # querying BinaryNode directly rejects otherwise valid report refs
        # such as ``eval.c`` or ``duplicate@2000.c``.
        callgraph = self._get_callgraph_for_binary(binary_name)
        if callgraph is None or not callgraph.has_node_by_name(function_name):
            return None
        return callgraph.get_node_by_name(function_name).ea

    def get_decompiled_name(self, binary_name: str, function_ea: int) -> str:
        callgraph = self._get_callgraph_for_binary(binary_name)
        if callgraph is None:
            raise ValueError(f"CallGraph for binary {binary_name} not found")
        try:
            return callgraph.get_node_by_ea(function_ea).artifact_stem
        except ValueError as error:
            raise RuntimeError(
                f"Function with EA {hex(function_ea)} not found in "
                f"binary {binary_name}: {error}"
            ) from error

    def get_disassembly_path(
        self, binary_name: str, function_ea: int,
    ) -> Path:
        """Return the persisted assembly artifact for one exact function.

        The artifact stem is resolved through the CallGraph rather than
        reconstructed from a model-provided function name.  This keeps the
        assembly path aligned with IDA's sanitized/EA-suffixed filename.
        """
        assembly_root = self.global_config.disassembled_code_dir
        if assembly_root is None:
            raise FileNotFoundError(
                "Disassembled code directory is not configured"
            )
        binary_name = Path(binary_name).name
        artifact_stem = self.get_decompiled_name(binary_name, function_ea)
        root = Path(assembly_root).resolve()
        listing_path = (root / binary_name / f"{artifact_stem}.s").resolve()
        try:
            listing_path.relative_to(root)
        except ValueError as error:
            raise ValueError(
                f"Assembly artifact escapes disassembled code directory: "
                f"{listing_path}"
            ) from error
        return listing_path

    def get_disassembly(
        self, binary_name: str, function_ea: int,
    ) -> tuple[Path, str]:
        """Return the complete address-annotated listing for one function."""
        listing_path = self.get_disassembly_path(binary_name, function_ea)
        if not listing_path.is_file():
            raise FileNotFoundError(
                f"Disassembly artifact not found: {listing_path}"
            )
        text = listing_path.read_text(encoding="utf-8")
        if not text.strip():
            raise ValueError(f"Disassembly artifact is empty: {listing_path}")
        return listing_path, text

    def get_binary_image_base(self, binary_name: str) -> int:
        """Return the ELF image base used to normalize IIB module offsets."""
        binary = self.lib_dep_graph.get_node_by_name(binary_name)
        if binary is None:
            raise ValueError(f"Binary {binary_name!r} not found")
        import lief

        parsed = lief.parse(str(binary.binary_path))
        if parsed is None:
            raise ValueError(f"Cannot parse ELF image base for {binary_name!r}")
        return int(parsed.imagebase)

    def get_callsite_resume_ea(
        self,
        binary_name: str,
        function_ea: int,
        source_ea: int,
    ) -> int:
        """Return the first instruction after an intercepted call completes.

        The persisted IDA listing is authoritative for instruction boundaries.
        MIPS includes one delay-slot instruction; ARM/Thumb and x86 resume at
        the immediately following decoded instruction.
        """
        import re
        import lief

        binary = self.lib_dep_graph.get_node_by_name(binary_name)
        if binary is None:
            raise ValueError(f"Binary {binary_name!r} not found")
        artifact_stem = self.get_decompiled_name(binary_name, function_ea)
        listing_path = (
            self.global_config.disassembled_code_dir
            / binary_name
            / f"{artifact_stem}.s"
        )
        if not listing_path.is_file():
            raise ValueError(f"Disassembly artifact not found: {listing_path}")
        instruction_re = re.compile(r"^0x([0-9a-fA-F]+):")
        addresses = [
            int(match.group(1), 16)
            for line in listing_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if (match := instruction_re.match(line)) is not None
        ]
        positions = [
            index for index, address in enumerate(addresses)
            if address == source_ea
        ]
        if len(positions) != 1:
            raise ValueError(
                f"Callsite source EA 0x{source_ea:x} occurs {len(positions)} "
                f"times in {listing_path}"
            )
        parsed = lief.parse(str(binary.binary_path))
        if not isinstance(parsed, lief.ELF.Binary):
            raise ValueError(f"Cannot parse ELF architecture: {binary.binary_path}")
        skip = 2 if parsed.header.machine_type == lief.ELF.ARCH.MIPS else 1
        resume_index = positions[0] + skip
        if resume_index >= len(addresses):
            raise ValueError(
                f"No resume instruction follows callsite 0x{source_ea:x} "
                f"in {listing_path}"
            )
        return addresses[resume_index]

    def get_function_caller_nodes(
        self, binary_name: str, func_name: str,
    ) -> List["FunctionNode"]:
        callgraph = self._get_callgraph_for_binary(binary_name)
        if callgraph is None:
            logger.warning(f"CallGraph for binary {binary_name!r} not found")
            return []
        try:
            function = callgraph.get_node_by_name(func_name)
        except ValueError:
            logger.warning(
                f"Function {func_name} not found in CallGraph for {binary_name}"
            )
            return []
        return callgraph.get_callers_of(function)

    def is_external_function(
        self,
        binary_name: str,
        func_name: str,
        resolve_thunk: bool = False,
    ) -> bool:
        callgraph = self._get_callgraph_for_binary(binary_name)
        if callgraph is None:
            return False
        try:
            function = callgraph.get_node_by_name(func_name)
        except ValueError:
            return False
        if function.has_attr(FunctionAttr.EXTERNAL):
            return True
        if resolve_thunk and function.has_attr(FunctionAttr.THUNK):
            target = callgraph.binary_node.find_thunk_target(function)
            return bool(target and target.has_attr(FunctionAttr.EXTERNAL))
        return False

    def get_function_param_name(
        self, binary_name: str, func_name: str, param_idx: int,
    ) -> Optional[str]:
        callgraph = self._get_callgraph_for_binary(binary_name)
        if callgraph is None:
            return None
        try:
            function = callgraph.get_node_by_name(func_name)
            if not function.concretized:
                return None
            for parameter in function.get_prototype_info().args:
                if parameter.index == param_idx:
                    return parameter.name
        except (ValueError, RuntimeError):
            return None
        return None

    @staticmethod
    def get_callsites_to(
        caller_func: "FunctionNode", callee_name: str,
    ) -> List["CallSite"]:
        return sorted(
            [
                callsite
                for callsite in caller_func.get_callsites().values()
                if callsite.callee_name == callee_name
            ],
            key=lambda callsite: callsite.ctree_index,
        )

    def get_full_code(self, binary_name: str, function_name: str) -> str:
        code_dir = self.global_config.decompiled_code_dir / binary_name
        function_ea = self.get_function_ea(binary_name, function_name)
        if function_ea is None:
            raise FileNotFoundError(f"Unknown function {binary_name}::{function_name}")
        artifact_stem = self.get_decompiled_name(binary_name, function_ea)
        function_file = code_dir / f"{artifact_stem}.c"
        if not function_file.resolve().is_relative_to(code_dir.resolve()):
            raise ValueError(
                f"Path escapes decompiled code directory: {function_name}"
            )
        if not function_file.exists():
            raise FileNotFoundError(
                f"Decompiled code for {binary_name}::{function_name} not "
                f"found at {function_file}"
            )
        return function_file.read_text(encoding="utf-8")

    def get_code_lines(
        self,
        binary_name: str,
        function_name: str,
        start_line: int,
        end_line: int,
    ) -> str:
        if start_line <= 0:
            raise ValueError(f"start_line must be positive, got {start_line}")
        if end_line < start_line:
            raise ValueError(
                f"end_line must be >= start_line "
                f"(got {end_line} < {start_line})"
            )
        lines = self.get_full_code(binary_name, function_name).splitlines()
        if start_line > len(lines):
            return ""
        return "\n".join(lines[start_line - 1:min(end_line, len(lines))])

    def _trace_variable_prop(
        self,
        binary_name: str,
        func_name: str,
        initial_var_name: str,
    ) -> VariablePropResult:
        import re

        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", initial_var_name) is None:
            raise ValueError(
                f"Invalid C identifier {initial_var_name!r} in {func_name}"
            )
        callgraph = self._get_callgraph_for_binary(binary_name)
        if callgraph is None:
            raise ValueError(f"CallGraph for binary {binary_name} not found")
        function = callgraph.get_node_by_name(func_name)
        return function.semantic_snapshot.trace_variable_prop(
            func_name, initial_var_name
        )

    def trace_variables(
        self,
        binary_name: str,
        func_name: str,
        var_name: str,
        direction: str | TraceDirection = "both",
        max_sink_depth: int = 2,
        max_rise_depth: int = 3,
    ) -> "DataFlowGraph":
        """Trace bounded same-binary dataflow from cached CTree semantics."""
        from .dataflow.tracer import _trace_variables

        return _trace_variables(
            self,
            binary_name=binary_name,
            func_name=func_name,
            var_name=var_name,
            direction=direction,
            max_sink_depth=max_sink_depth,
            max_rise_depth=max_rise_depth,
        )

    def resolve_view(self, binary_name: str) -> Optional[ApiDepGraph]:
        """Dispatch per-query view using this view as the preferred anchor.

        Delegates to ``LibDepGraph.resolve_view(binary_name, prefer=self.adg)``.
        Tools call this when they need to look up the "right" ADG for a
        specific `binary_name` — rule 1 returns `self.adg` if it covers
        the target, rule 2 falls back to the ADG rooted at the target,
        rule 3 returns None.
        """
        return self.lib_dep_graph.resolve_view(binary_name, prefer=self.adg)

    def collect_effective_callsites(
        self,
        target_binary: str,
        target_function: str,
        *,
        max_sites: int = 10,
        snippet_radius: int = 5,
        max_depth: int = 20,
    ) -> Tuple[List["EffectiveCallsite"], int]:
        """Collect top-K decision-point call sites in ``view.root`` that
        reach ``(target_binary, target_function)``.

        Returns ``(sites, total_count)`` where ``sites`` is lex-sorted
        by ``(binary, function, representative_line)`` and capped at
        ``max_sites``. ``total_count`` is the full set size before
        truncation so callers can surface "N of M" completeness.

        Functions marked as thunks by native metadata are skipped: BFS walks
        through them but their call sites never appear as entries.

        Returns ``([], 0)`` on unknown binary / unknown function /
        unreachable / exceeds ``max_depth``.
        """
        target_bin_node = self.lib_dep_graph.get_node_by_name(target_binary)
        if target_bin_node is None:
            return [], 0
        if target_bin_node not in self.adg.scope:
            return [], 0
        target_cg = self.adg.get_binary_callgraphs().get(target_bin_node)
        if target_cg is None or not target_cg.has_node_by_name(target_function):
            return [], 0
        target_fn = target_cg.get_node_by_name(target_function)
        if not self.adg.is_reachable(target_fn):
            return [], 0

        visited: Dict[int, "FunctionNode"] = {id(target_fn): target_fn}
        depth: Dict[int, int] = {id(target_fn): 0}
        parent_hop: Dict[int, Tuple["FunctionNode", int]] = {}
        queue = deque([target_fn])

        thunk_cache: Dict[Tuple[str, str], bool] = {}
        def _thunk(fn) -> bool:
            key = (fn.module, fn.decompiled_name)
            if key not in thunk_cache:
                # PLT/import thunks intentionally have no CTree snapshot or
                # published .c artifact.  Their structural IDA attribute is
                # authoritative; source text/name shapes are not thunk evidence.
                thunk_cache[key] = (
                    fn.has_attr(FunctionAttr.THUNK)
                    or fn.has_attr(FunctionAttr.PLT)
                    or fn.has_attr(FunctionAttr.EXTERNAL)
                )
            return thunk_cache[key]

        def _callers_of(fn):
            fn_bin = self.lib_dep_graph.get_node_by_name(fn.module)
            result = []
            if fn_bin is not None:
                fn_cg = self.adg.get_binary_callgraphs().get(fn_bin)
                if fn_cg is not None:
                    try:
                        result.extend(fn_cg.get_callers_of(fn))
                    except Exception:
                        pass
            result.extend(
                self.adg.get_predecessors_by_type(fn, EdgeType.IMPL)
            )
            dedup = list(dict.fromkeys(
                c for c in result if self.adg.is_reachable(c)
            ))
            dedup.sort(key=lambda c: (c.module, c.decompiled_name))
            return dedup

        def _callsite_line(caller, callee) -> Optional[int]:
            # CallSite.callee_name stores the original IDA symbol name
            # which may differ from FunctionNode.decompiled_name
            # (e.g., __imp_foo vs foo). Match against both to find the
            # callsite line. Mirrors the pattern in view_callers tool.
            try:
                match_names = {callee.decompiled_name}
                if hasattr(callee, "name") and callee.name:
                    match_names.add(callee.name)
                for cs in caller.get_callsites().values():
                    if cs.callee_name in match_names:
                        return cs.line_number
            except Exception:
                return None
            return None

        found: Dict[Tuple[str, str], EffectiveCallsite] = {}

        while queue:
            current = queue.popleft()
            if depth[id(current)] >= max_depth:
                continue
            for c in _callers_of(current):
                if id(c) in visited:
                    continue
                line = _callsite_line(c, current)
                visited[id(c)] = c
                depth[id(c)] = depth[id(current)] + 1
                parent_hop[id(c)] = (current, line if line is not None else 0)
                if _thunk(c):
                    # Walk through thunks — enqueue to find the real
                    # non-thunk callers upstream, but don't emit the
                    # thunk itself.
                    queue.append(c)
                    continue
                if c.module != self.root.name:
                    # Library-internal non-thunk wrappers (e.g.,
                    # libnvram::nvram_get checking `if (init_failed)
                    # return 0;`) are NOT decision points for
                    # view.root's system-level violation_effect — they
                    # only propagate failure signals. Walk through
                    # them just like thunks to reach the real
                    # view.root callsites that actually handle the
                    # resource failure.
                    queue.append(c)
                    continue
                # Non-thunk frame in view.root: this IS a decision
                # point. Emit it and DO NOT walk further up — the
                # caller of `c` reaches the target via `c`'s own
                # decision (checking c's return value), which is one
                # logical layer removed from the resource.
                key = (c.module, c.decompiled_name)
                rep_line = line if line is not None else 0

                # Build reached_via by walking forward from c to target_fn.
                chain = [c]
                cur = c
                while True:
                    nxt = parent_hop.get(id(cur))
                    if nxt is None:
                        break
                    chain.append(nxt[0])
                    cur = nxt[0]
                # Filter thunks from rendered chain (but keep the final
                # target). chain[0] == c itself (non-thunk, always kept).
                filtered_names = []
                for i, f in enumerate(chain):
                    if i == 0:
                        # c itself: include name only if this is NOT c
                        # (caller's perspective). Actually for reached_via,
                        # the semantics are "from the callsite's
                        # perspective, which downstream functions are
                        # hit?" so we DROP c (the function containing the
                        # decision point) and only render what it reaches.
                        continue
                    if i == len(chain) - 1:
                        filtered_names.append(f.decompiled_name)
                    elif not _thunk(f):
                        filtered_names.append(f.decompiled_name)
                reached_via = " → ".join(filtered_names) if filtered_names else (
                    target_fn.decompiled_name
                )

                # Extract ±radius lines around rep_line from c's body.
                # Always emit the `L<rep_line>:` line itself so agents
                # can cite by line number even when the body is short
                # or the representative line points past the available
                # decompiled text.
                try:
                    body = self.get_full_code(c.module, c.artifact_stem) or ""
                except FileNotFoundError:
                    # The usage-site slice is supplemental evidence.  Keep
                    # the stable function/line identity when an individual
                    # code artifact is unavailable instead of discarding the
                    # entire resource report that requested this traversal.
                    logger.warning(
                        "[collect_effective_callsites] code unavailable for "
                        f"{c.module}::{c.decompiled_name}; emitting location "
                        "without a context snippet"
                    )
                    body = ""
                snippet_lines: List[str] = []
                if rep_line > 0:
                    body_lines = body.splitlines() if body else []
                    lo = max(1, rep_line - snippet_radius)
                    hi = rep_line + snippet_radius
                    if rep_line > len(body_lines):
                        logger.debug(
                            "[collect_effective_callsites] rep_line "
                            f"{rep_line} exceeds body length "
                            f"{len(body_lines)} for "
                            f"{c.module}::{c.decompiled_name} — snippet "
                            "emits line prefix only, which may indicate "
                            "stale decompiled code or CallGraph line "
                            "drift"
                        )
                    for ln_no in range(lo, hi + 1):
                        if 1 <= ln_no <= len(body_lines):
                            snippet_lines.append(
                                f"L{ln_no}: {body_lines[ln_no - 1]}"
                            )
                        elif ln_no == rep_line:
                            snippet_lines.append(f"L{ln_no}:")
                context_snippet = "\n".join(snippet_lines)

                existing = found.get(key)
                if existing is None or rep_line < existing.representative_line:
                    found[key] = EffectiveCallsite(
                        binary=c.module,
                        function=c.decompiled_name,
                        representative_line=rep_line,
                        reached_via=reached_via,
                        context_snippet=context_snippet,
                    )

        sorted_sites = sorted(
            found.values(),
            key=lambda s: (s.binary, s.function, s.representative_line),
        )
        total = len(sorted_sites)
        return sorted_sites[:max_sites], total

    # ------------------------------------------------------------------
    # Structural and code queries
    # ------------------------------------------------------------------

    def get_reachable_callers_of_api(
        self, api_name: str,
    ) -> Dict["BinaryNode", List["FunctionNode"]]:
        """Reachable callers of `api_name` within this view's scope.

        View-dependent query: "who reaches this API from the analysis
        root of `self.adg`". Only searches binaries in ``self.adg.scope``
        and only counts callers that ``self.adg.is_reachable(...)``
        confirms.
        """
        binary_callgraphs = self.adg.get_binary_callgraphs()
        reachable_callers: Dict["BinaryNode", List["FunctionNode"]] = {}
        for binary_node, callgraph in binary_callgraphs.items():
            if not callgraph.has_node_by_name(api_name):
                continue
            api_node = callgraph.get_node_by_name(api_name)
            callers = callgraph.get_callers_of(api_node)

            for caller in callers:
                if not self.adg.is_reachable(caller):
                    continue
                if binary_node not in reachable_callers:
                    reachable_callers[binary_node] = []
                reachable_callers[binary_node].append(caller)

        return reachable_callers

    def collect_api_callsites(
        self, api_name: str,
    ) -> List["CallSite"]:
        """Gather callsites of `api_name` reachable from this view's root.

        Find reachable callers (via ``get_reachable_callers_of_api``),
        then return argument/return information captured from the same CTree
        snapshot that produced the decompiled C file.
        """
        reachable_callers = self.get_reachable_callers_of_api(api_name)
        if not reachable_callers:
            logger.debug(f"No reachable callers found for API {api_name}")
            return []

        all_callsites: List["CallSite"] = []
        for binary_node, callers in reachable_callers.items():
            for caller_func in callers:
                callsites = self.get_callsites_to(caller_func, api_name)
                invalid = [
                    callsite for callsite in callsites
                    if not callsite.is_populated
                ]
                if invalid:
                    raise RuntimeError(
                        f"Onboarded CTree callsites are not populated for "
                        f"{binary_node.name}::{caller_func.decompiled_name} "
                        f"calling {api_name}"
                    )
                all_callsites.extend(callsites)

        deduped = list(dict.fromkeys(all_callsites))
        logger.debug(f"Collected {len(deduped)} callsites for API {api_name}")
        return deduped

    def ctree_integrity_check(self) -> Dict[str, SemanticCheckResult]:
        """Validate semantic snapshots against the emitted C/S/xref artifacts."""
        import hashlib
        import json

        results: Dict[str, SemanticCheckResult] = {}
        for binary_node, callgraph in self.adg.get_binary_callgraphs().items():
            binary_name = binary_node.name
            expected = []
            available = []
            problems = []
            semantic_failure_eas = {
                failure.function_ea for failure in callgraph.semantic_failures
            }
            for function in callgraph.get_node_for_analysis():
                if function.has_attr(FunctionAttr.EXTERNAL):
                    continue
                if function.ea in semantic_failure_eas:
                    assembly_path = (
                        self.global_config.disassembled_code_dir
                        / binary_name / f"{function.artifact_stem}.s"
                    )
                    if (
                        not assembly_path.exists()
                        or not assembly_path.read_text(encoding="utf-8").strip()
                    ):
                        problems.append(
                            f"{function.decompiled_name}: missing assembly for "
                            "accounted semantic failure"
                        )
                    continue
                expected.append(function.artifact_stem)
                snapshot = getattr(function, "_semantic_snapshot", None)
                if snapshot is None or not snapshot.is_current:
                    problems.append(function.decompiled_name)
                    continue
                semantic_errors = snapshot.integrity_errors()
                if semantic_errors:
                    problems.extend(
                        f"{function.decompiled_name}: {error}"
                        for error in semantic_errors
                    )
                    continue
                code_path = (
                    self.global_config.decompiled_code_dir
                    / binary_name / f"{function.artifact_stem}.c"
                )
                if not code_path.exists():
                    problems.append(function.decompiled_name)
                    continue
                code = code_path.read_text(encoding="utf-8")
                if hashlib.sha256(code.encode("utf-8")).hexdigest() != (
                    snapshot.rendered_code_hash
                ):
                    problems.append(function.decompiled_name)
                    continue
                assembly_path = (
                    self.global_config.disassembled_code_dir
                    / binary_name / f"{function.artifact_stem}.s"
                )
                if (
                    not assembly_path.exists()
                    or not assembly_path.read_text(encoding="utf-8").strip()
                ):
                    problems.append(function.decompiled_name)
                    continue
                if set(snapshot.callsites) != set(function.get_callsites()):
                    problems.append(function.decompiled_name)
                    continue
                callsite_errors = []
                for ctree_index, info in snapshot.callsites.items():
                    callsite = function.get_callsites()[ctree_index]
                    if not callsite.is_populated:
                        callsite_errors.append(
                            f"call {ctree_index} is not populated"
                        )
                    if callsite.identity_key != (
                        snapshot.binary_identity,
                        snapshot.function_ea,
                        snapshot.snapshot_hash,
                        ctree_index,
                    ):
                        callsite_errors.append(
                            f"call {ctree_index} identity mismatch"
                        )
                    if info.location is None or (
                        callsite.source_ea != info.location.source_ea
                    ):
                        callsite_errors.append(
                            f"call {ctree_index} source EA mismatch"
                        )
                if callsite_errors:
                    problems.extend(
                        f"{function.decompiled_name}: {error}"
                        for error in callsite_errors
                    )
                    continue
                available.append(function.artifact_stem)

            code_dir = (
                self.global_config.decompiled_code_dir
                / binary_name
            )
            disk_stems = {
                path.stem for path in code_dir.glob("*.c")
            } if code_dir.exists() else set()
            for xref_name in ("string_xrefs.json", "global_var_xrefs.json"):
                xref_path = code_dir / xref_name
                try:
                    valid_xref = isinstance(
                        json.loads(xref_path.read_text(encoding="utf-8")), dict
                    )
                except (OSError, json.JSONDecodeError):
                    valid_xref = False
                if not valid_xref:
                    problems.append(f"[{xref_name}]")
            expected_set = set(expected)
            result = SemanticCheckResult(
                total_decompiled=len(expected),
                total_snapshots=len(available),
                missing_funcs=sorted(set(problems)),
                # Required assembly was checked above. Other published listings
                # can belong to structural consumers or earlier selections.
                extra_funcs=sorted(disk_stems - expected_set),
            )
            results[binary_name] = result
            logger.info(
                f"CTree integrity for {binary_name}: "
                f"snapshots={result.total_snapshots}/"
                f"{result.total_decompiled}, missing={result.missing_count}, "
                f"extra={result.extra_count}"
            )
        return results
