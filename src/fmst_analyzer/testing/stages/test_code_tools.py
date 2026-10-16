from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional, Tuple

from loguru import logger
from fmst_analyzer.testing.stages._utils import format_fail_detail

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


# A binary known to exist in R6700v3 but NOT in httpd's DT_NEEDED closure.
# Used by Phase 2 to exercise `_resolve_view_adg` rule 2 (ad-hoc peer path).
CROSS_SCOPE_BINARY = "bftpd"


def _pick_test_function(callgraph) -> Optional[str]:
    """Pick a concretized function in `callgraph` that has both callers
    and callees (so all 4 tools have non-empty results to validate)."""
    from fmst_analyzer.graphs.base_graph import EdgeType
    for func_node in callgraph.get_node_for_analysis():
        if not func_node.concretized:
            continue
        callers = callgraph.get_callers_of(func_node)
        callees = list(callgraph.get_successors_by_type(func_node, EdgeType.CALL))
        if callers and callees:
            return func_node.decompiled_name
    return None


def _run_four_tools(
    tool_map: dict,
    binary_name: str,
    function_name: str,
    phase_label: str,
) -> List[str]:
    """Run view_function / view_callers / view_callees / view_code_range
    against (binary_name, function_name) and return a list of issue strings
    (empty on success)."""
    issues: List[str] = []

    result = tool_map["view_function"].invoke({
        "function_name": function_name, "binary_name": binary_name,
    })
    if "not found" in result.lower():
        issues.append(format_fail_detail(f"[{phase_label}] view_function: ", result))
    else:
        logger.debug(f"[TEST]   [{phase_label}] view_function: {len(result)} chars")

    result = tool_map["view_callers"].invoke({
        "function_name": function_name, "binary_name": binary_name,
    })
    if "not onboarded" in result.lower():
        issues.append(format_fail_detail(f"[{phase_label}] view_callers routed wrong view: ", result))
    elif "no callers found" in result.lower():
        issues.append(f"[{phase_label}] view_callers: unexpected no callers")
    elif "callers of" not in result.lower():
        issues.append(format_fail_detail(f"[{phase_label}] view_callers: unexpected format: ", result))
    else:
        logger.debug(f"[TEST]   [{phase_label}] view_callers: {len(result)} chars")

    result = tool_map["view_callees"].invoke({
        "function_name": function_name, "binary_name": binary_name,
    })
    if "not available" in result.lower():
        issues.append(format_fail_detail(f"[{phase_label}] view_callees routed wrong view: ", result))
    elif "no callees found" in result.lower():
        issues.append(f"[{phase_label}] view_callees: unexpected no callees")
    elif "callees of" not in result.lower():
        issues.append(format_fail_detail(f"[{phase_label}] view_callees: unexpected format: ", result))
    else:
        logger.debug(f"[TEST]   [{phase_label}] view_callees: {len(result)} chars")

    result = tool_map["view_code_range"].invoke({
        "function_name": function_name, "binary_name": binary_name,
        "start_line": 1, "end_line": 5,
    })
    if "error" in result.lower() or "no code found" in result.lower():
        issues.append(format_fail_detail(f"[{phase_label}] view_code_range: ", result))
    else:
        logger.debug(f"[TEST]   [{phase_label}] view_code_range: {len(result)} chars")

    return issues


async def test_code_tools(tester: PipelineTester) -> Tuple[bool, str]:
    """Smoke test of view_function, view_callers, view_callees, view_code_range.

    Four phases:
      0. View-resolution identity (no tools): directly assert
         ``view.resolve_view`` and ``LibDepGraph.resolve_view`` 3-rule
         dispatch by ADG identity, plus AnalysisView convenience
         accessors. Catches rule-order regressions that tool-level
         smoke would silently route around.
      1. In-scope (rule 1): pick a function in the anchor ADG's scope,
         run all 4 tools, assert PASS. Exercises the common case.
      2. Cross-scope (rule 2): ad-hoc onboard a binary that is NOT in
         the anchor's scope but has its own per-root ADG, assert rule 2
         identity via ``view.resolve_view``, then run the 4 tools on
         one of its functions. Exercises the fallback used by
         assembly-only Peer Verification Agent.
      3. Unknown binary (rule 3): call view_callers with a bogus
         binary_name, assert the tool returns a "not onboarded" message
         instead of crashing.
    """
    await tester.ensure_analysis_view()

    from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import make_analyzer_tools

    tools = make_analyzer_tools(tester.view)
    tool_map = {t.name: t for t in tools}

    all_issues: List[str] = []
    summary_parts: List[str] = []

    # ------------------------------------------------------------------
    # Phase 0 — direct view-resolution identity checks
    #
    # These assertions prove the 3 rules route to the RIGHT ADG by
    # identity, not just that they return a non-error string. If rule 1
    # and rule 2 were accidentally swapped, Phases 1-3 below would still
    # pass (tools would resolve SOMETHING), but the resolution would be
    # semantically wrong. Phase 0 catches that.
    # ------------------------------------------------------------------
    view = tester.view
    lib_dep_graph = tester.lib_dep_graph

    # AnalysisView wiring: properties delegate to the right backing state
    if view.lib_dep_graph is not lib_dep_graph:
        all_issues.append(
            "[phase0] view.lib_dep_graph is not tester.lib_dep_graph — "
            "AnalysisView convenience property wired to wrong backend"
        )
    if view.adg is not tester.api_dep_graph:
        all_issues.append(
            "[phase0] view.adg is not tester.api_dep_graph"
        )
    if view.root.name != tester.analyzer.target_binary_name:
        all_issues.append(
            f"[phase0] view.root.name={view.root.name!r} != "
            f"target={tester.analyzer.target_binary_name!r}"
        )

    # Rule 1: an in-scope binary resolves back to the anchor ADG itself
    in_scope_name = next(
        iter(tester.api_dep_graph.binary_callgraphs)
    ).name
    rule1_adg = view.resolve_view(in_scope_name)
    if rule1_adg is not view.adg:
        all_issues.append(
            f"[phase0] rule 1: view.resolve_view({in_scope_name!r}) "
            f"should return the anchor ADG, got {rule1_adg!r}"
        )

    # Rule 3: a bogus name resolves to None (no node → not onboarded)
    rule3_adg = view.resolve_view("nonexistent_binary_xyz_phase0")
    if rule3_adg is not None:
        all_issues.append(
            f"[phase0] rule 3: view.resolve_view('nonexistent_...') "
            f"should return None, got {rule3_adg!r}"
        )

    # prefer=None path: without a preferred anchor, rule 1 never fires,
    # so an in-scope-but-not-a-root binary should resolve to None.
    if in_scope_name != view.root.name:
        no_prefer = lib_dep_graph.resolve_view(in_scope_name, prefer=None)
        if no_prefer is not None:
            all_issues.append(
                f"[phase0] prefer=None: resolve_view({in_scope_name!r}) "
                f"should be None for a non-root in-scope binary, "
                f"got {no_prefer!r}"
            )

    # prefer=None on the analysis root itself: the root IS in
    # `_semantic_adgs`, so it should resolve via rule 2 to its own ADG
    # even without a prefer hint.
    root_no_prefer = lib_dep_graph.resolve_view(
        view.root.name, prefer=None,
    )
    if root_no_prefer is not view.adg:
        all_issues.append(
            f"[phase0] prefer=None: resolve_view(root) should return "
            f"the root's own ADG via rule 2, got {root_no_prefer!r}"
        )

    logger.info(
        f"[TEST]   Phase 0 view-resolution identity: "
        f"{'PASS' if not all_issues else f'{len(all_issues)} issues'}"
    )
    summary_parts.append("phase0=identity-checks")

    # ------------------------------------------------------------------
    # Phase 1 — in-scope (rule 1)
    # ------------------------------------------------------------------
    in_scope_func = None
    in_scope_binary = None
    for bin_node, cg in tester.api_dep_graph.binary_callgraphs.items():
        fn = _pick_test_function(cg)
        if fn is not None:
            in_scope_func = fn
            in_scope_binary = bin_node.name
            break

    if in_scope_func is None:
        return False, "no in-scope function with both callers and callees found"

    logger.info(
        f"[TEST]   Phase 1 (in-scope / rule 1): "
        f"{in_scope_binary}::{in_scope_func}"
    )
    p1_issues = _run_four_tools(
        tool_map, in_scope_binary, in_scope_func, phase_label="in-scope",
    )
    all_issues.extend(p1_issues)
    summary_parts.append(f"in-scope={in_scope_binary}::{in_scope_func}")

    # ------------------------------------------------------------------
    # Phase 2 — cross-scope (rule 2)
    # ------------------------------------------------------------------
    peer_path = tester.binary_name2path.get(CROSS_SCOPE_BINARY)
    if peer_path is None:
        logger.warning(
            f"[TEST]   {CROSS_SCOPE_BINARY} not in rootfs, "
            f"skipping cross-scope phase"
        )
    else:
        logger.info(
            f"[TEST]   Phase 2 (cross-scope / rule 2): "
            f"ad-hoc onboarding {CROSS_SCOPE_BINARY}"
        )
        tester.lib_dep_graph.add_binary(peer_path)
        peer_node = tester.lib_dep_graph.get_node_by_name(CROSS_SCOPE_BINARY)
        if peer_node is None:
            all_issues.append(
                f"[cross-scope] add_binary succeeded but node not found"
            )
        else:
            await tester.lib_dep_graph.decompile_analysis(
                peer_node,
            )
            # Sanity: the peer is NOT in anchor's scope (rule 2 territory),
            # and it IS in _semantic_adgs (as an independent analysis root).
            if peer_node in tester.api_dep_graph.scope:
                logger.warning(
                    f"[TEST]   {CROSS_SCOPE_BINARY} is in anchor scope — "
                    f"rule 1 path, not rule 2. Skipping cross-scope assertion."
                )
            elif peer_node not in tester.lib_dep_graph._semantic_adgs:
                all_issues.append(
                    f"[cross-scope] {CROSS_SCOPE_BINARY} onboarded but "
                    f"has no ADG in _semantic_adgs"
                )
            else:
                # Rule 2 identity check: view.resolve_view(peer) must
                # return the peer's OWN per-root ADG, not the anchor.
                # This is the one assertion that proves rule 2 actually
                # fired — view_callers below would work either way.
                rule2_adg = view.resolve_view(CROSS_SCOPE_BINARY)
                expected = tester.lib_dep_graph._semantic_adgs[peer_node]
                if rule2_adg is view.adg:
                    all_issues.append(
                        f"[cross-scope] rule 2: resolve_view({CROSS_SCOPE_BINARY}) "
                        f"incorrectly returned the anchor ADG — rule 1 fired "
                        f"when it shouldn't have"
                    )
                elif rule2_adg is not expected:
                    all_issues.append(
                        f"[cross-scope] rule 2: resolve_view({CROSS_SCOPE_BINARY}) "
                        f"returned {rule2_adg!r}, expected peer's own ADG "
                        f"{expected!r}"
                    )

                peer_cg = tester.lib_dep_graph.get_callgraph_by_name(CROSS_SCOPE_BINARY)
                peer_func = _pick_test_function(peer_cg) if peer_cg else None
                if peer_func is None:
                    all_issues.append(
                        f"[cross-scope] no suitable function in {CROSS_SCOPE_BINARY}"
                    )
                else:
                    logger.info(
                        f"[TEST]   Phase 2 testing: {CROSS_SCOPE_BINARY}::{peer_func}"
                    )
                    p2_issues = _run_four_tools(
                        tool_map, CROSS_SCOPE_BINARY, peer_func,
                        phase_label="cross-scope",
                    )
                    all_issues.extend(p2_issues)
                    summary_parts.append(
                        f"cross-scope={CROSS_SCOPE_BINARY}::{peer_func}"
                    )

    # ------------------------------------------------------------------
    # Phase 3 — unknown binary (rule 3)
    # ------------------------------------------------------------------
    bogus = "nonexistent_binary_xyz_12345"
    logger.info(f"[TEST]   Phase 3 (rule 3): view_callers on {bogus!r}")
    result = tool_map["view_callers"].invoke({
        "function_name": "main", "binary_name": bogus,
    })
    if "not onboarded" not in result.lower():
        all_issues.append(
            format_fail_detail(
                "[rule-3] view_callers on bogus binary should say 'not onboarded', got: ",
                result,
            )
        )
    else:
        logger.debug(f"[TEST]   Phase 3 OK: {result[:80]}")
    summary_parts.append("rule3=onboarded-guard")

    if all_issues:
        return False, f"{len(all_issues)} failures:\n" + "\n".join(all_issues)
    return True, " | ".join(summary_parts)
