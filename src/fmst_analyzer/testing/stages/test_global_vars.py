from __future__ import annotations
from typing import TYPE_CHECKING, Tuple

from loguru import logger

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_global_vars(tester: PipelineTester) -> Tuple[bool, str]:
    """Verify resolve_all_global_values coverage AND value quality.

    The invariant is membership: every function-level reference must have a
    registered entry. ``unresolved`` values are an explicit, valid result
    for externals, linker metadata and addresses whose bytes cannot be
    interpreted as a scalar. Later analyzers keep those aliases as missing
    evidence; this smoke stage must not turn conservative uncertainty into a
    graph-build failure.
    """
    await tester.ensure_graphs()

    missing_issues = []
    unresolved_count = 0
    total_resolved = 0
    total_func_refs = 0
    covered_refs = 0

    for bin_node, cg in tester.api_dep_graph.binary_callgraphs.items():
        gvar_values = bin_node._global_var_values
        total_resolved += len(gvar_values)

        # Report type distribution
        by_type = {}
        for name, (vtype, _) in gvar_values.items():
            by_type[vtype] = by_type.get(vtype, 0) + 1
        type_summary = ", ".join(f"{t}:{c}" for t, c in sorted(by_type.items()))
        logger.info(f"[TEST]   {bin_node.name}: {len(gvar_values)} globals ({type_summary})")

        for func_node in cg.get_node_for_analysis():
            if not func_node.concretized:
                continue
            for ea, name in func_node._global_vars.items():
                total_func_refs += 1
                if name not in gvar_values:
                    # With the defense-in-depth registration, this
                    # branch should never fire. If it does, the alias
                    # collection in resolve_all_global_values has a
                    # gap — a real regression.
                    missing_issues.append(
                        f"{bin_node.name}::{func_node.decompiled_name}: "
                        f"GVar_{name} (0x{ea:x}) not resolved"
                    )
                    continue
                covered_refs += 1
                vtype, vdetail = gvar_values[name]
                if vtype == "unresolved":
                    unresolved_count += 1

    if total_func_refs == 0:
        return False, "no function-level global var references found — cannot validate coverage"

    detail = (
        f"{total_resolved} globals, {covered_refs}/{total_func_refs} func refs covered"
    )

    if missing_issues:
        return False, (
            detail + f"; {len(missing_issues)} missing (defense-in-depth "
            f"breach — alias collection has a gap):\n"
            + "\n".join(missing_issues[:10])
        )

    if unresolved_count:
        detail += f"; {unresolved_count} unresolved values retained as missing evidence"
    return True, detail
