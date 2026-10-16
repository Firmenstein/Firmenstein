from __future__ import annotations
from typing import TYPE_CHECKING, Tuple

from loguru import logger

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_tools(tester: PipelineTester) -> Tuple[bool, str]:
    """Smoke test of view_global tool data path."""
    await tester.ensure_analysis_view()

    from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import make_analyzer_tools
    tools = make_analyzer_tools(tester.view)
    view_global = next(t for t in tools if t.name == "view_global")

    # Collect sample GVar names from function globals across all binaries
    test_cases = []
    for bin_node, cg in tester.api_dep_graph.binary_callgraphs.items():
        for func_node in cg.get_node_for_analysis():
            if not func_node.concretized:
                continue
            for ea, name in func_node._global_vars.items():
                test_cases.append((f"GVar_{name}", bin_node.name))
                if len(test_cases) >= 10:
                    break
            if len(test_cases) >= 10:
                break
        if len(test_cases) >= 10:
            break

    if not test_cases:
        return False, "no global variables found to test — cannot validate tools"

    issues = []
    type_markers = ["(string)", "(integer)", "(address", "(runtime variable"]

    for gvar_name, binary_name in test_cases:
        result = view_global.invoke({
            "variable_name": gvar_name,
            "binary_name": binary_name,
        })
        if "not found" in result:
            issues.append(f"{gvar_name}: {result}")
        elif not any(marker in result for marker in type_markers):
            issues.append(f"{gvar_name}: unexpected format: {result}")
        else:
            logger.debug(f"[TEST]   {gvar_name}: {result}")

    if issues:
        return False, f"{len(issues)} tool failures:\n" + "\n".join(issues[:5])
    return True, f"{len(test_cases)} view_global queries passed"
