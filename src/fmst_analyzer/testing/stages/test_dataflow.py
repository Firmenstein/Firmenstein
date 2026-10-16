from __future__ import annotations
import re
from typing import TYPE_CHECKING, Tuple

from loguru import logger

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


async def test_dataflow(tester: PipelineTester) -> Tuple[bool, str]:
    """Smoke test of local semantic dataflow across function boundaries."""
    await tester.ensure_analysis_view()

    from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import make_analyzer_tools

    tools = make_analyzer_tools(tester.view)
    trace_variable = next(t for t in tools if t.name == "trace_variable")

    # Collect candidates: concretized functions with callers and a real parameter.
    MAX_CANDIDATES = 10
    candidates = []
    for bin_node, cg in tester.api_dep_graph.binary_callgraphs.items():
        for func_node in cg.get_node_for_analysis():
            if not func_node.concretized:
                continue
            callers = cg.get_callers_of(func_node)
            if not callers:
                continue
            # Extract first parameter name from prototype
            try:
                code = tester.view.get_full_code(
                    bin_node.name, func_node.artifact_stem
                )
                first_line = code.split('\n')[0] if code else ''
            except FileNotFoundError:
                continue
            # Skip void/empty parameter lists — no variable to trace
            match = re.search(r'\(([^)]*)\)', first_line)
            if not match:
                continue
            params_str = match.group(1).strip()
            if not params_str or params_str == 'void':
                continue
            # Try to parse the first parameter name
            first_param = params_str.split(',')[0].strip()
            candidate = first_param.split()[-1].lstrip('*')
            if candidate and re.match(r'^[a-zA-Z_]\w*$', candidate) and candidate != 'void':
                var_name = candidate
            else:
                # Fallback for complex signatures (function pointers, arrays, etc.)
                # IDA typically names parameters a1, a2, ...
                var_name = 'a1'
            candidates.append((bin_node.name, func_node.artifact_stem, var_name))
            if len(candidates) >= MAX_CANDIDATES:
                break
        if len(candidates) >= MAX_CANDIDATES:
            break

    if not candidates:
        return False, "no function with callers and parameters found — cannot validate dataflow"

    # Try candidates until one produces cross-function results (>= 2 functions)
    for test_binary, test_func, test_var in candidates:
        logger.info(f"[TEST]   Trying '{test_var}' in {test_binary}::{test_func}")

        result = await trace_variable.ainvoke({
            "variable_name": test_var,
            "function_name": test_func,
            "direction": "both",
            "binary_name": test_binary,
            "max_depth": 2,
        })

        if "DataFlow tracing failed" in result or "No dataflow found" in result:
            continue
        if "usage sites in" not in result:
            continue

        header = result.splitlines()[0]
        func_count_match = re.search(r'(\d+)\s+functions', header)
        if not func_count_match:
            continue
        func_count = int(func_count_match.group(1))
        if func_count < 2:
            logger.debug(f"[TEST]   Skipped (single function): {test_func}")
            continue

        logger.info(f"[TEST]   trace_variable result: {header}")
        return True, f"dataflow trace passed: {header}"

    return False, (
        f"tried {len(candidates)} candidates, none produced cross-function dataflow (>= 2 functions)"
    )
