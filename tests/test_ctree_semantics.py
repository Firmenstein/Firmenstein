"""Unit-level contracts for the CTree semantic replacement."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv
import pytest

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fmst_analyzer.nodes.callsite import CallSite
from fmst_analyzer.nodes.decompiler.ida.text_renderer import render_line
from fmst_analyzer.nodes.semantic import (
    SEMANTIC_RENDERER_VERSION,
    SEMANTIC_SNAPSHOT_SCHEMA_VERSION,
    SUPPORTED_IDA_DOMAIN_VERSION,
    CTreeLocation,
    CallsiteArgInfo,
    CallsiteInfo,
    FunctionSemanticSnapshot,
    PropagationTarget,
    VariablePropInfo,
    VariablePropResult,
)


def _variable(
    name: str,
    *,
    identity: str,
    flows_to=(),
    flows_from=(),
) -> VariablePropInfo:
    return VariablePropInfo(
        varname=name,
        is_parameter=False,
        is_global=False,
        is_return_value=False,
        affects_return_value=False,
        declaration_line=1,
        param_index=-1,
        usage_lines=[2],
        flows_to=list(flows_to),
        flows_from=list(flows_from),
        callsite_args=[],
        identity=identity,
    )


def _snapshot(variables) -> FunctionSemanticSnapshot:
    return FunctionSemanticSnapshot(
        schema_version=SEMANTIC_SNAPSHOT_SCHEMA_VERSION,
        renderer_version=SEMANTIC_RENDERER_VERSION,
        ida_version="9.2",
        ida_domain_version=SUPPORTED_IDA_DOMAIN_VERSION,
        binary_identity="fixture:sha256",
        idb_identity="/tmp/fixture.i64",
        function_ea=0x1000,
        snapshot_hash="snapshot",
        raw_pseudocode_hash="raw",
        raw_code="int f(void) {}",
        rendered_code_hash="rendered",
        rendered_code="int f(void) {}",
        callsites={},
        variables=variables,
    )


class TestLinePreservingRenderer(unittest.TestCase):
    def test_offsets_follow_length_changing_replacements(self):
        import re

        raw = "  __int32 value = global_counter + leaf(value);"
        rendered = render_line(
            raw,
            [
                (re.compile(r"\b__int32\b"), "int"),
                (re.compile(r"\bglobal_counter\b"), "GVar_global_counter"),
            ],
        )
        leaf_raw = raw.index("leaf")
        self.assertEqual(
            rendered.text,
            "  int value = GVar_global_counter + leaf(value);",
        )
        self.assertEqual(
            rendered.rendered_column(leaf_raw), rendered.text.index("leaf")
        )

    def test_renderer_never_changes_line_boundaries(self):
        import re

        lines = ["__int32 a;", "a = G;", "return a;"]
        rendered = [
            render_line(
                line,
                [
                    (re.compile(r"\b__int32\b"), "int"),
                    (re.compile(r"\bG\b"), "GVar_G"),
                ],
            ).text
            for line in lines
        ]
        self.assertEqual(len(rendered), len(lines))


class TestSemanticPropagation(unittest.TestCase):
    def test_assignment_cycle_terminates_and_keeps_direct_edges(self):
        first_to_second = PropagationTarget(
            code="second", name="second", type="IDENTIFIER", line=3
        )
        second_to_first = PropagationTarget(
            code="first", name="first", type="IDENTIFIER", line=4
        )
        snapshot = _snapshot(
            {
                "first": [
                    _variable(
                        "first",
                        identity="lvar:1",
                        flows_to=[first_to_second],
                        flows_from=[second_to_first],
                    )
                ],
                "second": [
                    _variable(
                        "second",
                        identity="lvar:2",
                        flows_to=[second_to_first],
                        flows_from=[first_to_second],
                    )
                ],
            }
        )
        result = snapshot.trace_variable_prop("flow_cycle", "first")
        self.assertEqual(
            [variable.varname for variable in result.variables],
            ["first", "second"],
        )
        self.assertEqual(result.variables[0].flows_to, [first_to_second])

    def test_complex_expression_is_terminal(self):
        expression = PropagationTarget(
            code="input + 1", name="", type="EXPR", line=2
        )
        snapshot = _snapshot(
            {
                "output": [
                    _variable(
                        "output", identity="lvar:1", flows_from=[expression]
                    )
                ]
            }
        )
        result = snapshot.trace_variable_prop("mixed_rhs", "output")
        self.assertEqual(len(result.variables), 1)
        self.assertEqual(result.variables[0].flows_from[0].type, "EXPR")

    def test_duplicate_display_name_is_explicitly_ambiguous(self):
        snapshot = _snapshot(
            {
                "value": [
                    _variable("value", identity="lvar:1"),
                    _variable("value", identity="lvar:2"),
                ]
            }
        )
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            snapshot.trace_variable_prop("ambiguous", "value")


class TestAnalysisViewFacade(unittest.TestCase):
    def test_trace_variables_is_synchronous_and_uses_local_semantics(self):
        literal = PropagationTarget(
            code='"/etc/config"',
            name="",
            type="LITERAL_STRING",
            line=2,
        )
        record = _variable(
            "path", identity="lvar:1", flows_from=[literal]
        )
        semantic_result = VariablePropResult(
            func_name="load_config",
            initial_var="path",
            variables=[record],
        )
        fake_view = SimpleNamespace(
            _trace_variable_prop=lambda **kwargs: semantic_result,
        )

        from fmst_analyzer.analysis.base.code_analyzer.analysis_view import (
            AnalysisView,
        )
        from fmst_analyzer.analysis.base.code_analyzer.dataflow.types import (
            VariableNodeType,
        )

        trace = AnalysisView.trace_variables.__get__(
            fake_view, type(fake_view)
        )
        graph = trace(
            "service", "load_config", "path", direction="backward"
        )

        self.assertIsNotNone(
            graph.get_node("service", "load_config", "path")
        )
        literals = [
            node for node in graph.nodes
            if node.node_type is VariableNodeType.LITERAL_STRING
        ]
        self.assertEqual(
            [node.literal_value for node in literals], ['"/etc/config"']
        )


class TestCallsiteIdentity(unittest.TestCase):
    def test_wrapped_cast_call_retains_verified_continuation_anchor(self):
        pytest.importorskip("idapro", reason="CTree visitor requires the optional SDK")
        from fmst_analyzer.nodes.decompiler.ida.ctree_visitor import CTreeVisitor

        visitor = object.__new__(CTreeVisitor)
        visitor.func_name = "wrapped_call"
        line = "          | mask & (unsigned int)fallback))("
        anchor = line.index("fallback")
        expression = (
            "((int (*)(int))((unsigned int)primary & ~mask "
            "| mask & (unsigned int)fallback))(value)"
        )
        self.assertEqual(
            visitor._expression_start_column(line, expression, anchor),
            anchor,
        )

    def test_long_string_call_uses_nearest_preceding_callee_line(self):
        pytest.importorskip("idapro", reason="CTree visitor requires the optional SDK")
        from fmst_analyzer.nodes.decompiler.ida.ctree_visitor import CTreeVisitor

        visitor = object.__new__(CTreeVisitor)
        visitor.func_name = "main"
        visitor._raw_lines = [
            '  log_message("first literal "',
            '              "continued literal");',
        ]
        self.assertEqual(
            visitor._expression_start_coordinate(
                'log_message("first literal continued literal")', 2, 14
            ),
            (1, 2),
        )

    def test_snapshot_integrity_accepts_split_string_at_callee(self):
        snapshot = _snapshot({})
        snapshot.raw_code = '  log_message("first "\n              "second");'
        snapshot.rendered_code = snapshot.raw_code
        snapshot.callsites = {
            9: CallsiteInfo(
                line_number=1,
                column_number=2,
                arguments=[],
                ctree_index=9,
                callee_name="log_message",
                callee_ea=0x2000,
                call_kind="direct",
                location=CTreeLocation(
                    binary_identity=snapshot.binary_identity,
                    function_ea=snapshot.function_ea,
                    snapshot_hash=snapshot.snapshot_hash,
                    ctree_index=9,
                    opcode=57,
                    source_ea=0x1010,
                    ida_line=2,
                    ida_column=14,
                    line_number=1,
                    column_number=2,
                    expression_text='log_message("first second")',
                ),
            )
        }
        self.assertEqual(snapshot.integrity_errors(), [])

    @staticmethod
    def _callsite(ctree_index: int) -> CallSite:
        return CallSite(
            binary_name="service",
            caller_ea=0x1000,
            caller_name="caller",
            callee_ea=0x2000,
            callee_name="callee",
            callsite_ea=0x1010,
            line_number=8,
            column_number=12,
            binary_identity="/rootfs/bin/service:sha",
            snapshot_hash="snapshot",
            ctree_index=ctree_index,
        )

    def test_same_line_and_ea_remain_distinct(self):
        first = self._callsite(10)
        second = self._callsite(11)
        self.assertNotEqual(first, second)
        self.assertEqual(len({first, second}), 2)
        self.assertEqual(first.key, 10)

    def test_callsite_query_is_stably_ordered_by_ctree_index(self):
        from types import SimpleNamespace

        from fmst_analyzer.analysis.base.code_analyzer.analysis_view import (
            AnalysisView,
        )

        caller = SimpleNamespace(get_callsites=lambda: {
            20: SimpleNamespace(ctree_index=20, callee_name="leaf"),
            10: SimpleNamespace(ctree_index=10, callee_name="leaf"),
            30: SimpleNamespace(ctree_index=30, callee_name="other"),
        })
        result = AnalysisView.get_callsites_to(caller, "leaf")
        self.assertEqual(
            [callsite.ctree_index for callsite in result], [10, 20]
        )

    def test_snapshot_integrity_accepts_multiline_call_anchor(self):
        snapshot = _snapshot({})
        snapshot.raw_code = "  value = callee(\n    first, second);"
        snapshot.rendered_code = snapshot.raw_code
        snapshot.callsites = {
            7: CallsiteInfo(
                line_number=1,
                column_number=10,
                arguments=[
                    CallsiteArgInfo(1, "LOCAL", "first", "first"),
                    CallsiteArgInfo(2, "LOCAL", "second", "second"),
                ],
                ctree_index=7,
                callee_name="callee",
                callee_ea=0x2000,
                call_kind="direct",
                location=CTreeLocation(
                    binary_identity=snapshot.binary_identity,
                    function_ea=snapshot.function_ea,
                    snapshot_hash=snapshot.snapshot_hash,
                    ctree_index=7,
                    opcode=57,
                    source_ea=0x1010,
                    ida_line=1,
                    ida_column=16,
                    line_number=1,
                    column_number=10,
                    expression_text="callee(first, second)",
                ),
            )
        }
        self.assertEqual(snapshot.integrity_errors(), [])

        snapshot.callsites[7].arguments[1] = CallsiteArgInfo(
            3, "LOCAL", "second", "second"
        )
        self.assertTrue(
            any("argument indexes" in error for error in snapshot.integrity_errors())
        )

    def test_snapshot_integrity_accepts_multiline_cast_call_anchor(self):
        snapshot = _snapshot({})
        expression = "((int (*)(int))callback)(value)"
        snapshot.raw_code = "  return ((int (*)(int))callback)(\n    value);"
        snapshot.rendered_code = snapshot.raw_code
        snapshot.callsites = {
            8: CallsiteInfo(
                line_number=1,
                column_number=9,
                arguments=[CallsiteArgInfo(1, "LOCAL", "value", "value")],
                ctree_index=8,
                callee_name="indirect_call_ctree_8",
                callee_ea=None,
                call_kind="indirect",
                location=CTreeLocation(
                    binary_identity=snapshot.binary_identity,
                    function_ea=snapshot.function_ea,
                    snapshot_hash=snapshot.snapshot_hash,
                    ctree_index=8,
                    opcode=57,
                    source_ea=0x1010,
                    ida_line=1,
                    ida_column=33,
                    line_number=1,
                    column_number=9,
                    expression_text=expression,
                ),
            )
        }
        self.assertEqual(snapshot.integrity_errors(), [])


if __name__ == "__main__":
    unittest.main()
