"""Numerical checks do not inherit host integer widths or execute expressions."""
import json

import pytest

from fmst_analyzer.analysis.base.code_analyzer.code_tools.integer_evaluation import evaluate_integer_cases


def test_branchless_comparison_and_storage_offsets():
    result = json.loads(evaluate_integer_cases.func("(status != 10) - 1", [{"status": 10}, {"status": 0}, {"status": -1}]))
    assert [case["result"] for case in result["cases"]] == [-1, 0, 0]
    assert json.loads(evaluate_integer_cases.func("0x34 - 0x20", [{}]))["cases"][0]["result"] == 20


def test_guest_width_is_explicit():
    assert json.loads(evaluate_integer_cases.func("(value + 1) & 0xffffffff", [{"value": 0xffffffff}]))["cases"][0]["result"] == 0
    assert json.loads(evaluate_integer_cases.func("value + 1", [{"value": 0xffffffff}]))["cases"][0]["result"] == 0x100000000


@pytest.mark.parametrize("expression", ["__import__('os')", "x.real", "x[0]", "2 ** 1000000", "1 << 1000000", "x / 2", "True"])
def test_unsupported_or_unbounded_operations_are_rejected(expression):
    with pytest.raises(ValueError):
        evaluate_integer_cases.func(expression, [{"x": 1}])
