"""Pure integer calculation for checking source-derived numeric claims."""
import ast
import json
import operator

from fmst_basic.agent.tool import tool


_BINARY = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor,
    ast.LShift: operator.lshift, ast.RShift: operator.rshift,
}
_COMPARE = {
    ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt,
    ast.LtE: operator.le, ast.Gt: operator.gt, ast.GtE: operator.ge,
}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Invert: operator.invert}


def _integer(value):
    if type(value) is not int or value.bit_length() > 4096:
        raise ValueError("Expected an integer with at most 4096 bits")
    return value


def _evaluate(node, bindings):
    if isinstance(node, ast.Constant):
        return _integer(node.value)
    if isinstance(node, ast.Name):
        if node.id not in bindings:
            raise ValueError(f"Missing integer binding: {node.id}")
        return _integer(bindings[node.id])
    if isinstance(node, ast.UnaryOp) and type(node.op) in _UNARY:
        return _integer(_UNARY[type(node.op)](_evaluate(node.operand, bindings)))
    if isinstance(node, ast.BinOp) and type(node.op) in _BINARY:
        left, right = _evaluate(node.left, bindings), _evaluate(node.right, bindings)
        if isinstance(node.op, (ast.LShift, ast.RShift)) and not 0 <= right <= 4096:
            raise ValueError("Shift count must be between 0 and 4096")
        return _integer(_BINARY[type(node.op)](left, right))
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in _COMPARE:
        return int(_COMPARE[type(node.ops[0])](_evaluate(node.left, bindings),
                                              _evaluate(node.comparators[0], bindings)))
    raise ValueError("Unsupported integer expression; calls, attributes, indexing and implicit C casts are not evaluated")


@tool
def evaluate_integer_cases(expression: str, cases: list[dict[str, int]]) -> str:
    """Check numerical cases of an expression recovered from source or assembly.

    Useful for branchless return arithmetic, comparisons, masks and byte-offset
    differences that are easy to reverse when described in prose. Supply the
    exact recovered expression using decimal/hex integer literals, variable
    names, parentheses, + - * ~ & | ^ << >> and single comparisons == != < <= > >=.
    Comparisons yield integer 0 or 1. Each case supplies the variable values;
    use [{}] for a constant expression. At most 32 cases and 128 AST nodes.

    This is mathematical integer arithmetic, not a C interpreter: there is no
    implicit guest width, signed overflow, division, C suffix/cast or memory
    model. Express a verified unsigned wrap with an explicit mask. The result
    verifies the calculation only; source citations must separately establish
    the expression, operand provenance, widths and feasible cases. No code is
    executed and no filesystem, process or network is accessed.
    """
    if not 1 <= len(cases) <= 32 or len(expression) > 2048:
        raise ValueError("Provide 1..32 cases and an expression of at most 2048 characters")
    tree = ast.parse(expression, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > 128:
        raise ValueError("Expression exceeds 128 AST nodes")
    return json.dumps({"expression": expression, "semantics": "mathematical integers; comparisons are 0/1",
        "cases": [{"bindings": values, "result": _evaluate(tree.body, values)} for values in cases]},
        ensure_ascii=False, indent=2)
