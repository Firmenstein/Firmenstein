"""Regression tests for complete, deterministic view_callers output."""
from dotenv import load_dotenv
load_dotenv()

from types import SimpleNamespace


def test_view_callers_sorts_caller_entries_lex():
    from fmst_analyzer.analysis.base.code_analyzer.code_tools import (
        analyzer_tools as at_module,
    )
    fn_node = SimpleNamespace(name="api", decompiled_name="api")
    def _has(name): return name == "api"
    def _get(name):
        if name == "api":
            return fn_node
        raise ValueError(name)
    def _callers_of(fn):
        # Anti-sorted order: z, a, m
        return [
            SimpleNamespace(decompiled_name="z_caller",
                            get_callsites=lambda: {
                                "k": SimpleNamespace(callee_name="api",
                                                     line_number=100)}),
            SimpleNamespace(decompiled_name="a_caller",
                            get_callsites=lambda: {
                                "k": SimpleNamespace(callee_name="api",
                                                     line_number=50)}),
            SimpleNamespace(decompiled_name="m_caller",
                            get_callsites=lambda: {
                                "k": SimpleNamespace(callee_name="api",
                                                     line_number=200)}),
        ]
    cg = SimpleNamespace(
        has_node_by_name=_has, get_node_by_name=_get,
        get_callers_of=_callers_of,
    )

    # BinaryNode stand-in: must be hashable to serve as a dict key in
    # binary_callgraphs. SimpleNamespace isn't, so use a tiny class.
    class _Bin:
        def __init__(self, name): self.name = name
    bin_node = _Bin("libfoo.so")
    adg = SimpleNamespace(binary_callgraphs={bin_node: cg})
    view = SimpleNamespace(
        resolve_view=lambda bn: adg if bn == "libfoo.so" else None,
        get_full_code=lambda bn, fn: "int fn() { return 0; }\n" * 10,
        lib_dep_graph=SimpleNamespace(get_callgraph_by_name=lambda bn: cg),
    )

    tools = at_module.make_analyzer_tools(view=view)
    view_callers = next(t for t in tools if t.name == "view_callers")
    result = view_callers.invoke(
        {"function_name": "api", "binary_name": "lib/libfoo.so"})

    a_pos = result.index("a_caller")
    m_pos = result.index("m_caller")
    z_pos = result.index("z_caller")
    assert a_pos < m_pos < z_pos, (
        f"Callers not lex-sorted. a={a_pos} m={m_pos} z={z_pos}\n{result}"
    )


def test_view_callers_includes_every_callsite_from_one_caller():
    from fmst_analyzer.analysis.base.code_analyzer.code_tools import (
        analyzer_tools as at_module,
    )

    fn_node = SimpleNamespace(name="api", decompiled_name="api")
    callsites = {
        41: SimpleNamespace(
            callee_name="api", line_number=12, column_number=4,
            ctree_index=41, source_ea=0x1010,
        ),
        42: SimpleNamespace(
            callee_name="api", line_number=12, column_number=18,
            ctree_index=42, source_ea=0x1014,
        ),
        43: SimpleNamespace(
            callee_name="api", line_number=24, column_number=8,
            ctree_index=43, source_ea=0x1040,
        ),
        99: SimpleNamespace(
            callee_name="other", line_number=30, column_number=2,
            ctree_index=99, source_ea=0x1080,
        ),
    }
    caller = SimpleNamespace(
        decompiled_name="multi_caller",
        get_callsites=lambda: callsites,
    )
    callgraph = SimpleNamespace(
        has_node_by_name=lambda name: name == "api",
        get_node_by_name=lambda name: fn_node,
        get_callers_of=lambda function: [caller],
    )

    class _Bin:
        name = "libfoo.so"

    adg = SimpleNamespace(binary_callgraphs={_Bin(): callgraph})
    code = "\n".join(f"line_{line}" for line in range(1, 41))
    view = SimpleNamespace(
        resolve_view=lambda binary: adg,
        get_full_code=lambda binary, function: code,
        lib_dep_graph=SimpleNamespace(
            get_callgraph_by_name=lambda binary: callgraph,
        ),
    )

    tools = at_module.make_analyzer_tools(view=view)
    view_callers = next(tool for tool in tools if tool.name == "view_callers")
    result = view_callers.invoke({
        "function_name": "api",
        "binary_name": "libfoo.so",
    })

    assert "located 3 matching callsites" in result
    assert "L12:C4, ctree=41, EA=0x1010" in result
    assert "L12:C18, ctree=42, EA=0x1014" in result
    assert "L24:C8, ctree=43, EA=0x1040" in result
    assert "ctree=99" not in result
