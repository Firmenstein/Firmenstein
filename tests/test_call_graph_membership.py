"""Repeated thunk membership must not duplicate analysis or published artifacts."""
from types import SimpleNamespace

import networkx as nx
import pytest

from fmst_analyzer.graphs.base_graph import Recursion
from fmst_analyzer.graphs.call_graph import CallGraph, CALL_GRAPH_CACHE_SCHEMA_VERSION
from fmst_analyzer.nodes.function import FunctionNode, FunctionAttr


class FixtureFunction(FunctionNode):
    def __init__(self, ea, name, *, thunk=False):
        self._ea, self._name = ea, name
        self.thunk, self.concretizations = thunk, 0
        self._global_vars = {}
        self.semantic_snapshot = SimpleNamespace(rendered_code="int fixture(void) { return 0; }\n")

    ea = property(lambda self: self._ea)
    name = property(lambda self: self._name)
    decompiled_name = property(lambda self: self._name)
    module = property(lambda self: "fixture")
    concretized = property(lambda self: True)

    def has_attr(self, attr):
        return attr == FunctionAttr.TEXT or (self.thunk and attr == FunctionAttr.THUNK)

    def activate(self): pass
    def concretize(self): self.concretizations += 1
    def get_callees(self): return []
    def get_processed_decompiled_code(self, **kwargs): return self.semantic_snapshot.rendered_code


# The fixtures exercise collection/publication without a native decompiler.
FixtureFunction.__abstractmethods__ = frozenset()


def test_thunk_seen_before_its_target_is_analyzed_once(monkeypatch):
    target = FixtureFunction(0x1000, "target")
    thunk = FixtureFunction(0x2000, "j_target", thunk=True)
    binary = SimpleNamespace(name="fixture", all_funcs={target.ea: target, thunk.ea: thunk},
        find_thunk_target=lambda node: target if node is thunk else None,
        find_thunk_funcs=lambda node: [thunk] if node is target else [],
        resolve_all_global_values=lambda values: None)
    graph = CallGraph(binary)
    graph._reverse_topological_sorted_nodes = [Recursion([thunk, target])]
    monkeypatch.setattr(FunctionNode, "close_database", lambda: None)
    graph.deep_analysis(SimpleNamespace(transitive_closure_from=lambda node: []))
    assert graph.get_node_for_analysis() == [thunk, target]
    assert thunk.concretizations == target.concretizations == 1


@pytest.mark.parametrize("names,stems", [
    (("same", "same"), ("same", "same@2000")),
    (("SYSTEM", "system"), ("SYSTEM", "system@2000")),
])
def test_cached_duplicate_membership_preserves_distinct_function_artifacts(tmp_path, names, stems):
    first, second = [FixtureFunction(ea, name) for ea, name in zip((0x1000, 0x2000), names)]
    graph = CallGraph(None)
    graph.__setstate__({"cache_schema_version": CALL_GRAPH_CACHE_SCHEMA_VERSION,
        "graph_data": nx.node_link_data(nx.DiGraph([(first, second)]), edges="edges"),
        "global_config": None, "external_funcs": [], "reverse_topological_sorted_nodes": [first, second],
        "nodes_for_analysis": [second, first, second], "_decompiled_name_map": {},
        "structural_complete": True, "semantic_complete": True})
    graph.binary_node = SimpleNamespace(name="fixture", all_funcs={first.ea: first, second.ea: second},
                                        get_function_by_name=lambda name: None)
    graph._assign_artifact_stems()
    graph._build_decompiled_name_map()
    graph.dump_decompiled_code(tmp_path)
    assert graph.get_node_for_analysis() == [second, first]
    assert (first.artifact_stem, second.artifact_stem) == stems
    assert {p.stem for p in (tmp_path / "fixture").glob("*.c")} == set(stems)
    for node in (first, second):
        assert graph.get_node_by_name(node.artifact_stem) is node
        assert (tmp_path / "fixture" / (node.artifact_stem + ".c")).read_text() == node.semantic_snapshot.rendered_code
