"""AnalysisView report coordinates use persisted artifact stems."""
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView


class _Function:
    ea = 0x2000


class _CallGraph:
    def has_node_by_name(self, name):
        return name == "duplicate@2000"

    def get_node_by_name(self, name):
        assert name == "duplicate@2000"
        return _Function()


class _LibDepGraph:
    def get_callgraph_by_name(self, binary_name):
        return _CallGraph() if binary_name == "libvendor.so" else None


class _ADG:
    analysis_level = "semantic"
    lib_dep_graph = _LibDepGraph()


def test_get_function_ea_accepts_persisted_artifact_stem():
    view = AnalysisView(_ADG())
    assert view.get_function_ea("libvendor.so", "duplicate@2000") == 0x2000
    assert view.get_function_ea("libvendor.so", "missing") is None
