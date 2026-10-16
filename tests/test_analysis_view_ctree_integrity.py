"""CTree integrity follows the explicit semantic-failure artifact contract."""
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.graphs.call_graph import SemanticExtractionFailure


class _Function:
    ea = 0x1000
    artifact_stem = "uloop_run"
    decompiled_name = "uloop_run"
    _semantic_snapshot = None

    @staticmethod
    def has_attr(_attr):
        return False


class _CallGraph:
    semantic_failures = [
        SemanticExtractionFailure(
            binary_name="libubox.so",
            function_ea=0x1000,
            function_name="uloop_run",
            error="Hex-Rays failed to decompile",
            binary_identity="binary-id",
            idb_identity="idb-id",
            ida_version="9.2",
            ida_domain_version="0.5.0",
        )
    ]

    @staticmethod
    def get_node_for_analysis():
        return [_Function()]


class _Binary:
    name = "libubox.so"


class _ADG:
    analysis_level = "semantic"
    lib_dep_graph = SimpleNamespace()

    def __init__(self, root: Path):
        self.global_config = SimpleNamespace(
            decompiled_code_dir=root / "c",
            disassembled_code_dir=root / "s",
        )

    @staticmethod
    def get_binary_callgraphs():
        return {_Binary(): _CallGraph()}


def test_accounted_semantic_failure_requires_assembly_but_not_ctree(tmp_path):
    c_dir = tmp_path / "c" / "libubox.so"
    s_dir = tmp_path / "s" / "libubox.so"
    c_dir.mkdir(parents=True)
    s_dir.mkdir(parents=True)
    (c_dir / "string_xrefs.json").write_text("{}", encoding="utf-8")
    (c_dir / "global_var_xrefs.json").write_text("{}", encoding="utf-8")
    (s_dir / "uloop_run.s").write_text("NOP\n", encoding="utf-8")

    result = AnalysisView(_ADG(tmp_path)).ctree_integrity_check()["libubox.so"]

    assert result.total_decompiled == 0
    assert result.total_snapshots == 0
    assert result.missing_funcs == []
    assert result.extra_funcs == []
