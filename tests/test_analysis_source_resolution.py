"""Source lookup follows graph identity, not an ELF symbol's spelling."""
from types import SimpleNamespace

import pytest

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView


def _view(tmp_path, aliases):
    view = AnalysisView.__new__(AnalysisView)
    view.adg = SimpleNamespace(global_config=SimpleNamespace(decompiled_code_dir=tmp_path))
    view._get_callgraph_for_binary = lambda binary: SimpleNamespace(
        has_node_by_name=lambda name: name in aliases,
        get_node_by_name=lambda name: aliases[name],
        get_node_by_ea=lambda ea: next(node for node in aliases.values() if node.ea == ea),
    )
    return view


def test_symbol_and_artifact_alias_resolve_to_the_same_source(tmp_path):
    node = SimpleNamespace(ea=0x1000, artifact_stem="eval@1000")
    view = _view(tmp_path, {"_eval": node, "eval@1000": node})
    path = tmp_path / "service" / "eval@1000.c"
    path.parent.mkdir()
    path.write_text("int eval(void) { return 1; }\n")
    assert view.get_full_code("service", "_eval") == view.get_full_code("service", "eval@1000")
    with pytest.raises(FileNotFoundError, match="Unknown function"):
        view.get_full_code("service", "other")


def test_canonical_stem_cannot_escape_source_directory(tmp_path):
    node = SimpleNamespace(ea=0x1000, artifact_stem="../../outside")
    with pytest.raises(ValueError, match="escapes"):
        _view(tmp_path, {"symbol": node}).get_full_code("service", "symbol")
