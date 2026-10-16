"""Tests for the bounded assembly evidence tool."""

from pathlib import Path
from types import SimpleNamespace

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import (
    make_analyzer_tools,
)


def test_view_disassembly_returns_exact_path_and_listing(tmp_path: Path):
    listing = tmp_path / "iperf" / "bind@11130.s"
    listing.parent.mkdir()
    listing.write_text("0x11130: jal bind\n0x11134: nop\n", encoding="utf-8")

    class _View:
        def get_disassembly(self, binary_name: str, function_ea: int):
            assert binary_name == "iperf"
            assert function_ea == 0x11130
            return listing, listing.read_text(encoding="utf-8")

    tool = next(
        item for item in make_analyzer_tools(_View())
        if item.name == "view_disassembly"
    )
    result = tool.invoke({"binary_name": "usr/bin/iperf", "function_ea": 0x11130})

    assert f"Assembly: {listing}" in result
    assert "0x11130: jal bind" in result
    assert "0x11134: nop" in result


def test_view_disassembly_reports_missing_artifact_without_guessing():
    class _View:
        def get_disassembly(self, binary_name: str, function_ea: int):
            raise FileNotFoundError("missing exact listing")

    tool = next(
        item for item in make_analyzer_tools(_View())
        if item.name == "view_disassembly"
    )
    result = tool.invoke({"binary_name": "httpd", "function_ea": 0x1000})

    assert "Assembly unavailable" in result
    assert "missing exact listing" in result


def test_view_disassembly_accepts_function_name_as_ea_fallback():
    class _View:
        def get_function_ea(self, binary_name: str, function_name: str):
            assert binary_name == "httpd"
            assert function_name == "handle_request"
            return 0x1234

        def get_disassembly(self, binary_name: str, function_ea: int):
            assert binary_name == "httpd"
            assert function_ea == 0x1234
            return Path("/tmp/handle_request.s"), "0x1234: nop\n"

    tool = next(
        item for item in make_analyzer_tools(_View())
        if item.name == "view_disassembly"
    )
    result = tool.invoke({"binary_name": "httpd", "function_name": "handle_request"})

    assert "function EA 0x1234" in result


def test_view_disassembly_stops_when_function_name_has_no_address():
    view = object.__new__(AnalysisView)
    view._get_callgraph_for_binary = lambda _name: SimpleNamespace(
        has_node_by_name=lambda _function: False,
    )

    def unexpected_lookup(*_args):
        raise AssertionError("an unresolved name must not reach the assembly backend")

    view.get_disassembly = unexpected_lookup
    tool = next(
        item for item in make_analyzer_tools(view)
        if item.name == "view_disassembly"
    )

    result = tool.invoke({"binary_name": "httpd", "function_name": "sub_409C40"})

    assert result == "Assembly unavailable for httpd::sub_409C40: function not found."


def test_analysis_view_resolves_ida_stem_and_rejects_escape(tmp_path: Path):
    class _CallGraph:
        def __init__(self, artifact_stem: str):
            self.artifact_stem = artifact_stem

        def get_node_by_ea(self, _function_ea: int):
            return SimpleNamespace(artifact_stem=self.artifact_stem)

    view = object.__new__(AnalysisView)
    view.adg = SimpleNamespace(
        global_config=SimpleNamespace(
            disassembled_code_dir=tmp_path / "disassembled_code"
        )
    )
    view._get_callgraph_for_binary = lambda _binary_name: _CallGraph(
        "bind@11130"
    )

    path = view.get_disassembly_path("usr/bin/iperf", 0x11130)
    assert path == (tmp_path / "disassembled_code" / "iperf" / "bind@11130.s").resolve()

    view._get_callgraph_for_binary = lambda _binary_name: _CallGraph(
        "../../outside"
    )
    try:
        view.get_disassembly_path("iperf", 0x11130)
    except ValueError as error:
        assert "escapes" in str(error)
    else:
        raise AssertionError("an assembly artifact path escaped its root")
