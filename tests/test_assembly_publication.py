"""Publishing one view must not invalidate another consumer's evidence."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.ipc_analyzer.candidate_index import ChannelCandidateIndex
from fmst_analyzer.graphs.call_graph import CallGraph


@pytest.mark.parametrize("structural_first", [False, True])
def test_ipc_and_semantic_publication_preserve_both_references(
    tmp_path: Path, structural_first: bool,
):
    binary = MagicMock()
    binary.name = "service"
    binary.structural_ready = binary.semantic_ready = True
    binary._source_sha256 = "b" * 64
    listing = f"; source_sha256: {binary._source_sha256}\n0x1000: nop\n"
    function = SimpleNamespace(
        ea=0x1000, name="helper", module=binary.name,
        decompiled_name="helper", artifact_stem="helper",
        structural_artifact_stem="helper@1000", has_attr=lambda attr: False,
        get_disassembly=lambda: listing,
    )
    binary.all_funcs = {function.ea: function}
    graph = CallGraph(binary)
    binary.call_graph = graph
    graph._nodes_for_analysis = [function]
    # An accounted decompilation failure still requires real assembly evidence.
    graph._semantic_failures = {function.ea: SimpleNamespace(function_ea=function.ea)}
    config = SimpleNamespace(
        disassembled_code_dir=tmp_path / "assembly",
        decompiled_code_dir=tmp_path / "code",
    )
    code_dir = config.decompiled_code_dir / binary.name
    code_dir.mkdir(parents=True)
    for name in ("string_xrefs.json", "global_var_xrefs.json"):
        (code_dir / name).write_text("{}", encoding="utf-8")
    view = AnalysisView.__new__(AnalysisView)
    view.adg = SimpleNamespace(
        global_config=config, get_binary_callgraphs=lambda: {binary: graph},
    )
    view.get_decompiled_name = lambda name, ea: function.artifact_stem

    executable = tmp_path / binary.name
    candidate = ChannelCandidateIndex.__new__(ChannelCandidateIndex)
    candidate.rootfs = tmp_path
    candidate._candidate_nodes = {executable.resolve(): binary}
    candidate._published_structural = set()

    def publish_structural():
        candidate._publish_candidate_assembly(
            executable, binary, [], SimpleNamespace(_global_config=config),
        )

    def publish_semantic():
        graph.dump_disassembled_code(config.disassembled_code_dir)

    publishers = [publish_structural, publish_semantic]
    if not structural_first:
        publishers.reverse()
    for publish in publishers:
        publish()

    structural_path = config.disassembled_code_dir / "ipc" / binary._source_sha256 / binary.name / "helper@1000.s"
    semantic_path, text = view.get_disassembly(binary.name, function.ea)
    assert text == structural_path.read_text(encoding="utf-8") == listing
    graph.verify_artifacts(config.decompiled_code_dir, config.disassembled_code_dir)
    integrity = view.ctree_integrity_check()[binary.name]
    assert integrity.missing_count == integrity.extra_count == 0

    # Neither a narrower selection nor repeated publication owns other listings.
    graph._nodes_for_analysis = []
    publish_semantic()
    assert semantic_path.is_file() and structural_path.is_file()

    graph._nodes_for_analysis = [function]
    semantic_path.unlink()
    with pytest.raises(RuntimeError, match="Incomplete C/S artifacts"):
        graph.verify_artifacts(config.decompiled_code_dir, config.disassembled_code_dir)
    assert view.ctree_integrity_check()[binary.name].missing_count == 1
