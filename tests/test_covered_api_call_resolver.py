from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.base.covered_api_call import (
    CoveredAPICall,
    CoveredAPICallResolver,
)


def _callsite(*, api="exit", column=4, ctree_index=7):
    return SimpleNamespace(
        is_populated=True,
        line_number=10,
        column_number=column,
        caller_name="main",
        callee_name=api,
        caller_ea=0x1000,
        snapshot_hash="snapshot",
        ctree_index=ctree_index,
        source_ea=0x1040 + ctree_index,
    )


def _resolver(*callsites):
    function = SimpleNamespace(
        decompiled_name="main",
        artifact_stem="main",
        get_callsites=lambda: {
            callsite.ctree_index: callsite for callsite in callsites
        },
    )
    callgraph = SimpleNamespace(get_node_for_analysis=lambda: [function])
    binary = type("Binary", (), {"name": "httpd"})()
    view = SimpleNamespace(
        adg=SimpleNamespace(
            get_binary_callgraphs=lambda: {binary: callgraph},
        ),
    )
    return CoveredAPICallResolver(view)


def _draft(**updates):
    values = {
        "binary_name": "httpd",
        "function_name": "main",
        "api_name": "exit",
        "line_number": 10,
        "reason": "termination: exit on setup failure",
    }
    values.update(updates)
    return CoveredAPICall(**values)


def test_unique_display_citation_is_resolved_to_stable_ctree_identity():
    resolved = _resolver(_callsite()).resolve(_draft())

    assert resolved.function_ea == 0x1000
    assert resolved.snapshot_hash == "snapshot"
    assert resolved.ctree_index == 7
    assert resolved.column_number == 4
    assert resolved.source_ea == 0x1047


def test_ambiguous_same_line_citation_remains_display_only():
    resolved = _resolver(
        _callsite(column=4, ctree_index=7),
        _callsite(column=20, ctree_index=8),
    ).resolve(_draft())

    assert resolved.function_ea is None
    assert resolved.snapshot_hash is None
    assert resolved.ctree_index is None


def test_column_disambiguates_same_line_calls():
    resolved = _resolver(
        _callsite(column=4, ctree_index=7),
        _callsite(column=20, ctree_index=8),
    ).resolve(_draft(column_number=20))

    assert resolved.ctree_index == 8
    assert resolved.column_number == 20


def test_rendered_exit_resolves_to_authoritative__exit_identity():
    resolved = _resolver(_callsite(api="_exit")).resolve(_draft(api_name="exit"))

    assert resolved.api_name == "_exit"
    assert resolved.ctree_index == 7
