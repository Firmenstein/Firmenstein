"""Immutable identities of the semantic artifacts exposed to Agent tools."""
from typing import Any
from .code_analyzer.analysis_view import AnalysisView


def view_semantic_identity(view: AnalysisView) -> list[dict[str, Any]]:
    """Return immutable identities for every semantic artifact visible to tools."""
    if not hasattr(view, "adg"):
        return []
    rows: list[dict[str, Any]] = []
    for binary, callgraph in sorted(
        view.adg.get_binary_callgraphs().items(),
        key=lambda item: str(item[0].binary_path),
    ):
        snapshots = []
        for function in sorted(callgraph.get_nodes(), key=lambda item: item.ea):
            snapshot = getattr(function, "_semantic_snapshot", None)
            if snapshot is not None:
                snapshots.append([function.ea, snapshot.snapshot_hash])
        failures = [
            [failure.function_ea, failure.error]
            for failure in callgraph.semantic_failures
        ]
        rows.append({
            "binary_identity": getattr(
                binary, "_binary_identity", str(binary.binary_path),
            ),
            "snapshots": snapshots,
            "failures": failures,
        })
    return rows

