"""Upstream callsite observations cannot close another analyzer's contexts."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from fmst_analyzer.analysis.file_resolver.analyzer import FileResolver
from fmst_analyzer.analysis.process_lifecycle.analyzer import ProcessLifecycleAnalyzer
from fmst_analyzer.analysis.process_lifecycle.analyzer_schema import ProcessEventCallsite


def test_file_enumeration_is_invariant_under_ipc_observations(tmp_path, monkeypatch):
    config = SimpleNamespace(agent_concurrency_limit=1, target_diagnostic_reports_dir=lambda: tmp_path)
    resolver = FileResolver(config)
    fact = SimpleNamespace(binary_name="httpd", caller_name="shared_open", caller_ea=0x100,
                           line_number=5, ctree_index=4)
    view = SimpleNamespace(adg=None, collect_api_callsites=lambda _: [fact],
                           get_decompiled_name=lambda *_: "shared_open")
    monkeypatch.setattr(resolver, "_select_candidate_apis", lambda _: ["open"])
    before = asyncio.run(resolver._node1_enumerate(view))
    ipc = tmp_path / "ipc_reports"
    ipc.mkdir()
    (ipc / "ipc_analysis_result.json").write_text(json.dumps({"covered_api_calls": [{
        "binary_name": "httpd", "function_name": "shared_open", "line_number": 5,
        "api_name": "open", "ctree_index": 4, "reason": "One FIFO invocation"}]}))
    after = asyncio.run(resolver._node1_enumerate(view))
    assert before == after == [fact]
    assert after[0].file_resolver_id.endswith("@ctree4")


def test_process_static_retains_termination_despite_upstream_coverage(tmp_path, monkeypatch):
    binary = tmp_path / "rootfs/usr/sbin/httpd"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"synthetic target")
    reports = tmp_path / "reports"
    config = SimpleNamespace(workdir=tmp_path, fw_rootfs_path=tmp_path / "rootfs",
        agent_concurrency_limit=1, target_diagnostic_reports_dir=lambda: reports)
    analyzer = ProcessLifecycleAnalyzer(config)
    fact = ProcessEventCallsite(callsite_id="process-event:1", binary_name="httpd", function_name="shared_exit",
        function_ea=0x100, snapshot_hash="snapshot", ctree_index=5, source_ea=0x140,
        line_number=9, column_number=0, api_name="exit", event_kind="termination")
    monkeypatch.setattr(analyzer, "_collect_callsites", lambda _: {fact.callsite_id: fact})
    view = SimpleNamespace(root=SimpleNamespace(name="httpd", binary_path=binary))
    before = asyncio.run(analyzer.run(view, phase="static"))
    for directory, filename in (
        ("file_reports", "file_resolver_result.json"),
        ("network_reports", "network_analysis_result.json"),
        ("ipc_reports", "ipc_analysis_result.json"),
    ):
        path = reports / directory
        path.mkdir()
        (path / filename).write_text(json.dumps({"covered_api_calls": [{
            "binary_name": fact.binary_name, "function_name": fact.function_name,
            "function_ea": fact.function_ea, "snapshot_hash": fact.snapshot_hash,
            "ctree_index": fact.ctree_index, "line_number": fact.line_number, "api_name": fact.api_name,
            "reason": "One conditional failure path"}]}))
    after = asyncio.run(analyzer.run(view, phase="static"))
    assert before == after
    assert set(after.callsites) == {fact.callsite_id}
    assert len(after.planning_findings) == 1
    assert after.execution.tasks == {}
