"""Coverage is an observation, never permission to drop another context."""
import asyncio
import json
from types import SimpleNamespace

from fmst_analyzer.analysis.network_analyzer.analyzer import NetworkAnalyzer
from test_network_analyzer_static_phase import _fact


def test_adding_upstream_coverage_cannot_close_network_context(tmp_path, monkeypatch):
    rootfs = tmp_path / "rootfs"
    target = rootfs / "usr/sbin/httpd"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"portable target")
    reports = tmp_path / "reports"
    config = SimpleNamespace(
        workdir=tmp_path, fw_rootfs_path=rootfs, agent_concurrency_limit=1,
        target_diagnostic_reports_dir=lambda: reports,
        target_agent_debug_dir=lambda: tmp_path / "debug",
    )
    fact = _fact()
    analyzer = NetworkAnalyzer(config)
    monkeypatch.setattr(analyzer, "_collect_callsites", lambda _: {fact.callsite_id: fact})
    view = SimpleNamespace(root=SimpleNamespace(name="httpd", binary_path=target))
    before = asyncio.run(analyzer.run(view, phase="static"))
    source = reports / "ipc_reports/ipc_analysis_result.json"
    source.parent.mkdir(parents=True)
    source.write_text(json.dumps({"covered_api_calls": [{
        "binary_name": "httpd", "function_name": "main", "api_name": "ioctl",
        "line_number": 2, "column_number": 0, "function_ea": 0x1000,
        "snapshot_hash": "b" * 64, "ctree_index": 1, "reason": "One IPC invocation only",
    }]}))
    after = asyncio.run(analyzer.run(view, phase="static"))
    assert before.pending_callsite_ids == after.pending_callsite_ids == [fact.callsite_id]
    assert before == after
