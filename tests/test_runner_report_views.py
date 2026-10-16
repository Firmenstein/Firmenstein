"""Bounded report navigation keeps every selected value addressable."""

import hashlib
import json

from fmst_analyzer.runner.agent import RuntimeEvidenceState, make_runner_tools


def report_tool(tmp_path):
    reports = tmp_path / "network_reports"
    reports.mkdir()
    path = reports / "network_analysis_result.json"
    path.write_text(json.dumps({
        "findings": [{"id": 1, "value": "first"}, {"id": 2, "value": "second"}],
        "empty": [],
        "nothing": None,
    }), encoding="utf-8")
    tools = make_runner_tools(
        view=object(), rootfs=tmp_path,
        diagnostic_reports_root=tmp_path,
        intervention_manifest=tmp_path / "Cargo.toml",
        evidence_state=RuntimeEvidenceState(),
    )
    return next(tool for tool in tools if tool.name == "view_analyzer_result"), path


def test_overview_and_exact_pages_are_bounded_and_hash_bound(tmp_path):
    tool, path = report_tool(tmp_path)
    overview = json.loads(tool.invoke({"analyzer": "network"}))
    assert overview["status"] == "ok"
    assert overview["source_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert overview["collection_sizes"] == {"findings": 2, "empty": 0, "nothing": None}
    assert overview["routes"][0]["json_pointer"] == "/findings"

    first = json.loads(tool.invoke({
        "analyzer": "network", "mode": "page", "json_pointer": "/findings", "limit": 1,
    }))
    assert first["page"]["items"][0]["value"] == {"id": 1, "value": "first"}
    assert first["page"]["next_start"] == 1
    second = json.loads(tool.invoke({
        "analyzer": "network", "mode": "page", "json_pointer": "/findings",
        "start": 1, "limit": 1, "source_sha256": first["source_sha256"],
    }))
    assert second["page"]["items"][0]["value"]["id"] == 2


def test_report_statuses_distinguish_null_empty_malformed_missing_and_source_change(tmp_path):
    tool, path = report_tool(tmp_path)
    assert json.loads(tool.invoke({"analyzer": "network", "mode": "page", "json_pointer": "/empty"}))["status"] == "empty"
    assert json.loads(tool.invoke({"analyzer": "network", "mode": "page", "json_pointer": "/nothing"}))["status"] == "null"
    path.write_text('{"findings": [', encoding="utf-8")
    assert json.loads(tool.invoke({"analyzer": "network"}))["status"] == "malformed"
    path.write_text("{}", encoding="utf-8")
    changed = json.loads(tool.invoke({
        "analyzer": "network", "mode": "page", "start": 1, "source_sha256": "0" * 64,
    }))
    assert changed["status"] == "source_changed"
    missing = json.loads(tool.invoke({"analyzer": "network", "json_pointer": "/absent"}))
    assert missing["status"] == "missing_selector"


def test_oversized_record_has_exact_route_without_truncation(tmp_path):
    tool, path = report_tool(tmp_path)
    path.write_text(json.dumps({"findings": [{"payload": "x" * 30_000}]}), encoding="utf-8")
    result = json.loads(tool.invoke({
        "analyzer": "network", "mode": "page", "json_pointer": "/findings", "limit": 1,
    }))
    assert result["page"]["items"] == []
    oversized = result["page"]["oversized_item"]
    assert oversized["json_pointer"] == "/findings/0"
    assert oversized["complete_artifact"] == str(path)
    assert "payload" not in json.dumps(result)
