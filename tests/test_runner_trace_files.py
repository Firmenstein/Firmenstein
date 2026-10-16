"""Current native process routing and lossless on-demand evidence files."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner.agent import RuntimeEvidenceState, make_runner_tools
from fmst_analyzer.runner.trace_files import read_trace, trace_inventory


def native_tools(tmp_path):
    reports, live, client = (tmp_path / name for name in ("reports", "live", "client"))
    for path in (reports, live, client):
        path.mkdir()
    state = RuntimeEvidenceState()
    state.attempt_json = reports / "attempt.json"
    state.attempt_json.write_text('{"attempt_number":1,"outcome":"blocked"}')
    state.trace_json = reports / "runtime_trace.json"
    state.trace_json.write_text('{"events":[{"kind":"startup-only"}]}')
    current = {"path": str(client), "runtime_source_root": str(live),
               "attempt_sha256":hashlib.sha256(state.attempt_json.read_bytes()).hexdigest()}
    view = SimpleNamespace(root=SimpleNamespace(name="server"),
                           lib_dep_graph=SimpleNamespace(get_nodes=lambda: []))
    tools = make_runner_tools(view=view, rootfs=tmp_path, diagnostic_reports_root=reports,
        intervention_manifest=tmp_path / "Cargo.toml", evidence_state=state,
        live_client=SimpleNamespace(current=current))
    return {tool.name: tool for tool in tools}, live, client, state


def write_process(path):
    value = {"schema_version":6,"host_pid":42,"origin_pid":7,"started_unix_ns":100,
        "dropped_events":3,"image_loads":[{"detail":"worker.cgi@0x55550000"}],
        "events":[{"sequence":1,"kind":"syscall_result","detail":"openat(nr=322,path=/dev/state) -> -2","pc":123,
                   "registers":[{"name":"r0","value":99}]},
                  {"sequence":2,"kind":"syscall_result","detail":"open(nr=2,path=/other) -> 3"}]}
    path.write_text(json.dumps(value))
    return value, hashlib.sha256(path.read_bytes()).hexdigest()


def test_native_queries_select_current_process_and_keep_payload_on_disk(tmp_path):
    tools, live, client, state = native_tools(tmp_path)
    path = live / "runtime_trace-42.json"
    original, digest = write_process(path)
    (live / "diagnostics-42.json").write_text(json.dumps({"trace_path":str(path)}))
    (live / "runtime_trace-42.transition.json").write_text(json.dumps(
        {"child_trace":str(path),"parent_trace":"runtime_trace-7.json","status":"started"}))
    (live / "runtime_trace-42.heartbeat.json").write_text('{}')
    index = json.loads(tools["view_runtime_trace_files"].invoke({"image":"worker.cgi"}))
    assert len(index["traces"]) == 1
    record = index["traces"][0]
    assert record["sha256"] == digest and record["dropped_events"] == 3
    assert record["diagnostic_paths"] and record["exec_transitions"][0]["status"] == "started"
    assert "events" not in record and "openat(nr=" not in json.dumps(index)
    raw = json.loads(tools["view_raw_runtime_trace"].invoke({}))
    assert raw["runtime_roots"] == [str(live)] and "events" not in raw
    assert json.loads(tools["query_runtime_events"].invoke({}))["status"] == "trace_selection_required"
    overview = json.loads(tools["view_runtime_evidence"].invoke({}))
    assert overview["raw_trace_path"] is None and "startup" in overview["trace_context_error"]
    selected = {"trace_path":str(path),"source_sha256":digest}
    result = json.loads(tools["query_runtime_events"].invoke({**selected,"syscall_name":"openat"}))
    assert "events" not in result and "openat(nr=" not in json.dumps(result)
    query = json.loads(Path(result["query_path"]).read_text())
    assert Path(result["query_path"]).is_relative_to(state.attempt_json.parent)
    assert len(query["events"]) == 1 and query["events"][0]["registers"][0]["value"] == 99
    snapshot = Path(query["raw_trace_path"])
    assert json.loads(snapshot.read_text()) == original
    page = json.loads(tools["view_runtime_evidence"].invoke({**selected,"section":"api"}))
    route = page["page"]["view"]["events"][0]["original_event"]
    assert route["trace_path"] == str(path) and route["source_sha256"] == digest
    original_page = json.loads(tools["view_runtime_evidence"].invoke(route))
    assert original_page["raw_trace_path"] == str(snapshot)
    path.write_text('{"events":[]}')
    with pytest.raises(ValueError, match="source_changed"):
        tools["query_runtime_events"].invoke(selected)
    assert json.loads(snapshot.read_text()) == original
    assert "startup-only" in state.trace_json.read_text()


def test_final_native_log_and_trace_roots_replace_live_routes(tmp_path):
    tools, live, client, state = native_tools(tmp_path)
    state.container_log = state.attempt_json.parent / "container.log"
    state.container_log.write_text("old startup")
    assert "not been retained" in tools["view_container_log"].invoke({})
    final = client / "runtime"
    final.mkdir()
    (final / "container.log").write_text("current child crash")
    assert "current child crash" in tools["view_container_log"].invoke({})
    assert "old startup" not in tools["view_container_log"].invoke({})
    old = live / "runtime_trace-old.json"
    write_process(old)
    with pytest.raises(ValueError, match="outside"):
        tools["query_runtime_events"].invoke({"trace_path":str(old)})


def test_trace_inventory_preserves_capture_errors_and_rejects_foreign_files(tmp_path):
    root = tmp_path / "owned"
    root.mkdir()
    foreign = tmp_path / "foreign.json"
    write_process(foreign)
    (root / "runtime_trace-link.json").symlink_to(foreign)
    (root / "runtime_trace-broken.json").write_text('{interrupted')
    result = trace_inventory(root)
    assert result["traces"] == [] and len(result["errors"]) == 2
    with pytest.raises(ValueError, match="outside"):
        read_trace(foreign, [root])


def test_new_partial_execution_does_not_select_previous_native_instance(tmp_path):
    tools, live, client, state = native_tools(tmp_path)
    previous = live / 'runtime_trace-old.json'
    write_process(previous)
    state.attempt_json.write_text('{"kind":"partial_execution","attempt_number":2}')
    result = json.loads(tools['view_raw_runtime_trace'].invoke({}))
    assert result['runtime_roots'] == [str(state.attempt_json.parent)]
    with pytest.raises(ValueError, match='outside'):
        tools['query_runtime_events'].invoke({'trace_path':str(previous)})
    assert 'native_client_receipt' not in json.loads(tools['view_runtime_evidence'].invoke({}))
