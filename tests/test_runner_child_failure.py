"""The Controller may reject a partial page only with a connected image failure."""

import json

import pytest

from fmst_analyzer.runner.child_failure import assess_child_failures
from fmst_analyzer.runner.schema import ScenarioResult, ScenarioStepResult


def _evidence(tmp_path, *, source_port=52100, peer_port=52100, signal=11,
              exit_status=None, output=True, trace_started=130,
              omit_trace=False, omit_connection=False):
    attempt = tmp_path / "attempt"
    attempt.mkdir()
    connections = tmp_path / "probe-connections.jsonl"
    requested = dict(schema_version=1, connection_id="c1", step_index=1,
                     probe_attempt=1, source_port=source_port,
                     destination_host="127.0.0.1", destination_port=80,
                     request_sha256="request", state="requested", unix_ns=100)
    completed = dict(requested, state="completed", unix_ns=300,
                     connected=True, response_bytes=20, response_sha256="response")
    if not omit_connection:
        connections.write_text(json.dumps(requested) + "\n" + json.dumps(completed) + "\n")
    identity = attempt / "diagnostics-120-pid-11.json"
    identity.write_text(json.dumps({
        "schema_version": 2, "kind": "host_diagnostics", "pid_namespace": "harness_container",
        "pid": 11, "parent_pid": 7, "origin_pid": 11, "process_start_ticks": 42,
        "process_identity_error": None, "binary": "/guest/cgi", "image_started_unix_ns": 120,
        "checkpoint_unix_ns": 220, "trace_path": "/fmst-output/runtime_trace.exec-1.pid-11.json",
        "collection_complete": False, "truncated": False,
        "write_failures_including_fork_prefix": 0,
        "stdio_at_checkpoint": [{"fd": 0,
            "local_socket": {"family": "ipv6", "address": "::ffff:127.0.0.1", "port": 80},
            "peer_socket": {"family": "ipv6", "address": "::ffff:127.0.0.1", "port": peer_port}}],
    }))
    identity.with_suffix(".log").write_text(
        f"qemu: uncaught target signal {signal} (fatal)\n" if signal else "ordinary trace\n")
    if not omit_trace:
        events = []
        if output:
            events.append({"kind": "stdio_io", "detail": "operation=write; fd=1; transferred_bytes=20"})
        if exit_status is not None:
            events.append({"kind": "process_exit", "detail": f"guest syscall 1; status=0x{exit_status:x}"})
        (attempt / "runtime_trace.exec-1.pid-11.json").write_text(json.dumps({
            "host_pid": 11, "origin_pid": 11, "started_unix_ns": trace_started,
            "events": events,
        }))
    result = ScenarioResult(status="success", steps=[
        ScenarioStepResult(index=1, connected=True, passed=True, response_text="HTTP/1.1 200 OK")])
    return attempt, connections, result


def test_request_associated_crash_after_partial_output_blocks_page_success(tmp_path):
    attempt, connections, result = _evidence(tmp_path)
    assessment = assess_child_failures(attempt_dir=attempt, probe_connections=connections,
                                       scenario_result=result)
    assert assessment["status"] == "related_failure"
    assert assessment["failures"][0]["matched_step"] == 1
    assert assessment["failures"][0]["signal"] == 11
    assert result.status == "blocked"
    assert not result.steps[0].passed
    assert "signal=11" in result.steps[0].error


def test_related_failure_does_not_erase_existing_specification_gap(tmp_path):
    attempt, connections, result = _evidence(tmp_path)
    result.status = "specification_gap"
    result.error = "source scenario has an unresolved requirement"
    assessment = assess_child_failures(attempt_dir=attempt, probe_connections=connections,
                                       scenario_result=result)
    assert assessment["status"] == "related_failure"
    assert result.status == "specification_gap"
    assert result.error.startswith("source scenario has an unresolved requirement")
    assert not result.steps[0].passed


@pytest.mark.parametrize("variation", ["other_connection", "missing_trace", "reused_pid",
                                        "missing_receipt", "no_output"])
def test_uncertain_or_unrelated_child_does_not_veto_scenario(tmp_path, variation):
    options = {
        "other_connection": {"peer_port": 52101},
        "missing_trace": {"omit_trace": True},
        "reused_pid": {"trace_started": 50},
        "missing_receipt": {"omit_connection": True},
        "no_output": {"output": False},
    }[variation]
    attempt, connections, result = _evidence(tmp_path, **options)
    assessment = assess_child_failures(attempt_dir=attempt, probe_connections=connections,
                                       scenario_result=result)
    assert assessment["failures"][0]["relation"] != "related"
    assert result.status == "success"
    assert result.steps[0].passed


def test_normal_child_exit_with_output_is_not_failure(tmp_path):
    attempt, connections, result = _evidence(tmp_path, signal=None, exit_status=0)
    assessment = assess_child_failures(attempt_dir=attempt, probe_connections=connections,
                                       scenario_result=result)
    assert assessment["status"] == "unrelated_or_no_failure"
    assert not assessment["failures"]
    assert result.status == "success"


def test_crash_without_image_checkpoint_is_explicitly_unknown(tmp_path):
    attempt, connections, result = _evidence(tmp_path, signal=None, exit_status=0)
    (attempt / "diagnostics-120-pid-19.log").write_text(
        "qemu: uncaught target signal 11 (Segmentation fault)\n")
    assessment = assess_child_failures(attempt_dir=attempt, probe_connections=connections,
                                       scenario_result=result)
    assert assessment["status"] == "unknown"
    assert any(item["signal"] == 11 and item["relation"] == "unknown"
               for item in assessment["failures"])
    assert any("identity/checkpoint missing" in error for error in assessment["collection_errors"])
    assert result.status == "success"


def test_symlinked_guest_trace_cannot_prove_request_failure(tmp_path):
    attempt, connections, result = _evidence(tmp_path)
    trace = attempt / "runtime_trace.exec-1.pid-11.json"
    relocated = tmp_path / "other-trace.json"
    trace.rename(relocated)
    trace.symlink_to(relocated)
    assessment = assess_child_failures(attempt_dir=attempt, probe_connections=connections,
                                       scenario_result=result)
    assert assessment["failures"][0]["relation"] == "unknown"
    assert "symlink evidence is not read" in assessment["failures"][0]["uncertainty"]
    assert result.status == "success"
