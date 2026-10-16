"""Receipt truthfulness and deterministic bounded runtime feedback."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json
from fmst_analyzer.runner.budget import RunnerStopped
from fmst_analyzer.runner.feedback import (
    FeedbackJournal, RunnerExchange, RuntimeFeedback, collect_runtime_feedback,
    file_preview, render_preview, render_runtime_feedback,
)
from fmst_analyzer.runner.schema import (
    ProbeResult, InteractionProbe, RunnerDecision, RuntimeAttempt, RuntimeEventContext,
    RuntimeMemorySnapshot, RuntimeRegister, RuntimeTraceContext, ScenarioResult, ScenarioStepResult,
)


def test_delivery_admission_and_execution_are_distinct(tmp_path):
    journal = FeedbackJournal(tmp_path, "controller")
    record = journal.prepare("actual feedback", kind="feedback", source_attempt_path=tmp_path / "attempt.json",
        parent_workspace_sha256="parent", remaining_seconds=60)
    assert record.delivery == "prepared"
    assert record.message_sha256 == hashlib.sha256(b"actual feedback").hexdigest()
    journal.started(record)
    assert record.delivery == "invocation_started"
    assert record.response_unix_ns is None
    decision = RunnerDecision(action="continue", summary="Evidence does not support another revision")
    journal.responded(record, decision, SimpleNamespace(text="full response", provider="real-adapter",
        session_id="same-agent-session", turn_id="turn1", status="completed"))
    assert record.admission == "pending"
    decision.summary = "Controller normalized copy"
    assert record.response.summary != decision.summary
    journal.accepted(record, decision_index=1, revision_number=None)
    assert record.executions == []
    journal.execution("guest", status="started", attempt_number=2)
    journal.execution("guest", status="completed", attempt_number=2, attempt_path="attempt2.json")
    loaded = load_model_json(tmp_path / "exchange-0001.json", RunnerExchange)
    assert loaded == record
    assert [event["status"] for event in loaded.executions] == ["started", "completed"]
    assert Path(loaded.response_text_path).read_text() == "full response"


@pytest.mark.parametrize("started,error,delivery", [
    (False, RunnerStopped("session_budget_exhausted"), "not_delivered"),
    (True, asyncio.CancelledError(), "interrupted_delivery_unknown"),
    (True, RuntimeError("provider unavailable"), "interrupted_delivery_unknown"),
])
def test_interrupted_invoke_does_not_claim_consumption(tmp_path, started, error, delivery):
    journal = FeedbackJournal(tmp_path, "session")
    record = journal.prepare("message", kind="feedback", source_attempt_path=None,
        parent_workspace_sha256="hash", remaining_seconds=0 if not started else 1)
    if started:
        journal.started(record)
    journal.failed(record, error)
    assert record.delivery == delivery
    assert record.admission == "not_received"
    assert record.response is None
    assert record.finished_unix_ns is not None


def test_rejections_preserve_original_response_without_fixed_correction_cap(tmp_path):
    journal = FeedbackJournal(tmp_path, "session")
    for index in range(20):
        record = journal.prepare(f"correction {index}", kind="correction", source_attempt_path=None,
            parent_workspace_sha256="hash", remaining_seconds=60-index)
        journal.started(record)
        journal.responded(record, RunnerDecision(action="continue", summary=f"response {index}"), SimpleNamespace())
        journal.failed(record, RuntimeError("admission rejected"))
    assert len(list(tmp_path.glob("exchange-*.json"))) == 20
    assert record.delivery == "response_received"
    assert record.admission == "rejected"
    assert record.previous_exchange_id == 19


def make_attempt(tmp_path):
    log = tmp_path / "container.log"
    log.write_text("old log\n" * 1000 + "last failure\n")
    return RuntimeAttempt(tree_identity_version=2, attempt_number=1, probe=InteractionProbe(port=80, request_text="req"),
        guest_args=[], guest_working_directory="/", guest_environment={}, rootfs_actions=[], disabled_unit_ids=[],
        outcome="blocked", probe_result=ProbeResult(connected=False, interacted=False, attempts=1, error="exited"),
        runtime_trace_path=str(tmp_path / "trace.json"), runtime_trace_context_path=str(tmp_path / "context.json"),
        container_log_path=str(log), runtime_trace_available=False, runtime_trace_context_available=False,
        termination_reason="target_exit", target_exit_code=42, agent_summary="initial decision",
        scenario_result=ScenarioResult(status="blocked", error="target exited during first step",
            steps=[ScenarioStepResult(index=1, connected=False, passed=False)]))


def test_preview_is_bounded_and_points_to_complete_original(tmp_path):
    path = tmp_path / "log"
    path.write_bytes(b"a" * 10000 + b"end")
    preview = file_preview(path, limit=20)
    assert preview.total_bytes == 10003
    assert preview.captured_bytes == 20
    rendered = render_preview(preview)
    assert "truncated, tail 20 of 10003 bytes" in rendered
    assert str(path) in rendered and rendered.endswith("end")
    assert path.stat().st_size == 10003
    assert file_preview(tmp_path / "missing").error


def test_feedback_exposes_persisted_guest_dump_without_inference(tmp_path):
    attempt = make_attempt(tmp_path).model_copy(update={
        "runtime_dump_manifest_path": str(tmp_path / "runtime-dump" / "manifest.json"),
        "runtime_dump_available": True,
        "runtime_dump_capture_kind": "crash",
    })
    dump = tmp_path / "runtime-dump"
    dump.mkdir()
    (dump / "manifest.json").write_text(json.dumps({
        "status": "complete", "capture_kind": "crash", "core_path": "runtime-dump/guest.core",
        "load_map_path": "runtime-dump/load-map.json", "missing": [], "errors": [],
    }), encoding="utf-8")
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    assert feedback.runtime_dump["status"] == "complete"
    assert feedback.artifacts["core_path"].endswith("runtime-dump/guest.core")
    write_model_json(tmp_path / "feedback.json", feedback)
    assert str(tmp_path / "feedback.json") in render_runtime_feedback(feedback)
    saved = load_model_json(tmp_path / "feedback.json", RuntimeFeedback)
    assert json.loads(Path(saved.artifacts["runtime_dump_manifest"]).read_text()) == saved.runtime_dump


def test_host_diagnostics_stay_separate_and_replay_with_explicit_extent(tmp_path):
    from pydantic import ValidationError
    attempt = make_attempt(tmp_path)
    original_log = Path(attempt.container_log_path).read_bytes()
    for index in range(6):
        (tmp_path / f"diagnostics-{index}-pid-7.log").write_text("x" * 3000 + "guest signal evidence\n")
        (tmp_path / f"diagnostics-{index}-pid-7.json").write_text('{"schema_version":1}')
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    rendered = render_runtime_feedback(feedback)
    assert feedback.diagnostic_log_count == 6
    assert len(feedback.diagnostic_logs) == 4
    assert "diagnostic_streams=6" in rendered and "guest signal evidence" not in rendered
    assert "truncated, tail 2048 of 3022 bytes" in render_preview(feedback.diagnostic_logs[0])
    assert len([key for key in feedback.artifacts if key.startswith("diagnostics-")]) == 12
    assert Path(attempt.container_log_path).read_bytes() == original_log
    assert feedback.historical_event is None  # signal text is not a PC or snapshot
    write_model_json(tmp_path / "feedback.json", feedback)
    assert rendered == render_runtime_feedback(load_model_json(tmp_path / "feedback.json", RuntimeFeedback))
    old = feedback.model_dump()
    old["schema_version"] = 2
    with pytest.raises(ValidationError):
        RuntimeFeedback.model_validate(old)


def test_diagnostic_capture_errors_preserve_other_evidence(tmp_path):
    attempt = make_attempt(tmp_path)
    (tmp_path / "diagnostics-1-pid-2.log").write_text("intact child evidence")
    (tmp_path / "diagnostics-1-pid-2.json").write_text(json.dumps({
        "schema_version":2, "kind":"host_diagnostics", "pid":2,
        "write_failures_including_fork_prefix":3, "last_write_errno":13,
        "collection_complete":False,
    }))
    (tmp_path / "diagnostics-2-pid-3.json").write_text('{interrupted')
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    rendered = render_runtime_feedback(feedback)
    assert "intact child evidence" not in rendered and "capture_limitations=" in rendered
    write_model_json(tmp_path / "feedback.json", feedback)
    saved = load_model_json(tmp_path / "feedback.json", RuntimeFeedback)
    assert Path(saved.artifacts["diagnostics-1-pid-2.log"]).read_text() == "intact child evidence"
    assert any("writes failed" in item and "errno=13" in item for item in saved.limitations)
    assert any("identity unavailable" in item for item in saved.limitations)
    assert feedback.diagnostic_identities[0]["collection_complete"] is False


def test_child_failure_assessment_is_rendered_with_full_receipt_paths(tmp_path):
    attempt = make_attempt(tmp_path)
    request_root = tmp_path / "requests"
    request_root.mkdir()
    (request_root / "probe-connections.jsonl").write_text('{"connection_id":"c1"}\n')
    assessment = {"schema_version": 1, "status": "related_failure",
                  "failures": [{"relation": "related", "matched_step": 1, "signal": 11}],
                  "collection_errors": []}
    (tmp_path / "child-failures.json").write_text(json.dumps(assessment))
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    assert feedback.child_failure_assessment == assessment
    assert feedback.artifacts["probe_connections"].endswith("probe-connections.jsonl")
    assert feedback.artifacts["child_failures"].endswith("child-failures.json")
    assert '"matched_step": 1' not in render_runtime_feedback(feedback)
    assert json.loads(Path(feedback.artifacts["child_failures"]).read_text()) == assessment
    write_model_json(tmp_path / "feedback.json", feedback)
    assert load_model_json(tmp_path / "feedback.json", RuntimeFeedback) == feedback

def test_missing_snapshot_and_malformed_observation_are_not_fabricated(tmp_path):
    attempt = make_attempt(tmp_path)
    (tmp_path / "processes.json").write_text("{interrupted")
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    assert feedback.failed_step == 1
    assert feedback.historical_event is None
    assert feedback.process_observation is None
    output = render_runtime_feedback(feedback)
    assert "termination_reason=target_exit" in output and "target_exit_code=42" in output
    assert "capture_limitations=" in output and str(tmp_path / "feedback.json") in output
    assert any("No persisted guest snapshot" in item for item in feedback.limitations)
    assert any("Process observation unavailable" in item for item in feedback.limitations)
    write_model_json(tmp_path / "feedback.json", feedback)
    assert output == render_runtime_feedback(load_model_json(tmp_path / "feedback.json", RuntimeFeedback))


def test_probe_progress_is_explicit_and_separate_from_process_sampling(tmp_path):
    from fmst_analyzer.runner.supervision import TargetProgressWatchdog
    watchdog = TargetProgressWatchdog(container_name="not-executed", attempt_dir=tmp_path, stall_seconds=60)
    watchdog.begin_step(2)
    watchdog.probe_attempted()
    watchdog.probe_attempted()
    watchdog.response_received()
    watchdog._write_state(1)
    attempt = make_attempt(tmp_path)
    attempt.watchdog_path = str(watchdog.path)
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    progress = feedback.probe_progress
    assert progress["step"] == 2 and progress["probe_attempts"] == 2
    assert progress["started_unix_ns"] <= progress["last_probe_unix_ns"] <= progress["last_response_unix_ns"]
    assert progress["response_seen"] and feedback.process_observation is None
    write_model_json(tmp_path / "feedback.json", feedback)
    assert str(tmp_path / "feedback.json") in render_runtime_feedback(feedback)
    assert load_model_json(tmp_path / "feedback.json", RuntimeFeedback).probe_progress == progress


def test_failed_final_sample_is_reported_instead_of_stale_monitor_liveness(tmp_path):
    attempt = make_attempt(tmp_path)
    (tmp_path / "processes.json").write_text(json.dumps({
        "sampled_unix_ns": 1, "processes": [{"pid": 42, "state": "S", "role": "target"}]}))
    final = {"schema_version": 1, "purpose": "after_probe", "status": "error",
             "sample_started_unix_ns": 3, "sample_finished_unix_ns": 4,
             "after_last_response": True, "last_response_unix_ns": 2,
             "error": "Docker unavailable", "processes": []}
    (tmp_path / "processes-final.json").write_text(json.dumps(final))
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    assert feedback.process_observation == final
    assert feedback.artifacts["processes"].endswith("processes-final.json")
    assert feedback.artifacts["monitor_processes"].endswith("processes.json")
    output = render_runtime_feedback(feedback)
    assert any("Final process observation unavailable: Docker unavailable" in item
               and "earlier monitor table is historical only" in item for item in feedback.limitations)
    write_model_json(tmp_path / "feedback.json", feedback)
    assert load_model_json(tmp_path / "feedback.json", RuntimeFeedback).process_observation == final
    assert '"pid": 42' not in output


def test_default_snapshot_extent_is_historical_and_values_remain_in_full_feedback(tmp_path):
    attempt = make_attempt(tmp_path)
    context = RuntimeTraceContext(raw_trace_schema_version=4, main_load_address=0,
        total_block_executions=10, mapped_unique_blocks=0, unmapped_unique_blocks=1,
        images=[], functions=[], recent_focus_blocks=[], recent_blocks=[],
        events=[RuntimeEventContext(sequence=1, last_sequence=1, repeat_count=1,
                    kind="hook", detail="old", runtime_pc=0x1100,
                    registers=[RuntimeRegister(name="r0", value=0x1111)]),
                RuntimeEventContext(sequence=2, last_sequence=2, repeat_count=1,
                    kind="exit", detail="last", runtime_pc=0x2200, elapsed_ns=10,
                    registers=[RuntimeRegister(name="r0", value=0x2222)],
                    memory=[RuntimeMemorySnapshot(address=0x3000, requested_bytes=100,
                        source_register="r1", bytes=list(range(100)))])])
    write_model_json(Path(attempt.runtime_trace_context_path), context)
    attempt.runtime_trace_context_available = True
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="session")
    output = render_runtime_feedback(feedback)
    assert "0x2222" not in output and "0x1111" not in output
    assert "register_names" not in output and "PC=0x2200" not in output
    assert str(tmp_path / "feedback.json") in output
    write_model_json(tmp_path / "feedback.json", feedback)
    assert load_model_json(tmp_path / "feedback.json", RuntimeFeedback) == feedback
    assert any("historical trace is not a crash-time snapshot" in item for item in feedback.limitations)
    assert feedback.historical_event.registers[0].value == 0x2222
    assert feedback.historical_event.memory[0].bytes == list(range(100))


def test_attempt_facts_cookie_continuity_and_comparison(tmp_path):
    from fmst_analyzer.runner.attempt_facts import build_attempt_facts, read_request_records
    from fmst_analyzer.runner.schema import InteractionScenario, InteractionStep, RuntimeExperiment
    from fmst_analyzer.runner.reports import _render_attempt
    scenario = InteractionScenario(protocol="http", port=80, evidence_refs=["original-plan"], steps=[
        InteractionStep(request_text="GET /login HTTP/1.0\r\n\r\n", expected_status_code=302, save_cookies=True),
        InteractionStep(request_text="GET /home HTTP/1.0\r\nCookie: session={{cookie:session}}\r\n\r\n", expected_status_code=200, response_contains="home"),
    ])
    attempt = make_attempt(tmp_path)
    attempt.scenario = scenario
    attempt.scenario_result = ScenarioResult(status="blocked", steps=[
        ScenarioStepResult(index=1, connected=True, passed=True, status_code=302,
            response_text="HTTP/1.0 302 Found\r\nSet-Cookie: session=private-value; Path=/\r\n\r\n"),
        ScenarioStepResult(index=2, connected=True, passed=False, status_code=500, response_text="HTTP/1.0 500 Error\r\n\r\n"),
    ])
    previous = attempt.model_copy(deep=True)
    attempt.attempt_number = 2
    attempt.guest_environment = {"MODE": "configured"}
    attempt.experiment = RuntimeExperiment(hypothesis="Session continuity might control this branch", evidence_refs=["attempt-1.json"],
        changed_variable="Cookie transport", expected_observations=["home returns 200"], preserved_behavior="Original home request and assertions", state_carrier="HTTP Cookie")
    raw = b"GET /home HTTP/1.0\r\nCookie: session=private-value\r\n\r\n"
    root = tmp_path / "requests"
    root.mkdir()
    (root / "step-02.bin").write_bytes(raw)
    metadata = {"path": "step-02.bin", "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    (root / "step-02.json").write_text(json.dumps(metadata))
    requests, errors = read_request_records(root, [1, 2])
    facts = build_attempt_facts(attempt, previous=previous, requests=requests, request_errors=errors)
    assert facts.previous_attempt_number == 1
    assert facts.changed_inputs == ["guest_environment"]
    assert facts.steps[1].expected_status == 200 and facts.steps[1].actual_status == 500
    assert facts.steps[1].content_matched is False
    assert facts.steps[1].prior_cookies[0].value_returned is True
    assert "private-value" not in facts.model_dump_json()
    assert facts.state_observations_added == [] and facts.observed_state_changes == []
    assert "Session continuity" in "\n".join(_render_attempt(attempt))
    # Hash mismatch stays unknown; it must not be interpreted as a missing Cookie.
    (root / "step-02.bin").write_bytes(b"tampered")
    requests, errors = read_request_records(root, [2])
    unknown = build_attempt_facts(attempt, previous=None, requests=requests, request_errors=errors)
    assert unknown.steps[1].prior_cookies[0].value_returned is None
    assert any("do not match" in error for error in unknown.limitations)
    missing = build_attempt_facts(attempt, previous=None, requests={2: b"GET /home HTTP/1.0\r\n\r\n"}, request_errors=[])
    assert missing.steps[1].prior_cookies[0].value_returned is False
    unresolved = build_attempt_facts(attempt, previous=None, requests={2: scenario.steps[1].request_text.encode()}, request_errors=[])
    assert unresolved.steps[1].unresolved_cookie_markers == ["session"]
    feedback = collect_runtime_feedback(attempt, tmp_path / "attempt.json", session_id="s", previous_attempt=previous)
    assert feedback.facts == unknown.model_copy(update={"previous_attempt_number": 1, "changed_inputs": ["guest_environment"], "limitations": feedback.facts.limitations})
    write_model_json(tmp_path / "feedback.json", feedback)
    assert render_runtime_feedback(feedback) == render_runtime_feedback(load_model_json(tmp_path / "feedback.json", RuntimeFeedback))


def test_partial_feedback_preserves_collected_core_and_manifest_paths(tmp_path):
    from fmst_analyzer.runner.feedback import collect_partial_feedback
    from fmst_analyzer.runner.budget import ExecutionBudget
    source = tmp_path / 'source'
    (source / 'collected-cores').mkdir(parents=True)
    (source / 'runtime-dump').mkdir()
    (source / 'collected-cores/0000.core').write_bytes(b'raw retained core')
    (source / 'runtime-dump/manifest.json').write_text('{"status":"partial"}')
    receipt = tmp_path / 'receipt.json'
    receipt.write_text('{"state":"error"}')
    result = collect_partial_feedback(source=source, receipt=receipt, destination=tmp_path / 'partial',
        session_id='session', attempt_number=1, error='controlled interruption', budget=ExecutionBudget(30))
    assert Path(result.artifacts['collected-cores/0000.core']).read_bytes() == b'raw retained core'
    assert Path(result.artifacts['runtime-dump/manifest.json']).is_file()
