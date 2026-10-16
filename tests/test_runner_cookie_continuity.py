"""Evidence-bound client session repair, separate from authentication success."""

import hashlib
import json

import pytest

from fmst_analyzer.analysis.base.report_io import write_model_json
from fmst_analyzer.runner.probe import build_probe_result, evaluate_interaction_scenario, inspect_http_response
from fmst_analyzer.runner.request_wire import admit_cookie_continuity, response_cookie_values, save_response_bytes
from fmst_analyzer.runner.runner import _scenario_weakening
from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario, RuntimeAttempt


@pytest.fixture
def cookie_case(tmp_path):
    floor = InteractionScenario(protocol="http", port=80, evidence_refs=["controlled protocol fixture"], steps=[
        {"request_text": "GET / HTTP/1.0\r\nHost: fixture\r\n\r\n", "expected_status_code": 401},
        {"request_text": "GET / HTTP/1.0\r\nAuthorization: Basic wrong\r\n\r\n", "expected_status_code": 401},
        {"request_text": "GET / HTTP/1.0\r\nAuthorization: Basic right\r\n\r\n", "expected_status_code": 200}])
    current = floor.model_copy(deep=True)
    current.steps[0].save_cookies = True
    for step in current.steps[1:]:
        step.request_text = step.request_text.replace("\r\n\r\n", "\r\nCookie: sid={{cookie:sid}}\r\n\r\n")
    root = tmp_path / "requests"
    root.mkdir()
    responses = []
    for index, step in enumerate(floor.steps, 1):
        raw = b"HTTP/1.0 401 Unauthorized\r\nSet-Cookie: sid=opaque; Path=/\r\nContent-Length: 0\r\n\r\n"
        save_response_bytes(root, index, raw, limit=1024)
        responses.append(build_probe_result(InteractionProbe(port=80, request_text=step.request_text), connected=True, response=raw, attempts=1))
    previous = RuntimeAttempt(tree_identity_version=2, attempt_number=1,
        probe=InteractionProbe(port=80, request_text=floor.steps[0].request_text), scenario=floor,
        scenario_result=evaluate_interaction_scenario(floor, responses), guest_args=[], guest_working_directory="/",
        guest_environment={}, rootfs_actions=[], disabled_unit_ids=[], outcome="blocked", probe_result=responses[-1],
        runtime_trace_path="unavailable", runtime_trace_context_path="unavailable", container_log_path="unavailable",
        runtime_trace_available=False, runtime_trace_context_available=False, agent_summary="controlled failure")
    path = tmp_path / "attempt.json"
    write_model_json(path, previous)
    return floor, current, dict(reason="Return the observed server session cookie", previous=previous, attempt_path=path)


def test_existing_counterexample_admitted_without_changing_authentication(cookie_case):
    floor, current, evidence = cookie_case
    assert _scenario_weakening(floor, current) == "scenario step 2 request was changed"
    revision = admit_cookie_continuity(floor, current, **evidence)
    assert revision.before == floor and revision.after == current
    assert revision.kind == "cookie_continuity" and revision.parent_sha256 != revision.result_sha256
    assert revision.source_attempt_sha256 == hashlib.sha256(evidence["attempt_path"].read_bytes()).hexdigest()
    assert [(item.step_index, item.cookie_names) for item in revision.cookie_sources] == [(1, ["sid"])]
    # Reissuance in unsaved step 2 must not replace the cookie captured at step 1.
    assert [step.expected_status_code for step in revision.after.steps] == [401, 401, 200]


@pytest.mark.parametrize("change", ["status", "request", "literal", "unknown_cookie", "first_step", "disabled_capture", "extra_capture", "no_change"])
def test_cookie_repair_is_not_general_scenario_edit_authority(cookie_case, change):
    floor, current, evidence = cookie_case
    if change == "status": current.steps[2].expected_status_code = 401
    elif change == "request": current.steps[1].request_text = current.steps[1].request_text.replace("wrong", "right")
    elif change == "literal": current.steps[1].request_text = current.steps[1].request_text.replace("{{cookie:sid}}", "opaque")
    elif change == "unknown_cookie": current.steps[1].request_text = current.steps[1].request_text.replace("sid", "admin")
    elif change == "first_step": current.steps[0].request_text = current.steps[1].request_text
    elif change == "disabled_capture": current.steps[0].save_cookies = False
    elif change == "extra_capture": current.steps[2].save_cookies = True
    else: current = floor.model_copy(deep=True)
    with pytest.raises(RuntimeError):
        admit_cookie_continuity(floor, current, **evidence)


@pytest.mark.parametrize("change", ["wire", "receipt", "truncated", "attempt", "result_binding", "body_only"])
def test_missing_or_forged_cookie_evidence_is_rejected(cookie_case, change):
    floor, current, evidence = cookie_case
    path = evidence["attempt_path"].parent / "requests/step-01-response.bin"
    if change == "wire": path.write_bytes(path.read_bytes() + b"changed")
    elif change in ("receipt", "truncated"):
        record = json.loads(path.with_suffix(".json").read_text())
        record["sha256" if change == "receipt" else "truncated"] = "wrong" if change == "receipt" else True
        path.with_suffix(".json").write_text(json.dumps(record))
    elif change == "attempt": evidence["attempt_path"].write_text("{}")
    elif change == "result_binding":
        evidence["previous"].scenario_result.steps[0].http_response.wire_sha256 = "wrong"
        write_model_json(evidence["attempt_path"], evidence["previous"])
    else:
        raw = b"HTTP/1.0 401 Unauthorized\r\n\r\nSet-Cookie: sid=opaque\r\n"
        save_response_bytes(path.parent, 1, raw, limit=1024)
        evidence["previous"].scenario_result.steps[0].http_response = inspect_http_response(raw, method="GET")
        write_model_json(evidence["attempt_path"], evidence["previous"])
    with pytest.raises((RuntimeError, ValueError)):
        admit_cookie_continuity(floor, current, **evidence)


def test_cookie_extraction_uses_final_headers_without_body_or_interim_headers():
    raw = (b"HTTP/1.1 103 Early Hints\r\nSet-Cookie: interim=bad\r\n\r\n"
           b"HTTP/1.1 401 Unauthorized\r\nSet-Cookie: sid=real; Path=/\r\n\r\n"
           b"Set-Cookie: sid=forged\r\nSet-Cookie: body=bad\r\n")
    evidence = inspect_http_response(raw, method="GET")
    assert response_cookie_values(evidence.headers_text) == {"sid": "real"}


def test_established_cookie_capture_cannot_be_silently_removed(cookie_case):
    _, current, _ = cookie_case
    later = current.model_copy(deep=True)
    later.steps[0].save_cookies = False
    assert "cookie capture was disabled" in _scenario_weakening(current, later)
