import pytest

from fmst_analyzer.runner.request_wire import escaped_http_header_repair, validate_request_representation
from fmst_analyzer.runner.runner import _scenario_weakening
from fmst_analyzer.runner.schema import InteractionScenario, InteractionStep


BAD = r"GET /index.htm HTTP/1.0\r\nHost: localhost\r\n\r\n"
GOOD = "GET /index.htm HTTP/1.0\r\nHost: localhost\r\n\r\n"


def scenario(text, protocol="http"):
    return InteractionScenario(protocol=protocol, port=80, evidence_refs=["fixture"],
        steps=[InteractionStep(request_text=text, expected_status_code=200)])


def test_double_escaped_header_is_correctable_before_freezing():
    with pytest.raises(RuntimeError, match="literal"):
        validate_request_representation(scenario(BAD))
    validate_request_representation(scenario(GOOD))
    assert escaped_http_header_repair(BAD) == GOOD


def test_repair_preserves_body_and_header_value_backslashes():
    body = r'{"value":"keep\r\nthis"}'
    old = r"POST / HTTP/1.0\r\nX-Path: C:\test\r\n\r\n" + body
    expected = "POST / HTTP/1.0\r\nX-Path: C:\\test\r\n\r\n" + body
    assert escaped_http_header_repair(old) == expected
    assert escaped_http_header_repair(expected) is None
    validate_request_representation(scenario(expected))
    validate_request_representation(scenario(BAD, "tcp"))


def test_frozen_request_repair_needs_explicit_reason_and_keeps_assertions():
    assert _scenario_weakening(scenario(BAD), scenario(GOOD)) is not None
    assert _scenario_weakening(scenario(BAD), scenario(GOOD), request_representation_reason="wire encoding") is None
    weaker = scenario(GOOD)
    weaker.steps[0].expected_status_code = None
    assert _scenario_weakening(scenario(BAD), weaker, request_representation_reason="wire encoding") is not None


@pytest.mark.parametrize("changed", [GOOD.replace("/index.htm", "/"), GOOD + "body",
    GOOD.replace("GET", "POST"), GOOD.replace("localhost", "elsewhere")])
def test_representation_reason_does_not_authorize_other_request_changes(changed):
    assert _scenario_weakening(scenario(BAD), scenario(changed), request_representation_reason="repair") is not None


def test_raw_tcp_and_already_valid_http_never_receive_unescaping_exception():
    assert _scenario_weakening(scenario(BAD, "tcp"), scenario(GOOD, "tcp"), request_representation_reason="repair")
    assert _scenario_weakening(scenario(GOOD), scenario(GOOD + "x"), request_representation_reason="repair")


def test_response_capture_preserves_non_utf8_bytes_and_marks_truncation(tmp_path):
    import hashlib
    from fmst_analyzer.runner.request_wire import save_response_bytes
    raw = b"wire\xff\x00payload"
    complete = save_response_bytes(tmp_path, 1, raw, limit=100)
    assert (tmp_path / complete["path"]).read_bytes() == raw
    assert complete["sha256"] == complete["received_sha256"] == hashlib.sha256(raw).hexdigest()
    assert not complete["truncated"]
    partial = save_response_bytes(tmp_path, 2, raw, limit=5)
    assert (tmp_path / partial["path"]).read_bytes() == raw[:5]
    assert partial["truncated"] and partial["received_length"] == len(raw)
    assert partial["sha256"] != partial["received_sha256"]
