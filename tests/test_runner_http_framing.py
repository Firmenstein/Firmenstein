"""Service success cannot come from an incomplete or contaminated HTTP reply."""
import pytest

from fmst_analyzer.runner.probe import build_probe_result, evaluate_interaction_scenario
from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario, InteractionStep


def evaluate(raw: bytes):
    request = "GET / HTTP/1.1\r\nHost: service\r\nConnection: close\r\n\r\n"
    probe = InteractionProbe(port=80, request_text=request, response_contains="accepted-marker")
    scenario = InteractionScenario(protocol="http", port=80,
        steps=[InteractionStep(request_text=request, expected_status_code=200, response_contains="accepted-marker")],
        evidence_refs=["fixture: bounded HTTP response framing"])
    captured = build_probe_result(probe, connected=True, response=raw, attempts=1)
    return evaluate_interaction_scenario(scenario, [captured])


@pytest.mark.parametrize("raw", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\naccepted-marker",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nf\r\naccepted-marker\r\n",
    b"host failure\nHTTP/1.0 200 OK\r\n\r\naccepted-marker",
    b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nContent-Length: 1\r\n\r\naccepted-marker",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nf\r\naccepted-marker\r\n0\r\n",
])
def test_invalid_http_framing_cannot_pass_a_body_marker(raw):
    result = evaluate(raw)
    assert result.status == "blocked"
    assert not result.steps[0].passed


@pytest.mark.parametrize("body", [b"accepted-marker", "accepted-marker 中文".encode(), b"accepted-marker\xff"])
def test_valid_content_length_counts_wire_bytes(body):
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    assert evaluate(raw).status == "success"


def test_complete_chunked_response_and_trailers():
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nf;tag=one\r\naccepted-marker\r\n0\r\nX-Finished: yes\r\n\r\n"
    assert evaluate(raw).status == "success"


def test_marker_split_across_chunk_boundaries_is_checked_in_decoded_body():
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\naccepted\r\n7\r\n-marker\r\n0\r\n\r\n"
    assert evaluate(raw).status == "success"


def test_informational_response_is_not_mistaken_for_final_status():
    raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\naccepted-marker"
    assert evaluate(raw).status == "success"


def test_full_large_response_is_checked_beyond_the_old_64k_preview():
    body = b"accepted-marker" + b"x" * 70000
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    assert evaluate(raw).status == "success"


def test_response_over_capture_bound_does_not_inherit_a_passing_prefix():
    from fmst_analyzer.runner.probe import MAX_RESPONSE_BYTES
    raw = b"HTTP/1.1 200 OK\r\n\r\naccepted-marker" + b"x" * MAX_RESPONSE_BYTES
    assert evaluate(raw).status == "blocked"
