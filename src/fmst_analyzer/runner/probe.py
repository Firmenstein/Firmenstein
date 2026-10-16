"""Helpers for interpreting bounded TCP probe output.

The probe process itself runs inside the Runner container. This module only
turns its captured stdout/stderr into the persisted, provider-independent
``ProbeResult``; it never opens a host-side socket.
"""

from __future__ import annotations

import hashlib
import re
from .request_wire import capture_response_values

from .schema import (
    InteractionProbe,
    InteractionScenario,
    HttpResponseEvidence,
    ProbeResult,
    ScenarioObservation,
    ScenarioResult,
    ScenarioStepResult,
)


MAX_RESPONSE_BYTES = 1024 * 1024


def inspect_http_response(raw: bytes, *, method: str, source: str = "wire") -> HttpResponseEvidence:
    """Check one captured HTTP response using byte lengths, before text decoding.

    Close-delimited responses have no declared body size: this proves their
    syntax, not that a timed-out capture or application output is complete.
    """
    evidence = HttpResponseEvidence(source=source, framing="invalid",
        wire_bytes=len(raw), wire_sha256=hashlib.sha256(raw).hexdigest())
    try:
        offset = 0
        while True:
            end = raw.find(b"\r\n\r\n", offset)
            if end < 0:
                raise ValueError("HTTP header terminator is missing")
            lines = raw[offset:end].split(b"\r\n")
            status_match = re.fullmatch(rb"HTTP/1\.[01] +([1-5][0-9]{2})(?:[ \t].*)?", lines[0])
            if not status_match:
                raise ValueError("HTTP status line is not at the start of the response")
            status = int(status_match[1])
            headers: dict[bytes, list[bytes]] = {}
            for line in lines[1:]:
                key, colon, value = line.partition(b":")
                if not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                    raise ValueError("invalid HTTP header field")
                headers.setdefault(key.lower(), []).append(value.strip())
            offset = end + 4
            if status in (100, 102, 103):
                continue
            if status < 200:
                raise ValueError("HTTP protocol switching is not a completed service response")
            break
        evidence.status_code = status
        evidence.headers_text = b"\r\n".join(lines).decode("latin-1")
        body = raw[offset:]
        lengths = [part.strip() for value in headers.get(b"content-length", []) for part in value.split(b",")]
        if lengths and (any(not re.fullmatch(rb"[0-9]+", item) for item in lengths)
                        or len({int(item) for item in lengths}) != 1):
            raise ValueError("invalid or conflicting Content-Length fields")
        transfer = b",".join(headers.get(b"transfer-encoding", [])).lower()
        if transfer and lengths:
            raise ValueError("ambiguous Transfer-Encoding and Content-Length")
        if method.upper() == "HEAD" or status in (204, 304):
            if body:
                raise ValueError("unexpected body for a bodyless HTTP response")
            framing = "no_body"
        elif transfer:
            if transfer.strip() != b"chunked":
                raise ValueError("unsupported HTTP transfer coding")
            chunks = []
            cursor = 0
            while True:
                end = body.find(b"\r\n", cursor)
                if end < 0:
                    raise ValueError("chunk size or final chunk is missing")
                size = body[cursor:end].split(b";", 1)[0]
                if not re.fullmatch(rb"[0-9A-Fa-f]+", size):
                    raise ValueError("invalid HTTP chunk size")
                size = int(size, 16)
                cursor = end + 2
                if not size:
                    while True:
                        end = body.find(b"\r\n", cursor)
                        if end < 0:
                            raise ValueError("final chunk trailer terminator is missing")
                        trailer = body[cursor:end]
                        cursor = end + 2
                        if not trailer:
                            break
                        key, colon, _ = trailer.partition(b":")
                        if not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                            raise ValueError("invalid HTTP trailer")
                    if cursor != len(body):
                        raise ValueError("extra bytes after the chunked response")
                    break
                if cursor + size + 2 > len(body) or body[cursor + size:cursor + size + 2] != b"\r\n":
                    raise ValueError("HTTP chunk data is incomplete")
                chunks.append(body[cursor:cursor + size])
                cursor += size + 2
            body = b"".join(chunks)
            framing = "chunked"
        elif lengths:
            expected = int(lengths[0])
            if len(body) != expected:
                raise ValueError(f"Content-Length declares {expected} bytes, captured {len(body)}")
            framing = "content_length"
        else:
            framing = "close_delimited"
        evidence.framing = framing
        evidence.body_bytes = len(body)
        evidence.body_sha256 = hashlib.sha256(body).hexdigest()
        evidence.body_text = body.decode("utf-8", errors="replace")
    except ValueError as error:
        evidence.error = str(error)
    return evidence


def build_probe_result(
    probe: InteractionProbe,
    *,
    connected: bool,
    response: bytes = b"",
    attempts: int,
    error: str | None = None,
) -> ProbeResult:
    """Build a result from output produced by an in-container TCP client."""
    truncated = len(response) > MAX_RESPONSE_BYTES
    bounded = response[:MAX_RESPONSE_BYTES]
    response_text = bounded.decode("utf-8", errors="replace")
    http_response = inspect_http_response(bounded, method=probe.request_text.split(" ", 1)[0])
    assertion_text = (http_response.headers_text + "\r\n\r\n" + http_response.body_text
        if http_response.framing != "invalid" else response_text)
    interacted = connected and bool(bounded) and (
        probe.response_contains is None
        or probe.response_contains in assertion_text
    )
    if not interacted and error is None and connected:
        error = "connected but response did not satisfy the interaction probe"
    return ProbeResult(
        connected=connected,
        interacted=interacted,
        attempts=attempts,
        error=None if interacted else error,
        response_text=response_text,
        response_truncated=truncated,
        status_code=http_response.status_code or _http_status(response_text),
        http_response=http_response,
    )


def _http_status(response_text: str) -> int | None:
    match = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})(?:\s|$)", response_text)
    return int(match.group(1)) if match else None


def evaluate_interaction_scenario(
    scenario: InteractionScenario,
    responses: list[ProbeResult],
    observations: list[ScenarioObservation] | None = None,
) -> ScenarioResult:
    """Evaluate caller-visible evidence without inferring missing state."""
    observed = list(observations or [])
    step_results: list[ScenarioStepResult] = []
    for index, (step, probe) in enumerate(zip(scenario.steps, responses), start=1):
        status = probe.status_code
        passed = probe.connected and bool(probe.response_text)
        error = probe.error
        http_response = None
        assertion_text = probe.response_text
        if scenario.protocol == "http":
            http_response = probe.http_response or inspect_http_response(
                probe.response_text.encode("utf-8"), method=step.request_text.split(" ", 1)[0], source="saved_text")
            status = http_response.status_code
            if http_response.framing != "invalid":
                assertion_text = http_response.headers_text + "\r\n\r\n" + http_response.body_text
            if probe.response_truncated or http_response.error:
                passed = False
                error = "HTTP capture exceeded the response bound" if probe.response_truncated else http_response.error
        if step.expected_status_code is not None and status != step.expected_status_code:
            passed = False
            error = f"expected HTTP {step.expected_status_code}, observed {status}"
        if step.response_contains is not None and step.response_contains not in assertion_text:
            passed = False
            error = f"required response text absent: {step.response_contains!r}"
        for forbidden in step.response_not_contains:
            if forbidden in assertion_text:
                passed = False
                error = f"rejected response text present: {forbidden!r}"
        captured = {}
        try:
            captured = capture_response_values(step, probe)
        except ValueError as capture_error:
            passed = False
            error = str(capture_error)
        step_results.append(ScenarioStepResult(index=index, connected=probe.connected,
                                  response_text=probe.response_text, status_code=status,
                                  passed=passed, error=error, http_response=http_response,
                                  captured_response_values=captured))
    # An early exit must not erase the completed failed step or lifecycle
    # observations. Keep the existing acceptance/status boundary unchanged.
    if scenario.specification_gap:
        return ScenarioResult(status="specification_gap", steps=step_results,
                              observations=observed, error=scenario.gap_reason)
    if len(responses) != len(scenario.steps):
        return ScenarioResult(status="unsupported", steps=step_results, observations=observed,
                              error="scenario execution did not produce every ordered step")
    for rejection in scenario.rejection_conditions:
        if any(rejection in result.response_text for result in step_results):
            return ScenarioResult(status="blocked", steps=step_results, observations=observed, rejection=rejection)
    if not all(result.passed for result in step_results):
        return ScenarioResult(status="blocked", steps=step_results, observations=observed,
                               error="one or more scenario steps failed")

    # A channel list is only a declaration.  Success requires a binding for
    # every claim and an exact Controller-produced fact for that binding.  No
    # substring matching or "some observation of this kind" inference is
    # allowed here.
    expected_facts = {
        "staged_rootfs_ready": (
            "staged_rootfs", "staged_rootfs_ready=true"
        ),
        "target_process_alive_at_probe": (
            "target_process_alive", "target_process_observed_alive=true"
        ),
        "ordered_response_sequence_complete": (
            "ordered_response_sequence",
            f"steps_interacted={len(scenario.steps)}",
        ),
        "same_target_process_identity": (
            "same_target_process", "target_identity_stable=true"
        ),
    }
    canonical_claims = {
        "staged_rootfs_ready": "staged rootfs is ready",
        "target_process_alive_at_probe": "target process is alive at probe",
        "ordered_response_sequence_complete": "ordered caller-visible response sequence completed",
        "same_target_process_identity": "target process identity remained stable",
    }
    assertions = list(scenario.observation_assertions)
    satisfied: list[str] = []
    missing_bindings: list[str] = []
    missing_facts: list[str] = []
    for target, claims in (
        ("precondition", scenario.preconditions),
        ("state_change", scenario.required_state_changes),
    ):
        for index, claim in enumerate(claims, start=1):
            bound = [
                item for item in assertions
                if item.target == target and item.target_index == index
            ]
            if not bound:
                missing_bindings.append(f"{target}[{index}] {claim}")
                continue
            for assertion in bound:
                expected_kind, expected_fact = expected_facts[assertion.predicate]
                if claim.strip().casefold() != canonical_claims[assertion.predicate].casefold():
                    missing_bindings.append(
                        f"{target}[{index}] claim is not the canonical "
                        f"predicate description for {assertion.predicate}"
                    )
                    continue
                if not any(
                    item.kind == expected_kind and item.fact == expected_fact
                    for item in observed
                ):
                    missing_facts.append(
                        f"{target}[{index}] {assertion.predicate}={expected_fact}"
                    )
                else:
                    satisfied.append(
                        f"{target}[{index}] {assertion.predicate}"
                    )
    if missing_bindings or missing_facts:
        details = []
        if missing_bindings:
            details.append("unbound claims: " + "; ".join(missing_bindings))
        if missing_facts:
            details.append("missing exact facts: " + "; ".join(missing_facts))
        return ScenarioResult(
            status="blocked",
            steps=step_results,
            observations=observed,
            observation_assertions_satisfied=satisfied,
            error=(
                "scenario claims were not independently proven by exact "
                "observation assertions; " + " | ".join(details)
            ),
        )
    # Retain the old channel list as a useful diagnostic, but it cannot satisfy
    # a claim. A declared channel with no claim is harmless; a claim with no
    # assertion was handled above.
    state_changes = [
        f"{item.target}[{item.target_index}]: {scenario.required_state_changes[item.target_index - 1]}"
        for item in assertions
        if item.target == "state_change"
    ]
    return ScenarioResult(
        status="success",
        steps=step_results,
        observations=observed,
        state_changes_observed=state_changes,
        observation_assertions_satisfied=satisfied,
    )


__all__ = ["MAX_RESPONSE_BYTES", "build_probe_result", "evaluate_interaction_scenario"]
