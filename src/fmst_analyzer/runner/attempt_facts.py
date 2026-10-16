"""Deterministic attempt comparisons; missing observations remain unknown."""
from __future__ import annotations

import hashlib
from http.cookies import CookieError, SimpleCookie
import json
from pathlib import Path
import re

from pydantic import Field

from .schema import RuntimeAttempt, StrictModel
from .request_wire import substitute_response_values


class CookieContinuity(StrictModel):
    name: str
    emitted_by_step: int
    saving_enabled: bool
    value_returned: bool | None = Field(description="Exact value found in a verified later Cookie header; null when request bytes are unavailable. This does not establish that the server requires it.")


class StepFacts(StrictModel):
    index: int
    expected_status: int | None
    actual_status: int | None
    expected_content: str | None
    content_matched: bool | None
    response_sha256: str | None
    response_bytes: int | None
    connected: bool | None
    passed: bool | None
    error: str | None
    request_sha256: str | None
    unresolved_cookie_markers: list[str]
    cookies_emitted: list[str]
    prior_cookies: list[CookieContinuity]
    http_framing: str | None = Field(default=None, description="Controller-parsed framing; close_delimited alone does not prove application completeness.")
    http_framing_error: str | None = Field(default=None, description="Malformed/incomplete HTTP capture, independent of content marker assertions.")
    body_sha256: str | None = Field(default=None, description="Hash of original dechunked body bytes when available.")
    response_values_captured: list[str] = Field(default_factory=list, description="Names captured from this step's wire-bound body under the scenario's literal rules.")
    response_value_target_matches: bool | None = Field(default=None, description="Exact saved request-target match after percent-encoding earlier captured values. Null for requests without response placeholders or missing source/request evidence.")


class AttemptFacts(StrictModel):
    previous_attempt_number: int | None
    steps: list[StepFacts]
    changed_inputs: list[str] = Field(description="Changed configuration fields/hashes, not observed guest state or proof of causality.")
    changed_step_statuses: list[dict[str, object]]
    observed_state_changes: list[str]
    state_observations_added: list[str]
    state_observations_removed: list[str]
    experiment: dict[str, object] | None
    limitations: list[str]


def _headers(text: str) -> list[str]:
    header, separator, _ = text.partition("\r\n\r\n")
    return header.split("\r\n")[1:] if separator else []


def _cookies(text: str, header_name: str) -> dict[str, str]:
    result = {}
    for line in _headers(text):
        name, separator, value = line.partition(":")
        if separator and name.casefold() == header_name:
            parsed = SimpleCookie()
            try:
                parsed.load(value.strip())
            except CookieError:
                continue
            result.update({key: morsel.value for key, morsel in parsed.items()})
    return result


def build_attempt_facts(attempt: RuntimeAttempt, *, previous: RuntimeAttempt | None,
                        requests: dict[int, bytes], request_errors: list[str]) -> AttemptFacts:
    """Project structured records into facts without filesystem or model calls."""
    observations = attempt.scenario_result.state_changes_observed if attempt.scenario_result else []
    old_observations = previous.scenario_result.state_changes_observed if previous and previous.scenario_result else []
    results = {step.index: step for step in attempt.scenario_result.steps} if attempt.scenario_result else {}
    previous_results = {step.index: step for step in previous.scenario_result.steps} if previous and previous.scenario_result else {}
    prior_cookies: dict[str, tuple[str, int, bool]] = {}
    prior_values: dict[str, str] = {}
    steps = []
    changed_statuses = []
    for index, expected in enumerate(attempt.scenario.steps if attempt.scenario else [], 1):
        actual = results.get(index)
        raw = requests.get(index)
        request_text = raw.decode("latin-1") if raw is not None else None
        sent_cookies = _cookies(request_text, "cookie") if request_text is not None else {}
        is_http = attempt.scenario.protocol == "http"
        emitted = _cookies(actual.response_text, "set-cookie") if actual and is_http else {}
        response = actual.response_text.encode("utf-8") if actual else None
        http = actual.http_response if actual else None
        assertion_text = (http.headers_text + "\r\n\r\n" + http.body_text
            if http and http.framing != "invalid" else actual.response_text if actual else "")
        target_matches = None
        if "{{response:" in expected.request_text and request_text is not None:
            try:
                target_matches = (substitute_response_values(expected.request_text, prior_values).split("\r\n", 1)[0]
                    == request_text.split("\r\n", 1)[0])
            except ValueError:
                pass
        steps.append(StepFacts(index=index, expected_status=expected.expected_status_code,
            actual_status=actual.status_code if actual else None, expected_content=expected.response_contains,
            content_matched=(expected.response_contains in assertion_text) if actual and expected.response_contains is not None else None,
            response_sha256=hashlib.sha256(response).hexdigest() if response is not None else None,
            response_bytes=len(response) if response is not None else None,
            connected=actual.connected if actual else None, passed=actual.passed if actual else None,
            error=actual.error if actual else None,
            request_sha256=hashlib.sha256(raw).hexdigest() if raw is not None else None,
            unresolved_cookie_markers=re.findall(r"\{\{cookie:([^{}]+)\}\}", request_text or "") if is_http else [],
            cookies_emitted=sorted(emitted),
            prior_cookies=[CookieContinuity(name=name, emitted_by_step=source,
                saving_enabled=saved, value_returned=(sent_cookies.get(name) == value) if raw is not None else None)
                for name, (value, source, saved) in sorted(prior_cookies.items())] if is_http else [],
            http_framing=http.framing if http else None,
            http_framing_error=http.error if http else None,
            body_sha256=http.body_sha256 if http else None,
            response_values_captured=sorted(actual.captured_response_values) if actual else [],
            response_value_target_matches=target_matches))
        if actual:
            prior_values.update(actual.captured_response_values)
        prior_cookies.update({name: (value, index, expected.save_cookies) for name, value in emitted.items()})
        old = previous_results.get(index)
        if old is not None and actual is not None and (old.status_code, old.passed) != (actual.status_code, actual.passed):
            changed_statuses.append({"index": index, "before_status": old.status_code,
                "after_status": actual.status_code, "before_passed": old.passed, "after_passed": actual.passed})
    fields = ("guest_args", "guest_working_directory", "guest_environment", "network", "companion_processes",
              "rootfs_actions", "disabled_unit_ids", "intervention_sha256", "rootfs_sha256",
              "target_binary_sha256", "harness_sha256", "scenario")
    changed_inputs = [name for name in fields if previous and getattr(previous, name) != getattr(attempt, name)]
    experiment = getattr(attempt, "experiment", None)
    return AttemptFacts(previous_attempt_number=previous.attempt_number if previous else None,
        steps=steps, changed_inputs=changed_inputs, changed_step_statuses=changed_statuses,
        observed_state_changes=list(observations),
        state_observations_added=sorted(set(observations)-set(old_observations)) if previous else [],
        state_observations_removed=sorted(set(old_observations)-set(observations)) if previous else [],
        experiment=experiment.model_dump(mode="json") if experiment else None,
        limitations=[*request_errors,
            "Response hashes in these facts cover saved response_text; original wire bytes, when captured, are in requests/step-NN-response.bin with separate hash receipts.",
            "Cookie presence is a transport fact, not proof of authentication or a server requirement.",
            "Configuration changes and observation-set changes do not establish guest state contents or causality.",
            "No arbitrary guest file/memory state snapshot is inferred; inspect the named original evidence."])


def read_request_records(root: Path, indices: list[int]) -> tuple[dict[int, bytes], list[str]]:
    """Read only bounded, hash-matched request bytes, keeping missing/tampered unknown."""
    requests, errors = {}, []
    for index in indices:
        path = root / f"step-{index:02d}.bin"
        metadata = path.with_suffix(".json")
        try:
            if path.is_symlink() or metadata.is_symlink():
                raise ValueError("symlink request receipt")
            with metadata.open("rb") as stream:
                content = stream.read(65537)
            if len(content) > 65536:
                raise ValueError("request metadata exceeds 65536 bytes")
            record = json.loads(content)
            with path.open("rb") as stream:
                raw = stream.read(2097153)
            if len(raw) > 2097152:
                raise ValueError("request exceeds 2097152-byte feedback bound; original remains available")
            if record.get("path") != path.name or record.get("length") != len(raw) or record.get("sha256") != hashlib.sha256(raw).hexdigest():
                raise ValueError("request bytes do not match their receipt")
            requests[index] = raw
        except (OSError, ValueError, AttributeError) as error:
            errors.append(f"Request step {index} unavailable: {path}: {error}")
    return requests, errors
