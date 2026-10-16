"""Exact request bytes and a narrow, explicit HTTP header representation repair.

Never interpret escape sequences in a body or an arbitrary TCP payload. This
recognizes only a complete HTTP/1.x header written with literal CRLF separators;
the Agent still submits the corrected text, which is compared byte for byte.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from .schema import InteractionScenario, RuntimeAttempt, RequestRepresentationRevision, InteractionStep, ProbeResult


def admit_client_request_correction(floor: InteractionScenario, current: InteractionScenario, *,
        proposal, previous: RuntimeAttempt, attempt_path: Path, readable_roots: list[Path],
        check_budget) -> RequestRepresentationRevision:
    """Check correction provenance and assertion preservation, not native semantics."""
    from .schema import RequestRepresentationRevision, RuntimeAttempt
    original = attempt_path.read_bytes()
    parent = hashlib.sha256(floor.model_dump_json().encode()).hexdigest()
    if previous.outcome != "blocked" or RuntimeAttempt.model_validate_json(original) != previous:
        raise RuntimeError("client request correction requires the exact latest failed attempt")
    if (proposal.parent_sha256 is not None and proposal.parent_sha256 != parent) or previous.scenario != floor:
        raise RuntimeError("client request correction refers to a stale scenario")
    if len(current.steps) < len(floor.steps):
        raise RuntimeError("client request correction cannot remove existing steps")
    changed = [i for i, (old, new) in enumerate(zip(floor.steps, current.steps), 1)
               if old.request_text != new.request_text]
    if not changed or sorted(proposal.step_indices) != changed:
        raise RuntimeError("client request correction must identify exactly the changed requests")
    corrected = floor.model_copy(deep=True)
    for old, new in zip(corrected.steps, current.steps):
        old.request_text = new.request_text
    # New steps may strengthen coverage. The existing checks and scenario
    # metadata are independently compared by the normal acceptance gate.
    normalized = current.model_copy(deep=True)
    normalized.steps = normalized.steps[:len(floor.steps)]
    normalized.evidence_refs = floor.evidence_refs
    if normalized != corrected:
        raise RuntimeError("client request correction must preserve all existing assertions and captures")
    roots = [Path(root).resolve() for root in readable_roots]
    runtime_source = native_source = False
    artifact = attempt_path.parent.resolve()
    for item in proposal.evidence:
        check_budget()
        path = Path(item.path)
        if not path.is_absolute():
            raise RuntimeError("client request evidence needs absolute paths")
        path = path.resolve()
        if not path.is_file() or not any(path.is_relative_to(root) for root in roots):
            raise RuntimeError("client request evidence is outside Controller read-only roots")
        if path.stat().st_size > 16 * 1024 * 1024:
            raise RuntimeError("client request evidence exceeds 16 MiB")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != item.sha256 or item.excerpt.encode() not in content:
            raise RuntimeError("client request evidence hash/excerpt mismatch")
        if path.is_relative_to(artifact):
            runtime_source = True
        else:
            native_source = True
    if not runtime_source or not native_source:
        raise RuntimeError("client request correction needs failed execution and independent native source")
    proposal = proposal.model_copy(update={"parent_sha256": parent})
    return RequestRepresentationRevision(kind="client_request", correction=proposal,
        source_attempt_path=str(attempt_path), source_attempt_sha256=hashlib.sha256(original).hexdigest(),
        parent_sha256=parent, result_sha256=hashlib.sha256(corrected.model_dump_json().encode()).hexdigest(),
        reason=proposal.reason, before=floor, after=corrected)


def capture_response_values(step: InteractionStep, response: ProbeResult) -> dict[str, str]:
    """Extract required, unambiguous values from a validated original HTTP body."""
    if not step.response_captures:
        return {}
    http = response.http_response
    if (not response.connected or response.response_truncated or http is None
            or http.source != "wire" or http.error or http.framing == "invalid"):
        raise ValueError("response capture requires valid original HTTP wire evidence")
    if step.expected_status_code is not None and http.status_code != step.expected_status_code:
        raise ValueError("response capture status assertion failed")
    assertion_text = http.headers_text + "\r\n\r\n" + http.body_text
    if ((step.response_contains is not None and step.response_contains not in assertion_text)
            or any(value in assertion_text for value in step.response_not_contains)):
        raise ValueError("response capture content assertion failed")
    # Replacement decoding cannot preserve a session value's wire identity.
    encoded = http.body_text.encode("utf-8")
    if hashlib.sha256(encoded).hexdigest() != http.body_sha256:
        raise ValueError("response capture requires lossless UTF-8 body decoding")
    values = {}
    for capture in step.response_captures:
        if http.body_text.count(capture.prefix) != 1:
            raise ValueError(f"response capture {capture.name}: prefix missing or ambiguous")
        start = http.body_text.index(capture.prefix) + len(capture.prefix)
        end = http.body_text.find(capture.suffix, start)
        if end < 0 or not 0 < end - start <= capture.max_chars:
            raise ValueError(f"response capture {capture.name}: missing suffix, empty or oversized value")
        value = http.body_text[start:end]
        if any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value):
            raise ValueError(f"response capture {capture.name}: control character in value")
        values[capture.name] = value
    return values


def substitute_response_values(request: str, values: dict[str, str]) -> str:
    """Percent-encode scenario values in the request target; never send missing values."""
    def replace(match: re.Match[str]) -> str:
        name = match[1]
        if name not in values:
            raise ValueError(f"response value {name} has not been captured")
        return quote(values[name], safe="")
    line, separator, rest = request.partition("\r\n")
    parts = line.split(" ")
    if len(parts) != 3:
        if "{{response:" in line:
            raise ValueError("response placeholders require a complete HTTP request line")
        return request
    target = re.sub(r"\{\{response:([A-Za-z][A-Za-z0-9_]{0,63})\}\}", replace, parts[1])
    if "{{response:" in target:
        raise ValueError("invalid response placeholder")
    return " ".join((parts[0], target, parts[2])) + separator + rest


def response_cookie_values(headers_text: str) -> dict[str, str]:
    """Read cookie pairs from an already parsed final HTTP header only."""
    return {match.group(1): match.group(2) for match in re.finditer(
        r"(?im)^Set-Cookie:[ \t]*([^=;\s]+)=([^;\r\n]*)", headers_text)}


def admit_cookie_continuity(floor: InteractionScenario, current: InteractionScenario, *,
                            reason: str, previous: RuntimeAttempt, attempt_path: Path) -> RequestRepresentationRevision:
    """Bind a narrow client-session repair to earlier, verified server responses.

    Preserve all other request bytes, assertions and scenario metadata. This
    proves transport provenance, not that the guest requires a cookie or that
    authentication succeeded. The next execution must independently establish it.
    """
    from .probe import MAX_RESPONSE_BYTES, inspect_http_response
    from .schema import CookieSourceEvidence, RequestRepresentationRevision, RuntimeAttempt
    if (not reason.strip() or previous.outcome != "blocked" or floor.protocol != "http"
            or previous.scenario is None or len(current.steps) != len(floor.steps)):
        raise RuntimeError("cookie continuity requires a failed HTTP scenario with the same ordered steps")
    original = attempt_path.read_bytes()
    if RuntimeAttempt.model_validate_json(original) != previous:
        raise RuntimeError("cookie evidence no longer matches the last Controller attempt")
    normalized = current.model_copy(deep=True)
    issued: dict[str, CookieSourceEvidence] = {}
    used: dict[int, CookieSourceEvidence] = {}
    added = 0
    for index, (old, new) in enumerate(zip(floor.steps, current.steps), 1):
        if old.save_cookies and not new.save_cookies:
            raise RuntimeError("cookie continuity cannot disable an existing capture")
        if old.request_text != new.request_text:
            header, separator, body = new.request_text.partition("\r\n\r\n")
            lines = header.split("\r\n")
            positions = [i for i, line in enumerate(lines[1:], 1) if line.lower().startswith("cookie:")]
            if not separator or len(positions) != 1:
                raise RuntimeError(f"step {index}: add exactly one Cookie header")
            cookie_line = lines.pop(positions[0])
            if "\r\n".join(lines) + separator + body != old.request_text:
                raise RuntimeError(f"step {index}: cookie repair changed other request bytes or an existing Cookie header")
            names = []
            for pair in cookie_line.partition(":")[2].strip().split(";"):
                match = re.fullmatch(r"([!#$%&'*+.^_`|~0-9A-Za-z-]+)=\{\{cookie:\1\}\}", pair.strip())
                if match is None or match[1] in names:
                    raise RuntimeError(f"step {index}: only distinct server-issued cookie placeholders are allowed")
                names.append(match[1])
                source = issued.get(match[1])
                if source is None or not current.steps[source.step_index - 1].save_cookies:
                    raise RuntimeError(f"step {index}: cookie {match[1]} lacks an earlier captured issuing step with save_cookies")
                if source.step_index not in used:
                    used[source.step_index] = source.model_copy(update={"cookie_names": []}, deep=True)
                if match[1] not in used[source.step_index].cookie_names:
                    used[source.step_index].cookie_names.append(match[1])
            added += 1
        normalized.steps[index - 1].request_text = old.request_text
        normalized.steps[index - 1].save_cookies = old.save_cookies
        # Only corresponding requests can prove issuance for the next step.
        if index > len(previous.scenario.steps) or previous.scenario.steps[index - 1].request_text != old.request_text:
            continue
        response_path = attempt_path.parent / "requests" / f"step-{index:02d}-response.bin"
        if not response_path.is_file():
            continue
        if response_path.stat().st_size > MAX_RESPONSE_BYTES:
            raise RuntimeError("cookie evidence exceeds the bounded response capture")
        raw = response_path.read_bytes()
        capture = json.loads(response_path.with_suffix(".json").read_text())
        digest = hashlib.sha256(raw).hexdigest()
        if (capture.get("truncated") is not False or capture.get("length") != len(raw)
                or capture.get("received_length") != len(raw) or capture.get("sha256") != digest
                or capture.get("received_sha256") != digest):
            raise RuntimeError("cookie response capture identity mismatch or truncation")
        http = inspect_http_response(raw, method=old.request_text.split(" ", 1)[0])
        if http.error:
            continue
        observed = next((step for step in previous.scenario_result.steps if step.index == index), None) if previous.scenario_result else None
        if observed is None or observed.http_response is None or observed.http_response.wire_sha256 != digest:
            raise RuntimeError("cookie response is not bound to the failed scenario result")
        names = sorted(response_cookie_values(http.headers_text))
        if names and new.save_cookies:
            evidence = CookieSourceEvidence(step_index=index, response_path=str(response_path), response_sha256=digest, cookie_names=names)
            for name in names:
                issued[name] = evidence
    if not added or normalized != floor:
        raise RuntimeError("cookie continuity must add a placeholder header while preserving all other scenario fields and assertions")
    for index, (old, new) in enumerate(zip(floor.steps, current.steps), 1):
        if old.save_cookies != new.save_cookies and index not in used:
            raise RuntimeError(f"step {index}: cookie capture change has no proven later use")
    return RequestRepresentationRevision(kind="cookie_continuity", reason=reason,
        parent_sha256=hashlib.sha256(floor.model_dump_json().encode()).hexdigest(),
        result_sha256=hashlib.sha256(current.model_dump_json().encode()).hexdigest(),
        before=floor.model_copy(deep=True), after=current.model_copy(deep=True),
        source_attempt_path=str(attempt_path), source_attempt_sha256=hashlib.sha256(original).hexdigest(),
        cookie_sources=list(used.values()))


def escaped_http_header_repair(text: str) -> str | None:
    header, separator, body = text.partition(r"\r\n\r\n")
    if not separator or "\r" in header or "\n" in header:
        return None
    lines = header.split(r"\r\n")
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\s]+ HTTP/1\.[01]", lines[0]):
        return None
    if any(not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\r\n]*", line) for line in lines[1:]):
        return None
    return "\r\n".join(lines) + "\r\n\r\n" + body


def validate_request_representation(scenario: InteractionScenario | None) -> None:
    if scenario is None or scenario.protocol != "http":
        return
    for index, step in enumerate(scenario.steps, 1):
        if escaped_http_header_repair(step.request_text) is not None:
            raise RuntimeError(
                f"HTTP step {index} header contains literal backslash-r/backslash-n "
                "separators, not CR/LF bytes. Submit actual CR/LF characters in the "
                "JSON-decoded header. Preserve the body and all acceptance assertions. "
                "The Controller has not sent or frozen this malformed request."
            )


def save_request_bytes(directory: Path, index: int, text: str) -> dict[str, object]:
    """Save the exact post-cookie-substitution bytes passed to the transport."""
    directory.mkdir(parents=True, exist_ok=True)
    data = text.encode("utf-8")
    path = directory / f"step-{index:02d}.bin"
    path.write_bytes(data)
    record = {"path": path.name, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    path.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def save_response_bytes(directory: Path, index: int, data: bytes, *, limit: int) -> dict[str, object]:
    """Retain bounded original response bytes with explicit full/prefix identity."""
    directory.mkdir(parents=True, exist_ok=True)
    saved = data[:limit]
    path = directory / f"step-{index:02d}-response.bin"
    path.write_bytes(saved)
    record = {"path": path.name, "length": len(saved), "sha256": hashlib.sha256(saved).hexdigest(),
        "received_length": len(data), "received_sha256": hashlib.sha256(data).hexdigest(),
        "truncated": len(saved) != len(data)}
    path.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record
