"""Deterministic identities for IPCAnalyzer controller-owned objects."""

from __future__ import annotations

import hashlib
import json
import re


def canonical_sysv_key(value: str | None) -> str | None:
    """Normalize exact numeric spelling, without assuming a host key_t width."""
    if value is None:
        return None
    text = value.strip()
    if re.fullmatch(r"[+-]?0[xX][0-9a-fA-F]+", text):
        return str(int(text, 16))
    if re.fullmatch(r"[+-]?[0-9]+", text):
        return str(int(text, 10))
    return value


def stable_id(prefix: str, *parts: object) -> str:
    encoded = json.dumps(parts, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:24]}"


def callsite_id(
    binary_path: str,
    binary_sha256: str,
    function_ea: int,
    snapshot_hash: str,
    ctree_index: int,
) -> str:
    return stable_id(
        "cs",
        binary_path,
        binary_sha256,
        function_ea,
        snapshot_hash,
        ctree_index,
    )


def dependency_id(
    channel: str,
    consumer_endpoints: list[str],
) -> str:
    return stable_id(
        "dependency", channel, sorted(consumer_endpoints),
    )


def unresolved_item_id(
    subject_kind: str,
    subject_id: str,
    reason_code: str,
) -> str:
    return stable_id("unresolved", subject_kind, subject_id, reason_code)


def endpoint_id(
    callsite: str,
    context_fingerprint: object,
) -> str:
    return stable_id("endpoint", callsite, context_fingerprint)


def channel_id(
    firmware_sha256: str,
    mechanism: str,
    resource_fingerprint: object,
) -> str:
    return stable_id("channel", firmware_sha256, mechanism, resource_fingerprint)


def resource_key(kind: str, canonical_value: str | None, expression: str) -> str:
    return stable_id("resource", kind, canonical_value, expression if canonical_value is None else "")


__all__ = [
    "callsite_id",
    "channel_id",
    "dependency_id",
    "endpoint_id",
    "unresolved_item_id",
    "resource_key",
    "stable_id",
]
