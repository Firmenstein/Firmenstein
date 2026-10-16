"""Bounded, lossless navigation over persisted Analyzer-family JSON."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


REPORT_VIEW_MAX_CHARS = 24_000
REPORT_VIEW_MAX_ITEMS = 128
REPORT_VIEW_PAYLOAD_MAX_CHARS = 20_000


def _pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _pointer_join(pointer: str, token: str) -> str:
    return f"{pointer}/{_pointer_token(token)}"


def _resolve_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("json_pointer must be empty or start with '/'")
    current = value
    for raw_token in pointer[1:].split("/"):
        token_parts: list[str] = []
        index = 0
        while index < len(raw_token):
            if raw_token[index] != "~":
                token_parts.append(raw_token[index])
                index += 1
                continue
            if index + 1 >= len(raw_token) or raw_token[index + 1] not in "01":
                raise ValueError("json_pointer contains an invalid '~' escape")
            token_parts.append("/" if raw_token[index + 1] == "1" else "~")
            index += 2
        token = "".join(token_parts)
        if isinstance(current, dict):
            if token not in current:
                raise KeyError(token)
            current = current[token]
        elif isinstance(current, list):
            if token == "-" or (token.startswith("0") and token != "0"):
                raise KeyError(token)
            try:
                index = int(token)
            except ValueError as error:
                raise KeyError(token) from error
            if index < 0 or index >= len(current):
                raise KeyError(token)
            current = current[index]
        else:
            raise KeyError(token)
    return current


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, (int, float)):
        return "number"
    return "string"


def _status(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, (dict, list)) and not value:
        return "empty"
    return "ok"


def _source(path: Path) -> tuple[bytes | None, str | None, dict[str, Any]]:
    base: dict[str, Any] = {
        "report_path": str(path),
        "complete_artifact": str(path),
    }
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None, None, {**base, "status": "missing"}
    except OSError as error:
        return None, None, {**base, "status": "unreadable", "error": str(error)}
    digest = hashlib.sha256(raw).hexdigest()
    base.update({"source_sha256": digest, "byte_length": len(raw)})
    return raw, digest, base


def _entry_overview(value: Any, pointer: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": _status(value),
        "json_pointer": pointer,
        "value_type": _kind(value),
        "collection_size": len(value) if isinstance(value, (dict, list)) else None,
    }
    if isinstance(value, dict):
        all_fields = list(value)
        fields = all_fields[:REPORT_VIEW_MAX_ITEMS]
        result["top_level_fields"] = fields
        result["top_level_fields_extent"] = {
            "showing": len(fields), "total": len(all_fields),
        }
        result["collection_sizes"] = {
            key: len(value[key]) if isinstance(value[key], (dict, list)) else None
            for key in fields
        }
        result["routes"] = [
            {"field": key, "json_pointer": _pointer_join(pointer, key)}
            for key in fields
        ]
        if len(fields) < len(all_fields):
            result["routes_notice"] = (
                "Top-level routes are a bounded preview; use the complete artifact "
                "for fields beyond this extent."
            )
    elif isinstance(value, list):
        result["routes"] = {
            "items": {
                "json_pointer": f"{pointer}/<index>" if pointer else "/<index>",
                "note": "Select a concrete numeric index for an exact item.",
            }
        }
    return result


def _page_payload(value: Any, pointer: str, start: int, limit: int) -> dict[str, Any]:
    if isinstance(value, dict):
        entries = list(value.items())
        total = len(entries)
        selected = entries[start:start + limit]
        items = [
            {"key": key, "json_pointer": _pointer_join(pointer, key), "value": item}
            for key, item in selected
        ]
        kind = "object"
    elif isinstance(value, list):
        total = len(value)
        selected = list(enumerate(value[start:start + limit], start=start))
        items = [
            {"index": index, "json_pointer": _pointer_join(pointer, str(index)), "value": item}
            for index, item in selected
        ]
        kind = "array"
    else:
        total = 1
        if start > 0:
            selected = []
        else:
            selected = [value]
        items = [{"json_pointer": pointer, "value": value}] if selected else []
        kind = _kind(value)
    next_start = start + len(items)
    return {
        "status": _status(value),
        "json_pointer": pointer,
        "value_type": kind,
        "total": total,
        "start": start,
        "count": len(items),
        "items": items,
        "next_start": next_start if next_start < total else None,
    }


def _fit_page(page: dict[str, Any], *, path: Path, source_sha256: str) -> dict[str, Any]:
    """Reduce item count only at record boundaries; never slice a JSON value."""
    while len(json.dumps(page, ensure_ascii=False, separators=(",", ":"))) > REPORT_VIEW_PAYLOAD_MAX_CHARS:
        items = page["items"]
        if len(items) <= 1:
            if not items:
                break
            item = items[0]
            encoded = json.dumps(item["value"], ensure_ascii=False, separators=(",", ":"))
            page["items"] = []
            page["count"] = 0
            page["next_start"] = page["start"] + 1 if page["start"] + 1 < page["total"] else None
            page["oversized_item"] = {
                "json_pointer": item["json_pointer"],
                "start": page["start"],
                "serialized_chars": len(encoded),
                "complete_artifact": str(path),
                "source_sha256": source_sha256,
                "note": "The item was not serialized into this response. Read the complete artifact or select the exact pointer with an unrestricted local reader.",
            }
            break
        page["items"] = items[:max(1, len(items) // 2)]
        page["count"] = len(page["items"])
        page["next_start"] = page["start"] + page["count"]
    return page


def view_report(
    path: Path,
    *,
    mode: str = "overview",
    json_pointer: str = "",
    start: int = 0,
    limit: int = 32,
    source_sha256: str | None = None,
) -> dict[str, Any]:
    """Render a bounded overview or exact JSON-pointer page."""
    if mode not in {"overview", "page"}:
        raise ValueError("mode must be 'overview' or 'page'")
    if start < 0:
        raise ValueError("start must be nonnegative")
    if not 1 <= limit <= REPORT_VIEW_MAX_ITEMS:
        raise ValueError(f"limit must be between 1 and {REPORT_VIEW_MAX_ITEMS}")
    raw, digest, source = _source(path)
    if raw is None:
        return source
    if source_sha256 is not None and source_sha256 != digest:
        return {
            **source,
            "status": "source_changed",
            "expected_source_sha256": source_sha256,
            "continuation_valid": False,
            "note": "The source changed; restart at start=0 and use the returned source_sha256.",
        }
    if start and source_sha256 is None:
        return {
            **source,
            "status": "invalid_continuation",
            "continuation_valid": False,
            "note": "A continuation page must include the source_sha256 returned by the first page.",
        }
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return {**source, "status": "malformed", "error": str(error)}
    try:
        selected = _resolve_pointer(value, json_pointer)
    except ValueError as error:
        return {**source, "status": "invalid_selector", "error": str(error)}
    except KeyError as error:
        return {
            **source,
            "status": "missing_selector",
            "json_pointer": json_pointer,
            "missing_token": error.args[0],
        }
    if mode == "overview":
        result = {**source, **_entry_overview(selected, json_pointer)}
        result["access"] = {
            "page": {"mode": "page", "json_pointer": json_pointer, "start": 0, "limit": limit},
            "complete_artifact": str(path),
        }
        if len(json.dumps(result, ensure_ascii=False, separators=(",", ":"))) > REPORT_VIEW_MAX_CHARS:
            return {
                **source,
                "status": "overview_oversized",
                "json_pointer": json_pointer,
                "value_type": _kind(selected),
                "collection_size": len(selected) if isinstance(selected, (dict, list)) else None,
                "complete_artifact": str(path),
                "note": "The bounded metadata itself exceeds the transport budget; use the complete artifact and an exact child pointer.",
            }
        return result
    page = _page_payload(selected, json_pointer, start, limit)
    page = _fit_page(page, path=path, source_sha256=digest)
    return {
        **source,
        "status": page.pop("status"),
        "continuation_valid": True,
        "page": page,
    }


__all__ = ["REPORT_VIEW_MAX_CHARS", "REPORT_VIEW_MAX_ITEMS", "view_report"]
