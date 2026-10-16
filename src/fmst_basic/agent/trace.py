"""Provider-neutral, incrementally persisted Markdown Agent traces."""

from __future__ import annotations

import json
from pathlib import Path
import threading
import time
from typing import Any

from .analysis_agent import AgentResult
from .usage_registry import record_usage


class AgentTraceHandler:
    """Persist complete turns and their in-flight events atomically.

    A handler is normally created for one Generator/Reviewer round. The
    lifecycle methods tolerate lightweight test doubles and ``record`` remains
    available for analyzers that only receive completed results.
    """

    def __init__(
        self,
        *,
        agent_name: str,
        md_path: Path,
        title: str,
        model: str,
    ) -> None:
        self.agent_name = agent_name
        self.md_path = Path(md_path)
        self.title = title
        self.model = model
        self._runs: list[tuple[str, AgentResult, list[dict[str, Any]]]] = []
        self._recorded_turns: set[tuple[str, str]] = set()
        self._active: dict[str, Any] | None = None
        self._lock = threading.RLock()

    def reset(self) -> None:
        with self._lock:
            self._runs.clear()
            self._recorded_turns.clear()
            self._active = None
            self.md_path.unlink(missing_ok=True)

    def start_turn(
        self,
        prompt: str,
        *,
        provider: str,
        session_id: str | None = None,
        turn_id: str | None = None,
        max_tool_calls: int | None = None,
        default_tool_timeout_seconds: float | None = None,
        turn_timeout_seconds: float | None = None,
    ) -> None:
        with self._lock:
            self._active = {
                "prompt": prompt,
                "provider": provider,
                "model": self.model,
                "session_id": session_id,
                "turn_id": turn_id,
                "status": "started",
                "reason_code": None,
                "events": [],
                "tool_calls_seen": 0,
                "last_tool": None,
                "limits": {
                    "max_tool_calls_per_turn": max_tool_calls,
                    "default_tool_timeout_seconds": default_tool_timeout_seconds,
                    "turn_timeout_seconds": turn_timeout_seconds,
                },
                "usage": {},
                "structured_output": None,
                "text": "",
                "started_at": time.monotonic(),
            }
            self._write()

    def bind_turn(self, *, session_id: str | None = None, turn_id: str | None = None) -> None:
        with self._lock:
            if self._active is None:
                return
            if session_id is not None:
                self._active["session_id"] = session_id
            if turn_id is not None:
                self._active["turn_id"] = turn_id
            self._write()

    def record_event(
        self,
        event_type: str,
        payload: Any,
        *,
        tool_call_id: str | None = None,
        tool_name: str | None = None,
        tool_call_count: int | None = None,
    ) -> None:
        with self._lock:
            if self._active is None:
                return
            event: dict[str, Any] = {
                "type": event_type,
                "payload": _json_value(payload),
            }
            if tool_call_id is not None:
                event["tool_call_id"] = tool_call_id
            if tool_name is not None:
                event["tool_name"] = tool_name
                self._active["last_tool"] = tool_name
            if tool_call_count is not None:
                self._active["tool_calls_seen"] = tool_call_count
            if event_type in {"token_usage", "thread/tokenUsage/updated"}:
                normalized_usage = _json_value(payload)
                if isinstance(normalized_usage, dict):
                    self._active["usage"] = normalized_usage
            self._active["events"].append(event)
            self._write()

    def finish_turn(self, result: AgentResult) -> None:
        with self._lock:
            prompt = self._active.get("prompt", "") if self._active else ""
            if self._active is not None:
                self._active["status"] = result.status
                self._active["text"] = result.text
                self._active["usage"] = dict(result.usage)
                self._active["structured_output"] = _json_value(
                    result.structured_response
                )
            self._runs.append((prompt, result, list(self._active["events"]) if self._active else []))
            self._record_usage(result)
            self._active = None
            self._write()

    def fail_turn(
        self,
        error: BaseException,
        *,
        reason_code: str,
        status: str = "failed",
        result: AgentResult | None = None,
    ) -> None:
        """Close an in-flight trace even when the provider returned no result."""
        with self._lock:
            active = self._active
            if active is None:
                return
            active["status"] = status
            active["reason_code"] = reason_code
            active["terminal_error"] = str(error)
            if result is not None:
                # A provider may have completed the turn but local structured
                # output validation can still fail. Preserve that completed
                # payload while making the terminal status explicit.
                active["text"] = result.text
                active["usage"] = dict(result.usage)
                active["structured_output"] = _json_value(
                    result.structured_response
                )
                active["items"] = list(result.items)
            result = AgentResult(
                text=(result.text if result is not None else str(error)),
                structured_response=(
                    result.structured_response if result is not None else None
                ),
                provider=str(active.get("provider", "unknown")),
                session_id=str(active.get("session_id") or "unknown"),
                turn_id=str(active.get("turn_id") or "unknown"),
                status=status,
                items=(list(result.items) if result is not None else []),
                usage=(
                    dict(result.usage)
                    if result is not None
                    else dict(active.get("usage", {}))
                ),
                skills=(list(result.skills) if result is not None else []),
                tool_calls_seen=int(
                    result.tool_calls_seen
                    if result is not None
                    else active.get("tool_calls_seen", 0)
                ),
                last_tool=(
                    result.last_tool
                    if result is not None and result.last_tool
                    else active.get("last_tool")
                ),
                elapsed_seconds=(
                    result.elapsed_seconds
                    if result is not None and result.elapsed_seconds
                    else time.monotonic()
                    - float(active.get("started_at", time.monotonic()))
                ),
            )
            # Keep terminal metadata alongside the normalized result so the
            # completed renderer retains the exact stop reason and limits.
            result.reason_code = reason_code  # type: ignore[attr-defined]
            result.terminal_error = str(error)  # type: ignore[attr-defined]
            result.limits = dict(active.get("limits", {}))  # type: ignore[attr-defined]
            self._runs.append((str(active.get("prompt", "")), result, list(active["events"])))
            self._active = None
            self._write()

    def record(self, result: AgentResult, *, prompt: str) -> None:
        with self._lock:
            self._runs.append((prompt, result, list(self._active["events"]) if self._active else []))
            self._record_usage(result)
            self._active = None
            self._write()

    def write_summary(self) -> None:
        with self._lock:
            self._write()

    def _record_usage(self, result: AgentResult) -> None:
        turn_identity = (result.session_id, result.turn_id)
        if turn_identity in self._recorded_turns:
            return
        usage = result.usage
        record_usage(
            agent_name=self.agent_name,
            title=self.title,
            model=self.model,
            queries=1,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            cache_read=usage.get("cache_read_input_tokens", 0),
            cache_creation=usage.get("cache_creation_input_tokens", 0),
            elapsed_seconds=result.elapsed_seconds,
        )
        self._recorded_turns.add(turn_identity)

    def _write(self) -> None:
        self.md_path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            f"# {self.title}",
            "",
            f"- Agent: `{self.agent_name}`",
            f"- Model: `{self.model}`",
            f"- Turns: {len(self._runs) + (1 if self._active else 0)}",
            "",
        ]
        for index, (prompt, result, events) in enumerate(self._runs, 1):
            lines.extend(_render_turn(index, prompt, result, events))
        if self._active is not None:
            lines.extend(_render_active_turn(len(self._runs) + 1, self._active))
        _atomic_write(self.md_path, "\n".join(lines))


def _render_turn(index: int, prompt: str, result: AgentResult, events: list[dict]) -> list[str]:
    lines = [
        f"## Turn {index}", "",
        f"- Provider: `{result.provider}`",
        f"- Session: `{result.session_id}`",
        f"- Turn: `{result.turn_id}`",
        f"- Status: `{result.status}`",
        f"- Elapsed: {result.elapsed_seconds:.2f}s",
        f"- Tool calls seen: `{result.tool_calls_seen}`",
        f"- Last tool: `{result.last_tool or '(none)'}`",
    ]
    reason_code = getattr(result, "reason_code", None)
    if reason_code:
        lines.append(f"- Reason code: `{reason_code}`")
    limits = getattr(result, "limits", None)
    if limits:
        lines.append(
            f"- Limits: `{json.dumps(limits, ensure_ascii=False)}`"
        )
    terminal_error = getattr(result, "terminal_error", None)
    if terminal_error:
        lines.append(f"- Terminal error: `{terminal_error}`")
    lines.extend([
        f"- Usage: `{json.dumps(result.usage, ensure_ascii=False)}`",
        f"- Skills: `{json.dumps(result.skills, ensure_ascii=False)}`", "",
        "### Prompt", "", "```text", prompt, "```", "",
        "### Completed items", "",
    ])
    for item_index, item in enumerate(result.items, 1):
        lines.extend([
            f"#### {item_index}. {item.get('type', 'unknown')}", "", "```json",
            json.dumps(item, ensure_ascii=False, indent=2, default=_json_default),
            "```", "",
        ])
    if events:
        lines.extend(["### Observed events", ""])
        lines.extend(_render_events(events))
    if result.structured_response is not None:
        lines.extend([
            "### Structured output", "", "```json",
            json.dumps(
                _json_value(result.structured_response),
                ensure_ascii=False,
                indent=2,
                default=_json_default,
            ),
            "```", "",
        ])
    lines.extend(["### Final response", "", "```text", result.text, "```", ""])
    return lines


def _render_active_turn(index: int, active: dict[str, Any]) -> list[str]:
    lines = [
        f"## Turn {index} (in progress)", "",
        f"- Provider: `{active.get('provider', 'unknown')}`",
        f"- Model: `{active.get('model', '')}`",
        f"- Session: `{active.get('session_id') or '(pending)'}`",
        f"- Turn: `{active.get('turn_id') or '(pending)'}`",
        f"- Status: `{active.get('status', 'started')}`",
        f"- Elapsed: `{time.monotonic() - float(active.get('started_at', time.monotonic())):.2f}s`",
        f"- Reason code: `{active.get('reason_code') or '(none)'}`",
        f"- Tool calls seen: `{active.get('tool_calls_seen', 0)}`",
        f"- Last tool: `{active.get('last_tool') or '(none)'}`",
        f"- Limits: `{json.dumps(active.get('limits', {}), ensure_ascii=False)}`", "",
        "### Prompt", "", "```text", str(active.get('prompt', '')), "```", "",
        "### Observed events", "",
    ]
    lines.extend(_render_events(active.get("events", [])))
    if active.get("items"):
        lines.extend(["### Completed items", ""])
        for item_index, item in enumerate(active["items"], 1):
            lines.extend([
                f"#### {item_index}. {item.get('type', 'unknown') if isinstance(item, dict) else 'unknown'}",
                "", "```json",
                json.dumps(item, ensure_ascii=False, indent=2, default=_json_default),
                "```", "",
            ])
    if active.get("structured_output") is not None:
        lines.extend([
            "### Structured output", "", "```json",
            json.dumps(
                active["structured_output"],
                ensure_ascii=False,
                indent=2,
                default=_json_default,
            ),
            "```", "",
        ])
    if active.get("text"):
        lines.extend([
            "### Final response", "", "```text",
            str(active["text"]), "```", "",
        ])
    if active.get("terminal_error"):
        lines.extend(["### Terminal error", "", "```text", str(active["terminal_error"]), "```", ""])
    return lines


def _render_events(events: list[dict]) -> list[str]:
    lines = []
    for event_index, event in enumerate(events, 1):
        lines.extend([
            f"#### {event_index}. {event.get('type', 'event')}", "", "```json",
            json.dumps(event, ensure_ascii=False, indent=2, default=_json_default),
            "```", "",
        ])
    return lines


def _json_value(value: Any) -> Any:
    if isinstance(value, AgentResult):
        return {"text": value.text, "provider": value.provider, "session_id": value.session_id,
                "turn_id": value.turn_id, "status": value.status, "items": value.items,
                "usage": value.usage}
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return value
    return str(value)


def _json_default(value: Any) -> str:
    return str(value)


def _atomic_write(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{threading.get_ident()}")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


__all__ = ["AgentTraceHandler"]
