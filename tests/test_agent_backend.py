"""Tests for the provider-neutral Agent SDK boundary."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_basic.agent import (  # noqa: E402
    AgentResult,
    AgentTraceHandler,
    AnalysisAgent,
    create_analysis_agent,
)
from fmst_basic.agent.claude_agent import ClaudeAnalysisAgent  # noqa: E402
from fmst_basic.agent.config import (  # noqa: E402
    DEFAULT_AGENT_PROVIDER,
    DEFAULT_CLAUDE_MODEL,
)


def test_default_factory_selects_claude_without_changing_construction(monkeypatch) -> None:
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = create_analysis_agent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        name="factory-test",
    )
    try:
        assert DEFAULT_AGENT_PROVIDER == "claude"
        assert isinstance(agent, ClaudeAnalysisAgent)
        assert isinstance(agent, AnalysisAgent)
        assert agent.max_tool_calls_per_turn is None
    finally:
        asyncio.run(agent.aclose())


def test_factory_rejects_unregistered_provider_before_invocation() -> None:
    with pytest.raises(ValueError, match="available providers: claude, codex"):
        create_analysis_agent(
            provider="unknown",
            model="unknown",
            developer_instructions="test",
        )


def test_normalized_result_uses_provider_neutral_session_identity() -> None:
    result = AgentResult(
        text="ok",
        structured_response=None,
        provider="codex",
        session_id="session-1",
        turn_id="turn-1",
        status="completed",
    )
    assert result.session_id == "session-1"


def test_generic_trace_renders_provider_session_and_claude_cache_usage(
    tmp_path: Path,
) -> None:
    result = AgentResult(
        text="done",
        structured_response=None,
        provider="claude",
        session_id="session-2",
        turn_id="turn-2",
        status="completed",
        usage={
            "input_tokens": 10,
            "output_tokens": 2,
            "cache_read_input_tokens": 7,
            "cache_creation_input_tokens": 3,
        },
    )
    trace_path = tmp_path / "trace.md"
    trace = AgentTraceHandler(
        agent_name="trace-test",
        md_path=trace_path,
        title="trace test",
        model="test-model",
    )
    trace.record(result, prompt="inspect")
    rendered = trace_path.read_text(encoding="utf-8")
    assert "Provider: `claude`" in rendered
    assert "Session: `session-2`" in rendered
    assert "cache_read_input_tokens" in rendered


def test_trace_persists_started_events_and_terminal_reason(tmp_path: Path) -> None:
    trace_path = tmp_path / "round-01__generator.md"
    trace = AgentTraceHandler(
        agent_name="execution-unit-u",
        md_path=trace_path,
        title="execution round",
        model="gpt-5.6-terra",
    )
    trace.start_turn(
        "implement",
        provider="codex",
        max_tool_calls=128,
        default_tool_timeout_seconds=120,
        turn_timeout_seconds=1800,
    )
    trace.record_event(
        "tool/started",
        {"path": "logic.rs"},
        tool_call_id="tool-1",
        tool_name="Read",
        tool_call_count=1,
    )
    trace.record_event("token_usage", {"input_tokens": 12})
    trace.fail_turn(
        TimeoutError("tool stalled"),
        reason_code="tool_timeout",
    )
    rendered = trace_path.read_text(encoding="utf-8")
    assert "Status: `failed`" in rendered
    assert "Reason code: `tool_timeout`" in rendered
    assert "Tool calls seen: `1`" in rendered
    assert "tool stalled" in rendered
    assert '"input_tokens": 12' in rendered


def test_trace_closes_cancelled_turn_instead_of_leaving_started_file(
    tmp_path: Path,
) -> None:
    trace_path = tmp_path / "round-01__reviewer.md"
    trace = AgentTraceHandler(
        agent_name="execution-review-u",
        md_path=trace_path,
        title="review round",
        model="gpt-5.6-terra",
    )
    trace.start_turn("review", provider="codex")
    trace.fail_turn(
        asyncio.CancelledError(),
        reason_code="cancelled",
    )
    rendered = trace_path.read_text(encoding="utf-8")
    assert "Status: `failed`" in rendered
    assert "Reason code: `cancelled`" in rendered


@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled"])
def test_trace_retains_observed_tool_evidence_after_terminal_and_next_turn(tmp_path, terminal):
    path = tmp_path / "trace.md"
    trace = AgentTraceHandler(agent_name="probe", md_path=path, title="probe", model="test")
    trace.start_turn("first", provider="codex")
    trace.record_event("tool/completed", {"source": "first.c", "evidence": "original source bytes"})
    result = AgentResult(text="done", structured_response=None, provider="codex",
                         session_id="test", turn_id="first", status="completed")
    if terminal == "completed":
        trace.finish_turn(result)
    else:
        trace.fail_turn(TimeoutError("stopped"), reason_code=terminal)
    trace.start_turn("second", provider="codex")
    trace.record_event("tool/completed", {"source": "second.c"})
    trace.fail_turn(TimeoutError("stopped again"), reason_code="turn_timeout")
    trace.write_summary()
    text = path.read_text()
    first, second = text.split("## Turn 2", 1)
    assert '"source": "first.c"' in first
    assert "original source bytes" in first
    assert "second.c" not in first
    assert '"source": "second.c"' in second
    assert "first.c" not in second
