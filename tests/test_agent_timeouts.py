"""Timeout policy at the Agent, tool and cancellation boundaries; no SDK process."""

from __future__ import annotations

import asyncio
import itertools
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from claude_agent_sdk import ResultMessage

from fmst_basic.agent import AgentProviderError, AgentTurnTimeoutError, tool
from fmst_basic.agent import claude_agent, codex_agent


def _note(method, **payload):
    return SimpleNamespace(method=method, payload=SimpleNamespace(**payload))


def _item(kind, identity="item-1"):
    return SimpleNamespace(
        type=kind, id=identity, text="done",
        model_dump=lambda **kwargs: {"type": kind, "id": identity},
    )


def _completed():
    return _note("turn/completed", turn=SimpleNamespace(
        status=SimpleNamespace(value="completed"), error=None,
        model_dump=lambda **kwargs: {"status": "completed"},
    ))


class _CodexClient:
    def __init__(self, notes):
        self.notes = iter(notes)
        self.interrupted = threading.Event()
        self.unregistered = threading.Event()

    def turn_start(self, *args, **kwargs):
        return SimpleNamespace(turn=SimpleNamespace(id="turn-1"))

    def next_turn_notification(self, turn_id):
        return next(self.notes)

    def turn_interrupt(self, thread_id, turn_id):
        self.interrupted.set()

    def unregister_turn_notifications(self, turn_id):
        self.unregistered.set()


def test_default_codex_turn_outlives_former_limits(monkeypatch):
    runtime = codex_agent._CodexRuntime()
    runtime._client = _CodexClient([_completed()])
    clock = itertools.count(step=3600)
    monkeypatch.setattr(codex_agent, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    try:
        result = runtime._run_turn_sync(
            "thread", "inspect", None, None, runtime.empty_cwd, [], -3600,
        )
        assert result.status == "completed"
        assert result.elapsed_seconds >= 3600
        assert not runtime._client.interrupted.is_set()
    finally:
        runtime.close()


def test_native_codex_tool_still_expires_without_turn_deadline():
    runtime = codex_agent._CodexRuntime()

    class Client(_CodexClient):
        def next_turn_notification(self, turn_id):
            try:
                return super().next_turn_notification(turn_id)
            except StopIteration:
                assert self.interrupted.wait(1)
                return _completed()

    runtime._client = Client([_note("item/started", item=_item("commandExecution"))])
    try:
        with pytest.raises(AgentTurnTimeoutError) as caught:
            runtime._run_turn_sync(
                "thread", "inspect", None, None, runtime.empty_cwd, [], 0,
                default_tool_timeout_seconds=0.01,
            )
        assert caught.value.code == "tool_timeout"
        assert runtime._client.interrupted.wait(1)
        assert runtime._client.unregistered.is_set()
    finally:
        runtime.close()


def test_dynamic_codex_tool_has_no_second_native_watchdog(monkeypatch):
    runtime = codex_agent._CodexRuntime()
    runtime._client = _CodexClient([
        _note("item/started", item=_item("dynamicToolCall")),
        _note("item/completed", item=_item("dynamicToolCall")),
        _completed(),
    ])
    clock = itertools.count(step=10)
    monkeypatch.setattr(codex_agent, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    try:
        result = runtime._run_turn_sync(
            "thread", "inspect", None, None, runtime.empty_cwd, [], 0,
            default_tool_timeout_seconds=0.01,
        )
        assert result.status == "completed"
    finally:
        runtime.close()


def test_codex_cancellation_wakes_unbounded_worker():
    runtime = codex_agent._CodexRuntime()
    receiving = threading.Event()

    class Client(_CodexClient):
        def next_turn_notification(self, turn_id):
            receiving.set()
            assert self.interrupted.wait(1)
            return _completed()

    runtime._client = Client([])

    async def run():
        task = asyncio.create_task(runtime.run_turn(
            thread_id="thread", prompt="inspect", output_model=None,
            cwd=runtime.empty_cwd, skills=[],
        ))
        assert await asyncio.to_thread(receiving.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await asyncio.to_thread(runtime._client.interrupted.wait, 1)
        assert await asyncio.to_thread(runtime._client.unregistered.wait, 1)

    try:
        asyncio.run(run())
    finally:
        runtime.close()


def test_codex_custom_tool_timeout_can_be_followed_by_another_tool():
    runtime = codex_agent._CodexRuntime()
    runtime._interrupt_turn_async = Mock()
    trace = SimpleNamespace(record_event=Mock())

    @tool(timeout_seconds=0.01)
    async def hang() -> str:
        await asyncio.Event().wait()
        return "never"

    @tool
    async def recover() -> str:
        return "recovered"

    async def run():
        runtime._contexts["thread"] = codex_agent._ThreadContext(
            tools={t.name: t for t in (hang, recover)}, loop=asyncio.get_running_loop(),
            active_turn=codex_agent._TurnBudgetState(
                None, 120, "codex", None, "turn-1", trace=trace,
            ),
        )
        results = []
        for name in ("hang", "recover"):
            results.append(await asyncio.to_thread(
                runtime._handle_server_request, "item/tool/call",
                {"threadId": "thread", "tool": name, "arguments": {}},
            ))
        assert results[0]["success"] is False
        assert "TimeoutError" in results[0]["contentItems"][0]["text"]
        assert results[1]["success"] is True
        runtime._interrupt_turn_async.assert_not_called()
        assert "tool/failed" in [call.args[0] for call in trace.record_event.call_args_list]

    try:
        asyncio.run(run())
    finally:
        runtime.close()


@pytest.mark.parametrize("provider", ["codex", "claude"])
def test_default_policy_and_transport_error_are_distinct(provider, monkeypatch):
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    cls = codex_agent.CodexAnalysisAgent if provider == "codex" else claude_agent.ClaudeAnalysisAgent
    agent = cls(model="test-model", developer_instructions="test")
    assert agent.turn_timeout_seconds is None
    assert agent.default_tool_timeout_seconds == 120
    assert agent.max_tool_calls_per_turn is None

    if provider == "codex":
        monkeypatch.setattr(codex_agent._RUNTIME, "start_thread", AsyncMock(side_effect=TimeoutError("transport timeout")))
    else:
        monkeypatch.setattr(agent, "_ensure_connected", AsyncMock(side_effect=TimeoutError("transport timeout")))

    async def run():
        try:
            with pytest.raises(AgentProviderError, match="transport timeout"):
                await agent.ainvoke("inspect")
        finally:
            await agent.aclose()

    asyncio.run(run())


class _ClaudeClient:
    async def connect(self):
        pass

    async def query(self, prompt):
        pass

    async def receive_response(self):
        yield ResultMessage(
            subtype="success", duration_ms=3600000, duration_api_ms=3600000,
            is_error=False, num_turns=1, session_id="session-1", result="done",
        )

    async def disconnect(self):
        self.disconnected = True


@pytest.mark.parametrize("outcome", ["timeout", "PostToolUse", "PostToolUseFailure", "denied"])
def test_claude_native_tool_deadline_only_applies_while_tool_active(outcome, monkeypatch, tmp_path):
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = claude_agent.ClaudeAnalysisAgent(
        model="test-model", developer_instructions="test", workdir=tmp_path,
        filesystem_access="read", default_tool_timeout_seconds=0.01,
    )

    class Client(_ClaudeClient):
        async def query(self, prompt):
            data = {"tool_name": "Read", "tool_use_id": "tool-1",
                    "tool_input": {"file_path": "../outside" if outcome == "denied" else "local"}}
            hook = agent._options.hooks["PreToolUse"][0].hooks[0]
            decision = await hook(data, "tool-1", None)
            if outcome == "denied":
                assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"
            elif outcome != "timeout":
                hook = agent._options.hooks[outcome][0].hooks[0]
                await hook(data, "tool-1", None)
            await asyncio.sleep(0.03)

    client = Client()
    monkeypatch.setattr(agent, "_ensure_connected", AsyncMock(return_value=client))

    async def run():
        if outcome == "timeout":
            with pytest.raises(AgentTurnTimeoutError) as caught:
                await agent.ainvoke("inspect")
            assert caught.value.code == "tool_timeout"
            assert caught.value.last_tool == "Read"
            assert client.disconnected
            import json
            diagnostic = json.loads((agent.session_dir / "native-tool-timeout.json").read_text())
            assert '"file_path": "local"' in diagnostic["diagnostic"]
            assert any("native-tool-timeout.json" in note for note in caught.value.__notes__)
        else:
            assert (await agent.ainvoke("inspect")).status == "completed"
        assert agent._native_tool_scope is None
        assert agent._active_native_tools == {}
        await agent.aclose()

    asyncio.run(run())


def test_claude_tool_timeout_does_not_reject_later_success(monkeypatch):
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")

    @tool(timeout_seconds=0.01)
    async def hang() -> str:
        await asyncio.Event().wait()
        return "never"

    agent = claude_agent.ClaudeAnalysisAgent(
        model="test-model", developer_instructions="test", tools=[hang],
    )

    class Client(_ClaudeClient):
        async def query(self, prompt):
            adapted = claude_agent._claude_tool(hang, budget=agent._tool_budget)
            assert (await adapted.handler({}))["is_error"] is True

    monkeypatch.setattr(agent, "_ensure_connected", AsyncMock(return_value=Client()))

    async def run():
        try:
            result = await agent.ainvoke("inspect")
            assert result.status == "completed"
        finally:
            await agent.aclose()

    asyncio.run(run())
