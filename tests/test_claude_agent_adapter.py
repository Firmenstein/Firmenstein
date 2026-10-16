"""Tests for the Claude Agent SDK adapter."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from claude_agent_sdk import AssistantMessage, ResultMessage, SystemMessage, TextBlock
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_basic.agent import (  # noqa: E402
    AgentProviderError,
    AgentTurnTimeoutError,
    AnalysisAgent,
    create_analysis_agent,
    tool,
)
from fmst_basic.agent.claude_agent import (  # noqa: E402
    ClaudeAnalysisAgent,
    _ClaudeToolBudget,
    _claude_tool,
    _make_tool_budget_hook,
    _make_filesystem_guard,
    _native_read_shell_settings,
    _prepare_native_shell_cwd,
)
from fmst_basic.agent.config import (  # noqa: E402
    CLAUDE_CODE_AUTO_COMPACT_WINDOW,
    DEFAULT_CLAUDE_EFFORT,
    DEFAULT_CLAUDE_MODEL,
    configured_claude_base_url,
)


class _Output(BaseModel):
    value: str = Field(description="Validated smoke-test value.")


@pytest.fixture(autouse=True)
def private_session_state(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))


def test_factory_builds_claude_provider(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = create_analysis_agent(
        provider="claude",
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        output_format=_Output,
        workdir=tmp_path,
        filesystem_access="read",
    )
    assert isinstance(agent, ClaudeAnalysisAgent)
    assert isinstance(agent, AnalysisAgent)
    assert agent._options.setting_sources == []
    assert agent._options.tools == ["Read", "Glob", "Grep"]
    matcher = agent._options.hooks["PreToolUse"][0]
    assert matcher.matcher == "^(?:Read|Glob|Grep)$"
    assert len(matcher.hooks) == 1
    assert agent._options.model == "sonnet"
    assert agent._options.effort == DEFAULT_CLAUDE_EFFORT == "high"
    assert agent._options.system_prompt == {
        "type": "preset",
        "preset": "claude_code",
        "append": "test",
    }
    assert agent._options.env["ANTHROPIC_BASE_URL"] == configured_claude_base_url()
    assert agent._options.env["ANTHROPIC_AUTH_TOKEN"] == "test-secret"
    assert agent._options.env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] == DEFAULT_CLAUDE_MODEL
    assert agent._options.env["ANTHROPIC_DEFAULT_SONNET_MODEL"] == DEFAULT_CLAUDE_MODEL
    assert agent._options.env["ANTHROPIC_DEFAULT_OPUS_MODEL"] == DEFAULT_CLAUDE_MODEL
    assert Path(agent._options.env["CLAUDE_CONFIG_DIR"]).is_dir()
    assert (
        agent._options.env["CLAUDE_CODE_AUTO_COMPACT_WINDOW"]
        == CLAUDE_CODE_AUTO_COMPACT_WINDOW
        == "1000000"
    )
    assert agent._options.output_format == {
        "type": "json_schema",
        "schema": _Output.model_json_schema(),
    }


def test_claude_state_workspace_survives_close(monkeypatch) -> None:
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
    )
    state_dir = Path(agent._options.env["CLAUDE_CONFIG_DIR"])
    history = state_dir / "retained.jsonl"
    history.write_text('{"message":"history"}\n')
    assert state_dir.is_dir()
    asyncio.run(agent.aclose())
    assert history.read_text() == '{"message":"history"}\n'
    assert agent.session_receipt.is_file()
    asyncio.run(agent.aclose())
    assert history.is_file()


def test_claude_model_suffix_is_lowercase_for_all_role_aliases(monkeypatch) -> None:
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = ClaudeAnalysisAgent(
        model="deepseek-flash[1M]",
        developer_instructions="test",
    )
    try:
        assert agent.model == "deepseek-flash[1m]"
        assert agent._options.model == "sonnet"
        assert agent._options.betas == ["context-1m-2025-08-07"]
        assert {
            agent._options.env["ANTHROPIC_DEFAULT_HAIKU_MODEL"],
            agent._options.env["ANTHROPIC_DEFAULT_SONNET_MODEL"],
            agent._options.env["ANTHROPIC_DEFAULT_OPUS_MODEL"],
        } == {"deepseek-flash[1m]"}
    finally:
        asyncio.run(agent.aclose())


def _guard_result(guard, tool_name: str, tool_input: dict) -> dict:
    return asyncio.run(
        guard(
            {"tool_name": tool_name, "tool_input": tool_input},
            None,
            None,
        )
    )


def test_claude_filesystem_guard_allows_paths_inside_workdir(tmp_path: Path) -> None:
    guard = _make_filesystem_guard(tmp_path)

    assert _guard_result(guard, "Read", {"file_path": "report.json"}) == {}
    assert _guard_result(
        guard,
        "Read",
        {"file_path": str(tmp_path / "report.json")},
    ) == {}
    assert _guard_result(guard, "Write", {"file_path": "created.txt"}) == {}
    assert _guard_result(guard, "Edit", {"file_path": "created.txt"}) == {}
    assert _guard_result(guard, "Grep", {"pattern": "needle"}) == {}
    assert _guard_result(
        guard,
        "Glob",
        {"path": str(tmp_path), "pattern": "**/*.json"},
    ) == {}
    assert _guard_result(
        guard,
        "Glob",
        {"path": ".", "pattern": "reports/*..json"},
    ) == {}


def test_claude_filesystem_guard_denies_traversal_and_symlink_escape(
    tmp_path: Path,
) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (tmp_path / "escape.txt").symlink_to(outside)
    (tmp_path / "escape-write.txt").symlink_to(outside)
    (tmp_path / "loop.txt").symlink_to(tmp_path / "loop.txt")
    guard = _make_filesystem_guard(tmp_path)

    for result in (
        _guard_result(guard, "Read", {"file_path": "../outside.txt"}),
        _guard_result(guard, "Read", {"file_path": "escape.txt"}),
        _guard_result(guard, "Read", {"file_path": "loop.txt"}),
        _guard_result(guard, "Write", {"file_path": "escape-write.txt"}),
        _guard_result(guard, "Edit", {"file_path": str(outside)}),
        _guard_result(guard, "Grep", {"path": str(tmp_path.parent)}),
        _guard_result(
            guard,
            "Glob",
            {"path": ".", "pattern": "../**/*.json"},
        ),
        _guard_result(
            guard,
            "Glob",
            {"path": ".", "pattern": "~/outside/*.json"},
        ),
    ):
        decision = result["hookSpecificOutput"]
        assert decision["hookEventName"] == "PreToolUse"
        assert decision["permissionDecision"] == "deny"


def test_claude_filesystem_modes_expose_only_required_native_tools(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    none_agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        filesystem_access="none",
    )
    write_agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        workdir=tmp_path,
        filesystem_access="write",
    )
    shell_agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        workdir=tmp_path,
        filesystem_access="read_shell",
    )

    assert none_agent._options.tools == []
    assert none_agent._options.hooks is None
    assert write_agent._options.tools == ["Read", "Write", "Edit", "Glob", "Grep"]
    assert (
        write_agent._options.hooks["PreToolUse"][0].matcher
        == "^(?:Read|Write|Edit|Glob|Grep)$"
    )
    assert shell_agent._options.tools == ["Read", "Glob", "Grep", "Bash"]
    assert (
        shell_agent._options.hooks["PreToolUse"][0].matcher
        == "^(?:Read|Glob|Grep|Bash)$"
    )


def test_claude_read_shell_uses_strict_native_sandbox(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        workdir=tmp_path,
        filesystem_access="read_shell",
    )

    settings = json.loads(agent._options.settings)
    sandbox = settings["sandbox"]
    session_cwd = Path(agent._options.cwd).resolve()
    assert sandbox["enabled"] is True
    assert sandbox["failIfUnavailable"] is True
    assert sandbox["allowUnsandboxedCommands"] is False
    assert sandbox["excludedCommands"] == []
    assert sandbox["filesystem"]["denyRead"] == [
        str(Path.home().resolve())
    ]
    assert str(tmp_path.resolve()) in sandbox["filesystem"]["allowRead"]
    assert session_cwd in [
        Path(item) for item in sandbox["filesystem"]["allowRead"]
    ]
    assert sandbox["filesystem"]["denyWrite"] == [
        str(tmp_path.resolve()),
        str(session_cwd),
    ]
    assert Path(agent._options.env["CLAUDE_CONFIG_DIR"]).resolve() in {
        Path(item) for item in sandbox["filesystem"]["allowWrite"]
    }
    assert Path(agent._options.env["CLAUDE_CONFIG_DIR"]).resolve() in {
        Path(item) for item in sandbox["filesystem"]["allowRead"]
    }
    assert agent._options.add_dirs == [tmp_path.resolve()]
    assert agent._options.env["CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR"] == "1"
    assert sandbox["network"]["allowedDomains"] == []
    assert sandbox["network"]["deniedDomains"] == ["*"]
    assert sandbox["network"]["allowUnixSockets"] == []
    assert sandbox["network"]["allowAllUnixSockets"] is False
    denied_env = {
        item["name"] for item in sandbox["credentials"]["envVars"]
    }
    assert {
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "FMST_CLAUDE_AUTH_TOKEN",
    } <= denied_env


def test_native_read_shell_settings_are_deterministic(tmp_path: Path) -> None:
    session_cwd = tmp_path / "session"
    assert _native_read_shell_settings(
        tmp_path, session_cwd
    ) == _native_read_shell_settings(
        tmp_path, session_cwd
    )


def test_native_read_shell_cwd_has_protected_mount_points(tmp_path) -> None:
    root = _prepare_native_shell_cwd(tmp_path / "shell-cwd")
    assert (root / ".gitconfig").is_file()
    assert (root / ".claude/settings.json").is_file()
    assert (root / ".git/hooks").is_dir()


def test_claude_read_shell_requires_workdir(monkeypatch) -> None:
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    with pytest.raises(ValueError, match="requires workdir"):
        ClaudeAnalysisAgent(
            model=DEFAULT_CLAUDE_MODEL,
            developer_instructions="test",
            filesystem_access="read_shell",
        )


def test_claude_dynamic_tool_uses_agent_tool_validation() -> None:
    @tool
    def add(left: int, right: int) -> int:
        """Add two integers."""
        return left + right

    adapted = _claude_tool(add)
    result = asyncio.run(adapted.handler({"left": 2, "right": 3}))
    assert result == {"content": [{"type": "text", "text": "5"}]}
    invalid = asyncio.run(adapted.handler({"left": "bad", "right": 3}))
    assert invalid["is_error"] is True


def test_claude_tool_budget_deduplicates_hook_events_and_stops_at_limit() -> None:
    budget = _ClaudeToolBudget(maximum=2, trace=None)
    hook = _make_tool_budget_hook(budget)

    async def run():
        first = await hook(
            {"tool_name": "Read", "tool_input": {}}, "tool-1", None
        )
        duplicate = await hook(
            {"tool_name": "Read", "tool_input": {}}, "tool-1", None
        )
        second = await hook(
            {"tool_name": "Grep", "tool_input": {}}, "tool-2", None
        )
        return first, duplicate, second

    first, duplicate, second = asyncio.run(run())
    assert first == {}
    assert duplicate == {}
    assert second["stopReason"] == "tool_step_limit"
    assert budget.count == 2


def test_claude_custom_tool_timeout_returns_actionable_error() -> None:
    @tool(timeout_seconds=0.01)
    async def hang() -> str:
        await asyncio.Event().wait()
        return "never"

    budget = _ClaudeToolBudget(maximum=None, trace=None)
    adapted = _claude_tool(hang, budget=budget)
    result = asyncio.run(adapted.handler({}))
    assert result["is_error"] is True
    assert "hang" in result["content"][0]["text"]
    assert "0.01s" in result["content"][0]["text"]


def test_claude_result_is_normalized_and_client_is_closed(
    monkeypatch,
) -> None:
    from fmst_basic.agent import claude_agent as module

    class _FakeClient:
        instances = []

        def __init__(self, options):
            self.options = options
            self.connected = False
            self.disconnected = False
            self.prompt = None
            self.__class__.instances.append(self)

        async def connect(self):
            self.connected = True

        async def query(self, prompt):
            self.prompt = prompt

        async def receive_response(self):
            yield SystemMessage(
                subtype="init",
                data={"session_id": "session-1"},
            )
            yield AssistantMessage(
                content=[TextBlock(text="done")],
                model="deepseek-flash[1m]",
            )
            yield ResultMessage(
                subtype="success",
                duration_ms=1250,
                duration_api_ms=1000,
                is_error=False,
                num_turns=1,
                session_id="session-1",
                usage={
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "cache_read_input_tokens": 7,
                },
                result="done",
                structured_output={"value": "ok"},
                uuid="turn-1",
            )

        async def disconnect(self):
            self.disconnected = True

    monkeypatch.setattr(module, "ClaudeSDKClient", _FakeClient)
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        output_format=_Output,
    )
    async def run():
        result = await agent.ainvoke("inspect")
        await agent.aclose()
        return result

    result = asyncio.run(run())
    assert result.provider == "claude"
    assert result.session_id == "session-1"
    assert result.turn_id == "turn-1"
    assert result.structured_response == _Output(value="ok")
    assert result.usage["cache_read_input_tokens"] == 7
    assert result.elapsed_seconds == 1.25
    assert _FakeClient.instances[0].disconnected is True


def test_claude_provider_error_preserves_official_message_and_fields(
    monkeypatch,
) -> None:
    from fmst_basic.agent import claude_agent as module

    official_message = (
        'API Error: 429 {"error":{"code":"1302",'
        '"message":"用户速率限制"}}'
    )

    class _FakeClient:
        def __init__(self, options):
            self.options = options

        async def connect(self):
            pass

        async def query(self, prompt):
            pass

        async def receive_response(self):
            yield ResultMessage(
                subtype="success",
                duration_ms=100,
                duration_api_ms=90,
                is_error=True,
                num_turns=1,
                session_id="session-error",
                result=official_message,
                errors=[official_message],
                api_error_status=429,
                terminal_reason="completed",
                uuid="turn-error",
            )

        async def disconnect(self):
            pass

    recorded = []

    class _Trace:
        def record(self, result, *, prompt):
            recorded.append((result, prompt))

    monkeypatch.setattr(module, "ClaudeSDKClient", _FakeClient)
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        output_format=_Output,
    )

    async def run():
        try:
            await agent.ainvoke("inspect", trace=_Trace())
        finally:
            await agent.aclose()

    with pytest.raises(AgentProviderError) as caught:
        asyncio.run(run())

    error = caught.value
    assert str(error) == official_message
    assert error.official_message == official_message
    assert error.provider == "claude"
    assert error.model == DEFAULT_CLAUDE_MODEL
    assert error.http_status == 429
    assert error.subtype == "success"
    assert error.terminal_reason == "completed"
    assert len(recorded) == 1
    assert recorded[0][0].status == "failed"
    assert recorded[0][0].text == official_message


def test_claude_turn_timeout_disconnects_unusable_stream(
    monkeypatch,
) -> None:
    from fmst_basic.agent import claude_agent as module

    class _FakeClient:
        instances = []

        def __init__(self, options):
            self.options = options
            self.disconnected = False
            self.__class__.instances.append(self)

        async def connect(self):
            pass

        async def query(self, prompt):
            del prompt
            await asyncio.Event().wait()

        async def disconnect(self):
            self.disconnected = True

    monkeypatch.setattr(module, "ClaudeSDKClient", _FakeClient)
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    agent = ClaudeAnalysisAgent(
        model=DEFAULT_CLAUDE_MODEL,
        developer_instructions="test",
        output_format=_Output,
        turn_timeout_seconds=0.01,
    )

    with pytest.raises(AgentTurnTimeoutError):
        asyncio.run(agent.ainvoke("inspect"))

    assert agent._client is None
    assert _FakeClient.instances[0].disconnected is True


class _ExhaustionOutput(BaseModel):
    value: str

@pytest.mark.parametrize("subtype,http_status,has_schema,correctable", [
    ("error_max_structured_output_retries", None, True, True),
    ("error_max_structured_output_retries", 429, True, False),
    ("error_max_structured_output_retries", None, False, False),
    ("error_during_execution", None, True, False),
])
def test_exhaustion_preserves_turn_and_only_corrects_output_boundary(
    monkeypatch, subtype, http_status, has_schema, correctable,
):
    from fmst_basic.agent import claude_agent as module
    official = "Failed to provide valid structured output after 5 attempts"
    class Client:
        instances=[]
        def __init__(self,options):
            self.prompts=[]
            self.closed=False
            self.__class__.instances.append(self)
        async def connect(self): pass
        async def query(self,prompt): self.prompts.append(prompt)
        async def disconnect(self): self.closed=True
        async def receive_response(self):
            if len(self.prompts)==1:
                yield ResultMessage(subtype=subtype,duration_ms=100,
                    duration_api_ms=90,is_error=True,num_turns=5,
                    session_id="retained-session",errors=[official],
                    api_error_status=http_status,uuid="failed-turn")
            else:
                yield ResultMessage(subtype="success",duration_ms=100,
                    duration_api_ms=90,is_error=False,num_turns=1,
                    session_id="retained-session",uuid="corrected-turn",
                    structured_output={"value":"recovered"})
    failures=[]
    class Trace:
        def fail_turn(self,error,*,reason_code,result):
            failures.append((error,reason_code,result))
    monkeypatch.setattr(module,"ClaudeSDKClient",Client)
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN","test-credential")
    agent=module.ClaudeAnalysisAgent(model="deepseek-flash[1m]",
        developer_instructions="",output_format=_ExhaustionOutput if has_schema else None)
    async def run_check():
        try:
            expected=module.AgentStructuredOutputError if correctable else module.AgentProviderError
            with pytest.raises(expected) as caught:
                await agent.ainvoke("initial",trace=Trace())
            error=caught.value
            assert str(error)==official
            assert len(failures)==1
            assert failures[0][1]==("structured_output_error" if correctable else "provider_error")
            assert failures[0][2].status=="failed"
            assert failures[0][2].text==official
            assert failures[0][2].turn_id=="failed-turn"
            if correctable:
                assert error.agent_result is failures[0][2]
                result=await agent.ainvoke("correct")
                assert result.structured_response==_ExhaustionOutput(value="recovered")
                assert result.turn_id=="corrected-turn"
                assert len(Client.instances)==1
                assert Client.instances[0].prompts==["initial","correct"]
            else:
                assert error.subtype==subtype
                assert error.http_status==http_status
        finally:await agent.aclose()
        assert Client.instances[0].closed
    asyncio.run(run_check())
