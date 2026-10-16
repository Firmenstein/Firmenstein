"""Retained native history and explicit resume, including failure boundaries."""
import asyncio
import json
from pathlib import Path

import pytest
from claude_agent_sdk import ResultMessage, SystemMessage

from fmst_basic.agent import create_analysis_agent
from fmst_basic.agent.claude_agent import ClaudeAnalysisAgent
from fmst_basic.agent.skill import AgentSkillSpec


@pytest.fixture
def options(monkeypatch, tmp_path):
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-secret")
    work = tmp_path / "work"
    work.mkdir()
    return dict(model="test", developer_instructions="policy", workdir=work,
                session_dir=tmp_path / "native-session", filesystem_access="read_shell")


def transcript(agent):
    path = Path(agent._options.env["CLAUDE_CONFIG_DIR"]) / "projects/project" / (agent._session_id + ".jsonl")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"type":"user","message":"retained input"}\n')
    return path


def test_resume_reuses_id_config_cwd_and_original_history(options):
    agent = create_analysis_agent(provider="claude", **options)
    history = transcript(agent)
    original = history.read_bytes()
    cwd = agent._options.cwd
    session_id = agent._session_id
    asyncio.run(agent.aclose())
    resumed = create_analysis_agent(provider="claude", resume=True, **options)
    try:
        assert resumed._options.resume == session_id
        assert resumed._options.session_id is None
        assert resumed._options.cwd == cwd
        assert history.read_bytes() == original
        assert resumed._options.setting_sources == []
        assert "test-secret" not in resumed.session_receipt.read_text()
        assert resumed.session_dir.stat().st_mode & 0o777 == 0o700
        assert resumed.session_receipt.stat().st_mode & 0o777 == 0o600
    finally:
        asyncio.run(resumed.aclose())


def test_fresh_session_cannot_overwrite_retained_state(options):
    agent = ClaudeAnalysisAgent(**options)
    history = transcript(agent)
    asyncio.run(agent.aclose())
    with pytest.raises(FileExistsError):
        ClaudeAnalysisAgent(**options)
    assert history.is_file()


@pytest.mark.parametrize("damage", ["missing_receipt", "missing_history", "wrong_workdir", "wrong_tools"])
def test_resume_fails_closed_without_matching_history_and_identity(options, damage):
    agent = ClaudeAnalysisAgent(**options)
    history = transcript(agent)
    asyncio.run(agent.aclose())
    if damage == "missing_receipt":
        agent.session_receipt.unlink()
    elif damage == "missing_history":
        history.unlink()
    elif damage == "wrong_workdir":
        options["workdir"] = options["workdir"].parent
    else:
        data = json.loads(agent.session_receipt.read_text())
        data["identity"]["tools"] = ["unrelated-tool"]
        agent.session_receipt.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        ClaudeAnalysisAgent(resume=True, **options)


def test_same_session_has_only_one_writer(options):
    agent = ClaudeAnalysisAgent(**options)
    transcript(agent)
    try:
        with pytest.raises(BlockingIOError):
            ClaudeAnalysisAgent(resume=True, **options)
    finally:
        asyncio.run(agent.aclose())
    resumed = ClaudeAnalysisAgent(resume=True, **options)
    asyncio.run(resumed.aclose())


def test_disconnect_failure_keeps_history_and_releases_lock(options):
    agent = ClaudeAnalysisAgent(**options)
    history = transcript(agent)

    class BrokenClient:
        async def disconnect(self):
            raise RuntimeError("disconnect failed")

    agent._client = BrokenClient()
    with pytest.raises(RuntimeError, match="disconnect failed"):
        asyncio.run(agent.aclose())
    assert history.is_file()
    resumed = ClaudeAnalysisAgent(resume=True, **options)
    asyncio.run(resumed.aclose())


def test_skill_plugin_survives_and_can_be_reattached(options):
    root = options["workdir"] / "skills/example"
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text('---\nname: example\ndescription: Example instructions.\n---\nRead a file.\n')
    options["skills"] = [AgentSkillSpec(name="example", skill_dir=root)]
    agent = ClaudeAnalysisAgent(**options)
    transcript(agent)
    plugins = agent._options.plugins
    asyncio.run(agent.aclose())
    resumed = ClaudeAnalysisAgent(resume=True, **options)
    try:
        assert resumed._options.plugins == plugins
        assert (Path(plugins[0]["path"]) / ".claude-plugin/plugin.json").is_file()
    finally:
        asyncio.run(resumed.aclose())


def test_sdk_init_identity_saved_before_interruption(monkeypatch, options):
    import fmst_basic.agent.claude_agent as module

    class Client:
        def __init__(self, *, options):
            self.options = options

        async def connect(self):
            pass

        async def query(self, *args, **kwargs):
            pass

        async def receive_response(self):
            yield SystemMessage(subtype="init", data={"session_id": self.options.session_id})
            raise asyncio.CancelledError()

        async def disconnect(self):
            pass

    monkeypatch.setattr(module, "ClaudeSDKClient", Client)
    agent = ClaudeAnalysisAgent(**options)
    history = transcript(agent)

    async def run():
        try:
            with pytest.raises(asyncio.CancelledError):
                await agent.ainvoke("test interruption")
        finally:
            await agent.aclose()
    asyncio.run(run())
    assert history.is_file()
    assert json.loads(agent.session_receipt.read_text())["session_id"] == agent._session_id


def test_same_client_followup_then_new_client_resume(monkeypatch, options):
    import fmst_basic.agent.claude_agent as module
    clients = []

    class Client:
        def __init__(self, *, options):
            self.options = options
            self.prompts = []
            clients.append(self)

        async def connect(self):
            pass

        async def query(self, prompt, **kwargs):
            self.prompts.append(prompt)

        async def receive_response(self):
            session_id = self.options.resume or self.options.session_id
            yield SystemMessage(subtype="init", data={"session_id": session_id})
            yield ResultMessage(subtype="success", duration_ms=1, duration_api_ms=1,
                                is_error=False, num_turns=1, session_id=session_id, result="done")

        async def disconnect(self):
            pass

    monkeypatch.setattr(module, "ClaudeSDKClient", Client)

    async def run():
        agent = ClaudeAnalysisAgent(**options)
        transcript(agent)
        await agent.ainvoke("business goal")
        await agent.ainvoke("organize delivery")
        await agent.aclose()
        resumed = ClaudeAnalysisAgent(resume=True, **options)
        try:
            await resumed.ainvoke("another follow-up")
            assert resumed._turn_count == 3
        finally:
            await resumed.aclose()
    asyncio.run(run())
    assert len(clients) == 2
    assert clients[0].prompts == ["business goal", "organize delivery"]
    assert clients[1].prompts == ["another follow-up"]
    assert clients[1].options.resume == clients[0].options.session_id
