"""InitLaunch uses one provider-native, read-only rootfs Agent."""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_basic.agent import AgentResult
from fmst_analyzer.analysis.init_launch.analyzer_schema import (
    AnalysisGap,
    InitLaunchAnalysisResult,
    LaunchRecipeAgentOutput,
    TargetIdentity,
)
from fmst_analyzer.analysis.init_launch.launch_recipe_agent import (
    LaunchRecipeAgent,
)
from fmst_analyzer.analysis.init_launch import launch_recipe_agent


def test_launch_agent_requests_native_read_shell_once(
    monkeypatch, tmp_path: Path,
) -> None:
    factory_calls = 0
    invoke_calls = 0
    captured: dict[str, object] = {}
    captured_prompt = ""
    closed = False

    class _FakeAgent:
        async def ainvoke(self, prompt: str, *, trace=None) -> AgentResult:
            nonlocal captured_prompt, invoke_calls
            del trace
            invoke_calls += 1
            captured_prompt = prompt
            return AgentResult(
                text="",
                structured_response=LaunchRecipeAgentOutput(
                    analysis_gaps=[AnalysisGap(reason="No launch site found.")]
                ),
                provider="claude",
                session_id="session",
                turn_id="turn",
                status="completed",
            )

        async def aclose(self) -> None:
            nonlocal closed
            closed = True

    def _fake_factory(**kwargs):
        nonlocal factory_calls
        factory_calls += 1
        captured.update(kwargs)
        return _FakeAgent()

    monkeypatch.setattr(
        "fmst_analyzer.analysis.init_launch.launch_recipe_agent."
        "create_analysis_agent",
        _fake_factory,
    )
    config = SimpleNamespace(
        diagnosis_model="test-model",
        agent_provider="claude",
        workdir=None,
    )
    identity = TargetIdentity(
        target_basename="httpd",
        selected_rootfs_path="sbin/httpd",
        target_aliases=[],
    )
    (tmp_path / "sbin").mkdir()
    (tmp_path / "sbin/httpd").write_bytes(b"synthetic target identity")
    result = asyncio.run(
        LaunchRecipeAgent(config).analyze(
            identity, tmp_path, ["etc/inittab", "sbin/init"], phase="full"
        )
    )
    assert isinstance(result, InitLaunchAnalysisResult)
    assert factory_calls == 1
    assert invoke_calls == 1
    assert captured["workdir"] == tmp_path
    assert captured["developer_instructions"] == ""
    assert captured_prompt.startswith(launch_recipe_agent.LAUNCH_RECIPE_TASK + "\n\n")
    assert captured["filesystem_access"] == "read_shell"
    assert {tool.name for tool in captured["tools"]} == {
        "read_source", "inspect_elf", "read_elf", "find_elf_references", "inspect_elf_function",
    }
    assert str(tmp_path.resolve()) in captured_prompt
    assert "etc/inittab" in captured_prompt
    assert closed is True
