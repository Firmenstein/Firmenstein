"""Tests for universal decompiler-to-assembly escalation guidance."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv
from pydantic import BaseModel
import pytest

load_dotenv()

from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as module  # noqa: E402
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (  # noqa: E402
    ASSEMBLY_EVIDENCE_GUIDANCE,
    CodeAnalyzerAgent,
)


class _Output(BaseModel):
    value: str


@pytest.mark.parametrize("line_count", [3, module.INITIAL_FULL_ASSEMBLY_MAX_LINES + 1])
def test_code_analyzer_injects_assembly_guidance_and_exact_path(monkeypatch, tmp_path, line_count):
    captured: dict[str, object] = {}
    prompts: list[str] = []
    assembly_path = tmp_path / "main@1000.s"
    listing = "\n".join(f"0x{0x1000 + index * 4:x}: source instruction {index}" for index in range(line_count))
    assembly_path.write_text(listing)

    class _View:
        def get_function_ea(self, binary_name: str, function_name: str) -> int:
            return 0x1000

        def get_disassembly_path(self, binary_name: str, function_ea: int) -> Path:
            return assembly_path

        def get_full_code(self, binary_name: str, function_name: str) -> str:
            return "int main(void) { return 0; }"

    class _Agent:
        async def ainvoke(self, prompt: str, *, trace=None):
            prompts.append(prompt)
            return SimpleNamespace(structured_response=_Output(value="ok"))

        async def aclose(self):
            return None

    def _create(**kwargs):
        captured.update(kwargs)
        return _Agent()

    monkeypatch.setattr(module, "create_analysis_agent", _create)
    monkeypatch.setattr(module, "make_analyzer_tools", lambda _view: [])

    agent = CodeAnalyzerAgent(
        agent_name="AssemblyGuidanceTest",
        task_prompt="task contract",
        output_format=_Output,
        model="gpt-test",
    )
    result = asyncio.run(
        agent.analyze(
            user_message="inspect the function",
            view=_View(),
            binary_name="httpd",
            function_name="main@1000",
        )
    )

    assert result.value == "ok"
    assert captured["developer_instructions"] == ""
    assert prompts[0].startswith("task contract\n\n")
    assert prompts[0].count(ASSEMBLY_EVIDENCE_GUIDANCE) == 1
    assert str(assembly_path) in prompts[0]
    if line_count <= module.INITIAL_FULL_ASSEMBLY_MAX_LINES:
        assert listing in prompts[0]
        assert f"({line_count} lines, complete)" in prompts[0]
    else:
        assert "source instruction" not in prompts[0]
        assert f"Listing omitted from initial context ({line_count} lines)" in prompts[0]
        assert assembly_path.read_text() == listing


def test_guidance_is_not_duplicated_when_prompt_already_contains_it(monkeypatch):
    captured: dict[str, object] = {}
    prompts: list[str] = []

    class _Agent:
        async def ainvoke(self, _prompt: str, *, trace=None):
            prompts.append(_prompt)
            return SimpleNamespace(structured_response=_Output(value="ok"))

        async def aclose(self):
            return None

    monkeypatch.setattr(
        module,
        "create_analysis_agent",
        lambda **kwargs: (captured.update(kwargs) or _Agent()),
    )
    monkeypatch.setattr(module, "make_analyzer_tools", lambda _view: [])

    prompt = f"task\n\n{ASSEMBLY_EVIDENCE_GUIDANCE}"
    agent = CodeAnalyzerAgent(
        agent_name="AssemblyGuidanceTest",
        task_prompt=prompt,
        output_format=_Output,
        model="gpt-test",
    )
    asyncio.run(agent.analyze(user_message="inspect", view=object()))

    assert captured["developer_instructions"] == ""
    assert prompts == [prompt + "\n\ninspect"]
