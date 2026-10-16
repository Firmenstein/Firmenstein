"""CodeAnalyzerAgent filesystem-boundary construction tests."""

from __future__ import annotations

import asyncio
import json
import inspect
from pathlib import Path
from types import SimpleNamespace

import pytest
from dotenv import load_dotenv
from fmst_analyzer.analysis.base.output_validation import OutputValidationError
from pydantic import BaseModel, ValidationError

load_dotenv()

from fmst_basic.agent.analysis_agent import AgentProviderError  # noqa: E402
from fmst_basic.agent.config import (  # noqa: E402
    DEFAULT_AGENT_PROVIDER,
    DEFAULT_CODEX_MODEL,
)
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (  # noqa: E402
    CodeAnalyzerAgent,
    _format_initial_function_code,
    _summarize_validation_error,
)


class _DummyOutput(BaseModel):
    value: str


def test_construction_defaults_to_dynamic_tools_only():
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent",
        task_prompt="x",
        output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
    )
    assert agent.filesystem_access == "none"
    assert agent.workdir is None


def test_read_access_requires_explicit_workdir():
    root = Path("/tmp/example")
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent",
        task_prompt="x",
        output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
        filesystem_access="read",
        workdir=root,
    )
    assert agent.filesystem_access == "read"
    assert agent.workdir == root


def test_read_shell_preserves_additional_read_only_roots():
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent",
        task_prompt="x",
        output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
        filesystem_access="read_shell",
        workdir=Path("/tmp/rootfs"),
        readable_roots=[Path("/tmp/decompiled"), Path("/tmp/disassembled")],
    )
    assert agent.filesystem_access == "read_shell"
    assert agent.readable_roots == [
        Path("/tmp/decompiled"),
        Path("/tmp/disassembled"),
    ]


def test_analyze_signature_binary_and_function_optional():
    signature = inspect.signature(CodeAnalyzerAgent.analyze)
    assert signature.parameters["binary_name"].default is None
    assert signature.parameters["function_name"].default is None


def test_analyze_selects_provider_filesystem_boundary(monkeypatch):
    captured = []
    analyzer_tool_calls = []
    from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as mod

    class _BailAgent:
        def __init__(self, **kwargs):
            captured.append(kwargs)

        async def ainvoke(self, _prompt, *, trace=None):
            raise RuntimeError("bail")

        async def aclose(self):
            pass

    monkeypatch.setattr(mod, "create_analysis_agent", _BailAgent)
    def make_tools(_view, **_kwargs):
        analyzer_tool_calls.append(True)
        return []

    monkeypatch.setattr(mod, "make_analyzer_tools", make_tools)

    class _DummyView:
        pass

    plain = CodeAnalyzerAgent(
        agent_name="TestAgent", task_prompt="x",
        output_format=_DummyOutput, model=DEFAULT_CODEX_MODEL,
    )
    try:
        asyncio.run(plain.analyze(user_message="hi", view=_DummyView()))
    except RuntimeError:
        pass

    readable = CodeAnalyzerAgent(
        agent_name="TestAgent", task_prompt="x",
        output_format=_DummyOutput, model=DEFAULT_CODEX_MODEL,
        filesystem_access="read", workdir=Path("/tmp/example"),
    )
    try:
        asyncio.run(readable.analyze(user_message="hi", view=_DummyView()))
    except RuntimeError:
        pass

    assembly_only = CodeAnalyzerAgent(
        agent_name="TestAgent", task_prompt="x",
        output_format=_DummyOutput, model=DEFAULT_CODEX_MODEL,
        filesystem_access="read", workdir=Path("/tmp/example"),
        include_analyzer_tools=False,
    )
    try:
        asyncio.run(assembly_only.analyze(
            user_message="hi", view=_DummyView(),
        ))
    except RuntimeError:
        pass

    assert captured[0]["filesystem_access"] == "none"
    assert captured[0]["provider"] == DEFAULT_AGENT_PROVIDER
    assert captured[1]["filesystem_access"] == "read"
    assert captured[2]["filesystem_access"] == "read"
    assert captured[2]["tools"] == []
    assert len(analyzer_tool_calls) == 2


def test_semantic_schema_failure_is_corrected_and_agent_is_closed(monkeypatch):
    prompts = []
    closed = []
    from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as mod

    class _CorrectingAgent:
        def __init__(self, **_kwargs):
            pass

        async def ainvoke(self, prompt, *, trace=None):
            prompts.append(prompt)
            if len(prompts) <= 7:
                _DummyOutput.model_validate({})
            return SimpleNamespace(
                structured_response=_DummyOutput(value="corrected"),
            )

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(mod, "create_analysis_agent", _CorrectingAgent)
    monkeypatch.setattr(
        mod, "make_analyzer_tools", lambda _view, **_kwargs: [],
    )
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent",
        task_prompt="x",
        output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
    )
    output = asyncio.run(agent.analyze(user_message="analyze", view=object()))

    assert output.value == "corrected"
    assert len(prompts) == 8
    assert "value" in prompts[1]
    assert "Field required" in prompts[1]
    assert closed == [True]


@pytest.mark.parametrize("failure", [
    ValueError("fenced structured output is not valid JSON"),
    json.JSONDecodeError("bad JSON", "", 0),
])
def test_tagged_structured_output_failure_is_corrected(monkeypatch, failure):
    prompts = []
    closed = []
    from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as mod

    setattr(failure, "code", "structured_output_error")

    class _CorrectingAgent:
        def __init__(self, **_kwargs):
            pass

        async def ainvoke(self, prompt, *, trace=None):
            prompts.append(prompt)
            if len(prompts) == 1:
                raise failure
            return SimpleNamespace(
                structured_response=_DummyOutput(value="corrected"),
            )

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(mod, "create_analysis_agent", _CorrectingAgent)
    monkeypatch.setattr(mod, "make_analyzer_tools", lambda _view, **_kwargs: [])
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent", task_prompt="x", output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
    )
    output = asyncio.run(agent.analyze(user_message="analyze", view=object()))
    assert output.value == "corrected"
    assert len(prompts) == 2
    assert str(failure) in prompts[1]
    assert closed == [True]


def test_untagged_value_error_is_not_retried(monkeypatch):
    prompts = []
    closed = []
    from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as mod

    class _FailingAgent:
        def __init__(self, **_kwargs):
            pass

        async def ainvoke(self, prompt, *, trace=None):
            prompts.append(prompt)
            raise ValueError("unrelated controller failure")

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(mod, "create_analysis_agent", _FailingAgent)
    monkeypatch.setattr(mod, "make_analyzer_tools", lambda _view, **_kwargs: [])
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent", task_prompt="x", output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
    )
    with pytest.raises(ValueError, match="unrelated controller failure"):
        asyncio.run(agent.analyze(user_message="analyze", view=object()))
    assert len(prompts) == 1
    assert closed == [True]


def test_repeated_schema_errors_preserve_every_location():
    class _Item(BaseModel):
        value: str

    class _Items(BaseModel):
        items: list[_Item]

    try:
        _Items.model_validate({"items": [{}, {}, {}]})
    except Exception as error:
        assert isinstance(error, ValidationError)
        summary = _summarize_validation_error(error)
    else:  # pragma: no cover - the fixture must remain invalid
        raise AssertionError("expected validation error")

    assert "3 validation error(s) in 1 group(s)" in summary
    assert "items.0.value, items.1.value, items.2.value" in summary
    assert "items.1.value" in summary


def test_long_initial_function_uses_prototype_and_all_focus_ranges():
    code = "\n".join([
        "int target(void)",
        "{",
        *(f"  line_{index};" for index in range(3, 250)),
        "}",
    ])
    rendered = _format_initial_function_code(
        "httpd", "target", code, [20, 220],
    )

    assert "showing " in rendered and " of 250 source lines" in rendered
    assert "L1: int target(void)" in rendered
    assert "L20:   line_20;" in rendered
    assert "L220:   line_220;" in rendered
    assert "L250: }" in rendered
    assert "(omitted L" in rendered
    assert "line_100" not in rendered


def test_controller_identity_failure_is_corrected_in_same_agent(monkeypatch):
    prompts = []
    closed = []
    from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as mod

    class _CorrectingAgent:
        def __init__(self, **_kwargs):
            pass

        async def ainvoke(self, prompt, *, trace=None):
            prompts.append(prompt)
            value = "invented-id" if len(prompts) == 1 else "controller-id"
            return SimpleNamespace(
                structured_response=_DummyOutput(value=value),
            )

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(mod, "create_analysis_agent", _CorrectingAgent)
    monkeypatch.setattr(
        mod, "make_analyzer_tools", lambda _view, **_kwargs: [],
    )
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent",
        task_prompt="x",
        output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
    )

    def validate(output):
        if output.value != "controller-id":
            raise OutputValidationError("unknown controller identity")

    output = asyncio.run(agent.analyze(
        user_message="analyze",
        view=object(),
        output_validator=validate,
    ))

    assert output.value == "controller-id"
    assert len(prompts) == 2
    assert "unknown controller identity" in prompts[1]
    assert closed == [True]


def test_provider_error_is_not_retried_and_agent_is_closed(monkeypatch):
    prompts = []
    closed = []
    from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as mod

    class _FailingAgent:
        def __init__(self, **_kwargs):
            pass

        async def ainvoke(self, prompt, *, trace=None):
            prompts.append(prompt)
            raise AgentProviderError(
                "用户速率限制",
                provider="claude",
                model="deepseek-flash[1m]",
                http_status=429,
            )

        async def aclose(self):
            closed.append(True)

    monkeypatch.setattr(mod, "create_analysis_agent", _FailingAgent)
    monkeypatch.setattr(mod, "make_analyzer_tools", lambda _view, **_kwargs: [])
    agent = CodeAnalyzerAgent(
        agent_name="TestAgent",
        task_prompt="x",
        output_format=_DummyOutput,
        model=DEFAULT_CODEX_MODEL,
    )

    with pytest.raises(AgentProviderError, match="用户速率限制"):
        asyncio.run(agent.analyze(user_message="analyze", view=object()))

    assert len(prompts) == 1
    assert closed == [True]
