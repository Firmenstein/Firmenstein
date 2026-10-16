"""Provider-neutral contract for task-scoped analysis agents."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Literal, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

from .config import (
    DEFAULT_AGENT_PROVIDER,
    DEFAULT_CLAUDE_CONCURRENCY_LIMIT,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_CODEX_CONCURRENCY_LIMIT,
    DEFAULT_CODEX_MODEL,
)
from .skill import AgentSkillSpec
from .tool import AgentTool

FilesystemAccess = Literal["none", "read", "read_shell", "write", "container"]
_T = TypeVar("_T")


class AgentProviderError(RuntimeError):
    """Provider-reported failure carrying the provider's original message.

    The exception is only a control-flow boundary.  Firmenstein does not
    invent provider error codes or rewrite the provider's diagnostic text.
    """

    def __init__(
        self,
        official_message: str,
        *,
        provider: str,
        model: str | None = None,
        http_status: int | None = None,
        subtype: str | None = None,
        stop_reason: str | None = None,
        terminal_reason: str | None = None,
        code: str = "provider_error",
    ) -> None:
        message = official_message.strip()
        if not message:
            message = "Provider returned an error without details."
        super().__init__(message)
        self.official_message = message
        self.provider = provider
        self.model = model
        self.http_status = http_status
        self.subtype = subtype
        self.stop_reason = stop_reason
        self.terminal_reason = terminal_reason
        self.code = code


class AgentTurnTimeoutError(TimeoutError):
    """A native tool or an explicitly time-limited turn expired."""

    def __init__(
        self,
        *,
        provider: str,
        model: str | None,
        timeout_seconds: float,
        turn_id: str | None = None,
        code: str = "turn_timeout",
        tool_calls_seen: int = 0,
        last_tool: str | None = None,
        limit: int | float | None = None,
    ) -> None:
        scope = f"tool {last_tool!r}" if code == "tool_timeout" else "Agent turn"
        super().__init__(f"{provider} {scope} exceeded {timeout_seconds:g}s")
        self.code = code
        self.provider = provider
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.turn_id = turn_id
        self.tool_calls_seen = tool_calls_seen
        self.last_tool = last_tool
        self.limit = limit


class AgentStructuredOutputError(ValueError):
    """A completed response failed local validation; it is not a provider outage."""

    def __init__(self, result: AgentResult, cause: Exception) -> None:
        super().__init__(str(cause))
        self.agent_result = result
        self.code = "structured_output_error"


class AgentToolStepLimitError(RuntimeError):
    """A turn stopped after consuming its configured tool-call budget."""

    def __init__(
        self,
        *,
        provider: str,
        model: str | None,
        limit: int,
        tool_calls_seen: int,
        turn_id: str | None = None,
        last_tool: str | None = None,
    ) -> None:
        super().__init__(
            f"{provider} Agent turn exceeded the {limit}-tool call limit"
        )
        self.code = "tool_step_limit"
        self.provider = provider
        self.model = model
        self.limit = limit
        self.tool_calls_seen = tool_calls_seen
        self.turn_id = turn_id
        self.last_tool = last_tool


async def gather_agent_tasks(*awaitables: Awaitable[_T]) -> list[_T]:
    """Gather Agent tasks and cancel unfinished siblings on one hard failure."""
    tasks = [asyncio.create_task(awaitable) for awaitable in awaitables]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


@dataclass
class AgentResult:
    """Normalized result returned by every Agent SDK adapter."""

    text: str
    structured_response: BaseModel | None
    provider: str
    session_id: str
    turn_id: str
    status: str
    items: list[dict[str, Any]] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0
    skills: list[dict[str, str]] = field(default_factory=list)
    tool_calls_seen: int = 0
    last_tool: str | None = None


@runtime_checkable
class AnalysisAgent(Protocol):
    """Minimal lifecycle used by Firmenstein's analyzer orchestration."""

    async def ainvoke(
        self,
        prompt: str,
        *,
        trace: Any | None = None,
    ) -> AgentResult: ...

    async def aclose(self) -> None: ...


def default_model_for_provider(provider: str) -> str:
    """Return the repository-defined model for one supported provider."""
    normalized = provider.strip().lower()
    if normalized == "codex":
        return DEFAULT_CODEX_MODEL
    if normalized == "claude":
        return DEFAULT_CLAUDE_MODEL
    raise ValueError(
        f"Unsupported agent provider {provider!r}; available providers: "
        "claude, codex"
    )


def default_concurrency_for_provider(provider: str) -> int:
    """Return the validated default request concurrency for a provider."""
    normalized = provider.strip().lower()
    if normalized == "codex":
        return DEFAULT_CODEX_CONCURRENCY_LIMIT
    if normalized == "claude":
        return DEFAULT_CLAUDE_CONCURRENCY_LIMIT
    raise ValueError(
        f"Unsupported agent provider {provider!r}; available providers: "
        "claude, codex"
    )


def create_analysis_agent(
    *,
    model: str,
    developer_instructions: str,
    tools: list[AgentTool] | None = None,
    output_format: type[BaseModel] | None = None,
    workdir: Path | None = None,
    filesystem_access: FilesystemAccess = "none",
    readable_roots: list[Path] | None = None,
    writable_roots: list[Path] | None = None,
    name: str | None = None,
    provider: str = DEFAULT_AGENT_PROVIDER,
    skills: list[AgentSkillSpec] | None = None,
    turn_timeout_seconds: float | None = None,
    max_tool_calls_per_turn: int | None = None,
    default_tool_timeout_seconds: float | None = None,
    reasoning_effort: str | None = None,
    session_dir: Path | None = None,
    resume: bool = False,
) -> AnalysisAgent:
    """Create one task-scoped Agent SDK adapter.

    Provider selection belongs here rather than in individual analyzers.
    Turns and tool-call counts are unbounded by default; individual tools
    default to 120 seconds. Finite turn deadlines require an explicit caller.
    Claude sessions are retained by default. Supply session_dir for a stable
    task location and resume=True to load its native history with fresh tools
    and authentication. Missing history or mismatched identity is an error.
    """
    normalized = provider.strip().lower()
    if normalized != "claude" and (session_dir is not None or resume):
        raise ValueError("session_dir/resume are currently supported by the Claude adapter")
    if filesystem_access == "container" and normalized != "claude":
        raise ValueError("The autonomous container runtime currently uses the Claude SDK")
    if normalized == "codex":
        from .codex_agent import CodexAnalysisAgent

        return CodexAnalysisAgent(
            model=model,
            developer_instructions=developer_instructions,
            tools=tools,
            output_format=output_format,
            workdir=workdir,
            filesystem_access=filesystem_access,
            readable_roots=readable_roots,
            writable_roots=writable_roots,
            name=name,
            skills=skills,
            turn_timeout_seconds=turn_timeout_seconds,
            max_tool_calls_per_turn=max_tool_calls_per_turn,
            default_tool_timeout_seconds=default_tool_timeout_seconds,
            reasoning_effort=reasoning_effort,
        )
    if normalized == "claude":
        from .claude_agent import ClaudeAnalysisAgent

        return ClaudeAnalysisAgent(
            session_dir=session_dir,
            resume=resume,
            model=model,
            developer_instructions=developer_instructions,
            tools=tools,
            output_format=output_format,
            workdir=workdir,
            filesystem_access=filesystem_access,
            readable_roots=readable_roots,
            writable_roots=writable_roots,
            name=name,
            skills=skills,
            turn_timeout_seconds=turn_timeout_seconds,
            max_tool_calls_per_turn=max_tool_calls_per_turn,
            default_tool_timeout_seconds=default_tool_timeout_seconds,
            reasoning_effort=reasoning_effort,
        )
    raise ValueError(
        f"Unsupported agent provider {provider!r}; available providers: "
        "claude, codex"
    )


__all__ = [
    "AgentProviderError",
    "AgentTurnTimeoutError",
    "AgentToolStepLimitError",
    "AgentResult",
    "AgentSkillSpec",
    "AnalysisAgent",
    "DEFAULT_AGENT_PROVIDER",
    "FilesystemAccess",
    "create_analysis_agent",
    "default_concurrency_for_provider",
    "default_model_for_provider",
    "gather_agent_tasks",
]
