"""Execution Unit implementation Agent factory."""
from __future__ import annotations

import asyncio
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field

from fmst_basic.agent.analysis_agent import (
    AgentResult,
    AnalysisAgent,
    create_analysis_agent,
)
from fmst_basic.agent.config import (
    DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS,
)
from fmst_basic.agent.tool import AgentTool, tool
from fmst_basic.agent.trace import AgentTraceHandler
from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools import (
    make_analyzer_tools,
)
from fmst_analyzer.synthesizer.intervention_skill import (
    APPLICATION_READ_ROOTS, application_guidance,
)
from fmst_analyzer.framework import guestweave_skill, runtime_workspace

if TYPE_CHECKING:
    from fmst_analyzer.analysis.base.code_analyzer.analysis_view import (
        AnalysisView,
    )


@dataclass
class AgentHandle:
    """Own one task-scoped execution generation session."""

    agent: AnalysisAgent
    trace_dir: Path
    agent_name: str
    title: str
    model: str

    def trace_for_round(self, round_index: int) -> AgentTraceHandler:
        return AgentTraceHandler(
            agent_name=self.agent_name,
            md_path=self.trace_dir / f"round-{round_index:02d}__generator.md",
            title=f"{self.title} (round {round_index:02d})",
            model=self.model,
        )

    async def aclose(self) -> None:
        await self.agent.aclose()


class GenerationAgentOutcome(BaseModel):
    """Minimal file-generation completion signal consumed by the Controller."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["completed", "unable"] = Field(
        description=(
            "completed when the Agent has written a concrete implementation "
            "and test candidate and performed its self-review; unable only "
            "when no candidate can be written because essential input/target "
            "is missing, or the Agent was interrupted before producing files. "
            "If an operation is difficult or uncertain, write the most useful "
            "bounded candidate and record the limitation instead."
        )
    )
    reason: str = Field(
        min_length=1,
        description="Concise verification summary or exact inability reason.",
    )


_VERIFY_UNIT_LOCK = threading.Lock()
def _run_cargo(
    manifest_path: Path, args: list[str], *, timeout: float,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["cargo", *args, "--manifest-path", str(manifest_path)],
        capture_output=True,
        text=True,
        timeout=timeout,
        env={
            **os.environ,
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
        },
    )


def _render_command_result(label: str, result: subprocess.CompletedProcess) -> str:
    return (
        f"{label}.exit_code={result.returncode}\n"
        f"--- {label}.stdout ---\n{result.stdout}\n"
        f"--- {label}.stderr ---\n{result.stderr}"
    )


def _make_verify_unit_tool(
    intervention_manifest: Path,
    test_manifest: Path,
    test_target: str,
) -> AgentTool:
    """Build the no-argument verifier bound to exactly one Unit."""
    def run_locked(deadline: float) -> str:
        def remaining() -> float:
            seconds = deadline - time.monotonic()
            if seconds <= 0:
                raise TimeoutError("verify_unit exceeded its tool deadline")
            return seconds

        # Queueing and both commands share one tool deadline. An expired
        # worker must not acquire the lock later and start another build.
        if not _VERIFY_UNIT_LOCK.acquire(timeout=remaining()):
            raise TimeoutError("verify_unit timed out waiting for Cargo")
        try:
            try:
                check = _run_cargo(
                    intervention_manifest, ["check"], timeout=remaining(),
                )
                rendered = [_render_command_result("intervention_check", check)]
                if check.returncode == 0:
                    test = _run_cargo(
                        test_manifest,
                        ["test", "--test", test_target],
                        timeout=remaining(),
                    )
                    rendered.append(_render_command_result("unit_test", test))
                else:
                    rendered.append(
                        "unit_test.skipped=true\n"
                        "reason=intervention_check_failed"
                    )
                return "\n\n".join(rendered)
            except subprocess.TimeoutExpired as error:
                raise TimeoutError(
                    f"verify_unit exceeded its tool deadline: {error.cmd}"
                ) from error
        finally:
            _VERIFY_UNIT_LOCK.release()

    @tool(
        "verify_unit",
        description=(
            "Verify the current Unit by running the controller-bound "
            "Intervention cargo check followed by its exact Test-Harness "
            "test target. Calls are serialized across Unit Agents to avoid "
            "shared Cargo cache races. Returns complete stdout and stderr. "
            "This tool accepts no arguments."
        ),
        timeout_seconds=DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS,
    )
    async def verify_unit() -> str:
        deadline = time.monotonic() + DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS
        return await asyncio.to_thread(run_locked, deadline)

    return verify_unit


def build_execution_unit_agent(
    *,
    unit_id: str,
    provider: str,
    model: str,
    workdir: Path,
    intervention_cargo_toml: Path,
    test_cargo_toml: Path,
    test_target: str,
    test_file: Path,
    view: "AnalysisView",
    trace_dir: Path,
    readable_roots: list[Path],
    extra_tools: list[AgentTool] | None = None,
    turn_timeout_seconds: float | None = None,
    framework_root: Path | None = None,
) -> AgentHandle:
    """Factory for one Unit's combined implementation and test agent."""
    code_tools = make_analyzer_tools(view)
    verify_tool = _make_verify_unit_tool(
        intervention_cargo_toml,
        test_cargo_toml,
        test_target,
    )
    agent = create_analysis_agent(
        provider=provider,
        model=model,
        developer_instructions=application_guidance("generation"),
        tools=[*code_tools, *(extra_tools or []), verify_tool],
        output_format=GenerationAgentOutcome,
        workdir=workdir,
        filesystem_access="write",
        readable_roots=[*readable_roots, *APPLICATION_READ_ROOTS],
        writable_roots=[test_file.parent],
        name=f"execution-unit-{unit_id}",
        skills=[guestweave_skill(framework_root or runtime_workspace())],
        turn_timeout_seconds=turn_timeout_seconds,
        default_tool_timeout_seconds=DEFAULT_AGENT_TOOL_TIMEOUT_SECONDS,
    )
    trace_dir.mkdir(parents=True, exist_ok=True)
    return AgentHandle(
        agent=agent,
        trace_dir=trace_dir,
        agent_name=f"execution-unit-{unit_id}",
        title=f"primary execution Unit implementation agent for {unit_id}",
        model=model,
    )


async def invoke_agent(
    handle: AgentHandle,
    user_message: str,
    *,
    trace: AgentTraceHandler | None = None,
) -> AgentResult:
    """Invoke or continue the handle's provider session."""
    return await handle.agent.ainvoke(
        user_message,
        trace=trace,
    )
