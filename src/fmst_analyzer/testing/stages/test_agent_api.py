"""Test stage: verify the selected Agent SDK, tools, and output schema."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Tuple

from loguru import logger
from pydantic import BaseModel, Field

from fmst_basic.agent.analysis_agent import create_analysis_agent
from fmst_basic.agent.tool import tool

if TYPE_CHECKING:
    from fmst_analyzer.testing.pipeline_tester import PipelineTester


class _PingResponse(BaseModel):
    status: str = Field(description="The fixed status returned by the ping tool")
    echo: str = Field(description="The exact string returned by the ping tool")


def _is_ping_call(item: dict) -> bool:
    return (
        item.get("type") == "dynamicToolCall" and item.get("tool") == "ping"
    ) or (
        item.get("type") == "ToolUseBlock"
        and item.get("name") == "mcp__fmst__ping"
    )


async def test_agent_api(tester: PipelineTester) -> Tuple[bool, str]:
    """Exercise the provider path used by production analyzers."""
    provider = tester.global_config.agent_provider
    model_id = tester.global_config.diagnosis_model

    @tool
    def ping(value: str) -> dict[str, str]:
        """Return a deterministic value for runtime verification.

        Args:
            value: Text to echo unchanged.
        """
        return {"status": "ok", "echo": value}

    agent = create_analysis_agent(
        provider=provider,
        model=model_id,
        developer_instructions=(
            "Call ping exactly once with value='hello'. Return its status and "
            "echo fields without changing them."
        ),
        tools=[ping],
        output_format=_PingResponse,
        name="agent-api-smoke",
    )

    started = time.perf_counter()
    try:
        result = await agent.ainvoke("Verify the dynamic tool runtime now.")
    except Exception as exc:  # noqa: BLE001
        return False, (
            f"{provider} Agent SDK call failed: {type(exc).__name__}: {exc}"
        )
    finally:
        await agent.aclose()
    latency_ms = (time.perf_counter() - started) * 1000

    output = result.structured_response
    if not isinstance(output, _PingResponse):
        return False, f"{provider} returned no validated PingResponse"
    if output.status != "ok" or output.echo != "hello":
        return False, f"Unexpected PingResponse: {output.model_dump()}"
    dynamic_calls = [item for item in result.items if _is_ping_call(item)]
    if len(dynamic_calls) != 1:
        return False, (
            f"Expected exactly one ping dynamic tool call, got {dynamic_calls}"
        )

    logger.info(
        f"[agent-api] provider={provider}, model={model_id}, "
        f"latency={latency_ms:.0f}ms, usage={result.usage}"
    )
    return True, (
        f"provider={provider} | model={model_id} | dynamic tool + "
        f"structured output passed in {latency_ms:.0f}ms"
    )

