"""Bounded per-callsite ProcessLifecycleAgent dispatch."""
from __future__ import annotations

import asyncio
from pathlib import Path

from loguru import logger

from fmst_basic.agent.analysis_agent import gather_agent_tasks
from fmst_analyzer.analysis.base.execution import execution_tracker
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import (
    CodeAnalyzerAgent,
)
from fmst_analyzer.global_config import GlobalConfig

from .analyzer_schema import (
    ProcessEventCallsite,
    ProcessLifecycleAgentResult,
)
from .controller import (
    finalize_analysis,
    validate_agent_result,
)
from .findings import ProcessEventAnalysis
from .process_lifecycle_prompt import (
    PROCESS_LIFECYCLE_TASK_PROMPT,
    PROCESS_LIFECYCLE_USER_PROMPT,
)


class ProcessLifecycleAgent:
    def __init__(
        self,
        global_config: GlobalConfig,
        concurrency_sem: asyncio.Semaphore,
    ) -> None:
        self.global_config = global_config
        self.concurrency_sem = concurrency_sem
        self.execution = execution_tracker()

    async def analyze_callsites(
        self,
        view: AnalysisView,
        callsites: list[ProcessEventCallsite],
        *,
        phase: str,
    ) -> dict[str, ProcessEventAnalysis]:
        """Return one assessment per input callsite.

        The phase gate is local to the LLM-owning node so a future caller
        cannot accidentally dispatch paid work during a static run.
        """
        if phase != "full":
            logger.info(
                "[ProcessLifecycleAgent] phase is not full; zero Agent calls"
            )
            return {}
        if not callsites:
            return {}

        ordered = sorted(
            callsites,
            key=lambda item: (
                item.binary_name,
                item.function_ea,
                item.ctree_index,
                item.api_name,
            ),
        )
        logger.info(
            f"[ProcessLifecycleAgent] dispatching {len(ordered)} process "
            f"events (concurrency={self.global_config.agent_concurrency_limit})"
        )

        async def run_one(source: ProcessEventCallsite):
            return await self.execution.call(
                "process", source.callsite_id,
                lambda: self._analyze_one(view, source, phase=phase),
            )

        outcomes = await gather_agent_tasks(
            *(run_one(source) for source in ordered)
        )
        return {
            source.callsite_id: assessment
            for source, assessment in zip(ordered, outcomes, strict=True)
            if assessment is not None
        }

    async def _analyze_one(
        self,
        view: AnalysisView,
        source: ProcessEventCallsite,
        *, phase: str,
    ) -> ProcessEventAnalysis:
        if phase != "full":
            raise ValueError("ProcessLifecycleAgent requires full phase")
        trace_dir: Path | None = None
        if self.global_config.workdir is not None:
            trace_dir = (
                self.global_config.target_agent_debug_dir()
                / "process_lifecycle"
                / "events"
            )
        agent = CodeAnalyzerAgent(
            agent_name="ProcessLifecycleAgent",
            task_prompt=PROCESS_LIFECYCLE_TASK_PROMPT,
            output_format=ProcessLifecycleAgentResult,
            model=self.global_config.diagnosis_model,
            provider=self.global_config.agent_provider,
        )
        user_message = PROCESS_LIFECYCLE_USER_PROMPT.format(
            callsite_id=source.callsite_id,
            event_kind=source.event_kind.value,
            api_name=source.api_name,
            binary_name=source.binary_name,
            function_name=source.function_name,
            function_ea=source.function_ea,
            snapshot_hash=source.snapshot_hash,
            ctree_index=source.ctree_index,
            source_ea=(
                f"{source.source_ea:#x}"
                if source.source_ea is not None
                else "BADADDR"
            ),
            line_number=source.line_number,
            column_number=source.column_number,
        )

        def validator(output) -> None:
            validate_agent_result(output, view, source)

        async with self.concurrency_sem:
            self.execution.check_dispatch()
            output = await agent.analyze(
                user_message=user_message,
                view=view,
                binary_name=source.binary_name,
                function_name=source.function_name,
                callsite_line=source.line_number,
                initial_focus_lines=[source.line_number],
                trace_dir=trace_dir,
                trace_name=source.callsite_id.rsplit(":", 1)[-1],
                output_validator=validator,
            )
        return finalize_analysis(source, output, view)


__all__ = ["ProcessLifecycleAgent"]
