"""Single Agent invocation that discovers target launch candidates."""
from __future__ import annotations

from pathlib import Path
import json
from typing import List, Optional

from loguru import logger
from pydantic import ValidationError

from fmst_basic.agent.analysis_agent import create_analysis_agent
from fmst_basic.agent.trace import AgentTraceHandler
from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.analysis.base.execution import check_analysis_dispatch, diagnostic_reason

from .analyzer_schema import InitLaunchAnalysisResult, LaunchCorrection, LaunchRecipeAgentOutput, TargetIdentity
from fmst_analyzer.analysis.base.output_validation import OutputValidationError
from .controller import finalise_agent_output
from .launch_recipe_prompt import LAUNCH_RECIPE_TASK, LAUNCH_RECIPE_USER
from .elf_evidence import make_elf_evidence_tools
from .code_evidence import make_launcher_code_tools
from .source_evidence import SourceEvidence, make_source_tool


def _raw_response(result) -> dict | None:
    value = getattr(result, "structured_response", None)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return json.loads(json.dumps(value))
    return None


class LaunchRecipeAgent:
    """Run one Agent session over the extracted rootfs."""

    def __init__(
        self,
        global_config: GlobalConfig,
    ) -> None:
        self.global_config = global_config
        self.model = global_config.diagnosis_model
        self.correction_history: list[LaunchCorrection] = []

    async def analyze(
        self,
        target_identity: TargetIdentity,
        rootfs: Path,
        initialization_roots: List[str],
        *, phase: str,
    ) -> InitLaunchAnalysisResult:
        if phase != "full":
            raise ValueError("LaunchRecipeAgent requires full phase")
        self.correction_history = []
        sources = SourceEvidence()
        tools = [make_source_tool(rootfs, sources), *make_elf_evidence_tools(rootfs, sources),
                 *make_launcher_code_tools(rootfs, self.global_config, phase=phase, sources=sources)]

        user_msg = LAUNCH_RECIPE_TASK + "\n\n" + LAUNCH_RECIPE_USER.format(
            target_basename=target_identity.target_basename,
            rootfs_path=rootfs.resolve(),
            selected_rootfs_path=target_identity.selected_rootfs_path,
            target_aliases=target_identity.target_aliases,
            initialization_roots=initialization_roots,
        )

        from fmst_analyzer.analysis.base.task_recovery import (
            checkpoint_path, load_checkpoint, record_rejected, record_revalidated, store_checkpoint,
        )
        from .analyzer_schema import SourceSnippet
        from pydantic import BaseModel
        class Checkpoint(BaseModel):
            output: LaunchRecipeAgentOutput
            sources: dict[str, SourceSnippet]
            corrections: list[LaunchCorrection]
        checkpoint = checkpoint_path(contract={
            "agent": "LaunchRecipeAgent", "message": user_msg, "model": self.model,
            "target_identity": target_identity.model_dump(mode="json"),
            "output_schema": Checkpoint.model_json_schema(),
            "tools": [{"name": tool.name, "description": tool.description,
                       "schema": tool.args_schema.model_json_schema()} for tool in tools],
        })
        recovered = load_checkpoint(checkpoint, Checkpoint)
        if recovered is not None:
            sources.sources = recovered.sources
            try:
                validated = finalise_agent_output(rootfs, target_identity, sources.materialize(recovered.output))
            except (OutputValidationError, ValidationError) as error:
                record_rejected(checkpoint, error)
                sources.sources = {}
            else:
                self.correction_history = recovered.corrections
                record_revalidated(checkpoint)
                return validated.model_copy(update={"correction_history": self.correction_history})
        agent = create_analysis_agent(
            name="LaunchRecipeAgent", model=self.model, developer_instructions="",
            output_format=LaunchRecipeAgentOutput, workdir=rootfs, filesystem_access="read_shell",
            provider=self.global_config.agent_provider, tools=tools,
        )

        trace_handler = self._maybe_build_trace_handler(target_identity)
        try:
            attempt = 0
            while True:
                attempt += 1
                try:
                    check_analysis_dispatch()
                    result = await agent.ainvoke(user_msg, trace=trace_handler)
                except ValueError as error:
                    if not isinstance(error, ValidationError) and getattr(error, "code", None) != "structured_output_error":
                        raise
                    self.correction_history.append(LaunchCorrection(
                        attempt=attempt, rejection_reason=diagnostic_reason(error),
                        rejected_response=_raw_response(getattr(error, "agent_result", None)),
                    ))
                    user_msg = (
                        "Correct the schema/locator error and return the complete result. Preserve supported behavior. "
                        "Changed or withdrawn behavioral claims require revision_explanation with source basis or a precise gap.\n"
                        f"Validation error:\n{error}"
                    )
                    continue
                output = result.structured_response if result else None
                if not isinstance(output, LaunchRecipeAgentOutput):
                    raise RuntimeError("LaunchRecipeAgent returned no valid structured output")
                try:
                    if self.correction_history:
                        self.correction_history[-1].revision_explanation = output.revision_explanation
                    validated = finalise_agent_output(rootfs, target_identity, sources.materialize(output))
                except (OutputValidationError, ValidationError) as error:
                    self.correction_history.append(LaunchCorrection(
                        attempt=attempt, rejection_reason=diagnostic_reason(error),
                        rejected_response=_raw_response(result),
                    ))
                    logger.warning(f"[LaunchRecipeAgent] evidence rejected; correction {attempt}: {error}")
                    user_msg = (
                        "Correct the rejected evidence in your previous analysis and return the complete result. "
                        "Retain source locations and exact quoted content; do not invent evidence. "
                        "Preserve explicit gaps where evidence is unavailable. Changed behavioral claims require "
                        "revision_explanation with source basis or the precise resulting gap.\n\n"
                        f"Validation error:\n{error}"
                    )
                    continue
                break
        finally:
            await agent.aclose()
            if trace_handler:
                from fmst_analyzer.analysis.base.report_io import write_text
                path = self.global_config.target_agent_debug_dir() / "init_launch/source_reads.json"
                write_text(path, json.dumps({key: source.model_dump(mode="json") for key, source in sources.sources.items()},
                                            ensure_ascii=False, indent=2) + "\n")
                trace_handler.write_summary()

        logger.info(
            f"[LaunchRecipeAgent] completed: "
            f"{len(output.launch_recipes)} recipes, "
            f"{len(output.analysis_gaps)} analysis gaps"
        )
        store_checkpoint(checkpoint, Checkpoint(output=output, sources=sources.sources, corrections=self.correction_history))
        return validated.model_copy(update={"correction_history": self.correction_history})

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _maybe_build_trace_handler(
        self, target_identity: TargetIdentity,
    ) -> Optional[AgentTraceHandler]:
        if self.global_config.workdir is None:
            return None
        trace_base = (
            self.global_config.target_agent_debug_dir()
            / "init_launch"
            / "traces"
        )
        trace_base.mkdir(parents=True, exist_ok=True)
        stem = target_identity.target_basename.replace("/", "_")
        return AgentTraceHandler(
            agent_name="LaunchRecipeAgent",
            md_path=trace_base / f"{stem}.md",
            title=f"InitLaunch::{target_identity.target_basename}",
            model=self.model,
        )

__all__ = ["LaunchRecipeAgent"]
