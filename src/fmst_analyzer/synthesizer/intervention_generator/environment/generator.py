"""Generate one Agent-authored rootfs setup script for environment Units."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from fmst_basic.agent import create_analysis_agent
from fmst_basic.agent.trace import AgentTraceHandler
from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import (
    FindingEvidenceResolver,
    make_finding_evidence_tool,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionPlanResult,
)
from fmst_analyzer.synthesizer.intervention_skill import (
    APPLICATION_READ_ROOTS, application_guidance,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    PlanningEvidenceCatalog,
)

from ..agents import GenerationAgentOutcome

from .prompts import ENVIRONMENT_TASK_PROMPT
from .schema import (
    EnvironmentGenerationResult,
)


class EnvironmentGenerator:
    """Ask one Agent to implement all selected environment Units directly."""

    def __init__(self, global_config: Any) -> None:
        self.global_config = global_config
        self.model = global_config.synthesizer_model

    async def run(
        self,
        *,
        plan: InterventionPlanResult,
        catalog: PlanningEvidenceCatalog,
        diagnostic_reports_root: Path,
        env_scripts_root: Path,
        rootfs_path: Path | None,
        trace_root: Path,
        unit_ids: set[str] | None = None,
    ) -> EnvironmentGenerationResult:
        units = [
            unit
            for unit in plan.units.values()
            if unit.strategy == "environment_setup"
            and (unit_ids is None or unit.unit_id in unit_ids)
        ]
        out_dir = Path(env_scripts_root) / catalog.target_identity.target_basename
        script_path = out_dir / "setup_rootfs.py"
        out_dir.mkdir(parents=True, exist_ok=True)
        if script_path.is_file():
            script_path.unlink()
        selected_unit_ids = sorted(unit.unit_id for unit in units)
        if not units:
            return EnvironmentGenerationResult()
        if rootfs_path is None:
            raise ValueError(
                "Environment Generation requires GlobalConfig.fw_rootfs_path"
            )
        rootfs_path = Path(rootfs_path).resolve()
        if not rootfs_path.is_dir():
            raise ValueError(
                f"Environment Generation rootfs is not a directory: {rootfs_path}"
            )

        resolver = FindingEvidenceResolver(diagnostic_reports_root, catalog)
        finding_refs = {ref for unit in units for ref in unit.finding_refs}
        finding_evidence = {
            ref: resolver.finding_evidence(ref)
            for ref in sorted(finding_refs)
        }
        evidence_tool = make_finding_evidence_tool(resolver, finding_refs)
        selected_recipe = (
            catalog.launch_candidates[plan.launch_choice.recipe_id]
            if plan.launch_choice.recipe_id is not None else None
        )
        trace_root.mkdir(parents=True, exist_ok=True)
        trace = AgentTraceHandler(
            agent_name="EnvironmentGenerator",
            md_path=trace_root / "environment_script.md",
            title="Environment setup script generation",
            model=self.model,
        )

        trace_paths = []

        def outcome_result(status, reason, failure_code=None):
            candidate = str(script_path) if script_path.is_file() else None
            return EnvironmentGenerationResult(
                status="failed" if status == "unable" and candidate else status,
                unit_ids=selected_unit_ids, script_path=candidate,
                reason=reason, failure_code=failure_code,
                trace_path=str(trace_root / "environment-traces.md"),
            )

        agent = create_analysis_agent(
            provider=self.global_config.agent_provider,
            model=self.model,
            developer_instructions=application_guidance("environment-generation"),
            tools=[evidence_tool],
            output_format=GenerationAgentOutcome,
            workdir=out_dir,
            filesystem_access="write",
            readable_roots=[rootfs_path, *APPLICATION_READ_ROOTS],
            name="environment-generator",
            skills=[],
        )
        message = ENVIRONMENT_TASK_PROMPT + "\n\n" + """Implement the supplied environment setup Units now.

Write exactly one `setup_rootfs.py` at the requested output path. Use the
read-only rootfs and evidence below as task input. Do not execute the generated
script; the Runner owns dynamic validation.

Environment generation input:
""" + json.dumps(
            {
                "selected_launch_recipe": (
                    selected_recipe.model_dump(mode="json")
                    if selected_recipe is not None else None
                ),
                "service_goal": plan.service_goal,
                "launch_choice": plan.launch_choice.model_dump(mode="json"),
                "runtime_tasks": {key: task.model_dump(mode="json") for key, task in plan.runner_tasks.items()},
                "rootfs_path": str(rootfs_path),
                "units": [unit.model_dump(mode="json") for unit in units],
                "finding_evidence": finding_evidence,
                "output_file": "setup_rootfs.py",
                "output_path": str(script_path.resolve()),
            },
            ensure_ascii=False,
            indent=2,
        )
        deadline = time.monotonic() + 3600
        seen = set()
        round_index = 0
        original_failure_code = None
        try:
            while True:
                round_index += 1
                if round_index > 1:
                    trace = AgentTraceHandler(agent_name="EnvironmentGenerator",
                        md_path=trace_root / f"environment_script-round-{round_index:02d}.md",
                        title=f"Environment setup script correction {round_index}", model=self.model)
                trace_paths.append(trace.md_path)
                (trace_root / "environment-traces.md").write_text("# Environment author turns\n\n" + "\n".join(f"- [{path.name}]({path.name})" for path in trace_paths) + "\n")
                response = None
                envelope_error = None
                try:
                    response = await asyncio.wait_for(agent.ainvoke(message, trace=trace),
                        timeout=max(0.001, deadline - time.monotonic()))
                except Exception as error:
                    trace.write_summary()
                    code = getattr(error, "code", None) or "provider_error"
                    if code != "structured_output_error":
                        return outcome_result(status="unable", reason=str(error).strip() or repr(error), failure_code=code)
                    envelope_error = str(error)
                trace.write_summary()
                outcome = getattr(response, "structured_response", None)
                if isinstance(outcome, GenerationAgentOutcome) and outcome.status == "unable":
                    return outcome_result(status="unable", reason=outcome.reason)
                if not isinstance(outcome, GenerationAgentOutcome):
                    envelope_error = envelope_error or getattr(response, "text", "") or "No GenerationAgentOutcome"
                validation_error = _validate_static_script(script_path, out_dir)
                if validation_error is None and envelope_error is None:
                    return outcome_result(status="completed", reason=outcome.reason, failure_code=original_failure_code)
                code = "static_compilation" if validation_error else "structured_output_error"
                original_failure_code = original_failure_code or code
                reason = validation_error or ("Environment Agent wrote a candidate but returned an invalid structured envelope: " + envelope_error)
                candidate = {str(path.relative_to(out_dir)): path.read_bytes() for path in out_dir.rglob("*") if path.is_file()}
                key = (tuple(sorted(candidate.items())), reason)
                evidence = trace_root / f"environment-feedback-{round_index:02d}"
                evidence.mkdir(parents=True, exist_ok=True)
                for name, content in candidate.items():
                    destination = evidence / "candidate" / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(content)
                message = (
                    "Controller static delivery validation failed. Correct setup_rootfs.py or the structured envelope "
                    "in this same session. Preserve the supplied environment Contracts; do not execute the script. "
                    "Return unable with a concrete blocker if it cannot be repaired. Complete failure: " + reason
                )
                (evidence / "feedback.txt").write_text(message)
                if key in seen or time.monotonic() >= deadline:
                    # A valid candidate survives an envelope-only defect; syntax never becomes readiness.
                    return outcome_result(status="completed" if validation_error is None else "unable",
                        reason=reason, failure_code=code)
                seen.add(key)
        finally:
            await agent.aclose()



def _validate_static_script(script_path: Path, output_dir: Path) -> str | None:
    """Validate only deterministic delivery properties; never execute the script."""
    if not script_path.is_file():
        return (
            "Environment Agent reported completed but did not create the required "
            f"script: {script_path.resolve()}"
        )
    generated_files = sorted(
        path.relative_to(output_dir).as_posix()
        for path in output_dir.rglob("*")
        if path.is_file()
    )
    if generated_files != ["setup_rootfs.py"]:
        return (
            "Environment output must contain only setup_rootfs.py; found "
            + ", ".join(generated_files)
        )
    try:
        source = script_path.read_text(encoding="utf-8")
        compile(source, str(script_path), "exec")
    except (OSError, UnicodeDecodeError, SyntaxError) as error:
        return f"Environment setup script failed static compilation: {error}"
    return None


__all__ = ["EnvironmentGenerator"]
