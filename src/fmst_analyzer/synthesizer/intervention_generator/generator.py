"""Unit implementation, self-test, and candidate delivery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from loguru import logger

from fmst_basic.agent.usage_registry import scoped
from fmst_basic.agent.analysis_agent import (
    AgentProviderError,
    AgentToolStepLimitError,
    AgentTurnTimeoutError,
)
from fmst_basic.agent.config import (
    configured_codex_model,
)
from fmst_analyzer.analysis.base.artifact_lifecycle import archive_stage_outputs
from fmst_analyzer.analysis.base.report_io import model_content_sha256
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.synthesizer.intervention_generator.environment import (
    EnvironmentGenerationResult,
    EnvironmentGenerator,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import (
    FindingEvidenceResolver,
    make_finding_evidence_tool,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionPlanResult,
    InterventionUnit,
    ResolvedCallsiteAnchor,
    ResolvedFunctionAnchor,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    PlanningEvidenceCatalog,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer import (
    load_persisted_intervention_plan,
)
from fmst_analyzer.framework import runtime_workspace as configured_framework

from .agents import (
    AgentHandle,
    GenerationAgentOutcome,
    build_execution_unit_agent,
    invoke_agent,
)
from .architecture import GeneratorArch
from .publication import contract_digest
from .cargo import parse_build_errors, parse_test_failures
from .prompts.execution_unit import build_execution_unit_user_message
from .reports import (
    load_persisted_intervention_generation,
    persist_generation,
    unit_report_stem,
)
from .resolve import AnchorResolutionError, resolve_unit, resolve_units
from .schema import (
    FailureSignal,
    InterventionGenerationResult,
    UnitGenerationResult,
    UnitRoundTrace,
)
from .shell import (
    callsite_short_slug,
    configure_active_units,
    generate_shell,
    slugify,
    unit_module_name,
    unit_test_relative_path,
    unit_test_target,
)


_CARGO_BUILD_TIMEOUT = 1800
_CARGO_TEST_TIMEOUT = 600


def _contract_digest(unit: InterventionUnit) -> str:
    return contract_digest(unit)


def _failure_code(error: BaseException) -> str:
    explicit = getattr(error, "code", None)
    if isinstance(explicit, str):
        return explicit
    if isinstance(error, AgentToolStepLimitError):
        return "tool_step_limit"
    if isinstance(error, AgentTurnTimeoutError):
        return getattr(error, "code", "turn_timeout")
    if isinstance(error, AgentProviderError):
        return "provider_error"
    if isinstance(error, asyncio.CancelledError):
        return "cancelled"
    return "provider_error"


def _mark_unit_failure(
    state: _UnitState,
    *,
    code: str,
    phase: str,
    reason: str,
    error: BaseException | None = None,
) -> None:
    valid_codes = {
        "provider_error", "structured_output_error", "tool_timeout",
        "tool_step_limit", "turn_timeout", "cancelled", "no_candidate",
        "input_validation", "build", "test", "environment_generation",
    }
    normalized = code if code in valid_codes else "provider_error"
    diagnostic = _failure_diagnostic(error, reason)
    state.status = "generation_failed"
    state.failure_reason = diagnostic
    state.failure_code = normalized
    state.last_failure = FailureSignal(
        code=normalized,
        phase=phase if phase in {"input_validation", "review", "environment_generation", "build", "test_compile", "test_runtime"} else "input_validation",
        message=diagnostic,
    )


def _failure_diagnostic(error: BaseException | None, reason: str) -> str:
    """Keep the provider's message and attach useful execution metadata."""
    if error is None:
        return reason
    raw = str(getattr(error, "official_message", "") or error).strip()
    if not raw:
        raw = reason
    fields: list[str] = []
    for label, attribute in (
        ("provider", "provider"),
        ("model", "model"),
        ("turn_id", "turn_id"),
        ("last_tool", "last_tool"),
        ("tool_calls_seen", "tool_calls_seen"),
        ("limit", "limit"),
    ):
        value = getattr(error, attribute, None)
        if value is not None:
            fields.append(f"{label}={value}")
    if fields:
        return f"{raw}\n[{' '.join(fields)}]"
    return reason if raw == str(error).strip() else f"{raw}\n{reason}"


def _round_trace(handle: AgentHandle, round_index: int) -> Any | None:
    factory = getattr(handle, "trace_for_round", None)
    return factory(round_index) if factory is not None else None


def _run_cargo(
    manifest_path: Path,
    subcommand: str,
    *,
    extra_args: list[str] | None = None,
    timeout: int,
) -> subprocess.CompletedProcess:
    command = ["cargo", subcommand, "--manifest-path", str(manifest_path)]
    if extra_args:
        command.extend(extra_args)
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, "CARGO_TERM_COLOR": "never"},
    )


@dataclass
class _UnitState:
    unit: InterventionUnit
    status: Literal[
        "pending",
        "ok",
        "generation_failed",
        "build_failed",
        "test_failed",
        "skipped",
    ] = "pending"
    failure_reason: str | None = None
    failure_code: str | None = None
    last_failure: FailureSignal | None = None
    agent_handle: AgentHandle | None = None
    agent_outcome: GenerationAgentOutcome | None = None
    revision_count: int = 0
    round_traces: list[UnitRoundTrace] = field(default_factory=list)


class InterventionGenerator:
    def __init__(self, global_config: Any) -> None:
        self.global_config = global_config
        self.model = (
            configured_codex_model()
            if global_config.agent_provider == "codex"
            else global_config.synthesizer_model
        )
        self._sem = asyncio.Semaphore(
            max(1, int(global_config.agent_concurrency_limit))
        )
        self._active_handles: list[AgentHandle] = []
        self._dispatch_stop: BaseException | None = None
        self._generation_started = False

    @scoped("InterventionGenerator")
    async def run(
        self,
        *,
        view: AnalysisView,
        image_name: str,
        arch: GeneratorArch,
        diagnostic_reports_root: Path,
        trace_root: Path,
        interventions_root: Path,
        test_harnesses_root: Path,
        env_scripts_root: Path,
        iib_api_abspath: Path,
    ) -> InterventionGenerationResult:
        self._generation_started = False
        self._dispatch_stop = None
        catalog, plan = load_persisted_intervention_plan(
            diagnostic_reports_root, global_config=self.global_config,
            require_current_implementation=False,
        )
        archive_stage_outputs(self.global_config, "generation")
        self._generation_started = True
        self._active_handles = []
        try:
            await self._run_impl(
                plan=plan,
                catalog=catalog,
                view=view,
                image_name=image_name,
                arch=arch,
                diagnostic_reports_root=Path(diagnostic_reports_root),
                trace_root=Path(trace_root),
                interventions_root=Path(interventions_root),
                test_harnesses_root=Path(test_harnesses_root),
                env_scripts_root=Path(env_scripts_root),
                iib_api_abspath=Path(iib_api_abspath),
            )
            if self._dispatch_stop is not None:
                raise self._dispatch_stop
            return load_persisted_intervention_generation(
                diagnostic_reports_root,
                plan,
                require_complete=True,
            )
        finally:
            handles, self._active_handles = self._active_handles, []
            if handles:
                await asyncio.gather(
                    *(handle.aclose() for handle in handles),
                    return_exceptions=True,
                )

    async def _run_impl(
        self,
        *,
        plan: InterventionPlanResult,
        catalog: PlanningEvidenceCatalog,
        view: AnalysisView,
        image_name: str,
        arch: GeneratorArch,
        diagnostic_reports_root: Path,
        trace_root: Path,
        interventions_root: Path,
        test_harnesses_root: Path,
        env_scripts_root: Path,
        iib_api_abspath: Path,
    ) -> InterventionGenerationResult:
        units = {
            unit_id: unit
            for unit_id, unit in plan.units.items()
        }
        target_binary = catalog.target_identity.target_basename
        _reset_trace_root(trace_root)
        generation_reports = (
            diagnostic_reports_root / "intervention_generation_reports"
        )
        if generation_reports.exists():
            shutil.rmtree(generation_reports)
        selected_launch = (
            catalog.launch_candidates[plan.launch_choice.recipe_id]
            if plan.launch_choice.recipe_id is not None else None
        )

        states: dict[str, _UnitState] = {}
        execution_units: list[InterventionUnit] = []
        for unit in units.values():
            state = _UnitState(unit=unit)
            states[unit.unit_id] = state
            if unit.strategy != "environment_setup":
                try:
                    resolve_unit(unit, view)
                except AnchorResolutionError as error:
                    state.status = "generation_failed"
                    state.failure_reason = str(error)
                    state.failure_code = "input_validation"
                    state.last_failure = FailureSignal(
                        code="input_validation",
                        phase="input_validation",
                        message=str(error),
                    )
                else:
                    execution_units.append(unit)

        # Resolve deterministic anchors before any Agent is allowed to write
        # a generated artifact. Capability feasibility is established by the
        # public IIB API and later by Runner evidence, not a Generator list.
        env_units = [unit for unit in units.values() if unit.strategy == "environment_setup"]
        framework_root = (iib_api_abspath.resolve().parent if execution_units
                          else configured_framework(self.global_config))
        selected_env_ids = {unit.unit_id for unit in env_units}
        try:
            environment = await EnvironmentGenerator(self.global_config).run(
                plan=plan,
                catalog=catalog,
                diagnostic_reports_root=diagnostic_reports_root,
                env_scripts_root=env_scripts_root,
                rootfs_path=getattr(self.global_config, "fw_rootfs_path", None),
                trace_root=trace_root / "environment",
                unit_ids=selected_env_ids,
            )
        except Exception as error:
            from fmst_analyzer.runner.repair_intake import blocks_new_runner
            if blocks_new_runner(error):
                raise
            environment = EnvironmentGenerationResult(
                status="unable",
                unit_ids=sorted(selected_env_ids),
                reason=str(error).strip() or repr(error),
            )

        for unit in env_units:
            state = states[unit.unit_id]
            if environment.status != "completed":
                state.status = "generation_failed"
                state.failure_reason = environment.reason
                state.failure_code = "environment_generation"
                state.last_failure = FailureSignal(
                    code="environment_generation",
                    phase="environment_generation",
                    message=state.failure_reason,
                )
            else:
                state.status = "ok"

        crate_root = interventions_root / target_binary
        test_root = test_harnesses_root / target_binary
        for path in (crate_root, test_root):
            if path.exists():
                shutil.rmtree(path)

        cargo_build_status: Literal["ok", "failed", "not_run"] = "not_run"
        cargo_test_status: Literal["ok", "failed", "not_run"] = "not_run"
        cargo_build_failure: FailureSignal | None = None
        cargo_test_failure: FailureSignal | None = None
        if execution_units:
            resolved_manifest = resolve_units(execution_units, view)
            generate_shell(
                target_binary=target_binary,
                image_name=image_name,
                arch=arch,
                units=execution_units,
                resolved_manifest=resolved_manifest,
                interventions_root=interventions_root,
                test_harnesses_root=test_harnesses_root,
                iib_api_abspath=iib_api_abspath,
            )
            shell_check = _run_cargo(
                crate_root / "Cargo.toml",
                "check",
                timeout=_CARGO_BUILD_TIMEOUT,
            )
            if shell_check.returncode != 0:
                cargo_build_status = "failed"
                cargo_build_failure = FailureSignal(
                    code="build",
                    phase="build",
                    file_path=str(crate_root / "Cargo.toml"),
                    message=_cargo_result_message(shell_check),
                )
                for unit in execution_units:
                    state = states[unit.unit_id]
                    if state.status == "pending":
                        state.status = "build_failed"
                        state.failure_reason = "cargo_preflight_failed"
                        state.failure_code = "build"
                        state.last_failure = FailureSignal(
                            code="build",
                            phase="build",
                            file_path=str(crate_root / "Cargo.toml"),
                            message=_cargo_result_message(shell_check),
                        )
                result = _build_result(
                    plan=plan,
                    target_binary=target_binary,
                    arch=arch,
                    states=states,
                    catalog=catalog,
                    cargo_build_status=cargo_build_status,
                    cargo_test_status=cargo_test_status,
                    cargo_build_failure=cargo_build_failure,
                    cargo_test_failure=cargo_test_failure,
                    crate_root=crate_root,
                    test_root=test_root,
                    environment=environment,
                )
                _persist_generation_with_baseline(
                    diagnostic_reports_root=diagnostic_reports_root,
                    result=result,
                    plan=plan,
                    workdir=self.global_config.workdir,
                    runtime_workspace=framework_root,
                )
                logger.info(
                    f"[InterventionGenerator] {target_binary}: "
                    f"ok={result.ok_count}, not_ready={result.not_ready_count}, "
                    f"skipped={result.skipped_count}"
                )
                return result

            resolver = FindingEvidenceResolver(diagnostic_reports_root, catalog)
            context_roots = [
                getattr(self.global_config, "fw_rootfs_path", None),
                getattr(self.global_config, "decompiled_code_dir", None),
                getattr(self.global_config, "disassembled_code_dir", None),
                diagnostic_reports_root,
                iib_api_abspath.parent,
            ]
            readable_roots = [
                Path(path) for path in context_roots
                if path is not None and Path(path).exists()
            ]
            # Each Unit owns an independent source/test directory. Run one
            # self-checking Generator Agent per Unit; failures are returned
            # instead of cancelling sibling tasks.
            checkpoint_lock = asyncio.Lock()
            started_units: set[str] = set()

            async def checkpoint() -> None:
                async with checkpoint_lock:
                    partial = _build_result(
                        plan=plan,
                        target_binary=target_binary,
                        arch=arch,
                        states=states,
                        catalog=catalog,
                        cargo_build_status="not_run",
                        cargo_test_status="not_run",
                        cargo_build_failure=None,
                        cargo_test_failure=None,
                        crate_root=crate_root,
                        test_root=test_root,
                        environment=environment,
                        completion_status="partial",
                    )
                    _persist_generation_with_baseline(
                        diagnostic_reports_root=diagnostic_reports_root,
                        result=partial,
                        plan=plan,
                        workdir=self.global_config.workdir,
                        runtime_workspace=framework_root,
                        create_baseline=False,
                    )

            async def run_one(unit: InterventionUnit) -> None:
                if self._dispatch_stop is not None:
                    return
                started_units.add(unit.unit_id)
                try:
                    await self._run_unit(
                        state=states[unit.unit_id],
                        unit=unit,
                        related_units=[
                            peer.model_dump(mode="json")
                            for peer in units.values()
                            if peer.unit_id != unit.unit_id
                        ],
                        selected_launch=(
                            selected_launch.model_dump(mode="json")
                            if selected_launch is not None else None
                        ),
                        service_goal=plan.service_goal,
                        launch_choice=plan.launch_choice.model_dump(mode="json"),
                        runtime_tasks={key: task.model_dump(mode="json") for key, task in plan.runner_tasks.items()},
                        resolver=resolver,
                        view=view,
                        crate_root=crate_root,
                        test_root=test_root,
                        trace_root=trace_root / "units",
                        target_binary=target_binary,
                        image_name=image_name,
                        arch=arch,
                        readable_roots=readable_roots,
                        framework_root=framework_root,
                    )
                except asyncio.CancelledError:
                    state = states[unit.unit_id]
                    if state.status == "pending":
                        _mark_unit_failure(
                            state,
                            code="cancelled",
                            phase="input_validation",
                            reason="Execution Unit task was cancelled",
                        )
                    raise
                except Exception as error:  # noqa: BLE001 - isolate Unit
                    from fmst_analyzer.runner.repair_intake import blocks_new_runner
                    if blocks_new_runner(error):
                        self._dispatch_stop = self._dispatch_stop or error
                    _mark_unit_failure(
                        states[unit.unit_id],
                        code=_failure_code(error),
                        phase="input_validation",
                        reason=str(error).strip() or repr(error),
                        error=error,
                    )
                finally:
                    await checkpoint()

            tasks = [asyncio.create_task(run_one(unit)) for unit in execution_units]
            try:
                await asyncio.gather(*tasks, return_exceptions=True)
            except BaseException:
                for unit_id, state in states.items():
                    if unit_id in started_units and state.status in {
                        "pending"
                    }:
                        _mark_unit_failure(
                            state,
                            code="cancelled",
                            phase="input_validation",
                            reason="Execution Generator stage was cancelled",
                        )
                await checkpoint()
                raise
            if self._dispatch_stop is not None:
                raise self._dispatch_stop
            correction_deadline = time.monotonic() + 3600
            seen_failures: set[tuple] = set()
            self._mark_inactive(states, crate_root, test_root)
            await self._correct_failed_units(states, crate_root, test_root,
                seen_failures, deadline=correction_deadline)
            while True:
                self._mark_inactive(states, crate_root, test_root)
                cargo_build_status, build_result = self._build_generated_units(
                    execution_units=execution_units, states=states, view=view,
                    target_binary=target_binary, image_name=image_name, arch=arch,
                    crate_root=crate_root,
                )
                test_results: dict[str, subprocess.CompletedProcess] = {}
                if cargo_build_status == "ok":
                    cargo_test_status, test_results = self._test_generated_units(states, test_root)
                corrected = await self._correct_failed_units(
                    states, crate_root, test_root, seen_failures,
                    deadline=correction_deadline,
                )
                await checkpoint()
                if not corrected:
                    break
                # Any authored change can affect shared compilation/test imports.
                for state in states.values():
                    if state.status == "ok":
                        state.status = "pending"
            if cargo_build_status == "failed":
                cargo_build_failure = FailureSignal(
                    code="build",
                    phase="build",
                    file_path=str(crate_root / "Cargo.toml"),
                    message=_cargo_result_message(build_result),
                )
            failed_test_results = {
                unit_id: result
                for unit_id, result in test_results.items()
                if result.returncode != 0
            }
            if failed_test_results:
                cargo_test_failure = FailureSignal(
                    code="test",
                    phase="test_runtime",
                    file_path=str(test_root / "Cargo.toml"),
                    message=_unit_test_results_message(failed_test_results),
                )
            for state in states.values():
                if state.status == "pending":
                    state.status = (
                        "build_failed"
                        if cargo_build_status == "failed"
                        else "test_failed"
                    )
                    state.failure_reason = "shared_crate_verification_incomplete"
                    state.failure_code = (
                        "build" if cargo_build_status == "failed" else "test"
                    )
                    state.last_failure = FailureSignal(
                        code=(
                            "build" if cargo_build_status == "failed" else "test"
                        ),
                        phase=(
                            "build"
                            if cargo_build_status == "failed"
                            else "test_runtime"
                        ),
                        message=(
                            "The shared generated crate did not complete Cargo "
                            "verification; this Unit cannot be reported as verified."
                        ),
                    )
            self._configure_active_units(
                execution_units=execution_units,
                states=states,
                view=view,
                target_binary=target_binary,
                image_name=image_name,
                arch=arch,
                crate_root=crate_root,
                eligible_statuses={"ok"},
            )

        result = _build_result(
            plan=plan,
            target_binary=target_binary,
            arch=arch,
            states=states,
            catalog=catalog,
            cargo_build_status=cargo_build_status,
            cargo_test_status=cargo_test_status,
            cargo_build_failure=cargo_build_failure,
            cargo_test_failure=cargo_test_failure,
            crate_root=crate_root if execution_units else None,
            test_root=test_root if execution_units else None,
            environment=environment,
        )
        _persist_generation_with_baseline(
            diagnostic_reports_root=diagnostic_reports_root,
            result=result,
            plan=plan,
            workdir=self.global_config.workdir,
            runtime_workspace=framework_root,
        )
        logger.info(
            f"[InterventionGenerator] {target_binary}: "
            f"ok={result.ok_count}, not_ready={result.not_ready_count}, "
            f"skipped={result.skipped_count}"
        )
        return result

    async def _run_unit(
        self,
        *,
        state: _UnitState,
        unit: InterventionUnit,
        related_units: list[dict],
        selected_launch: dict | None,
        resolver: FindingEvidenceResolver,
        view: AnalysisView,
        crate_root: Path,
        test_root: Path,
        trace_root: Path,
        target_binary: str,
        image_name: str,
        arch: GeneratorArch,
        readable_roots: list[Path],
        framework_root: Path | None = None,
        service_goal: str | None = None,
        launch_choice: dict | None = None,
        runtime_tasks: dict | None = None,
    ) -> None:
        module = unit_module_name(unit.unit_id)
        trace_dir = trace_root / unit.unit_id
        evidence_tool = make_finding_evidence_tool(
            resolver,
            set(unit.finding_refs),
        )
        test_file = test_root / unit_test_relative_path(unit.unit_id)
        state.agent_handle = build_execution_unit_agent(
            unit_id=unit.unit_id,
            provider=self.global_config.agent_provider,
            model=self.model,
            workdir=crate_root / "src" / module,
            intervention_cargo_toml=crate_root / "Cargo.toml",
            test_cargo_toml=test_root / "Cargo.toml",
            test_target=unit_test_target(unit.unit_id),
            test_file=test_file,
            view=view,
            trace_dir=trace_dir,
            readable_roots=readable_roots,
            extra_tools=[evidence_tool],
            framework_root=framework_root,
        )
        self._active_handles.append(state.agent_handle)
        target_context = {
            "service_goal": service_goal,
            "launch_choice": launch_choice,
            "runtime_tasks": runtime_tasks or {},
            "image_name": image_name,
            "target_binary": target_binary,
            "architecture": arch,
            "byte_order": "big" if arch == "mipsbe" else "little",
        }
        message = build_execution_unit_user_message(
            target_context=target_context,
            unit=unit.model_dump(mode="json"),
            related_units=related_units,
            selected_launch=selected_launch,
            intervention_files=_shell_files(unit, crate_root),
            test_file=str(test_file.resolve()),
            target_crate_name=f"intervention_{slugify(target_binary)}",
            import_paths=_import_paths(unit, target_binary),
            manifest_global_state_path=(
                f"intervention_{slugify(target_binary)}::state::GlobalState"
            ),
            read_only_context_roots=[str(path.resolve()) for path in readable_roots],
        )
        round_index = 1
        source_snapshot = _unit_source_snapshot(unit, crate_root, test_root)
        state.round_traces.append(UnitRoundTrace(
            round_index=round_index,
            generator_trace_path=str(
                (trace_dir / f"round-{round_index:02d}__generator.md").resolve()
            ),
        ))
        try:
            response = await self._invoke_limited(
                state.agent_handle,
                message,
                trace=_round_trace(state.agent_handle, round_index),
            )
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - isolate this Unit
            from fmst_analyzer.runner.repair_intake import blocks_new_runner
            if blocks_new_runner(error):
                raise
            response = error
        state.agent_outcome = self._record_agent_response(
            state,
            response,
            crate_root=crate_root,
            test_root=test_root,
            source_snapshot=source_snapshot,
        )
        # The Agent owns the first implementation and its self-review. The
        # Controller deliberately does not invent a second semantic verdict;
        # build/test evidence is handled after all Units have produced a
        # candidate.

    async def _correct_failed_units(
        self, states: dict[str, _UnitState], crate_root: Path, test_root: Path,
        seen_failures: set[tuple], *, deadline: float,
    ) -> bool:
        """Return attributed deterministic failures to the original author session."""
        corrected = False
        for unit_id, state in sorted(states.items()):
            if state.agent_handle is None or state.status not in {"pending", "build_failed", "test_failed", "generation_failed"}:
                continue
            if state.failure_code not in {"build", "test", "input_validation", "structured_output_error"} or state.last_failure is None:
                continue
            if state.status == "pending" and state.failure_code != "structured_output_error":
                continue
            envelope_only = state.status == "pending" and state.failure_code == "structured_output_error"
            snapshot = _unit_source_snapshot(state.unit, crate_root, test_root)
            key = (unit_id, tuple(sorted(snapshot.items())), state.last_failure.model_dump_json())
            if key in seen_failures or time.monotonic() >= deadline:
                continue
            seen_failures.add(key)
            round_index = len(state.round_traces) + 1
            trace_dir = Path(state.agent_handle.trace_dir)
            evidence = trace_dir / f"round-{round_index:02d}__feedback"
            evidence.mkdir(parents=True, exist_ok=True)
            for path in [*(crate_root / "src" / unit_module_name(unit_id)).rglob("*.rs"), test_root / unit_test_relative_path(unit_id)]:
                if path.is_file():
                    relative = path.relative_to(crate_root) if path.is_relative_to(crate_root) else Path("test_harness") / path.relative_to(test_root)
                    destination = evidence / "candidate" / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(path, destination)
            failure = state.last_failure
            (evidence / "failure.json").write_text(failure.model_dump_json(indent=2) + "\n")
            message = (
                "Controller verification failed for your current Unit candidate. Correct the owned implementation "
                "and its test in this same session, preserving the supplied Contract. Return unable with the "
                "concrete blocker if it cannot be repaired. Source identity and complete failure are retained at "
                + str(evidence) + "\n\n" + failure.message
            )
            (evidence / "message.txt").write_text(message)
            state.round_traces.append(UnitRoundTrace(round_index=round_index,
                generator_trace_path=str(trace_dir / f"round-{round_index:02d}__generator.md")))
            state.revision_count += 1
            state.status = "pending"
            try:
                response = await asyncio.wait_for(self._invoke_limited(state.agent_handle, message,
                    trace=_round_trace(state.agent_handle, round_index)), timeout=max(0.001, deadline - time.monotonic()))
            except asyncio.CancelledError:
                raise
            except Exception as error:
                from fmst_analyzer.runner.repair_intake import blocks_new_runner
                if blocks_new_runner(error):
                    raise
                response = error
            state.agent_outcome = self._record_agent_response(state, response,
                crate_root=crate_root, test_root=test_root, source_snapshot=snapshot)
            if state.status == "pending":
                if envelope_only and state.agent_outcome is not None:
                    state.failure_reason = None
                    state.failure_code = None
                    state.last_failure = None
                    corrected = True
                elif _unit_source_snapshot(state.unit, crate_root, test_root) == snapshot:
                    state.status = "generation_failed"
                    state.failure_code = failure.code
                    state.last_failure = failure
                    state.failure_reason = "Author correction produced no source change; " + failure.message
                else:
                    corrected = True
        return corrected

    async def _invoke_limited(
        self,
        handle: AgentHandle,
        message: str,
        *,
        trace: Any | None = None,
    ):
        async with self._sem:
            if self._dispatch_stop is not None:
                raise self._dispatch_stop
            try:
                try:
                    return await invoke_agent(handle, message, trace=trace)
                except TypeError as error:
                    if "unexpected keyword argument 'trace'" not in str(error):
                        raise
                    return await invoke_agent(handle, message)
            except BaseException as error:
                from fmst_analyzer.runner.repair_intake import blocks_new_runner
                if blocks_new_runner(error):
                    self._dispatch_stop = self._dispatch_stop or error
                raise

    @staticmethod
    def _record_agent_response(
        state: _UnitState,
        response: Any,
        *,
        crate_root: Path | None = None,
        test_root: Path | None = None,
        source_snapshot: dict[str, str] | None = None,
    ) -> GenerationAgentOutcome | None:
        if isinstance(response, BaseException):
            code = _failure_code(response)
            reason = f"execution_unit {code}: {response}"
        else:
            outcome = response.structured_response
            if not isinstance(outcome, GenerationAgentOutcome):
                code = "structured_output_error"
                reason = "execution_unit returned no GenerationAgentOutcome"
            else:
                if outcome.status == "unable":
                    _mark_unit_failure(
                        state,
                        code="no_candidate",
                        phase="input_validation",
                        reason=outcome.reason,
                    )
                return outcome
        # A structured-output decoder error can happen after the provider has
        # written a candidate, so that case is retained for deterministic
        # build/test checks. A provider/transport/tool failure is not a
        # completed turn: files left in the workdir must never be promoted as
        # this turn's result (they may be stale or only partially written).
        has_candidate = False
        if (
            code == "structured_output_error"
            and crate_root is not None
            and test_root is not None
        ):
            changed = (
                source_snapshot is None
                or _unit_source_snapshot(state.unit, crate_root, test_root)
                != source_snapshot
            )
            has_candidate = changed and not _generated_source_blockers(
                state.unit, crate_root, test_root
            )
        if has_candidate:
            state.failure_reason = reason
            state.failure_code = code
            state.last_failure = FailureSignal(
                code=code if code in {
                    "provider_error", "structured_output_error", "tool_timeout",
                    "tool_step_limit", "turn_timeout", "cancelled",
                    "no_candidate", "input_validation", "build", "test",
                    "environment_generation",
                } else "provider_error",
                phase="input_validation",
                message=_failure_diagnostic(
                    response if isinstance(response, BaseException) else None,
                    reason,
                ),
            )
        else:
            _mark_unit_failure(
                state,
                code=code,
                phase="input_validation",
                reason=reason,
                error=response if isinstance(response, BaseException) else None,
            )
        return None

    @staticmethod
    def _mark_inactive(
        states: dict[str, _UnitState],
        crate_root: Path,
        test_root: Path,
    ) -> None:
        for state in states.values():
            if state.status != "pending":
                continue
            blockers = _generated_source_blockers(
                state.unit, crate_root, test_root
            )
            if blockers:
                state.status = "generation_failed"
                state.failure_reason = "generated_source_is_incomplete"
                state.failure_code = "input_validation"
                state.last_failure = FailureSignal(
                    code="input_validation",
                    phase="input_validation",
                    file_path=str(blockers[0][0]),
                    message="\n".join(
                        f"{path}: {reason}" for path, reason in blockers
                    ),
                )

    def _build_generated_units(
        self,
        *,
        execution_units: list[InterventionUnit],
        states: dict[str, _UnitState],
        view: AnalysisView,
        target_binary: str,
        image_name: str,
        arch: GeneratorArch,
        crate_root: Path,
    ) -> tuple[Literal["ok", "failed"], subprocess.CompletedProcess]:
        while True:
            self._configure_active_units(
                execution_units=execution_units,
                states=states,
                view=view,
                target_binary=target_binary,
                image_name=image_name,
                arch=arch,
                crate_root=crate_root,
                eligible_statuses={"pending"},
            )
            result = _run_cargo(
                crate_root / "Cargo.toml", "build", extra_args=["--release"],
                timeout=_CARGO_BUILD_TIMEOUT,
            )
            if result.returncode == 0:
                return "ok", result
            errors = parse_build_errors(result.stderr,
                owner_modules={unit_module_name(key): key for key in states})
            failed_ids = sorted({
                error.unit_id for error in errors
                if error.unit_id in states
                and states[error.unit_id].status == "pending"
            })
            if failed_ids:
                for unit_id in failed_ids:
                    state = states[unit_id]
                    unit_errors = [
                        error for error in errors if error.unit_id == unit_id
                    ]
                    state.status = "build_failed"
                    state.failure_reason = "final Controller build failed"
                    state.failure_code = "build"
                    state.last_failure = FailureSignal(
                        code="build",
                        phase="build",
                        file_path=(
                            unit_errors[0].file_path if unit_errors else None
                        ),
                        message=_cargo_result_message(result),
                    )
                continue
            return "failed", result

    @staticmethod
    def _configure_active_units(
        *,
        execution_units: list[InterventionUnit],
        states: dict[str, _UnitState],
        view: AnalysisView,
        target_binary: str,
        image_name: str,
        arch: GeneratorArch,
        crate_root: Path,
        eligible_statuses: set[str],
    ) -> list[InterventionUnit]:
        active = [
            unit for unit in execution_units
            if states[unit.unit_id].status in eligible_statuses
        ]
        configure_active_units(
            target_binary=target_binary,
            image_name=image_name,
            arch=arch,
            units=active,
            resolved_manifest=resolve_units(active, view),
            crate_root=crate_root,
        )
        return active

    def _test_generated_units(
        self,
        states: dict[str, _UnitState],
        test_root: Path,
    ) -> tuple[
        Literal["ok", "failed"],
        dict[str, subprocess.CompletedProcess],
    ]:
        results: dict[str, subprocess.CompletedProcess] = {}
        selected_unit_ids = {
            unit_id for unit_id, state in states.items()
            if state.status == "pending"
        }
        for unit_id, state in sorted(states.items()):
            if state.status != "pending":
                continue
            result = _run_cargo(
                test_root / "Cargo.toml",
                "test",
                extra_args=["--test", unit_test_target(unit_id)],
                timeout=_CARGO_TEST_TIMEOUT,
            )
            results[unit_id] = result
            if result.returncode == 0:
                state.status = "ok"
            else:
                self._reconcile_unit_test_failure(state, result)
        status = "ok" if all(
            states[unit_id].status == "ok" for unit_id in selected_unit_ids
        ) else "failed"
        return status, results

    @staticmethod
    def _reconcile_unit_test_failure(
        state: _UnitState,
        result: subprocess.CompletedProcess,
    ) -> None:
        unit_id = state.unit.unit_id
        owners = {unit_module_name(unit_id): unit_id}
        for error in parse_build_errors(result.stderr, owner_modules=owners):
            if error.unit_id == unit_id:
                state.status = "test_failed"
                state.failure_reason = "final Controller test compilation failed"
                state.failure_code = "test"
                state.last_failure = FailureSignal(
                    code="test",
                    phase="test_compile",
                    file_path=error.file_path,
                    message=_cargo_result_message(result),
                )
                return
        for failure in parse_test_failures(result.stdout + "\n" + result.stderr, owner_modules=owners):
            if failure.unit_id == unit_id:
                state.status = "test_failed"
                state.failure_reason = "final Controller Unit test failed"
                state.failure_code = "test"
                state.last_failure = FailureSignal(
                    code="test",
                    phase="test_runtime",
                    file_path=unit_test_relative_path(unit_id).as_posix(),
                    message=_cargo_result_message(result),
                )
                return
        state.status = "test_failed"
        state.failure_reason = "unattributed Unit test failure"
        state.failure_code = "test"
        state.last_failure = FailureSignal(
            code="test",
            phase="test_runtime",
            file_path=unit_test_relative_path(unit_id).as_posix(),
            message=_cargo_result_message(result),
        )


def _persist_generation_with_baseline(
    *,
    diagnostic_reports_root: Path,
    result: InterventionGenerationResult,
    plan: InterventionPlanResult,
    workdir: Path,
    create_baseline: bool = True,
    runtime_workspace: Path | None = None,
) -> None:
    persist_generation(diagnostic_reports_root, result, plan, snapshot=create_baseline,
        runtime_workspace=runtime_workspace)


def _generated_source_blockers(
    unit: InterventionUnit,
    crate_root: Path,
    test_root: Path,
) -> list[tuple[Path, str]]:
    unit_id = unit.unit_id
    module = unit_module_name(unit_id)
    intervention_paths = sorted((crate_root / "src" / module).rglob("*.rs"))
    test_path = test_root / unit_test_relative_path(unit_id)
    blockers: list[tuple[Path, str]] = []
    if not intervention_paths:
        blockers.append((
            crate_root / "src" / module,
            "Unit implementation directory is missing generated source files",
        ))
    if not test_path.is_file():
        blockers.append((
            test_path,
            "Unit test file is missing",
        ))
    for unexpected in sorted(test_path.parent.rglob("*")):
        if unexpected.is_file() and unexpected != test_path:
            blockers.append((
                unexpected,
                "Unit Agent may only edit the supplied test file",
            ))
    return blockers


def _unit_source_snapshot(
    unit: InterventionUnit, crate_root: Path, test_root: Path
) -> dict[str, str]:
    """Capture authored Unit files so decoder fallback cannot accept templates."""
    module_root = crate_root / "src" / unit_module_name(unit.unit_id)
    test_file = test_root / unit_test_relative_path(unit.unit_id)
    paths = sorted((*module_root.rglob("*.rs"), test_file))
    return {
        str(path): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in paths
        if path.is_file()
    }


def _reset_trace_root(trace_root: Path) -> None:
    if trace_root.exists():
        shutil.rmtree(trace_root)
    trace_root.mkdir(parents=True, exist_ok=True)


def _shell_files(unit: InterventionUnit, crate_root: Path) -> list[dict]:
    root = crate_root / "src" / unit_module_name(unit.unit_id)
    return [
        {"path": str(path.resolve()), "current": path.read_text(encoding="utf-8")}
        for path in sorted(root.rglob("*")) if path.is_file()
    ]


def _text_file_payload(path: Path) -> dict[str, str]:
    return {
        "path": str(path.resolve()),
        "current": path.read_text(encoding="utf-8"),
    }


def _import_paths(unit: InterventionUnit, target_binary: str) -> list[str]:
    crate = f"intervention_{slugify(target_binary)}"
    module = unit_module_name(unit.unit_id)
    state_path = f"{crate}::state::GlobalState"
    if unit.strategy == "function_stub":
        return [state_path, *[
            f"{crate}::{module}::function_stubs::stub_{slugify(anchor.function_name)}::intercept"
            for anchor in unit.anchors if isinstance(anchor, ResolvedFunctionAnchor)
        ]]
    if unit.strategy == "callsite_hook":
        return [state_path, *[
            f"{crate}::{module}::callsite_hooks::hook_{callsite_short_slug(anchor.callsite_id)}::intercept"
            for anchor in unit.anchors if isinstance(anchor, ResolvedCallsiteAnchor)
        ]]
    return [
        state_path,
        f"{crate}::{module}::pseudo_files::factory",
        f"{crate}::{module}::pseudo_files::PseudoFileImpl",
    ]


def _build_result(
    *,
    plan: InterventionPlanResult,
    target_binary: str,
    arch: str,
    states: dict[str, _UnitState],
    catalog: PlanningEvidenceCatalog,
    cargo_build_status: str,
    cargo_test_status: str,
    cargo_build_failure: FailureSignal | None,
    cargo_test_failure: FailureSignal | None,
    crate_root: Path | None,
    test_root: Path | None,
    environment: EnvironmentGenerationResult,
    completion_status: Literal["partial", "complete"] = "complete",
) -> InterventionGenerationResult:
    unit_results = [
        UnitGenerationResult(
            unit_id=unit_id,
            contract_digest=_contract_digest(state.unit),
            report_stem=unit_report_stem(
                catalog.finding_index[state.unit.finding_refs[0]].summary,
                unit_id,
            ),
            strategy=state.unit.strategy,
            status=(
                state.status
            ),
            failure_reason=state.failure_reason,
            failure_code=state.failure_code,
            last_failure_signal=state.last_failure,
            generated_files=_generated_files_for_unit(
                state.unit,
                crate_root=crate_root,
                test_root=test_root,
                environment=environment,
            ),
            round_traces=state.round_traces,
            revision_count=state.revision_count,
        )
        for unit_id, state in sorted(states.items())
    ]
    not_ready_statuses = {
        "pending",
        "generation_failed",
        "build_failed",
        "test_failed",
    }
    return InterventionGenerationResult(
        plan_digest=model_content_sha256(plan),
        target_binary=target_binary,
        arch=arch,
        total_units=len(unit_results),
        ok_count=sum(item.status == "ok" for item in unit_results),
        not_ready_count=sum(
            item.status in not_ready_statuses for item in unit_results
        ),
        skipped_count=sum(item.status == "skipped" for item in unit_results),
        completion_status=completion_status,
        units=unit_results,
        cargo_build_status=cargo_build_status,
        cargo_test_status=cargo_test_status,
        cargo_build_failure=cargo_build_failure,
        cargo_test_failure=cargo_test_failure,
        intervention_crate_path=str(crate_root) if crate_root is not None else None,
        test_crate_path=str(test_root) if test_root is not None else None,
        environment=environment,
    )


def _generated_files_for_unit(
    unit: InterventionUnit,
    *,
    crate_root: Path | None,
    test_root: Path | None,
    environment: EnvironmentGenerationResult,
) -> list[str]:
    if unit.strategy == "environment_setup":
        if (
            unit.unit_id in environment.unit_ids
            and environment.script_path
            and Path(environment.script_path).is_file()
        ):
            return [str(Path(environment.script_path).resolve())]
        return []
    paths: list[Path] = []
    if crate_root is not None:
        module_root = crate_root / "src" / unit_module_name(unit.unit_id)
        if module_root.is_dir():
            paths.extend(path for path in sorted(module_root.rglob("*")) if path.is_file())
    if test_root is not None:
        test_path = test_root / unit_test_relative_path(unit.unit_id)
        if test_path.is_file():
            paths.append(test_path)
    return [str(path.resolve()) for path in paths]


def _cargo_result_message(result: subprocess.CompletedProcess) -> str:
    return (
        f"exit_code={result.returncode}\n"
        f"--- stdout ---\n{result.stdout}\n"
        f"--- stderr ---\n{result.stderr}"
    )


def _unit_test_results_message(
    results: dict[str, subprocess.CompletedProcess],
) -> str:
    return "\n\n".join(
        f"=== {unit_id} ===\n{_cargo_result_message(result)}"
        for unit_id, result in sorted(results.items())
    )


__all__ = ["InterventionGenerator"]
