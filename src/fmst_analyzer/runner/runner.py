"""Agent-first, container-isolated rehosting refinement loop."""

from __future__ import annotations

import asyncio
import hashlib
import json
import difflib
import shutil
import subprocess
import sys
import tomllib
import time
import uuid
import socket
from urllib.parse import urlsplit
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fmst_basic.utils.archive_paths import resolve_archived_path
from fmst_basic.agent import AgentProviderError, AgentTurnTimeoutError
from fmst_analyzer.analysis.base.artifact_lifecycle import archive_stage_outputs
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json
from fmst_analyzer.synthesizer.intervention_generator.schema import (
    InterventionGenerationResult,
)
from fmst_analyzer.synthesizer.intervention_generator import (
    load_persisted_intervention_generation,
)
from fmst_analyzer.synthesizer.intervention_generator.baseline import (
    materialize_generation_workspace,
)
from fmst_analyzer.synthesizer.intervention_generator.publication import validate_generation_publication
from fmst_analyzer.synthesizer.intervention_plan_analyzer import (
    load_persisted_intervention_plan,
)
from fmst_analyzer.synthesizer.intervention_generator.shell import (
    configure_active_units,
    generate_shell, generate_unit_shell, ResolvedManifest,
    unit_module_name,
    unit_test_relative_path,
    unit_test_target,
)
from fmst_analyzer.synthesizer.intervention_generator.resolve import resolve_units

from .agent import RunnerAgentSession, RuntimeEvidenceState
from .live_client import RunnerLiveClient
from .budget import ExecutionBudget, RunnerStopped
from .identity import copy_file, tree_sha256 as _tree_sha256
from .docker_sandbox import DockerRootfsSandbox, SandboxAttempt
from .feedback import (FeedbackJournal, collect_runtime_feedback, render_runtime_feedback,
                       collect_partial_feedback, render_partial_feedback, file_preview, render_preview)
from .reports import persist_result
from .request_wire import escaped_http_header_repair, validate_request_representation, admit_cookie_continuity
from .launch import admit_launch_proposal
from .dependencies import bind_guestweave_api
from .adaptation import validate_proposal, snapshot_evidence
from .adaptation_schema import RuntimeAdaptation
from .publication import publish_success
from .schema import (
    EnvironmentPreparation,
    InteractionScenario,
    ProbeResult,
    RehostingResult,
    RunnerDecision,
    RuntimeAttempt,
    RunnerRevision,
    RunnerSessionReceipt,
    RuntimeNetwork,
    RequestRepresentationRevision,
)
from .rootfs_actions import normalize_rootfs_actions
from .runtime_builder import RuntimeBuilder, create_runtime_builder
from .trace_context import persist_runtime_trace_context
from .owner_context import persist_runtime_owners


def _local_service_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _file_sha256(path: Path) -> str | None:
    """Hash an evidence file without turning a missing artifact into a guess."""
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _unit_contract_digest(unit: Any) -> str:
    contract = getattr(unit, "contract", None)
    payload = contract.model_dump(mode="json") if contract is not None else {}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_bootstrap_decision(
    decision: RunnerDecision,
    *,
    changed_unit_ids: set[str],
    allow_input_request: bool = False,
) -> None:
    """Keep the first attempt evidence-free and identical to Generator output."""
    if decision.action != "run" and not (allow_input_request and decision.action == "request_input"):
        raise RuntimeError(
            "The first Runner decision must run the unchanged Generator baseline "
            "before runtime refinement."
        )
    if changed_unit_ids or decision.rootfs_actions:
        raise RuntimeError(
            "The first Runner decision cannot modify Intervention code or staged-"
            "rootfs state before runtime evidence."
        )
    # A frozen Generation candidate may contain failed or incomplete Units.
    # Bootstrap still cannot edit or disable anything before runtime evidence,
    # but the Runner is allowed to discover that the candidate needs repair.
    if decision.disabled_unit_ids:
        raise RuntimeError(
            "The first Runner decision cannot disable Units from the complete "
            "baseline before runtime evidence."
        )


def _scenario_weakening(floor: InteractionScenario, current: InteractionScenario, *, request_representation_reason: str | None = None,
                        scenario_resolution_reason: str | None = None) -> str | None:
    """Reject a later Agent decision that silently lowers the service goal."""
    if floor.protocol != current.protocol or floor.port != current.port:
        return "protocol or port changed"
    if floor.specification_gap and not current.specification_gap and not (scenario_resolution_reason or "").strip():
        return "resolving a specification gap requires an explicit evidence-based reason"
    if not floor.specification_gap and current.specification_gap:
        return "a decidable bootstrap scenario cannot be weakened to a gap"
    if len(current.steps) < len(floor.steps):
        return "ordered scenario steps were removed"
    for index, expected in enumerate(floor.steps):
        actual = current.steps[index]
        if expected.save_cookies and not actual.save_cookies:
            return f"scenario step {index + 1} cookie capture was disabled"
        if actual.response_captures != expected.response_captures:
            return f"scenario step {index + 1} response capture was changed or removed"
        if actual.request_text != expected.request_text:
            if not (floor.protocol == "http" and (request_representation_reason or "").strip()
                    and escaped_http_header_repair(expected.request_text) == actual.request_text):
                return f"scenario step {index + 1} request was changed"
        if expected.expected_status_code is not None and actual.expected_status_code != expected.expected_status_code:
            return f"scenario step {index + 1} status assertion was weakened"
        if expected.response_contains and actual.response_contains != expected.response_contains:
            return f"scenario step {index + 1} response assertion was weakened"
        missing = set(expected.response_not_contains) - set(actual.response_not_contains)
        if missing:
            return f"scenario step {index + 1} rejection assertion was removed"
    for label, required, observed in (
        ("precondition", floor.preconditions, current.preconditions),
        ("required state change", floor.required_state_changes, current.required_state_changes),
        ("rejection condition", floor.rejection_conditions, current.rejection_conditions),
        ("observation requirement", floor.observation_requirements, current.observation_requirements),
    ):
        missing = set(required) - set(observed)
        if missing:
            return f"{label} assertion was removed"
    floor_assertions = {
        (item.target, item.target_index, item.predicate)
        for item in floor.observation_assertions
    }
    current_assertions = {
        (item.target, item.target_index, item.predicate)
        for item in current.observation_assertions
    }
    if floor_assertions - current_assertions:
        return "observation assertion binding was removed or weakened"
    return None


def _generation_readiness_errors(
    generation: InterventionGenerationResult,
    *,
    planned_unit_ids: set[str],
    planned_units: dict[str, Any] | None = None,
) -> list[str]:
    """Return readiness notes; non-ok candidates remain repairable inputs."""
    generated_unit_ids = {item.unit_id for item in generation.units}
    errors: list[str] = []
    if generated_unit_ids != planned_unit_ids:
        errors.append(
            "Generation Unit identities do not exactly match the selected Plan"
        )
    if planned_units is not None:
        generated_by_id = {item.unit_id: item for item in generation.units}
        for unit_id, unit in planned_units.items():
            generated = generated_by_id.get(unit_id)
            if generated is None:
                continue
            expected_digest = _unit_contract_digest(unit)
            if generated.contract_digest and generated.contract_digest != expected_digest:
                errors.append(
                    f"Unit {unit_id} contract digest does not match the selected Plan"
                )
    non_ok = [
        f"{item.unit_id}:{item.status}"
        for item in generation.units
        if item.status != "ok"
    ]
    if non_ok:
        errors.append(
            "Generator candidate has non-ok Units; Runner must repair or record the gap; "
            "non-ok Units: " + ", ".join(sorted(non_ok))
        )
    if generation.not_ready_count or generation.skipped_count:
        errors.append(
            "Generation summary is incomplete; Runner must validate before success "
            f"(not_ready={generation.not_ready_count}, "
            f"skipped={generation.skipped_count})"
        )
    environment_unit_ids = {
        item.unit_id
        for item in generation.units
        if item.strategy == "environment_setup"
    }
    reported_environment_ids = set(generation.environment.unit_ids)
    if reported_environment_ids != environment_unit_ids:
        errors.append(
            "Environment Generation Unit identities do not exactly match the "
            "generated environment Units"
        )
    if environment_unit_ids and generation.environment.status != "completed":
        errors.append(
            "environment_setup Units require a completed setup_rootfs.py; "
            f"status={generation.environment.status}"
        )
    if generation.environment.status == "completed":
        script_path = generation.environment.script_path
        if not script_path or not Path(script_path).is_file():
            errors.append(
                "Environment Generation completed but setup_rootfs.py is missing"
            )
    return errors


def _initial_environment_preparation(
    generation: InterventionGenerationResult,
) -> EnvironmentPreparation:
    """Describe the static script before this Runner session applies it."""
    if not generation.environment.unit_ids:
        return EnvironmentPreparation()
    script_path = generation.environment.script_path
    if not script_path or not Path(script_path).is_file():
        return EnvironmentPreparation(
            status="failed",
            source_script_path=script_path,
            failure_reason=(
                "Environment Generation completed but setup_rootfs.py is missing"
            ),
        )
    return EnvironmentPreparation(
        status="not_started",
        source_script_path=script_path,
    )


def _protected_files(root: Path) -> dict[str, bytes]:
    """Snapshot authored crate files, excluding reproducible Cargo outputs."""
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and path.relative_to(root).parts[0] != "target"
    }


def _unit_source_module(relative_path: str) -> str | None:
    parts = Path(relative_path).parts
    if (
        len(parts) >= 3
        and parts[0] == "src"
        and parts[1].startswith("unit_")
        and relative_path.endswith(".rs")
    ):
        return parts[1]
    return None


def _restore_workspace(root: Path, before: dict[str, bytes]) -> None:
    after = _protected_files(root)
    for name in set(after) - set(before):
        path = root / name
        if path.is_file():
            path.unlink()
    for name, content in before.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.is_file() and not path.is_symlink() and path.read_bytes() == content:
            continue
        # Build tools may have left a root-owned, read-only inode on the host
        # mount. The disposable directory is ours; replace the inode rather
        # than opening it for writing (or following an unadmitted symlink).
        temporary = path.with_name(f".{path.name}.restore-{uuid.uuid4().hex}")
        try:
            temporary.write_bytes(content)
            if path.is_file() and not path.is_symlink():
                temporary.chmod(path.stat().st_mode & 0o777)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def _workspace_snapshots(
    *,
    intervention_root: Path,
    test_root: Path | None,
    environment_root: Path | None,
) -> dict[str, dict[str, bytes]]:
    """Snapshot the three disposable authored trees with stable namespaces."""
    roots = {"intervention": intervention_root}
    if test_root is not None:
        roots["test_harness"] = test_root
    if environment_root is not None:
        roots["environment"] = environment_root
    return {namespace: _protected_files(root) for namespace, root in roots.items()}


def _workspace_snapshot_sha256(snapshots: dict[str, dict[str, bytes]]) -> str:
    digest = hashlib.sha256()
    for namespace in sorted(snapshots):
        for name in sorted(snapshots[namespace]):
            digest.update(f"{namespace}/{name}".encode("utf-8"))
            digest.update(b"\0")
            digest.update(snapshots[namespace][name])
            digest.update(b"\0")
    return digest.hexdigest()


def _restore_workspace_snapshots(
    snapshots: dict[str, dict[str, bytes]],
    *,
    intervention_root: Path,
    test_root: Path | None,
    environment_root: Path | None,
) -> None:
    roots = {
        "intervention": intervention_root,
        "test_harness": test_root,
        "environment": environment_root,
    }
    for namespace, before in snapshots.items():
        root = roots.get(namespace)
        if root is not None:
            _restore_workspace(root, before)


def _validate_workspace_files(
    snapshots: dict[str, dict[str, bytes]],
    *,
    intervention_root: Path,
    test_root: Path | None,
    environment_root: Path | None,
    declared_paths: list[str],
    declared_unit_ids: list[str],
    editable_unit_ids: set[str],
) -> tuple[set[str], list[str]]:
    """Validate a declared disposable-workspace edit and return its identities."""
    roots = {
        "intervention": intervention_root,
        "test_harness": test_root,
        "environment": environment_root,
    }
    actual_paths: list[str] = []
    changed_units: set[str] = set()
    editable_modules = {
        unit_module_name(unit_id): unit_id for unit_id in editable_unit_ids
    }
    for namespace, before in snapshots.items():
        root = roots[namespace]
        assert root is not None
        for candidate in root.rglob("*"):
            if candidate.is_symlink():
                try:
                    candidate.resolve().relative_to(root.resolve())
                except ValueError as error:
                    _restore_workspace_snapshots(
                        snapshots,
                        intervention_root=intervention_root,
                        test_root=test_root,
                        environment_root=environment_root,
                    )
                    raise RuntimeError(
                        f"RunnerAgent created an escaping workspace symlink: {namespace}/{candidate.relative_to(root)}"
                    ) from error
        after = _protected_files(root)
        changed = set(before) ^ set(after)
        changed |= {
            name for name in set(before) & set(after) if before[name] != after[name]
        }
        actual_paths.extend(f"{namespace}/{name}" for name in sorted(changed))
        if namespace == "intervention":
            for name in changed:
                module = _unit_source_module(name)
                if module is not None and module in editable_modules:
                    changed_units.add(editable_modules[module])
                elif name.startswith("src/") and name.endswith(".rs"):
                    _restore_workspace_snapshots(
                        snapshots,
                        intervention_root=intervention_root,
                        test_root=test_root,
                        environment_root=environment_root,
                    )
                    raise RuntimeError(
                        "RunnerAgent modified a non-editable Intervention source: "
                        + name
                    )
    # Agents often report the workspace-relative crate directory as part of a
    # path (``intervention/<crate>/src/...``), while the Controller's namespace
    # is already rooted at that crate. Accept that unambiguous spelling and
    # persist the canonical namespace-relative path below.
    aliases: list[str] = []
    for path in declared_paths:
        namespace, _, relative = path.partition("/")
        root = roots.get(namespace)
        if root is not None and relative.startswith(root.name + "/"):
            aliases.append(namespace + "/" + relative[len(root.name) + 1:])
        else:
            aliases.append(path)
    declared_set = set(aliases)
    actual_set = set(actual_paths)
    # The filesystem is the authoritative edit record. A model may declare a
    # stale path after a failed tool call, or omit the path while the tool did
    # make an allowed edit. Canonicalize to the observed diff; reject only a
    # declaration that conflicts with a non-empty observed diff.
    if actual_set and declared_set - actual_set:
        _restore_workspace_snapshots(
            snapshots,
            intervention_root=intervention_root,
            test_root=test_root,
            environment_root=environment_root,
        )
        raise RuntimeError(
            "RunnerAgent changed_paths does not match workspace diff: "
            f"declared={sorted(declared_paths)}, actual={sorted(actual_paths)}"
        )
    if set(declared_unit_ids) != changed_units and changed_units:
        _restore_workspace_snapshots(
            snapshots,
            intervention_root=intervention_root,
            test_root=test_root,
            environment_root=environment_root,
        )
        raise RuntimeError(
            "RunnerAgent changed_unit_ids does not match edited Unit sources: "
            f"declared={sorted(declared_unit_ids)}, actual={sorted(changed_units)}"
        )
    return changed_units, sorted(actual_paths)


def _validate_protected_files(
    root: Path,
    before: dict[str, bytes],
    *,
    declared_unit_ids: list[str] | None = None,
    editable_unit_ids: set[str] | None = None,
) -> set[str]:
    after = _protected_files(root)
    added_or_deleted = set(before).symmetric_difference(after)
    modified = {
        name for name in set(before).intersection(after)
        if before[name] != after[name]
    }
    changed = added_or_deleted | modified
    # Use Generator's forward mapping; slugs cannot reconstruct arbitrary IDs.
    editable_modules = {unit_module_name(unit_id): unit_id for unit_id in (editable_unit_ids or set())}
    invalid = sorted(
        name for name in changed
        if name in added_or_deleted or _unit_source_module(name) not in editable_modules
    )
    changed_units = {
        editable_modules[module]
        for name in modified
        if (module := _unit_source_module(name)) in editable_modules
    }
    if invalid:
        _restore_workspace(root, before)
        raise RuntimeError(
            "RunnerAgent modified protected or non-editable Generator files: "
            + ", ".join(invalid)
        )
    if declared_unit_ids is not None and set(declared_unit_ids) != changed_units:
        _restore_workspace(root, before)
        raise RuntimeError(
            "RunnerAgent changed_unit_ids does not match edited Unit sources: "
            f"declared={sorted(declared_unit_ids)}, actual={sorted(changed_units)}"
        )
    return changed_units


def _run_cargo(
    builder: RuntimeBuilder,
    manifest: Path,
    subcommand: str,
    timeout: int,
) -> subprocess.CompletedProcess:
    return builder.run_cargo(
        manifest,
        subcommand,
        timeout=timeout,
    )


def _locate_cdylib(
    crate_root: Path, builder: RuntimeBuilder | None = None,
) -> Path:
    manifest = tomllib.loads((crate_root / "Cargo.toml").read_text(encoding="utf-8"))
    crate_name = manifest.get("lib", {}).get("name") or manifest["package"]["name"]
    target_builder = builder or RuntimeBuilder()
    path = target_builder.cargo_target_dir(crate_root) / "release" / f"lib{crate_name.replace('-', '_')}.so"
    if not path.is_file():
        raise RuntimeError(f"intervention cdylib is missing after Cargo build: {path}")
    return path


def _run_enabled_tests(
    builder: RuntimeBuilder,
    test_root: Path,
    enabled_unit_ids: set[str],
    timeout: int,
) -> subprocess.CompletedProcess:
    outputs: list[str] = []
    errors: list[str] = []
    returncode = 0
    for unit_id in sorted(enabled_unit_ids):
        target = unit_test_target(unit_id)
        test_file = test_root / unit_test_relative_path(unit_id)
        if not test_file.is_file():
            returncode = 1
            errors.append(
                f"=== {unit_id} stderr ===\n"
                f"missing generated self-test: {test_file}"
            )
            continue
        result = builder.run_cargo(
            test_root / "Cargo.toml",
            "test",
            timeout=timeout,
            extra_args=("--test", target),
        )
        outputs.append(f"=== {unit_id} stdout ===\n{result.stdout}")
        errors.append(f"=== {unit_id} stderr ===\n{result.stderr}")
        if result.returncode != 0:
            returncode = result.returncode
    return subprocess.CompletedProcess(
        args=["cargo", "test", "--test", "<enabled-units>"],
        returncode=returncode,
        stdout="\n".join(outputs),
        stderr="\n".join(errors),
    )


class RehostingRunner:
    def __init__(
        self,
        global_config: Any,
        *,
        max_attempts: int | None = None,
        runtime_timeout_seconds: float = 7200.0,
        watchdog_stall_seconds: float = 60.0,
        scenario_floor: InteractionScenario | None = None,
        service_goal: str | None = None,
    ) -> None:
        self.global_config = global_config
        self.max_attempts = max(1, max_attempts) if max_attempts is not None else None
        self.runtime_timeout_seconds = max(5.0, runtime_timeout_seconds)
        self.watchdog_stall_seconds = max(1.0, watchdog_stall_seconds)
        self.scenario_floor = scenario_floor.model_copy(deep=True) if scenario_floor is not None else None
        self.service_goal = service_goal.strip() if service_goal is not None else None
        if self.service_goal == "":
            raise ValueError("Runner service goal must not be empty")

    async def run(
        self,
        *,
        view: AnalysisView,
        rootfs: Path,
        runtime_workspace: Path,
    ) -> RehostingResult:
        budget = ExecutionBudget(self.runtime_timeout_seconds)
        receipt = RunnerSessionReceipt(
            session_id=uuid.uuid4().hex, started_unix_ns=budget.started_unix_ns,
            budget_seconds=self.runtime_timeout_seconds,
        )
        receipt_path = Path(self.global_config.workdir) / "runner_controller_sessions" / receipt.session_id / "session.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=False)
        write_model_json(receipt_path, receipt)
        if self.scenario_floor is not None:
            write_model_json(receipt_path.parent / "input-scenario.json", self.scenario_floor)
        (receipt_path.parent / "input-goal.json").write_text(
            json.dumps({"service_goal": self.service_goal, "source": "caller" if self.service_goal is not None else "plan"}, indent=2) + "\n")
        try:
            result = await self._run_session(
                view=view, rootfs=rootfs, runtime_workspace=runtime_workspace,
                budget=budget, receipt=receipt, receipt_path=receipt_path,
            )
            result.session_receipt_path = str(receipt_path)
            result = persist_result(self.global_config.target_diagnostic_reports_dir(), result)
            receipt.result_path = str(self.global_config.target_diagnostic_reports_dir() / "runner_reports/rehosting_result.json")
            receipt.state = "stopped" if result.status == "attempts_exhausted" else result.status
            receipt.stop_reason = result.stop_reason
            receipt.input_request = result.input_request
            return result
        except asyncio.CancelledError:
            budget.cancelled.set()
            receipt.state = "cancelled"
            receipt.stop_reason = "user_cancelled"
            raise
        except RunnerStopped as error:
            receipt.state = "stopped"
            receipt.stop_reason = error.reason
            raise
        except Exception as error:
            receipt.state = "error"
            receipt.detail = str(error)
            raise
        finally:
            receipt.finished_unix_ns = time.time_ns()
            receipt.elapsed_seconds = time.monotonic() - budget.started
            write_model_json(receipt_path, receipt)

    async def _run_session(
        self, *, view: AnalysisView, rootfs: Path, runtime_workspace: Path,
        budget: ExecutionBudget, receipt: RunnerSessionReceipt, receipt_path: Path,
    ) -> RehostingResult:
        ensure_runtime_budget = budget.check
        journal = FeedbackJournal(receipt_path.parent / "feedback", receipt.session_id)
        receipt.feedback_root = str(journal.root)

        def phase(name: str) -> None:
            receipt.phase = name
            receipt.elapsed_seconds = time.monotonic() - budget.started
            write_model_json(receipt_path, receipt)
            ensure_runtime_budget()
            if name in {"build", "self_test", "prepare"}:
                journal.execution(name, status="started")

        reports_root = self.global_config.target_diagnostic_reports_dir()
        archive_stage_outputs(self.global_config, "runner")
        rootfs = Path(rootfs).resolve()
        if not rootfs.is_dir():
            raise ValueError(f"Runner firmware rootfs is not a directory: {rootfs}")
        runtime_builder = create_runtime_builder(
            runtime_workspace=runtime_workspace,
            workdir=self.global_config.workdir,
            image=getattr(self.global_config, "runtime_builder_image", None),
            platform_name=getattr(
                self.global_config,
                "runtime_builder_platform",
                None,
            ),
            budget=budget,
        )
        catalog, plan = load_persisted_intervention_plan(
            reports_root, global_config=self.global_config, require_current_implementation=False,
        )
        generation = load_persisted_intervention_generation(
            reports_root,
            plan,
            # Runner owns the Generation→Runtime closure.  It may inspect and
            # repair a frozen failed/partial candidate, but only a later
            # build/test/runtime proof can produce success.
            require_complete=False,
        )
        service_goal = self.service_goal or plan.service_goal or "Unspecified; preserve the selected service protocol behavior."
        (receipt_path.parent / "input-goal.json").write_text(json.dumps({
            "service_goal": service_goal, "source": "caller" if self.service_goal is not None else "plan"
        }, indent=2) + "\n")
        ensure_runtime_budget()
        target = generation.target_binary
        environment_preparation = _initial_environment_preparation(generation)
        runner_root = reports_root / "runner_reports"
        attempts_root = runner_root / "attempts"
        runner_root.mkdir(parents=True, exist_ok=True)
        for managed in ("rehosting_result.json", "index.md"):
            path = runner_root / managed
            if path.is_file():
                path.unlink()
        if attempts_root.exists():
            shutil.rmtree(attempts_root)
        attempts_root.mkdir(parents=True, exist_ok=True)
        recipe = (
            catalog.launch_candidates.get(plan.launch_choice.recipe_id)
            if plan.launch_choice.recipe_id is not None
            else None
        )
        missing_launch = recipe is None
        selected_executable_path = (recipe.executable_path if recipe is not None else
            "/" + catalog.target_identity.selected_rootfs_path.lstrip("/"))
        launch_resolution = None
        known_units = {
            unit_id for unit_id in plan.units
        }
        readiness_errors = _generation_readiness_errors(
            generation,
            planned_unit_ids=known_units,
            planned_units={
                unit_id: unit
                for unit_id, unit in plan.units.items()
            },
        )
        readiness_notes = readiness_errors

        runtime_units = dict(plan.units)
        plan_execution_units = {
            unit_id: unit
            for unit_id, unit in plan.units.items()
            if unit.strategy != "environment_setup"
        }
        execution_unit_ids = set(plan_execution_units)
        editable_unit_ids = {
            unit_id for unit_id, unit in plan_execution_units.items()
            if unit.contract.allowed_refinement_scope
        }
        generated_intervention_root = (
            resolve_archived_path(Path(generation.intervention_crate_path))
            if generation.intervention_crate_path
            else None
        )
        generated_test_root = (
            resolve_archived_path(Path(generation.test_crate_path))
            if generation.test_crate_path
            else None
        )
        if execution_unit_ids:
            if generated_intervention_root is None or not (
                generated_intervention_root / "Cargo.toml"
            ).is_file():
                result = RehostingResult(
                    target_binary=target,
                    guest_arch=generation.arch,
                    selected_recipe_id=recipe.recipe_id if recipe is not None else None,
                    status="error",
                    environment_preparation=environment_preparation,
                    final_summary=(
                        "No generated intervention crate is available for the "
                        "selected Execution Units."
                    ),
                )
                return persist_result(reports_root, result)
        baseline = validate_generation_publication(generation, plan)
        workspace = materialize_generation_workspace(
            baseline,
            workdir=self.global_config.workdir,
            target_binary=target,
            project_src=Path(__file__).resolve().parents[2],
        )
        ensure_runtime_budget()
        intervention_root = workspace.intervention_root
        test_root = workspace.test_harness_root or workspace.root / "test_harnesses" / target
        intervention_root.mkdir(parents=True, exist_ok=True)
        test_root.mkdir(parents=True, exist_ok=True)
        environment_root = workspace.root / "environment"
        adaptation_root = workspace.root / "runtime_adaptations"
        adaptation_root.mkdir()
        dependency_bindings = bind_guestweave_api([intervention_root, test_root], runtime_workspace)
        (adaptation_root / "guestweave-api-binding.json").write_text(
            json.dumps(dependency_bindings, indent=2) + "\n", encoding="utf-8")
        original_manifest: dict[str, object] | None = None
        if execution_unit_ids:
            intervention_manifest = intervention_root / "manifest.json"
            original_manifest = json.loads(
                intervention_manifest.read_text(encoding="utf-8")
            )
            # The immutable Generator baseline remains untouched. Controller-
            # owned indexes and Agent edits are confined to this disposable
            # workspace.
            configure_active_units(
                target_binary=target,
                image_name=original_manifest["target_image"],
                arch=generation.arch,
                units=[
                    plan_execution_units[unit_id]
                    for unit_id in sorted(execution_unit_ids)
                ],
                resolved_manifest=resolve_units(
                    [
                        plan_execution_units[unit_id]
                        for unit_id in sorted(execution_unit_ids)
                    ],
                    view,
                ),
                crate_root=intervention_root,
            )
        env_script = workspace.environment_script
        sandbox = DockerRootfsSandbox(
            rootfs=rootfs,
            workdir=self.global_config.workdir,
            target_binary=target,
            executable_path=selected_executable_path,
            guest_arch=generation.arch,
            runtime_workspace=runtime_workspace,
            env_script=env_script,
            runtime_builder=runtime_builder,
            budget=budget,
            expose_service=True,
        )
        evidence_state = RuntimeEvidenceState()
        live_evidence_root = sandbox.session_root
        live_evidence_root.mkdir(parents=True, exist_ok=True)
        runner_readable_roots = [
            rootfs,
            reports_root,
            getattr(self.global_config, "decompiled_code_dir", None),
            getattr(self.global_config, "disassembled_code_dir", None),
            generated_test_root,
            receipt_path.parent,
            adaptation_root,
            live_evidence_root,
        ]
        live_client = RunnerLiveClient(root=receipt_path.parent / "native-client", budget=budget, runtime_builder=runtime_builder)
        agent = RunnerAgentSession(
            view=view,
            rootfs=rootfs,
            diagnostic_reports_root=reports_root,
            intervention_root=intervention_root,
            trace_path=(
                self.global_config.target_agent_debug_dir()
                / "runner" / "runner_trace.md"
            ),
            evidence_state=evidence_state,
            live_client=live_client,
            readable_roots=[
                Path(path).resolve()
                for path in runner_readable_roots
                if path is not None and Path(path).exists()
            ],
            writable_roots=[
                path for path in (intervention_root, test_root, environment_root)
                if path is not None and path.is_dir()
            ],
            runtime_builder=runtime_builder,
            runtime_workspace=runtime_workspace,
            budget=budget,
        )
        receipt.artifact_root = str(sandbox.session_root)
        attempts: list[RuntimeAttempt] = []
        decision_history: list[RunnerDecision] = []
        revision_history: list[RunnerRevision] = []
        request_revisions: list[RequestRepresentationRevision] = []
        adaptation_history: list[RuntimeAdaptation] = []
        active_adaptations: list[tuple[RuntimeAdaptation, dict, dict]] = []
        revisions_root = runner_root / "revisions"
        revisions_root.mkdir(parents=True, exist_ok=True)
        status = "attempts_exhausted"
        completion = None
        executed_workspace_sha256 = None
        executed_decision_index = None
        final_summary = "Runtime attempt budget exhausted without satisfying the Interaction Scenario."
        sandbox_prepared = False
        runner_tasks = [
            task
            for task in plan.runner_tasks.values()
        ]

        def client_candidate():
            if not attempts:
                raise ValueError("run the candidate before starting a native client")
            current_hash = _workspace_snapshot_sha256(_workspace_snapshots(
                intervention_root=intervention_root, test_root=test_root,
                environment_root=environment_root if environment_root.is_dir() else None))
            if current_hash != executed_workspace_sha256:
                raise ValueError("candidate source changed; return an edit/run decision before native interaction")
            return {"attempt": attempts[-1], "attempt_sha256": _file_sha256(evidence_state.attempt_json),
                "workspace_sha256": current_hash, "sandbox": sandbox,
                "intervention_so": (sandbox.bundle_dir / "intervention.so" if attempts[-1].intervention_binary_path else None),
                "executable_path": recipe.executable_path}

        live_client.start_candidate = client_candidate

        def refresh_environment_preparation() -> None:
            nonlocal environment_preparation
            if env_script is None:
                environment_preparation = EnvironmentPreparation()
            elif sandbox.environment_script_failure is not None:
                environment_preparation = EnvironmentPreparation(
                    status="failed",
                    source_script_path=str(env_script),
                    application_count=sandbox.environment_script_applications,
                    failure_reason=sandbox.environment_script_failure,
                )
            else:
                environment_preparation = EnvironmentPreparation(
                    status=(
                        "applied"
                        if sandbox.environment_script_applications
                        else "not_started"
                    ),
                    source_script_path=str(env_script),
                    application_count=sandbox.environment_script_applications,
                )

        def mark_revision(status: str, detail: str | None = None) -> None:
            if revision_history and revision_history[-1].verification == "not_run":
                revision_history[-1].verification = status
                revision_history[-1].verification_detail = detail

        async def run_cargo_stage(name: str, function, *args, **kwargs):
            """Single-operation expiry is repair feedback; session expiry propagates."""
            try:
                return await budget.run_sync(function, *args, **kwargs)
            except subprocess.TimeoutExpired as error:
                def decode(value):
                    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
                return subprocess.CompletedProcess(error.cmd, 124, decode(error.stdout),
                    decode(error.stderr) + f"\n{name} operation_timeout: {error}")

        def cargo_feedback(name: str, result: subprocess.CompletedProcess) -> str:
            directory = journal.root / f"stage-{len(journal.records):04d}-{name}"
            directory.mkdir(parents=True, exist_ok=True)
            out_path, err_path = directory / "stdout.txt", directory / "stderr.txt"
            out_path.write_text(result.stdout or "", encoding="utf-8")
            err_path.write_text(result.stderr or "", encoding="utf-8")
            journal.execution(name, status="failed", returncode=result.returncode,
                stdout_path=str(out_path), stderr_path=str(err_path))
            return (f"{name} returncode={result.returncode}\n"
                + render_preview(file_preview(out_path)) + "\n" + render_preview(file_preview(err_path)))

        try:
            scenario_floor = self.scenario_floor.model_copy(deep=True) if self.scenario_floor is not None else None
            def current_specification_gap() -> str | None:
                if missing_launch and launch_resolution is None and decision.action == "request_input":
                    return decision.summary
                for attempt in reversed(attempts[-1:]):
                    scenario_result = attempt.scenario_result
                    if scenario_result is not None and scenario_result.status == "specification_gap":
                        return scenario_result.error or "Interaction Scenario is not decidable from available evidence."
                return None

            async def invoke_guarded(
                message: str,
                *,
                bootstrap: bool = False,
                source_attempt_path: Path | None = None,
            ) -> RunnerDecision:
                nonlocal scenario_floor, recipe, launch_resolution, original_manifest
                correction_message = message
                while True:
                    proposed_launch = None
                    cookie_revision = None
                    previous_unit = None
                    snapshots = _workspace_snapshots(
                        intervention_root=intervention_root,
                        test_root=test_root,
                        environment_root=environment_root if environment_root.is_dir() else None,
                    )
                    parent_sha256 = _workspace_snapshot_sha256(snapshots)
                    identity = ""
                    if scenario_floor is not None:
                        identity += "\nController scenario_sha256=" + hashlib.sha256(scenario_floor.model_dump_json().encode()).hexdigest()
                    if evidence_state.attempt_json is not None:
                        identity += "\nController attempt_path=" + str(evidence_state.attempt_json)
                        identity += "\nController attempt_sha256=" + str(_file_sha256(evidence_state.attempt_json))
                    delivered_message = correction_message + identity
                    exchange = journal.prepare(
                        delivered_message,
                        kind=("correction" if correction_message != message else "bootstrap" if bootstrap else "feedback"),
                        source_attempt_path=source_attempt_path or evidence_state.attempt_json,
                        parent_workspace_sha256=parent_sha256,
                        remaining_seconds=budget.remaining(),
                    )
                    try:
                        phase("agent_bootstrap" if bootstrap else "agent_feedback")
                        remaining = budget.remaining()
                        journal.started(exchange)
                        try:
                            next_decision, agent_result = await asyncio.wait_for(
                                agent.invoke(delivered_message),
                                timeout=remaining,
                            )
                        except AgentTurnTimeoutError:
                            raise
                        except asyncio.TimeoutError as error:
                            if budget.remaining() > 0:
                                raise
                            raise RunnerStopped("session_budget_exhausted") from error
                        journal.responded(exchange, next_decision, agent_result)
                        changed, changed_paths = _validate_workspace_files(
                            snapshots,
                            intervention_root=intervention_root,
                            test_root=test_root,
                            environment_root=environment_root if environment_root.is_dir() else None,
                            declared_paths=next_decision.changed_paths,
                            declared_unit_ids=next_decision.changed_unit_ids,
                            editable_unit_ids=editable_unit_ids,
                        )
                        bind_guestweave_api([intervention_root, test_root], runtime_workspace, check_only=True)
                        if changed_paths and next_decision.action not in {"edit_unit", "edit_workspace"}:
                            raise RuntimeError(
                                f"{next_decision.action} decisions must not modify workspace files; "
                                f"observed changed_paths={changed_paths}. "
                                "Use an explicit edit decision when source changes are authorized."
                            )
                        # Keep the persisted decision/report aligned with the
                        # Controller namespace even when the Agent used the
                        # equivalent crate-prefixed spelling.
                        if next_decision.action == "edit_workspace" and not changed_paths:
                            raise RuntimeError(
                                "edit_workspace declared a revision but the disposable "
                                "workspace has no actual file diff"
                            )
                        if next_decision.action == "edit_unit" and not changed:
                            raise RuntimeError(
                                "edit_unit declared changed Units but the disposable "
                                "workspace has no actual Unit diff"
                            )
                        try:
                            next_decision = RunnerDecision.model_validate({
                                **next_decision.model_dump(), "changed_paths": changed_paths,
                            })
                        except ValueError as error:
                            raise RuntimeError(f"Observed workspace diff invalidates Runner decision: {error}") from error
                        if scenario_floor is not None and next_decision.scenario is not None:
                            # Evidence revisions extend the supplied acceptance
                            # lineage. Keep original references, including their
                            # order, even when an Agent corrects its explanation.
                            original_refs = scenario_floor.evidence_refs
                            refs = original_refs + list(dict.fromkeys(
                                ref for ref in next_decision.scenario.evidence_refs
                                if ref not in original_refs
                            ))
                            next_decision = next_decision.model_copy(update={
                                "scenario": next_decision.scenario.model_copy(
                                    update={"evidence_refs": refs}),
                            })
                        self._validate_decision(
                            next_decision,
                            execution_unit_ids,
                            rootfs,
                        )
                        if next_decision.action == "complete":
                            claim = next_decision.completion
                            latest = attempts[-1] if attempts else None
                            latest_path = (attempts_root / f"attempt-{latest.attempt_number:02d}" / "attempt.json"
                                           if latest is not None else None)
                            if (latest is None or latest.attempt_number != attempt_number):
                                raise RuntimeError("Completion requires current execution evidence")
                            if len(decision_history) != executed_decision_index or latest.scenario != scenario_floor:
                                raise RuntimeError("A subsequent decision requires fresh execution before completion")
                            if (claim.attempt_number != latest.attempt_number
                                    or claim.attempt_sha256 != _file_sha256(latest_path)
                                    or load_model_json(latest_path, RuntimeAttempt) != latest):
                                raise RuntimeError("Completion must reference the exact latest Controller attempt.json and its SHA-256")
                            if parent_sha256 != executed_workspace_sha256:
                                raise RuntimeError("The candidate changed since execution; run the current candidate before completion")
                            if claim.unverified_requirements:
                                raise RuntimeError("Your completion still lists unverified required behavior; continue investigating and repairing")
                            if not claim.client_receipt and (latest.scenario_result is None or latest.scenario_result.status != "success"):
                                raise RuntimeError("Attach actual native interaction evidence or execute the corrected protocol checks before completion")
                            if claim.client_receipt:
                                client = live_client.current
                                if (client is None or claim.client_receipt != str(Path(client["path"]) / "receipt.json")
                                        or client["attempt_sha256"] != claim.attempt_sha256
                                        or client["workspace_sha256"] != parent_sha256
                                        or not client["commands"]):
                                    raise RuntimeError("Completion client receipt must belong to this current candidate's actual native interactions")
                        if next_decision.unit_proposal is not None:
                            if bootstrap or evidence_state.attempt_json is None:
                                raise RuntimeError("Runtime Unit admission requires existing runtime or partial execution evidence")
                            if changed_paths:
                                raise RuntimeError("Submit a Unit proposal without workspace edits; implement only after admission")
                            latest_path = evidence_state.attempt_json
                            native_roots = []
                            client = live_client.current
                            if client and client.get("attempt_sha256") == _file_sha256(latest_path):
                                native_roots.append(Path(client["path"]))
                                if client.get("runtime_source_root"):
                                    native_roots.append(Path(client["runtime_source_root"]))
                            previous_unit = validate_proposal(next_decision.unit_proposal,
                                units=runtime_units,
                                active_id=active_adaptations[-1][0].adaptation_id if active_adaptations else None,
                                view=view, readable_roots=[Path(p) for p in runner_readable_roots if p is not None],
                                attempt_path=latest_path, artifact_root=latest_path.parent,
                                check_budget=ensure_runtime_budget, runtime_artifact_roots=native_roots)
                        if next_decision.action == "continue":
                            journal.accepted(exchange, decision_index=None, revision_number=None)
                            correction_message = (
                                "The rehosting goal remains active. Continue with the next useful investigation, "
                                "repair or native interaction in this same session. Current goal and evidence: "
                                + str(receipt_path.parent / "input-goal.json") + "; " + str(journal.root)
                            )
                            continue
                        if bootstrap:
                            _validate_bootstrap_decision(
                                next_decision,
                                changed_unit_ids=changed,
                                allow_input_request=True,
                            )
                        if missing_launch and bootstrap and next_decision.action != "request_input":
                            proposed_launch = admit_launch_proposal(next_decision,
                                target_identity=catalog.target_identity, rootfs=rootfs,
                                readable_roots=[Path(p) for p in runner_readable_roots if p is not None],
                                check_budget=ensure_runtime_budget)
                        elif next_decision.launch_proposal is not None and (
                            launch_resolution is None or next_decision.launch_proposal != launch_resolution.proposal
                        ):
                            raise RuntimeError("launch_proposal is only admitted for a missing bootstrap recipe; retain the selected target and use the existing runtime argv/cwd/env fields")
                    except RuntimeError as error:
                        journal.failed(exchange, error)
                        _restore_workspace_snapshots(
                            snapshots,
                            intervention_root=intervention_root,
                            test_root=test_root,
                            environment_root=environment_root if environment_root.is_dir() else None,
                        )
                        if isinstance(error, AgentProviderError):
                            # Restore unadmitted edits, but do not mistake a
                            # provider failure for a correctable decision.
                            raise
                        correction_message = (
                            "The Controller rejected the previous Runner decision before execution. "
                            "Correct the decision in this same session; do not claim that an edit "
                            "occurred unless the file was actually changed. Every changed_paths "
                            "entry must exactly match the disposable workspace diff, and unsafe or "
                            "outside edits must be reverted. Full rejection:\n" + str(error)
                        )
                        continue
                    except BaseException as error:
                        journal.failed(exchange, error)
                        _restore_workspace_snapshots(
                            snapshots,
                            intervention_root=intervention_root,
                            test_root=test_root,
                            environment_root=environment_root if environment_root.is_dir() else None,
                        )
                        raise
                    break
                if next_decision.unit_proposal is not None:
                    proposal = next_decision.unit_proposal
                    before_units = dict(runtime_units)
                    evidence_snapshots = snapshot_evidence(proposal, adaptation_root, check_budget=ensure_runtime_budget)
                    rollback_snapshot = adaptation_root / f"before-{len(adaptation_history) + 1:03d}"
                    rollback_snapshot.mkdir(parents=True)
                    for namespace, files in snapshots.items():
                        (rollback_snapshot / namespace).mkdir()
                        for name, content in files.items():
                            destination = rollback_snapshot / namespace / name
                            destination.parent.mkdir(parents=True, exist_ok=True)
                            destination.write_bytes(content)
                    # Controller scaffolding is a transaction: a failure restores
                    # both source bytes and owner definitions before propagation.
                    try:
                        if proposal.operation == "rollback":
                            reverted, restored_units, restored_files = active_adaptations[-1]
                            previous_unit, next_unit = reverted.after, reverted.before
                            _restore_workspace_snapshots(restored_files, intervention_root=intervention_root,
                                test_root=test_root, environment_root=environment_root if environment_root.is_dir() else None)
                            runtime_units.clear()
                            runtime_units.update(restored_units)
                        else:
                            next_unit = proposal.unit
                            if next_unit.strategy != "environment_setup" and not (intervention_root / "Cargo.toml").is_file():
                                generate_shell(target_binary=target, image_name=Path(selected_executable_path).name,
                                    arch=generation.arch, units=[], resolved_manifest=ResolvedManifest(),
                                    interventions_root=intervention_root.parent, test_harnesses_root=test_root.parent,
                                    iib_api_abspath=runtime_workspace / "fmst-iib-api")
                                original_manifest = json.loads((intervention_root / "manifest.json").read_text())
                            if next_unit.strategy != "environment_setup" and next_unit.unit_id not in runtime_units:
                                generate_unit_shell(unit=next_unit, crate_root=intervention_root)
                                manifest = test_root / "Cargo.toml"
                                if not manifest.is_file():
                                    raise RuntimeError("Runtime owner requires an existing test crate")
                                with manifest.open("a") as stream:
                                    stream.write("\n[[test]]\nname = " + json.dumps(unit_test_target(next_unit.unit_id))
                                        + "\npath = " + json.dumps(unit_test_relative_path(next_unit.unit_id).as_posix()) + "\n")
                            runtime_units[next_unit.unit_id] = next_unit
                            if next_unit.strategy != "environment_setup":
                                plan_execution_units[next_unit.unit_id] = next_unit
                                configure_active_units(target_binary=target, image_name=original_manifest["target_image"],
                                    arch=generation.arch, units=list(plan_execution_units.values()),
                                    resolved_manifest=resolve_units(list(plan_execution_units.values()), view), crate_root=intervention_root)
                            bind_guestweave_api([intervention_root, test_root], runtime_workspace)
                    except BaseException:
                        runtime_units.clear()
                        runtime_units.update(before_units)
                        plan_execution_units.clear()
                        plan_execution_units.update({key: unit for key, unit in runtime_units.items() if unit.strategy != "environment_setup"})
                        _restore_workspace_snapshots(snapshots, intervention_root=intervention_root,
                            test_root=test_root, environment_root=environment_root if environment_root.is_dir() else None)
                        raise
                    plan_execution_units.clear()
                    plan_execution_units.update({key: unit for key, unit in runtime_units.items() if unit.strategy != "environment_setup"})
                    execution_unit_ids.clear()
                    execution_unit_ids.update(plan_execution_units)
                    editable_unit_ids.clear()
                    editable_unit_ids.update(key for key, unit in plan_execution_units.items() if unit.contract.allowed_refinement_scope)
                    after_admission = _workspace_snapshots(intervention_root=intervention_root,
                        test_root=test_root, environment_root=environment_root if environment_root.is_dir() else None)
                    identifier = hashlib.sha256((proposal.model_dump_json() + parent_sha256 + str(latest_path) + str(len(adaptation_history))).encode()).hexdigest()
                    record = RuntimeAdaptation(adaptation_id=identifier, proposal=proposal,
                        source_attempt_path=str(latest_path), parent_workspace_sha256=parent_sha256,
                        result_workspace_sha256=_workspace_snapshot_sha256(after_admission),
                        before=previous_unit, after=next_unit, evidence_snapshots=evidence_snapshots,
                        rollback_snapshot_path=rollback_snapshot.relative_to(adaptation_root).as_posix())
                    adaptation_history.append(record)
                    write_model_json(adaptation_root / (identifier + ".json"), record)
                    if proposal.operation == "rollback":
                        active_adaptations.pop()
                    else:
                        active_adaptations.append((record, before_units, snapshots))
                    changed_paths = sorted(f"{namespace}/{name}" for namespace in set(snapshots) | set(after_admission)
                        for name in set(snapshots.get(namespace, {})) | set(after_admission.get(namespace, {}))
                        if snapshots.get(namespace, {}).get(name) != after_admission.get(namespace, {}).get(name))
                    journal.execution("runtime_unit_admission", adaptation_id=identifier,
                        operation=proposal.operation, path=str(adaptation_root / (identifier + ".json")))
                if proposed_launch is not None:
                    launch_resolution = proposed_launch
                    recipe = proposed_launch
                    write_model_json(runner_root / "launch-resolution.json", proposed_launch)
                    journal.execution("launch_resolution", recipe_id=recipe.recipe_id,
                        path=str(runner_root / "launch-resolution.json"))
                revision = cookie_revision
                if scenario_floor is not None and next_decision.scenario is not None and next_decision.scenario != scenario_floor:
                    revision = RequestRepresentationRevision(
                        kind="scenario_revision",
                        parent_sha256=hashlib.sha256(scenario_floor.model_dump_json().encode()).hexdigest(),
                        result_sha256=hashlib.sha256(next_decision.scenario.model_dump_json().encode()).hexdigest(),
                        reason=(next_decision.scenario_revision_reason or next_decision.request_representation_reason
                                or next_decision.summary),
                        before=scenario_floor, after=next_decision.scenario,
                    )
                if revision is not None:
                    request_revisions.append(revision)
                    revision_path = revisions_root / f"request-{len(request_revisions):02d}.json"
                    write_model_json(revision_path, revision)
                    journal.execution("request_representation_revision", kind=revision.kind, path=str(revision_path),
                        parent_sha256=revision.parent_sha256, result_sha256=revision.result_sha256)
                    scenario_floor = revision.after.model_copy(deep=True)
                decision_history.append(next_decision)
                if next_decision.scenario is not None and next_decision.action != "request_input":
                    # Keep every accepted addition, not merely the bootstrap
                    # prefix. Attempt records preserve original scenes/gaps.
                    scenario_floor = next_decision.scenario.model_copy(deep=True)
                if changed_paths:
                    after = _workspace_snapshots(
                        intervention_root=intervention_root,
                        test_root=test_root,
                        environment_root=environment_root if environment_root.is_dir() else None,
                    )
                    diff_lines: list[str] = []
                    for namespace in sorted(set(snapshots) | set(after)):
                        before_files = snapshots.get(namespace, {})
                        after_files = after.get(namespace, {})
                        for name in sorted(set(before_files) | set(after_files)):
                            old = before_files.get(name, b"").decode("utf-8", errors="replace").splitlines(keepends=True)
                            new = after_files.get(name, b"").decode("utf-8", errors="replace").splitlines(keepends=True)
                            if old != new:
                                diff_lines.extend(difflib.unified_diff(
                                    old,
                                    new,
                                    fromfile=f"a/{namespace}/{name}",
                                    tofile=f"b/{namespace}/{name}",
                                ))
                    revision_number = len(revision_history) + 1
                    diff_path = revisions_root / f"revision-{revision_number:02d}.patch"
                    diff_path.write_text("".join(diff_lines), encoding="utf-8")
                    revision_history.append(RunnerRevision(
                        revision_number=revision_number,
                        parent_sha256=parent_sha256,
                        result_sha256=_workspace_snapshot_sha256(after),
                        changed_unit_ids=sorted(changed),
                        changed_paths=changed_paths,
                        action=next_decision.action,
                        reason=next_decision.summary,
                        diff_path=str(diff_path),
                    ))
                journal.accepted(exchange, decision_index=len(decision_history),
                    revision_number=revision_history[-1].revision_number if changed_paths else None)
                if next_decision.unit_proposal is not None:
                    return await invoke_guarded(
                        "Controller admitted the runtime derivation below. Admission verifies source identity and ownership, "
                        "not semantic correctness or runtime success. Original Plan/Generator and scenario remain unchanged. "
                        "Implement the admitted owner and validate through real interaction in this same session; "
                        "An environment Contract revision retains its existing script and creates no Rust adapter. "
                        "For rollback, the complete pre-admission "
                        "authored file contents were restored; re-evaluate cumulative disabled_unit_ids and launch settings. "
                        "The latest active parent_adaptation_id is "
                        + (active_adaptations[-1][0].adaptation_id if active_adaptations else "null")
                        + ". Retain the service goal and provide run/edit_unit/edit_workspace/continue.\n"
                        + record.model_dump_json(indent=2))
                return next_decision

            decision = await invoke_guarded(
                "Host execution environment: Python interpreter=" + sys.executable
                + ". Use the absolute interpreter path for native Python commands; guest tools belong to the firmware, not this host.\n\n"
                + "Service goal: " + service_goal + "\n\n"
                + ("Supplied historical regression scenario (tests may be corrected with a reason; preserve original evidence):\n"
                   + scenario_floor.model_dump_json(indent=2) + "\n\n" if scenario_floor is not None else "")
                + "Bootstrap the current candidate. For a web UI, return action=run with browser_origin "
                "and concrete launch arguments; omit probe and scenario. The executor builds and starts "
                "the service and returns its live browser. Discover operations through native pages, "
                "interact, repair from feedback, and verify a fresh instance before complete. No separate "
                "protocol tests or self-test phase is required. Protocol scenarios are optional diagnostics "
                "for non-browser goals or explicit regressions. Do not edit code/rootfs before initial runtime "
                "evidence. The selected "
                "LaunchRecipe and current Generation status are:\n\n"
                + (recipe.model_dump_json(indent=2) if recipe is not None else
                    "No Catalog recipe was selected. Keep the original Plan/Generation unchanged. "
                    "Inspect the supplied source evidence and submit launch_proposal with exact "
                    "source file hashes/excerpts and matching guest argv/cwd/env for this selected "
                    "ELF. Continue investigating unresolved launch dependencies. Admission verifies "
                    "identity and evidence binding, not semantic correctness or firmware success.\n"
                    + catalog.target_identity.model_dump_json(indent=2)
                    + "\nOriginal Plan launch choice:\n" + plan.launch_choice.model_dump_json(indent=2))
                + "\n\nThe complete persisted Runner tasks are:\n\n"
                + json.dumps(
                    [task.model_dump(mode="json") for task in runner_tasks],
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n\n"
                + "Frozen Generation readiness notes (diagnostic only; do not treat "
                "them as success or as permission to invent a new Plan):\n"
                + ("\n".join(f"- {note}" for note in readiness_notes) if readiness_notes else "- none")
                + "\n\n"
                + generation.model_dump_json(indent=2),
                bootstrap=True,
            )
            scenario_floor = decision.scenario
            attempt_number = 0
            while True:
                ensure_runtime_budget()
                if decision.action == "request_input":
                    status = "waiting_for_input"
                    final_summary = decision.summary
                    break
                if decision.action == "complete":
                    completion = decision.completion
                    if completion.client_receipt:
                        await budget.run_sync(live_client.stop)
                        client_root = Path(completion.client_receipt).parent
                        destination = attempts_root / f"attempt-{attempts[-1].attempt_number:02d}" / "native-client"
                        await budget.run_sync(shutil.copytree, client_root, destination, symlinks=True)
                    attempt = attempts[-1]
                    artifact_dir = attempts_root / f"attempt-{attempt.attempt_number:02d}"
                    write_model_json(artifact_dir / "completion.json", completion)
                    mark_revision("runtime_success")
                    phase("publish_success")
                    success_configuration_path = await budget.run_sync(publish_success,
                        root=Path(self.global_config.workdir) / "runner_successes" / sandbox.target_slug,
                        sandbox=sandbox, attempt=attempt, attempt_dir=artifact_dir,
                        controller_session_id=receipt.session_id,
                        baseline_id=baseline.baseline_id, baseline_root=baseline.root,
                        authored_root=workspace.root,
                        source_records={"catalog": catalog, "plan": plan, "generation": generation},
                        revisions=revision_history, budget=budget,
                        completion=completion,
                        watchdog_stall_seconds=self.watchdog_stall_seconds)
                    journal.execution("publish_success", status="completed",
                        attempt_number=attempt.attempt_number, manifest_path=str(success_configuration_path))
                    status = "success"
                    final_summary = decision.summary
                    break
                if self.max_attempts is not None and attempt_number >= self.max_attempts:
                    break
                await budget.run_sync(live_client.stop)
                enabled_unit_ids = (
                    execution_unit_ids - set(decision.disabled_unit_ids)
                )
                if execution_unit_ids:
                    phase("build")
                    assert original_manifest is not None
                    configure_active_units(
                        target_binary=target,
                        image_name=original_manifest["target_image"],
                        arch=generation.arch,
                        units=[
                            plan_execution_units[unit_id]
                            for unit_id in sorted(enabled_unit_ids)
                        ],
                        resolved_manifest=resolve_units(
                            [
                                plan_execution_units[unit_id]
                                for unit_id in sorted(enabled_unit_ids)
                            ],
                            view,
                        ),
                        crate_root=intervention_root,
                    )
                    build = await run_cargo_stage("build", _run_cargo,
                        runtime_builder,
                        intervention_root / "Cargo.toml", "build", timeout=1800
                    )
                    if build.returncode != 0:
                        mark_revision("build_failed", build.stderr)
                        decision = await invoke_guarded(
                "Service goal: " + service_goal + "\n\n"
                +                             "The current intervention did not build. Return "
                            "action=edit_unit or edit_workspace after correcting the "
                            "owned disposable workspace. Declare changed_paths and do "
                            "not change immutable Generator files. Retain the "
                            "native origin and launch values. "
                            "Cargo feedback and full output paths:\n\n"
                            + cargo_feedback("build", build)
                        )
                        continue
                    journal.execution("build", status="completed", returncode=build.returncode)
                    mark_revision("build_passed")
                try:
                    phase("prepare")
                    await budget.run_sync(sandbox.configure_network, decision.network)
                    if not sandbox_prepared:
                        await budget.run_sync(sandbox.prepare,
                            decision.rootfs_actions,
                            decision.companion_processes,
                        )
                        sandbox_prepared = True
                    else:
                        sandbox.refresh_environment_script()
                        await budget.run_sync(sandbox.update_rootfs_actions,
                            decision.rootfs_actions,
                            decision.companion_processes,
                        )
                except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                    journal.execution("prepare", status="failed", error=f"{type(error).__name__}: {error}")
                    refresh_environment_preparation()
                    mark_revision("prepare_failed", str(error))
                    decision = await invoke_guarded(
                        "Service goal: "
                        + service_goal
                        + "\n\nEnvironment preparation failed before an attempt could run. "
                        "Inspect the complete failure below and return a concrete "
                        "run/edit_unit/edit_workspace/continue decision. You may revise only "
                        "an existing owned file or the typed cumulative rootfs/peer decision supported "
                        "by evidence; do not hide the failure or claim success.\n\n"
                        + str(error)
                    )
                    continue
                journal.execution("prepare", status="completed")
                attempt_number += 1
                phase(f"attempt_{attempt_number}")
                attempt_started_ns = time.time_ns()
                journal.execution("guest", status="started", attempt_number=attempt_number)
                intervention_so = (
                    _locate_cdylib(intervention_root, runtime_builder)
                    if execution_unit_ids
                    else None
                )
                artifact_dir = attempts_root / f"attempt-{attempt_number:02d}"
                persist_runtime_owners(artifact_dir / "runtime-owners.json",
                    units=runtime_units,
                    enabled_ids=enabled_unit_ids | {key for key, unit in runtime_units.items()
                                                   if unit.strategy == "environment_setup"},
                    manifest=intervention_root / "manifest.json",
                    adaptation_ids=[entry[0].adaptation_id for entry in active_adaptations],
                    environment_script=env_script)
                staged_binary_hashes = {}
                if sandbox._active_rootfs:
                    for binary in view.lib_dep_graph.get_nodes():
                        budget.check()
                        try:
                            relative = Path(binary.binary_path).relative_to(rootfs)
                            staged_binary = (sandbox._active_rootfs / relative).resolve(strict=True)
                            staged_binary.relative_to(sandbox._active_rootfs.resolve())
                            staged_binary_hashes[binary.name] = _file_sha256(staged_binary)
                        except (ValueError, OSError):
                            # Missing identities stay missing; they cannot support a mapping.
                            continue
                evidence_state.executed_binary_hashes = staged_binary_hashes
                try:
                    executed_workspace_sha256 = _workspace_snapshot_sha256(_workspace_snapshots(
                        intervention_root=intervention_root, test_root=test_root,
                        environment_root=environment_root if environment_root.is_dir() else None))
                    executed_decision_index = len(decision_history)
                    if decision.browser_origin:
                        origin = urlsplit(decision.browser_origin)
                        host_port = _local_service_port()
                        ready = await budget.run_sync(sandbox.start_service,
                            attempt_number=attempt_number, intervention_so=intervention_so,
                            executable_path=recipe.executable_path, guest_args=decision.guest_args,
                            guest_working_directory=decision.guest_working_directory,
                            guest_environment=decision.guest_environment, companion_processes=decision.companion_processes,
                            port=origin.port or (443 if origin.scheme == "https" else 80), host_port=host_port,
                            timeout_seconds=min(120, budget.remaining()))
                        live_client.pending_service = (ready, host_port, attempt_number)
                        output = sandbox.output_root / f"attempt-{attempt_number:02d}"
                        sandbox_attempt = SandboxAttempt(container_exit_code=None, target_exit_code=None,
                            timed_out=False, probe_result=ProbeResult(connected=False, interacted=False, attempts=0),
                            scenario_result=None, runtime_trace_path=output / "runtime_trace.json",
                            runtime_trace_paths=tuple(output.glob("runtime_trace*.json")),
                            container_log_path=output / "container.log", companion_log_paths=(),
                            rootfs_adaptations=tuple(sandbox.staging_adaptations), heartbeat_paths=(),
                            watchdog_path=output / "watchdog.json", watchdog_triggered=False,
                            termination_reason="unknown")
                    else:
                        sandbox_attempt = await budget.run_sync(sandbox.run_attempt,
                            attempt_number=attempt_number,
                            intervention_so=intervention_so,
                            executable_path=recipe.executable_path,
                            guest_args=decision.guest_args,
                            guest_working_directory=decision.guest_working_directory,
                            guest_environment=decision.guest_environment,
                            companion_processes=decision.companion_processes,
                            probe=decision.probe,
                            timeout_seconds=budget.remaining(),
                            scenario=decision.scenario,
                            watchdog_stall_seconds=self.watchdog_stall_seconds,
                        )
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    partial_path = sandbox.session_root / "attempt_receipts" / f"attempt-{attempt_number:02d}.json"
                    journal.execution("guest", status="failed", attempt_number=attempt_number,
                        error=f"{type(error).__name__}: {error}", partial_receipt_path=str(partial_path) if partial_path.is_file() else None)
                    mark_revision("runtime_failed", str(error))
                    evidence_state.reset()
                    evidence_state.executed_binary_hashes = staged_binary_hashes
                    artifact_dir = attempts_root / f"attempt-{attempt_number:02d}"
                    partial_feedback = collect_partial_feedback(
                        source=sandbox.session_root / "attempts" / f"attempt-{attempt_number:02d}",
                        receipt=partial_path, destination=artifact_dir, session_id=receipt.session_id,
                        attempt_number=attempt_number, error=f"{type(error).__name__}: {error}", budget=budget)
                    evidence_state.attempt_json = artifact_dir / "partial-feedback.json"
                    evidence_state.emulator_harness = sandbox.harness_path
                    evidence_state.emulator_harness_sha256 = (
                        _file_sha256(sandbox.bundle_dir / sandbox.harness_path.name)
                        if sandbox.harness_path is not None else None)
                    for field, name in (("container_log", "container.log"), ("watchdog_json", "watchdog.json"),
                                        ("trace_json", "runtime_trace.json"),
                                        ("runtime_dump_manifest", "runtime-dump/manifest.json")):
                        setattr(evidence_state, field, Path(partial_feedback.artifacts[name]) if name in partial_feedback.artifacts else None)
                    evidence_state.companion_logs = [Path(path) for name, path in partial_feedback.artifacts.items()
                                                    if name.startswith("companion-") and name.endswith(".log")]
                    evidence_state.trace_context_error = "Partial execution: source mapping and guest snapshot were not collected; raw artifacts may be incomplete."
                    if self.max_attempts is not None and attempt_number >= self.max_attempts:
                        final_summary = f"Explicit attempt cap reached after execution error: {error}"
                        break
                    decision = await invoke_guarded(
                        render_partial_feedback(partial_feedback) + "\n"
                        + (f"Partial execution/cleanup receipt: {partial_feedback.artifacts.get('execution-receipt.json', partial_path)}\n" if partial_path.is_file()
                           else "No execution receipt was created; do not assume the guest started.\n")
                        + "This is an execution/observation failure, not proof of a guest bug. "
                        "Use existing evidence to choose a revision/run or continue investigating; correct mistaken tests as needed. "
                        "Earlier completed attempt evidence is historical, not the failed attempt's state.",
                        source_attempt_path=partial_path if partial_path.is_file() else None,
                    )
                    continue
                attempt_finished_ns = time.time_ns()
                phase("persist_attempt")
                artifact_dir = attempts_root / f"attempt-{attempt_number:02d}"
                artifact_dir.mkdir(exist_ok=True)
                trace_path = artifact_dir / "runtime_trace.json"
                log_path = artifact_dir / "container.log"
                watchdog_path = artifact_dir / "watchdog.json"
                source_path = artifact_dir / "intervention_src"
                binary_path = artifact_dir / "intervention.so"
                if intervention_so is not None:
                    shutil.copytree(intervention_root / "src", source_path)
                    shutil.copy2(intervention_so, binary_path)
                trace_paths: list[Path] = []
                for trace_source in sandbox_attempt.runtime_trace_paths:
                    trace_destination = (
                        trace_path
                        if trace_source.name == "runtime_trace.json"
                        else artifact_dir / trace_source.name
                    )
                    shutil.copy2(trace_source, trace_destination)
                    trace_paths.append(trace_destination)
                if not trace_path.is_file() and sandbox_attempt.runtime_trace_path.is_file():
                    shutil.copy2(sandbox_attempt.runtime_trace_path, trace_path)
                    trace_paths.append(trace_path)
                shutil.copy2(sandbox_attempt.container_log_path, log_path)
                heartbeat_paths: list[Path] = []
                for heartbeat_source in sandbox_attempt.heartbeat_paths:
                    heartbeat_destination = artifact_dir / heartbeat_source.name
                    shutil.copy2(heartbeat_source, heartbeat_destination)
                    heartbeat_paths.append(heartbeat_destination)
                if sandbox_attempt.watchdog_path.is_file():
                    shutil.copy2(sandbox_attempt.watchdog_path, watchdog_path)
                if (
                    sandbox_attempt.runtime_dump_manifest_path is not None
                    and sandbox_attempt.runtime_dump_manifest_path.is_file()
                ):
                    shutil.copytree(
                        sandbox_attempt.runtime_dump_manifest_path.parent,
                        artifact_dir / "runtime-dump",
                        dirs_exist_ok=True,
                    )
                supervision_root = sandbox_attempt.watchdog_path.parent
                request_source = sandbox.session_root / "attempt_receipts" / f"attempt-{attempt_number:02d}-requests"
                if request_source.is_dir():
                    shutil.copytree(request_source, artifact_dir / "requests")
                execution_receipt_path = sandbox.session_root / "attempt_receipts" / f"attempt-{attempt_number:02d}.json"
                if execution_receipt_path.is_file():
                    shutil.copy2(execution_receipt_path, artifact_dir / "execution-receipt.json")
                for evidence_source in (
                    supervision_root / "processes.json",
                    supervision_root / "processes-final.json",
                    supervision_root / "cleanup.json",
                    supervision_root / "peer-readiness.json",
                    supervision_root / "child-failures.json",
                    *supervision_root.glob("*-exit.json"),
                    *supervision_root.glob("diagnostics-*.json"),
                    *supervision_root.glob("diagnostics-*.log"),
                ):
                    if evidence_source.is_file() and not evidence_source.is_symlink():
                        copy_file(evidence_source, artifact_dir / evidence_source.name, budget=budget)
                companion_log_paths: list[Path] = []
                for index, source in enumerate(
                    sandbox_attempt.companion_log_paths, start=1,
                ):
                    destination = artifact_dir / f"companion-{index:02d}.log"
                    shutil.copy2(source, destination)
                    companion_log_paths.append(destination)
                trace_context_path = artifact_dir / "runtime_trace_context.json"
                trace_context_error: str | None = "Controller primary runtime_trace.json is unavailable; descendant traces remain separate evidence"
                if trace_path.is_file():
                    try:
                        trace_context_path, _ = persist_runtime_trace_context(
                            trace_path,
                            artifact_dir,
                            view,
                            executed_binary_hashes=staged_binary_hashes,
                        )
                        trace_context_error = None
                    except (OSError, ValueError, json.JSONDecodeError) as error:
                        trace_context_error = str(error)
                # Keep the controller/target/peer/probe relationship as a
                # machine-readable timeline next to the raw trace.  This is
                # deliberately independent of source mapping and remains
                # useful when the guest exits before a trace can be decoded.
                target_lifecycle_path = artifact_dir / "target-lifecycle.json"
                target_lifecycle_path.write_text(
                    json.dumps(
                        {
                            "attempt_number": attempt_number,
                            "started_unix_ns": attempt_started_ns,
                            "finished_unix_ns": attempt_finished_ns,
                            "target": {
                                "binary": recipe.executable_path,
                                "exit_code": sandbox_attempt.container_exit_code,
                                "target_exit_code": sandbox_attempt.target_exit_code,
                            "timed_out": sandbox_attempt.timed_out,
                            "watchdog_triggered": sandbox_attempt.watchdog_triggered,
                            "termination_reason": sandbox_attempt.termination_reason,
                            "rootfs_adaptations": list(sandbox_attempt.rootfs_adaptations),
                            },
                            "companions": [
                                {
                                    "executable": process.executable_path,
                                    "args": process.args,
                                    "log_path": str(path),
                                }
                                for process, path in zip(
                                    decision.companion_processes,
                                    sandbox_attempt.companion_log_paths,
                                )
                            ],
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                probe_timeline_path = artifact_dir / "probe-timeline.json"
                probe_timeline_path.write_text(
                    json.dumps(
                        {
                            "attempt_number": attempt_number,
                            "started_unix_ns": attempt_started_ns,
                            "finished_unix_ns": attempt_finished_ns,
                            "scenario": decision.scenario.model_dump(mode="json") if decision.scenario else None,
                            "result": sandbox_attempt.scenario_result.model_dump(mode="json") if sandbox_attempt.scenario_result else None,
                            "last_probe": sandbox_attempt.probe_result.model_dump(mode="json"),
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
                staged_rootfs = sandbox._active_rootfs
                rootfs_sha256 = _tree_sha256(staged_rootfs, budget) if staged_rootfs and staged_rootfs.is_dir() else None
                target_binary_sha256 = (
                    _file_sha256(staged_rootfs / recipe.executable_path.lstrip("/"))
                    if staged_rootfs and staged_rootfs.is_dir()
                    else None
                )
                harness_sha256 = _tree_sha256(sandbox.bundle_dir, budget) if sandbox.bundle_dir.is_dir() else None
                attempt = RuntimeAttempt(
                    browser_origin=decision.browser_origin,
                    network=decision.network,
                    adaptation_ids=[entry[0].adaptation_id for entry in active_adaptations],
                    experiment=decision.experiment,
                    launch_resolution=launch_resolution,
                    request_revisions=list(request_revisions),
                    tree_identity_version=2,
                    attempt_number=attempt_number,
                    probe=decision.probe,
                    scenario=decision.scenario,
                    scenario_result=sandbox_attempt.scenario_result,
                    guest_args=decision.guest_args,
                    guest_working_directory=decision.guest_working_directory,
                    guest_environment=decision.guest_environment,
                    companion_processes=decision.companion_processes,
                    companion_log_paths=[str(path) for path in companion_log_paths],
                    ipc=decision.ipc,
                    rootfs_actions=decision.rootfs_actions,
                    disabled_unit_ids=decision.disabled_unit_ids,
                    intervention_sha256=(
                        _tree_sha256(intervention_root / "src", budget)
                        if intervention_so is not None
                        else None
                    ),
                    intervention_source_path=(
                        str(source_path) if intervention_so is not None else None
                    ),
                    intervention_binary_path=(
                        str(binary_path) if intervention_so is not None else None
                    ),
                    container_exit_code=sandbox_attempt.container_exit_code,
                    target_exit_code=sandbox_attempt.target_exit_code,
                    timed_out=sandbox_attempt.timed_out,
                    outcome=(
                        "success"
                        if sandbox_attempt.scenario_result is not None
                        and sandbox_attempt.scenario_result.status == "success"
                        else "blocked"
                    ),
                    probe_result=sandbox_attempt.probe_result,
                    runtime_trace_path=str(trace_path),
                    runtime_trace_paths=[str(path) for path in trace_paths],
                    runtime_trace_context_path=str(trace_context_path),
                    container_log_path=str(log_path),
                    runtime_trace_available=trace_path.is_file(),
                    runtime_trace_context_available=trace_context_path.is_file(),
                    runtime_trace_context_error=trace_context_error,
                    runtime_dump_manifest_path=(
                        str(artifact_dir / "runtime-dump" / "manifest.json")
                        if (artifact_dir / "runtime-dump" / "manifest.json").is_file()
                        else None
                    ),
                    runtime_dump_capture_kind=sandbox_attempt.runtime_dump_capture_kind,
                    runtime_dump_available=sandbox_attempt.runtime_dump_available,
                    runtime_trace_heartbeat_paths=[str(path) for path in heartbeat_paths],
                    watchdog_path=(str(watchdog_path) if watchdog_path.is_file() else None),
                    watchdog_triggered=sandbox_attempt.watchdog_triggered,
                    termination_reason=sandbox_attempt.termination_reason,
                    rootfs_sha256=rootfs_sha256,
                    rootfs_adaptations=list(sandbox_attempt.rootfs_adaptations),
                    target_binary_sha256=target_binary_sha256,
                    harness_sha256=harness_sha256,
                    target_lifecycle_path=str(target_lifecycle_path),
                    probe_timeline_path=str(probe_timeline_path),
                    agent_summary=decision.summary,
                )
                attempt_json = artifact_dir / "attempt.json"
                write_model_json(attempt_json, attempt)
                attempt = load_model_json(attempt_json, RuntimeAttempt)
                dump_manifest = artifact_dir / "runtime-dump" / "manifest.json"
                if dump_manifest.is_file():
                    dump_payload = json.loads(dump_manifest.read_text(encoding="utf-8"))
                    dump_payload["execution_identity_version"] = attempt.tree_identity_version
                    dump_payload["execution_hashes"] = {
                        name: getattr(attempt, name)
                        for name in ("intervention_sha256", "rootfs_sha256", "target_binary_sha256", "harness_sha256")
                    }
                    dump_manifest.write_text(
                        json.dumps(dump_payload, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8",
                    )
                attempts.append(attempt)
                journal.execution("guest", status="completed", attempt_number=attempt_number,
                    attempt_path=str(attempt_json), termination_reason=attempt.termination_reason,
                    outcome=attempt.outcome)
                feedback = collect_runtime_feedback(attempt, attempt_json, session_id=receipt.session_id,
                    previous_attempt=attempts[-2] if len(attempts) > 1 else None)
                write_model_json(artifact_dir / "feedback.json", feedback)
                feedback_text = render_runtime_feedback(feedback)
                (artifact_dir / "feedback.txt").write_text(feedback_text, encoding="utf-8")
                evidence_state.attempt_json = attempt_json
                evidence_state.emulator_harness = sandbox.harness_path
                evidence_state.emulator_harness_sha256 = (
                    _file_sha256(sandbox.bundle_dir / sandbox.harness_path.name)
                    if sandbox.harness_path is not None else None
                )
                evidence_state.trace_json = (
                    trace_path if trace_path.is_file() else None
                )
                evidence_state.trace_context_json = (
                    trace_context_path if trace_context_path.is_file() else None
                )
                evidence_state.trace_context_error = trace_context_error
                evidence_state.container_log = log_path
                evidence_state.companion_logs = companion_log_paths
                evidence_state.watchdog_json = (
                    watchdog_path if watchdog_path.is_file() else None
                )
                evidence_state.runtime_dump_manifest = (
                    Path(attempt.runtime_dump_manifest_path)
                    if attempt.runtime_dump_manifest_path
                    else None
                )
                if decision.browser_origin:
                    try:
                        native = await budget.run_sync(live_client.start, decision.browser_origin)
                    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
                        native = f"Native browser startup failed: {type(error).__name__}: {error}"
                    decision = await invoke_guarded(
                        "Service goal: " + service_goal
                        + "\n\nThe candidate was started for direct browser interaction. No protocol scenario was executed. "
                        "Use native_browser to inspect the actual page and perform major operations. Repair source/launch/resources "
                        "when needed, or start a fresh native client for final verification. You decide when to complete, with "
                        "current attempt identity and client_receipt. Do not write a redundant protocol test just to complete.\n"
                        + native + "\n" + feedback_text)
                elif (
                    attempt.scenario_result is not None
                    and attempt.scenario_result.status == "success"
                ):
                    mark_revision("scenario_passed")
                    decision = await invoke_guarded(
                        "Service goal: " + service_goal
                        + f"\n\nRuntime attempt {attempt_number} passed the submitted scenario. This is feedback, "
                        "not automatic task completion or publication. Assess whether these executed checks "
                        "cover the representative major operations and required state continuity under the "
                        "Service Interact contract. You own test selection and service semantics. Preserve "
                        "the business goal and failure history; revise mistaken tests and add missing checks. Use "
                        "start_native_client and native_browser for actual client interactions and fresh-instance acceptance; "
                        "repair from actual failures. If required behavior remains unverified, continue "
                        "investigation, native interaction and repair. If the service goal is "
                        "satisfied, return complete without changes, with coverage, limitations, client_receipt and the "
                        "latest attempt identity below. Controller checks evidence identity, not business coverage.\n"
                        + f"attempt_number={attempt_number}\nattempt_sha256={_file_sha256(attempt_json)}\n"
                        + feedback_text
                    )
                else:
                    mark_revision(
                        "runtime_failed",
                        attempt.scenario_result.error if attempt.scenario_result else None,
                    )
                    decision = await invoke_guarded(
                "Service goal: " + service_goal + "\n\n"
                +                         f"Runtime attempt {attempt_number} failed or could not decide the "
                        "Interaction Scenario. Inspect the bounded runtime evidence and container "
                        "log with the supplied tools. Compare the expected and actual step results, "
                        "verified Cookie continuity, changed inputs and child-failure evidence. "
                        "For a diagnostic retry, record an experiment: the evidence-backed hypothesis, "
                        "the variable or observation being tested, predicted observations and preserved "
                        "behavior. Treat unknown state as unknown; a configuration delta is not an "
                        "observed guest state change. Then use edit_unit or edit_workspace "
                        "for a proven existing owner, run without source edits, or continue investigating. If the failure "
                        "needs a new owner or Contract, submit propose_unit with source-bound failed-attempt "
                        "evidence before editing. Admission preserves the original Plan and uses this same "
                        "Agent session. An unknown root cause is a reason to investigate while useful tools "
                        "or discriminating experiments remain. Request input only for a specific external "
                        "input or capability you cannot obtain in the available environment; retain the unfinished goal.\n\n"
                        + feedback_text
                    )
            refresh_environment_preparation()
            result = RehostingResult(
                target_binary=target,
                guest_arch=generation.arch,
                selected_recipe_id=recipe.recipe_id if recipe is not None else None,
                launch_resolution=launch_resolution,
                status=status,
                completion=completion,
                input_request=decision.input_request if status == "waiting_for_input" else None,
                stop_reason=("external_input_required" if status == "waiting_for_input" else
                             "attempt_limit_reached" if status == "attempts_exhausted" else None),
                success_configuration_path=str(success_configuration_path) if status == "success" else None,
                environment_preparation=environment_preparation,
                attempts=attempts,
                decision_history=decision_history,
                revision_history=revision_history,
                adaptation_history=adaptation_history,
                final_summary=final_summary,
                specification_gap=current_specification_gap(),
                generation_baseline_id=(baseline.baseline_id if baseline else None),
                generation_baseline_path=(str(baseline.root) if baseline else None),
            )
            return persist_result(reports_root, result)
        except asyncio.CancelledError:
            budget.cancelled.set()
            refresh_environment_preparation()
            persist_result(reports_root, RehostingResult(
                target_binary=target, guest_arch=generation.arch,
                selected_recipe_id=recipe.recipe_id if recipe is not None else None,
                launch_resolution=launch_resolution, status="stopped", stop_reason="user_cancelled",
                session_receipt_path=str(receipt_path), environment_preparation=environment_preparation,
                attempts=attempts, decision_history=decision_history, revision_history=revision_history,
                adaptation_history=adaptation_history,
                final_summary="Controller cancelled; incomplete attempt evidence is in the session receipt.",
                generation_baseline_id=baseline.baseline_id, generation_baseline_path=str(baseline.root),
            ))
            receipt.result_path = str(reports_root / "runner_reports/rehosting_result.json")
            raise
        except (
            RunnerStopped,
            AgentProviderError,
            AgentTurnTimeoutError,
            RuntimeError,
            ValueError,
            OSError,
            subprocess.SubprocessError,
        ) as error:
            refresh_environment_preparation()
            if sandbox.environment_script_failure is not None:
                mark_revision("prepare_failed", sandbox.environment_script_failure)
            final_summary = (
                error.official_message
                if isinstance(error, AgentProviderError)
                else str(error)
            )
            result = RehostingResult(
                target_binary=target,
                guest_arch=generation.arch,
                selected_recipe_id=recipe.recipe_id if recipe is not None else None,
                launch_resolution=launch_resolution,
                status="stopped" if isinstance(error, RunnerStopped) else "error",
                stop_reason=error.reason if isinstance(error, RunnerStopped) else (
                    error.code if isinstance(error, (AgentProviderError, AgentTurnTimeoutError)) else "execution_error"
                ),
                environment_preparation=environment_preparation,
                attempts=attempts,
                decision_history=decision_history,
                revision_history=revision_history,
                adaptation_history=adaptation_history,
                final_summary=final_summary,
                specification_gap=(
                    next(
                        (
                            attempt.scenario_result.error
                            for attempt in reversed(attempts)
                            if attempt.scenario_result is not None
                            and attempt.scenario_result.status == "specification_gap"
                        ),
                        None,
                    )
                ),
                generation_baseline_id=(baseline.baseline_id if baseline else None),
                generation_baseline_path=(str(baseline.root) if baseline else None),
            )
            return persist_result(reports_root, result)
        finally:
            receipt.phase = "cleanup"
            try:
                try:
                    await asyncio.to_thread(live_client.stop)
                finally:
                    await asyncio.to_thread(sandbox.close)
            finally:
                receipt.cleanup_records.extend(sandbox.cleanup_records)
                receipt.cleanup_records.extend(runtime_builder.cleanup_records)
                try:
                    await asyncio.wait_for(agent.aclose(), timeout=budget.limit(10, cleanup=True))
                except (RunnerStopped, asyncio.TimeoutError) as error:
                    receipt.cleanup_records.append({"operation": "agent_close", "error": str(error)})

    @staticmethod
    def _validate_decision(
        decision: RunnerDecision,
        editable_unit_ids: set[str],
        rootfs: Path,
    ) -> None:
        if decision.action not in {"continue", "request_input", "complete"}:
            validate_request_representation(decision.scenario)
        if decision.action in {"complete", "continue", "request_input"} and (
            decision.rootfs_actions or decision.disabled_unit_ids or decision.companion_processes
            or decision.guest_args or decision.guest_environment or decision.guest_working_directory != "/"
            or decision.browser_origin or decision.launch_proposal or decision.cookie_continuity_reason or decision.request_representation_reason
            or decision.scenario_resolution_reason or decision.experiment
            or decision.network != RuntimeNetwork()
            or decision.ipc.strategy != "none"
        ):
            raise RuntimeError("Non-executing decisions reference the current candidate; omit new execution configuration")
        unknown = (
            set(decision.changed_unit_ids)
            | set(decision.disabled_unit_ids)
        ) - editable_unit_ids
        if unknown:
            raise RuntimeError(
                "RunnerAgent referenced unknown Intervention Units: "
                + ", ".join(sorted(unknown))
            )
        decision.rootfs_actions = normalize_rootfs_actions(
            decision.rootfs_actions,
            rootfs,
            # Environment setup is applied later to a fresh staged copy and
            # may create a source used by a Runner action.  Defer the
            # existence check until DockerRootfsSandbox applies the actions.
            require_sources=False,
        )
        for process in decision.companion_processes:
            candidate = (rootfs / process.executable_path.lstrip("/")).resolve()
            try:
                candidate.relative_to(rootfs.resolve())
            except ValueError as error:
                raise RuntimeError(
                    "companion executable escapes the firmware rootfs: "
                    f"{process.executable_path}"
                ) from error
            if not candidate.is_file():
                raise RuntimeError(
                    "companion executable is not a firmware ELF: "
                    f"{process.executable_path}"
                )
            with candidate.open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    raise RuntimeError(
                        "companion executable is not a firmware ELF: "
                        f"{process.executable_path}"
                    )


__all__ = ["RehostingRunner"]
