"""Preserve attempts without cascading deletion into independent stages.

Current reports remain the sole consumer entry point. History is evidence, not
a fallback cache. Consumers validate input digests instead of inferring freshness
from the presence or absence of neighboring directories.
"""
from __future__ import annotations

from datetime import datetime, timezone
from contextlib import contextmanager
from enum import Enum
from functools import wraps
import hashlib
import inspect
import json
from pathlib import Path
import re
import shutil
from typing import Any, Literal
import uuid

from .execution import diagnostic_reason, execution_snapshot
from .report_io import write_text

PipelineStage = Literal["ipc", "file", "network", "process", "init_launch", "catalog", "plan", "generation", "runner"]

_REPORT_DIR = {
    "ipc": "ipc_reports", "file": "file_reports", "network": "network_reports",
    "process": "process_lifecycle_reports", "init_launch": "init_launch_reports",
    "plan": "intervention_plan_reports", "generation": "intervention_generation_reports",
    "runner": "runner_reports",
    "catalog": "intervention_planner_inputs",
}
_TRACE_DIR = {
    "ipc": "ipc", "file": "file_resolver", "network": "network_analyzer",
    "process": "process_lifecycle", "init_launch": "init_launch",
    "plan": "intervention_plan", "generation": "intervention_generator", "runner": "runner",
    "catalog": "intervention_catalog",
}


def _managed_paths(config: Any, stage: PipelineStage) -> dict[str, Path]:
    if stage not in _REPORT_DIR:
        raise ValueError(f"unknown pipeline stage: {stage}")
    if not hasattr(config, "target_diagnostic_reports_dir"):
        return {}
    reports = Path(config.target_diagnostic_reports_dir())
    paths = {"reports": reports / _REPORT_DIR[stage]}
    if hasattr(config, "target_agent_debug_dir"):
        paths["traces"] = Path(config.target_agent_debug_dir()) / _TRACE_DIR[stage]
    if stage == "plan":
        paths["catalog"] = reports / "intervention_planner_inputs"
    workdir = getattr(config, "workdir", None)
    target = str(getattr(config, "current_target", None) or reports.name)
    if workdir is not None and stage == "generation":
        for name in ("interventions", "test_harnesses", "env_scripts", "intervention_baselines"):
            paths[name] = Path(workdir) / name / target
    if workdir is not None and stage == "runner":
        paths["workspace"] = Path(workdir) / "runner_workspaces" / target
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", target).strip("-._") or "target"
        paths["session"] = Path(workdir) / "runner_sessions" / slug
    return paths


def _manifest(root: Path) -> dict[str, str]:
    files = {}
    if root.exists():
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                files[path.relative_to(root).as_posix()] = "symlink:" + str(path.readlink())
            elif path.is_file():
                files[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return files


def _setting_value(value):
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    return value


def archive_stage_outputs(config: Any, stage: PipelineStage) -> Path | None:
    """Move only this stage's current artifacts into a new immutable attempt."""
    paths = _managed_paths(config, stage)
    if not paths:
        return None
    root = Path(config.target_diagnostic_reports_dir())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    attempt = root / ".attempts" / stage / f"{stamp}-{uuid.uuid4().hex}"
    attempt.mkdir(parents=True)
    previous = attempt / "previous"
    for name, path in paths.items():
        if path.exists() or path.is_symlink():
            previous.mkdir(exist_ok=True)
            path.rename(previous / name)
    write_text(attempt / "previous_manifest.json", json.dumps(_manifest(previous), indent=2) + "\n")
    return attempt


def preserve_stage_attempt(stage: PipelineStage):
    """Retain input identities, results and traces on success or failure."""
    def decorate(function):
        @wraps(function)
        async def wrapped(self, *args, **kwargs):
            config = self.global_config
            arguments = inspect.signature(function).bind(self, *args, **kwargs)
            arguments.apply_defaults()
            values = arguments.arguments
            view = values.get("view")
            target_path = values.get("target_binary_path") or getattr(getattr(view, "root", None), "binary_path", None)
            with stage_attempt(config, stage, phase=values.get("phase"), target_path=target_path) as metadata:
                from .input_provenance import ANALYZER_FILES, analysis_input_scope, capture_inputs, publish_receipt
                inputs = None
                if stage in ANALYZER_FILES and target_path is not None and getattr(config, "fw_rootfs_path", None) is not None:
                    inputs = capture_inputs(config, stage, values["phase"], target_path)
                    metadata["analysis_inputs"] = inputs.model_dump(mode="json")
                    if metadata.get("attempt_path"):
                        write_text(Path(metadata["attempt_path"]) / "attempt.json", json.dumps(metadata, indent=2) + "\n")
                from .task_recovery import task_recovery_scope
                with analysis_input_scope(inputs), task_recovery_scope(config, metadata):
                    result = await function(self, *args, **kwargs)
                execution = getattr(result, "execution", execution_snapshot())
                metadata.update(status=execution.status, execution=execution.model_dump(mode="json"))
                if inputs is not None and config.workdir is not None and execution.status == "complete":
                    current = capture_inputs(config, stage, values["phase"], target_path)
                    if current != inputs:
                        raise ValueError("Analyzer inputs changed during execution; publication cannot satisfy a cache request")
                    publish_receipt(Path(config.target_diagnostic_reports_dir()) / ANALYZER_FILES[stage], result, inputs)
                if stage == "plan":
                    catalog = result[0]
                    metadata["consumed_artifacts"] = {
                        key.value: artifact.model_dump(mode="json") for key, artifact in catalog.source_artifacts.items()
                    }
                return result
        return wrapped
    return decorate


@contextmanager
def stage_attempt(config, stage: PipelineStage, *, phase=None, target_path=None):
    """Shared sync/async attempt publication boundary, including early failures."""
    available = {}
    if hasattr(config, "target_diagnostic_reports_dir"):
        root = Path(config.target_diagnostic_reports_dir())
        for directory in _REPORT_DIR.values():
            for path in sorted((root / directory).glob("*.json")):
                available[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    target = None
    if target_path is not None:
        path = Path(target_path)
        target = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None}
    metadata = {
        "stage": stage, "started_at": datetime.now(timezone.utc).isoformat(), "status": "running",
        "phase": phase, "target": target, "available_source_digests": available,
        "settings": {key: _setting_value(getattr(config, key, None)) for key in (
            "agent_provider", "diagnosis_model", "synthesizer_model", "agent_concurrency_limit",
            "planner_model", "planner_reasoning_effort", "rehosting_goal",
            "file_resolver_scope", "file_resolver_normal_fs_ext_allowlist",
        )},
    }
    # Validate serializability before moving any existing current artifacts.
    encoded = json.dumps(metadata, indent=2) + "\n"
    attempt = archive_stage_outputs(config, stage)
    if attempt is not None:
        metadata["attempt_path"] = str(attempt)
        write_text(attempt / "attempt.json", encoded)
    try:
        yield metadata
        if metadata["status"] == "running":
            metadata["status"] = "complete"
    except BaseException as error:
        metadata.update(status="failed", failure=diagnostic_reason(error),
                        execution=execution_snapshot().model_dump(mode="json"))
        raise
    finally:
        if attempt is not None:
            artifacts = attempt / "artifacts"
            artifacts.mkdir()
            for name, path in _managed_paths(config, stage).items():
                if (stage in {"ipc", "file", "network", "process", "init_launch"}
                        and name == "reports" and metadata["status"] != "complete"
                        and path.exists()):
                    # Incomplete reports remain diagnostic evidence, never a current source.
                    path.rename(artifacts / name)
                elif path.is_dir() and not path.is_symlink():
                    shutil.copytree(path, artifacts / name, symlinks=True)
                elif path.exists() or path.is_symlink():
                    shutil.copy2(path, artifacts / name, follow_symlinks=False)
            metadata.update(finished_at=datetime.now(timezone.utc).isoformat(), artifacts=_manifest(artifacts))
            write_text(attempt / "attempt.json", json.dumps(metadata, indent=2) + "\n")


__all__ = ["PipelineStage", "archive_stage_outputs", "preserve_stage_attempt", "stage_attempt"]
