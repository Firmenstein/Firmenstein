"""Portable input receipts for Analyzer publication and cache validation.

The Result is the only semantic source. This receipt binds those exact bytes to
the inputs of one attempt; it never supplies or repairs analysis facts.
"""
from __future__ import annotations

import hashlib
import json
import stat
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .report_io import load_model_json, model_content_sha256, write_model_json, write_text


ANALYZER_FILES = {
    "file": "file_reports/file_resolver_result.json",
    "network": "network_reports/network_analysis_result.json",
    "process": "process_lifecycle_reports/process_lifecycle_analysis_result.json",
    "ipc": "ipc_reports/ipc_analysis_result.json",
    "init_launch": "init_launch_reports/init_launch_analysis_result.json",
}
_MODULES = {"file": "file_resolver", "network": "network_analyzer", "process": "process_lifecycle",
            "ipc": "ipc_analyzer", "init_launch": "init_launch"}
_active_inputs = ContextVar("analyzer_inputs", default=None)


@contextmanager
def analysis_input_scope(inputs):
    token = _active_inputs.set(inputs)
    try:
        yield
    finally:
        _active_inputs.reset(token)


def active_input_digest() -> str | None:
    inputs = _active_inputs.get()
    return model_content_sha256(inputs) if inputs is not None else None


def active_analysis_inputs() -> AnalysisInputs | None:
    return _active_inputs.get()


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rootfs_digest(rootfs: Path) -> str:
    """Hash source bytes, guest names, types and permissions, never symlink targets on host."""
    entries = []
    for path in sorted(rootfs.rglob("*")):
        info = path.lstat()
        value = (str(path.readlink()) if stat.S_ISLNK(info.st_mode) else
                 file_digest(path) if stat.S_ISREG(info.st_mode) else None)
        entries.append((path.relative_to(rootfs).as_posix(), info.st_mode, value))
    return _digest(entries)


def implementation_digest(stage: str) -> str:
    source = Path(__file__).resolve().parents[3]
    directories = [source / "fmst_analyzer" / part for part in
                   ("analysis/base", "analysis/" + _MODULES[stage], "nodes", "graphs")]
    directories += [source / "fmst_basic" / part for part in ("agent", "utils")]
    paths = {source / "fmst_analyzer/global_config.py"}
    for directory in directories:
        paths.update(path for path in directory.rglob("*.py") if "tests" not in path.parts)
    return _digest([(path.relative_to(source).as_posix(), file_digest(path)) for path in sorted(paths)])


class AnalysisInputs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage: Literal["file", "network", "process", "ipc", "init_launch"]
    phase: Literal["static", "full"]
    target_path: str
    target_sha256: str
    rootfs_sha256: str
    implementation_sha256: str
    settings: dict


class AnalysisReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    inputs: AnalysisInputs
    result_sha256: str
    result_content_sha256: str
    execution_status: Literal["complete", "partial", "failed"]


def capture_inputs(config, stage: str, phase: str, target_path: Path, *, rootfs: Path | None = None) -> AnalysisInputs:
    rootfs = Path(rootfs or config.fw_rootfs_path).resolve()
    target_path = Path(target_path).resolve()
    settings = {}
    for key in ("agent_provider", "diagnosis_model", "agent_concurrency_limit", "DEFAULT_LIB",
                "file_resolver_scope", "file_resolver_normal_fs_ext_allowlist", "file_resolver_resource_chunk_size"):
        value = getattr(config, key, None)
        settings[key] = sorted(value) if isinstance(value, (set, frozenset)) else value
    if settings["agent_provider"] == "codex":
        from fmst_basic.agent.config import configured_codex_model_provider, configured_codex_reasoning_effort
        settings.update(model_provider=configured_codex_model_provider(), reasoning_effort=configured_codex_reasoning_effort())
    elif settings["agent_provider"] == "claude":
        from fmst_basic.agent.config import configured_claude_base_url, configured_claude_model, configured_claude_reasoning_effort
        from importlib.metadata import version
        settings.update(base_url=configured_claude_base_url(), mapped_model=configured_claude_model(),
                        reasoning_effort=configured_claude_reasoning_effort(), sdk_version=version("claude-agent-sdk"))
    return AnalysisInputs(stage=stage, phase=phase, target_path=target_path.relative_to(rootfs).as_posix(),
        target_sha256=file_digest(target_path), rootfs_sha256=rootfs_digest(rootfs),
        implementation_sha256=implementation_digest(stage), settings=settings)


def publish_receipt(result_path: Path, result: BaseModel, inputs: AnalysisInputs) -> AnalysisReceipt:
    result.execution.require_complete()
    receipt = AnalysisReceipt(inputs=inputs, result_sha256=file_digest(result_path),
        result_content_sha256=model_content_sha256(result), execution_status=result.execution.status)
    write_model_json(result_path.parent / "input_provenance.json", receipt)
    write_text(result_path.parent / "input_provenance.md", render_receipt(receipt))
    return receipt


def render_receipt(receipt: AnalysisReceipt) -> str:
    from .finding_reports import render_fields
    return "# Analyzer Input Provenance\n\n" + render_fields(receipt.model_dump(mode="json"))


def require_receipt(result_path: Path, *, expected_inputs: AnalysisInputs | None = None,
                    result: BaseModel | None = None) -> AnalysisReceipt:
    receipt = load_model_json(result_path.parent / "input_provenance.json", AnalysisReceipt)
    if receipt.result_sha256 != file_digest(result_path):
        raise ValueError(f"Analyzer publication digest mismatch: {result_path}")
    if receipt.execution_status != "complete":
        raise ValueError(f"Analyzer publication is {receipt.execution_status}: {result_path}")
    if expected_inputs is not None and receipt.inputs != expected_inputs:
        raise ValueError(f"Analyzer input provenance is stale: {result_path}")
    if result is not None:
        result.execution.require_complete()
    if result is not None and receipt.result_content_sha256 != model_content_sha256(result):
        raise ValueError(f"In-memory Analyzer content differs from published receipt: {result_path}")
    return receipt


def cache_matches_inputs(config, stage, phase, target_path, result, *, rootfs=None) -> bool:
    if getattr(config, "workdir", None) is None:
        return False
    try:
        expected = capture_inputs(config, stage, phase, target_path, rootfs=rootfs)
        require_receipt(Path(config.target_diagnostic_reports_dir()) / ANALYZER_FILES[stage],
                        expected_inputs=expected, result=result)
    except (OSError, ValueError, TypeError):
        return False
    return True
