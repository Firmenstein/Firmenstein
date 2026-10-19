"""Explicit repair input when upstream analysis cannot publish a full Plan.

This does not certify partial Analyzer output, relax its cache contract, or
start a second Runner. It binds a valid guest input and preserves the failure.
"""
from __future__ import annotations

import errno
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from fmst_basic.agent.analysis_agent import AgentProviderError
from fmst_basic.FirmProbe.admission import inspect_target_input
from fmst_basic.utils.guest_paths import resolve_guest_file
from fmst_analyzer.analysis.base.execution import diagnostic_reason, exception_chain
from fmst_analyzer.analysis.base.input_provenance import file_digest
from fmst_analyzer.analysis.base.report_io import write_model_json


RESOURCE_ERRNOS = {errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOSPC}


def blocks_new_runner(error: BaseException) -> bool:
    """Do not work around provider/resource/cancellation stops by dispatching.

    An AgentProviderError identifies a failed boundary, not a remote root cause.
    """
    for item in exception_chain(error):
        if isinstance(item, AgentProviderError) or not isinstance(item, Exception):
            return True
        if isinstance(item, OSError) and item.errno in RESOURCE_ERRNOS:
            return True
        execution = getattr(item, "execution", None)
        if execution is not None and any(
            task.failure and (task.failure.kind in {"provider", "cancelled"}
                              or task.failure.errno in RESOURCE_ERRNOS)
            for task in execution.tasks.values()
        ):
            return True
    return False


class FailureCause(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error_type: str
    reason: str
    code: str | None = None
    errno: int | None = None
    tool_diagnostic: dict | None = None
    notes: list[str] = Field(default_factory=list)


class UpstreamRepairInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    target_path: str = Field(description="Selected regular ELF, relative to the original guest rootfs.")
    target_sha256: str
    rootfs_sha256: str
    failed_stage: str
    causes: list[FailureCause] = Field(min_length=1)
    execution: dict | None = Field(default=None, description="Original unsuccessful task ledger; never semantic findings.")
    dispatch_blocked: bool = False
    generator_materials_current: bool = Field(default=False, description="This attempt archived old Generation artifacts and began authoring fresh candidate material.")

    @field_validator("target_path")
    @classmethod
    def guest_relative_path(cls, value):
        path = PurePosixPath(value)
        if not value or path.is_absolute() or ".." in path.parts or "\x00" in value:
            raise ValueError("Repair target must be a rootfs-relative guest path")
        return path.as_posix()

    @classmethod
    def capture(cls, *, error, stage, rootfs, target):
        from .identity import tree_sha256
        admission = inspect_target_input(rootfs, target)
        resolution = resolve_guest_file(Path(rootfs), admission.resolved_path)
        if resolution is None:
            raise ValueError("Repair target no longer exists inside guest rootfs")
        chain = list(exception_chain(error))
        execution = next((item.execution for item in chain if getattr(item, "execution", None) is not None), None)
        return cls(target_path=admission.resolved_path, target_sha256=file_digest(resolution[1]),
                   rootfs_sha256=tree_sha256(Path(rootfs)), failed_stage=stage,
                   causes=[FailureCause(error_type=type(item).__name__, reason=diagnostic_reason(item),
                                        code=getattr(item, "code", None), errno=getattr(item, "errno", None),
                                        tool_diagnostic=getattr(item, "tool_diagnostic", None),
                                        notes=[diagnostic_reason(RuntimeError(note)) for note in getattr(item, "__notes__", [])])
                           for item in chain],
                   execution=execution.model_dump(mode="json") if execution is not None else None,
                   dispatch_blocked=blocks_new_runner(error))

    def validate_source(self, rootfs: Path) -> Path:
        from .identity import tree_sha256
        if self.dispatch_blocked:
            raise ValueError("Upstream provider/resource stop prohibits a new Runner")
        admission = inspect_target_input(rootfs, self.target_path)
        resolution = resolve_guest_file(rootfs, admission.resolved_path)
        if (resolution is None or admission.resolved_path != self.target_path
                or file_digest(resolution[1]) != self.target_sha256
                or tree_sha256(rootfs) != self.rootfs_sha256):
            raise ValueError("Repair input target/rootfs identity changed")
        return resolution[1]


def persist_repair_input(reports: Path, repair_input: UpstreamRepairInput) -> Path:
    path = reports / "upstream_repair_input.json"
    write_model_json(path, repair_input)
    return path


def persist_pipeline_failure(reports: Path, error: BaseException, stage: str) -> None:
    """Save a small failure record before Runner handoff or dispatcher cleanup."""
    from .task.common import write_json
    chain = list(exception_chain(error))
    execution = next((item.execution for item in chain if getattr(item, "execution", None) is not None), None)
    write_json(reports / "pipeline_failure.json", {
        "schema_version": 1, "failed_stage": stage, "dispatch_blocked": blocks_new_runner(error),
        "causes": [FailureCause(error_type=type(item).__name__, reason=diagnostic_reason(item),
                                code=getattr(item, "code", None), errno=getattr(item, "errno", None),
                                tool_diagnostic=getattr(item, "tool_diagnostic", None),
                                notes=[diagnostic_reason(RuntimeError(note)) for note in getattr(item, "__notes__", [])]).model_dump(mode="json")
                   for item in chain],
        "execution": execution.model_dump(mode="json") if execution is not None else None,
    })
