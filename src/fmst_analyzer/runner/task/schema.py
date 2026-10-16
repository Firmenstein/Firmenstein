"""Versioned service results with independent Agent, handoff and package status."""
import json
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class Interaction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation: str = Field(min_length=1, description="Native user operation actually performed.")
    observed: str = Field(min_length=1, description="Observed business result, including state readback where relevant.")
    evidence: list[str] = Field(min_length=1, description="Absolute files under /task/evidence supporting this observation.")


class ServiceCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, description="Service goal achieved on this running experimental instance.")
    native_url: str = Field(min_length=1, description="Native service URL used for interaction, including original hostname and port.")
    service_pid: int = Field(gt=1, description="Live service or namespace supervisor PID in the task container PID namespace.")
    service_start_ticks: int = Field(gt=0, description="Field 22 of /proc/PID/stat, to bind the running instance.")
    interactions: list[Interaction] = Field(min_length=1, description="Representative native business operations actually verified; choose coverage from the service goal.")
    access: str = Field(min_length=1, description="How the user reaches this same service, including browser/proxy commands if needed. No model credentials.")
    limitations: list[str] = Field(default_factory=list, description="Known limitations; unverified restart or migration behavior stays explicit.")


class TaskResultV1(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    backend: Literal["agent_container"] = "agent_container"
    task_id: str
    target: str
    container_id: str | None = None
    status: Literal["preparing", "repairing", "serving", "budget_exhausted", "resource_stopped", "cancelled", "error", "stopped"]
    started_at: float
    finished_at: float | None = None
    reason: str = ""
    completion: ServiceCompletion | None = None
    socks_proxy: str | None = None
    archive: str | None = None
    container_removed: bool = False
    cleanup_error: str | None = None
    independent_replay: Literal[False] = False
    report_dir: str


class TaskResult(TaskResultV1):
    schema_version: Literal[2] = 2
    agent_phase: Literal["not_started", "repairing", "handoff", "exited"] = "not_started"
    handoff_status: Literal["not_started", "collecting", "ready", "invalid", "timeout", "error", "interrupted"] = "not_started"
    package_status: Literal["not_started", "capturing", "ready", "incomplete", "error"] = "not_started"
    package_path: str | None = None
    package_error: str | None = None
    session_volume: str | None = None


def read_result(text: str) -> TaskResult | TaskResultV1:
    """Read old receipts explicitly, without inventing handoff or package facts."""
    value = json.loads(text)
    if value.get("schema_version") == 1:
        return TaskResultV1.model_validate(value)
    if value.get("schema_version") != 2:
        raise ValueError("Unsupported Runner result schema_version")
    return TaskResult.model_validate(value)
