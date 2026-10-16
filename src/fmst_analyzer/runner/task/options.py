"""Explicit options read before starting a task, separate from result schemas."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ContainerResources(BaseModel):
    """Optional Docker limits selected by the caller, without host admission policy."""
    model_config = ConfigDict(extra="forbid")
    memory_bytes: int | None = Field(default=None, gt=0, strict=True, description="Docker memory limit in bytes; omitted leaves the engine default.")
    memory_swap_bytes: int | None = Field(default=None, gt=0, strict=True, description="Docker total memory plus swap limit; equal to memory_bytes disables swap.")
    cpus: float | None = Field(default=None, gt=0, allow_inf_nan=False, description="Docker CPU quota, for example 0.5 or 2; omitted leaves the engine default.")
    pids_limit: int | None = Field(default=None, gt=0, strict=True, description="Optional container process limit.")
    shm_bytes: int | None = Field(default=None, gt=0, strict=True, description="Optional /dev/shm size for native browser tools.")

    @model_validator(mode="after")
    def check_swap(self):
        if self.memory_swap_bytes is not None and (
            self.memory_bytes is None or self.memory_swap_bytes < self.memory_bytes
        ):
            raise ValueError("memory_swap_bytes requires memory_bytes and cannot be smaller")
        return self

    def docker_arguments(self, engine_info: dict) -> list[str]:
        arguments = []
        for name, option, capability in (
            ("memory_bytes", "--memory", "MemoryLimit"),
            ("memory_swap_bytes", "--memory-swap", "SwapLimit"),
            ("cpus", "--cpus", "CpuCfsQuota"),
            ("pids_limit", "--pids-limit", "PidsLimit"),
            ("shm_bytes", "--shm-size", None),
        ):
            value = getattr(self, name)
            if value is None:
                continue
            if capability and not engine_info.get(capability):
                raise RuntimeError(f"Docker does not support requested limit {option}")
            arguments.extend([option, str(value)])
        return arguments


class RunnerOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    delivery_mode: Literal["full", "rehosting_only"] = Field(
        default="full", description="full collects a post-Goal handoff and captures a delivery image; rehosting_only retains native completion, evidence, service and session without packaging.")
    resources: ContainerResources | None = Field(default=None, description="Optional caller-selected container limits. Firmware concurrency and host disk/memory reserves belong to the external batch launcher.")
