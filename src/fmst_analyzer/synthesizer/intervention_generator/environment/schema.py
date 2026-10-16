"""Persisted status for static Environment Agent generation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EnvironmentGenerationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["not_needed", "completed", "failed", "unable"] = "not_needed"
    unit_ids: list[str] = Field(default_factory=list)
    script_path: str | None = Field(default=None, description="Candidate script, including invalid or incomplete scripts when status=failed; never evidence of readiness by itself.")
    failure_code: str | None = Field(default=None, description="Original provider, structured-output or static-check failure category; retained even when a usable candidate exists.")
    trace_path: str | None = Field(default=None, description="Full Environment Agent trajectory, including failure evidence.")
    reason: str = "No environment_setup Units were supplied."


__all__ = [
    "EnvironmentGenerationResult",
]
