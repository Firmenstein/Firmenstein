"""Execution accounting, distinct from firmware semantic uncertainty.

Each analyzer owns one ledger. Failed tasks return no semantic result; siblings
already in flight may finish. A provider failure closes the dispatch gate for
subsequent requests in that analyzer without discarding successful observations.
"""
from __future__ import annotations

from contextvars import ContextVar
import asyncio
from functools import wraps
import re
from typing import Awaitable, Callable, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError, computed_field, model_validator

from .output_validation import OutputValidationError

from fmst_basic.agent.analysis_agent import AgentProviderError, AgentTurnTimeoutError, AgentToolStepLimitError

T = TypeVar("T")


def diagnostic_reason(error: BaseException) -> str:
    """Preserve diagnostic text while removing recognizable credentials."""
    text = f"{type(error).__name__}: {error}"
    text = re.sub(r"(?i)(bearer\s+)[^\s\"',;]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:api[_-]?key|authorization|access_token)[\"']?\s*[=:]\s*[\"']?)[^\s\"',;&]+", r"\1[REDACTED]", text)
    return re.sub(r"\bsk-[A-Za-z0-9_-]{12,}\b", "[REDACTED]", text)


class TaskFailure(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["provider", "timeout", "limit", "invalid_output", "tool", "internal", "not_started", "cancelled"]
    reason: str = Field(min_length=1, description="Execution diagnostic, never a claim about firmware semantics.")
    provider: str | None = None
    code: str | None = None


class TaskOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject_id: str = Field(min_length=1, description="Exact resource, callsite, channel, or target identity assigned by the controller.")
    status: Literal["completed", "failed", "not_started"]
    failure: TaskFailure | None

    @model_validator(mode="after")
    def check_failure(self):
        if (self.status == "completed") != (self.failure is None):
            raise ValueError("completed tasks have no failure; unsuccessful tasks require a diagnostic")
        if self.status == "not_started" and self.failure.kind != "not_started":
            raise ValueError("not_started tasks require a not_started failure")
        return self


class AnalysisExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tasks: dict[str, TaskOutcome] = Field(description="Every dispatched or withheld task, keyed by operation and source identity. Explicitly empty for static or empty work.")

    @model_validator(mode="before")
    @classmethod
    def discard_computed(cls, value):
        if isinstance(value, dict):
            value = dict(value)
            value.pop("status", None)
        return value

    @computed_field
    @property
    def status(self) -> Literal["complete", "partial", "failed"]:
        states = {item.status for item in self.tasks.values()}
        if states <= {"completed"}:
            return "complete"
        return "partial" if "completed" in states else "failed"

    def unsuccessful_subjects(self, operation: str) -> set[str]:
        return {item.subject_id for key, item in self.tasks.items()
                if key.startswith(operation + ":") and item.status != "completed"}

    def require_complete(self) -> None:
        if self.status != "complete":
            raise ValueError("Analyzer execution is " + self.status + ": " + "; ".join(
                f"{key}: {item.failure.reason}" for key, item in self.tasks.items() if item.failure
            ))

    def validate_phase(self, phase: str) -> None:
        if phase == "static" and self.tasks:
            raise ValueError("static phase cannot contain Agent execution tasks")


class AnalysisNotStarted(RuntimeError):
    pass


class ExecutionTracker:
    def __init__(self):
        self.record = AnalysisExecution(tasks={})
        self.provider_failure: TaskFailure | None = None
        self._running: set[str] = set()

    def check_dispatch(self) -> None:
        if self.provider_failure is not None:
            raise AnalysisNotStarted("Dispatch stopped after " + self.provider_failure.reason)

    async def call(self, operation: str, subject_id: str, invoke: Callable[[], Awaitable[T]]) -> T | None:
        key = f"{operation}:{subject_id}"
        if key in self.record.tasks or key in self._running:
            raise ValueError(f"duplicate execution task {key}")
        self._running.add(key)
        try:
            self.check_dispatch()
            value = await invoke()
            if value is None:
                raise ValueError("analysis task returned no validated result")
        except BaseException as error:
            if getattr(error, "code", None) == "structured_output_error":
                kind = "invalid_output"
            elif isinstance(error, AgentProviderError):
                kind = "provider"
            elif isinstance(error, (AgentTurnTimeoutError, TimeoutError)):
                kind = "timeout"
            elif isinstance(error, AgentToolStepLimitError):
                kind = "limit"
            elif isinstance(error, AnalysisNotStarted):
                kind = "not_started"
            elif isinstance(error, asyncio.CancelledError):
                kind = "cancelled"
            elif isinstance(error, (OutputValidationError, ValidationError)):
                kind = "invalid_output"
            elif isinstance(error, OSError):
                kind = "tool"
            else:
                kind = "internal"
            failure = TaskFailure(kind=kind, reason=diagnostic_reason(error),
                                  provider=getattr(error, "provider", None), code=getattr(error, "code", None))
            self.record.tasks[key] = TaskOutcome(subject_id=subject_id,
                status="not_started" if kind == "not_started" else "failed", failure=failure)
            if kind == "provider":
                self.provider_failure = failure
            if not isinstance(error, Exception):
                raise
            return None
        finally:
            self._running.remove(key)
        self.record.tasks[key] = TaskOutcome(subject_id=subject_id, status="completed", failure=None)
        return value


_current: ContextVar[ExecutionTracker | None] = ContextVar("analysis_execution", default=None)


def execution_tracker() -> ExecutionTracker:
    return _current.get() or ExecutionTracker()


def execution_snapshot() -> AnalysisExecution:
    return execution_tracker().record.model_copy(deep=True)


def check_analysis_dispatch() -> None:
    tracker = _current.get()
    if tracker is not None:
        tracker.check_dispatch()


def record_analysis_execution(function):
    """Give a top-level analyzer call its own ledger, including async children."""
    @wraps(function)
    async def wrapped(*args, **kwargs):
        token = _current.set(ExecutionTracker())
        try:
            return await function(*args, **kwargs)
        finally:
            _current.reset(token)
    return wrapped
