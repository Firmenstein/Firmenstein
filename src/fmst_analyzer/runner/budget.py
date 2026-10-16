"""One Controller deadline and cooperative cancellation for a Runner session."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import threading
import time
from typing import Callable, TypeVar

T = TypeVar("T")


class RunnerStopped(Exception):
    """Controller stop, deliberately not a provider or subprocess failure."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ExecutionBudget:
    """Share a monotonic deadline; reserve the final window for evidence/cleanup.

    ``run_sync`` is only for cooperative, non-IDA work whose blocking process
    calls use ``run_process`` and whose file loops call ``check``. Moving an
    arbitrary blocking native function into a thread does not make it bounded.
    """

    def __init__(self, seconds: float = 7200, *, cleanup_seconds: float = 30) -> None:
        if seconds <= 0 or cleanup_seconds < 0:
            raise ValueError("budget must be positive and cleanup reserve nonnegative")
        self.started_unix_ns = time.time_ns()
        self.started = time.monotonic()
        self.deadline = self.started + seconds
        self.cleanup_seconds = min(cleanup_seconds, seconds * 0.5)
        self.work_deadline = self.deadline - self.cleanup_seconds
        self.cancelled = threading.Event()

    def remaining(self, *, cleanup: bool = False) -> float:
        return max(0.0, (self.deadline if cleanup else self.work_deadline) - time.monotonic())

    def check(self, *, cleanup: bool = False) -> None:
        if self.remaining(cleanup=cleanup) <= 0:
            raise RunnerStopped("session_budget_exhausted")
        if not cleanup and self.cancelled.is_set():
            raise RunnerStopped("user_cancelled")

    def limit(self, seconds: float, *, cleanup: bool = False) -> float:
        self.check(cleanup=cleanup)
        return min(seconds, self.remaining(cleanup=cleanup))

    async def run_sync(self, function: Callable[..., T], *args, **kwargs) -> T:
        self.check()
        worker = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            self.cancelled.set()
            # The worker owns its resources. Let it observe cancellation and
            # finish bounded cleanup before the Controller closes the session.
            try:
                await asyncio.wait_for(asyncio.shield(worker), timeout=min(
                    self.cleanup_seconds, self.remaining(cleanup=True),
                ))
            except (RunnerStopped, asyncio.TimeoutError):
                pass
            raise


def run_process(
    command: list[str], *, budget: ExecutionBudget, timeout: float,
    cleanup: bool = False, check: bool = False, input=None,
    capture_output: bool = False, **kwargs,
) -> subprocess.CompletedProcess:
    """Bound a local process group; callers must separately own Docker resources.

    Terminating a Docker client does not terminate its container. Its owner
    must remove that exact container in a finally/stop path using the cleanup
    reserve. stdout/stderr file handles can stream evidence without buffering.
    """
    limit = budget.limit(timeout, cleanup=cleanup)
    operation_deadline = time.monotonic() + limit
    if capture_output:
        if "stdout" in kwargs or "stderr" in kwargs:
            raise ValueError("capture_output conflicts with stdout/stderr")
        kwargs.update(stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if input is not None:
        if "stdin" in kwargs:
            raise ValueError("input conflicts with stdin")
        kwargs["stdin"] = subprocess.PIPE
    process = subprocess.Popen(command, start_new_session=True, **kwargs)
    pending_input = input
    completed = False
    partial_output = None
    partial_error = None
    try:
        while True:
            budget.check(cleanup=cleanup)
            remaining = operation_deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, limit, output=partial_output, stderr=partial_error)
            try:
                stdout, stderr = process.communicate(input=pending_input, timeout=min(0.2, remaining))
                completed = True
                break
            except subprocess.TimeoutExpired as error:
                pending_input = None
                partial_output, partial_error = error.output, error.stderr
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result
    except RunnerStopped as error:
        # Preserve partial diagnostics for a Controller that has no budget
        # left to ask the Agent to repair this operation.
        error.output, error.stderr = partial_output, partial_error
        raise
    finally:
        if not completed:
            # POSIX process groups cover compiler/script descendants as well
            # as their immediate parent on the supported Linux/macOS hosts.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=min(0.5, budget.remaining(cleanup=True)))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=max(0.01, min(0.5, budget.remaining(cleanup=True))))
