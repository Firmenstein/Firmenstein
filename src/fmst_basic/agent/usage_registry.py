"""
LLM usage registry — aggregates token usage by analyzer "component scope".

AgentTraceHandler records one UsageRecord per completed agent turn.
An analyzer entry point wraps its work in `with usage_scope("IPCAnalyzer")`,
and on scope exit the registry logs a rollup summary of every record
captured inside that scope: wall-clock time + total queries/tokens plus a
breakdown by agent_name.

Scopes are ContextVar-backed. When an analyzer fans out agents via
asyncio.gather inside a scope, each spawned task inherits the scope tag
at creation time, so concurrent agent runs all roll up to the same scope.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import Dict, List, Optional

from loguru import logger


@dataclass
class UsageRecord:
    component: Optional[str]
    agent_name: str
    title: str
    model: str
    queries: int
    input_tokens: int
    output_tokens: int
    cache_read: int
    cache_creation: int
    elapsed_seconds: float


_current_scope: ContextVar[Optional[str]] = ContextVar(
    "fmst_usage_scope", default=None
)
_records: List[UsageRecord] = []


def record_usage(
    *,
    agent_name: str,
    title: str,
    model: str,
    queries: int,
    input_tokens: int,
    output_tokens: int,
    cache_read: int,
    cache_creation: int,
    elapsed_seconds: float,
) -> None:
    """Append one record, tagged with the currently active scope (if any).

    Called by AgentTraceHandler after each completed agent turn.
    """
    _records.append(UsageRecord(
        component=_current_scope.get(),
        agent_name=agent_name,
        title=title,
        model=model,
        queries=queries,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cache_read=cache_read,
        cache_creation=cache_creation,
        elapsed_seconds=elapsed_seconds,
    ))


@contextmanager
def usage_scope(component: str):
    """Open a usage scope named `component`.

    All agent runs completing inside the scope (including asyncio children
    spawned from within) get tagged with `component`. On exit, a rollup
    `[USAGE] <component> TOTAL` line plus per-agent breakdown is logged.
    If no agent runs happened inside the scope, nothing is logged.
    """
    token = _current_scope.set(component)
    start_idx = len(_records)
    start_time = time.monotonic()
    try:
        yield
    finally:
        wall_elapsed = time.monotonic() - start_time
        _current_scope.reset(token)
        scope_records = _records[start_idx:]
        if scope_records:
            _log_rollup(component, scope_records, wall_elapsed)


def _log_rollup(
    component: str, recs: List[UsageRecord], wall_elapsed: float
) -> None:
    total_q = sum(r.queries for r in recs)
    total_in = sum(r.input_tokens for r in recs)
    total_out = sum(r.output_tokens for r in recs)
    total_cr = sum(r.cache_read for r in recs)
    total_cw = sum(r.cache_creation for r in recs)

    logger.info(
        f"[USAGE] {component} TOTAL | "
        f"{total_q} queries across {len(recs)} runs | "
        f"{total_in:,} in ({total_cr:,} cache_r, {total_cw:,} cache_w) / "
        f"{total_out:,} out | "
        f"wall {wall_elapsed:.1f}s"
    )

    by_agent: Dict[str, Dict[str, float]] = {}
    for r in recs:
        bucket = by_agent.setdefault(r.agent_name, {
            "runs": 0, "queries": 0, "in": 0, "out": 0,
            "cache_r": 0, "cache_w": 0, "elapsed": 0.0,
        })
        bucket["runs"] += 1
        bucket["queries"] += r.queries
        bucket["in"] += r.input_tokens
        bucket["out"] += r.output_tokens
        bucket["cache_r"] += r.cache_read
        bucket["cache_w"] += r.cache_creation
        bucket["elapsed"] += r.elapsed_seconds

    for agent_name in sorted(by_agent.keys()):
        s = by_agent[agent_name]
        logger.info(
            f"[USAGE]   - {agent_name}: "
            f"{int(s['runs'])} runs | "
            f"{int(s['queries'])} queries | "
            f"{int(s['in']):,} in "
            f"({int(s['cache_r']):,} cache_r, {int(s['cache_w']):,} cache_w) / "
            f"{int(s['out']):,} out | "
            f"agent-sum {s['elapsed']:.1f}s"
        )


def scoped(component: str):
    """Decorator form of ``usage_scope`` for async methods.

    Usage::

        @scoped("IPCAnalyzer")
        async def run(self, ...):
            ...

    Wraps the method body in ``with usage_scope(component):``, so the
    existing body doesn't need to be re-indented.
    """
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*args, **kwargs):
            with usage_scope(component):
                return await fn(*args, **kwargs)
        return wrapper
    return decorator


def all_records() -> List[UsageRecord]:
    """Return a shallow copy of every recorded UsageRecord so far.

    Useful for writing a final JSON dump or inspecting cross-scope totals.
    """
    return list(_records)


def reset() -> None:
    """Clear the registry. Intended for tests."""
    _records.clear()
