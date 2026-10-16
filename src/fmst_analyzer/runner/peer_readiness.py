"""Bounded Controller-owned peer endpoint gate; no guest protocol substitution."""

from __future__ import annotations

import json
import time
from pathlib import Path


def unix_listeners(output: str, path: str) -> list[str]:
    """Return kernel socket inodes with stream type and SO_ACCEPTCON flag."""
    rows = output.splitlines()
    if not rows or rows[0].split() != ["Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path"]:
        raise RuntimeError("peer readiness observation: unexpected /proc/net/unix header")
    inodes = []
    for row in rows[1:]:
        fields = row.split(maxsplit=7)
        if len(fields) < 7:
            raise RuntimeError("peer readiness observation: incomplete UNIX socket row")
        if len(fields) == 8 and fields[7] == path:
            if int(fields[3], 16) & 0x10000 and int(fields[4], 16) == 1:
                inodes.append(fields[6])
    return inodes


def wait_for_peers(*, companions, observer, observe_endpoint, deadline: float,
                   evidence_path: Path, check_budget) -> None:
    """Release only after all declared endpoints and peer roles are observed.

    The supplied observer is the independent process-tree monitor. Its latest
    successful sample must be fresh. Endpoint ownership and protocol readiness
    are deliberately not inferred from a pathname or a live process.
    """
    started = time.monotonic()
    required = [(f"peer-{i:02d}", p.readiness) for i, p in enumerate(companions, 1) if p.readiness]
    record = {"schema_version": 1, "state": "waiting", "started_unix_ns": time.time_ns(),
              "condition": "fresh live peer role and existing kernel UNIX stream listener",
              "limitations": ["Listener ownership and protocol initialization are not proven."],
              "peers": {}, "error": None}

    def save():
        evidence_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    save()
    try:
        while True:
            check_budget()
            if observer.interrupted.is_set():
                raise RuntimeError(f"peer readiness interrupted: {observer.termination_reason}; {observer.observation_error}")
            ready = True
            for role, condition in required:
                if time.monotonic() >= min(deadline, started + condition.timeout_seconds):
                    raise RuntimeError(f"peer_readiness_timeout: {role} {condition.unix_socket}; target not launched")
                identities = [p for p in observer.last_processes if p.get("role") == role
                              and not str(p["state"]).startswith(("Z", "X"))]
                fresh = (observer.observation_error is None and observer.last_sample_monotonic is not None
                         and time.monotonic() - observer.last_sample_monotonic <= 2.0)
                inodes = observe_endpoint(condition.unix_socket) if identities and fresh else []
                ready = ready and bool(identities and fresh and inodes)
                record["peers"][role] = {"endpoint": condition.unix_socket, "sampled_unix_ns": time.time_ns(),
                    "live_identities": identities, "process_sample_fresh": fresh, "listening_inodes": inodes}
            save()
            if ready:
                check_budget()
                if observer.interrupted.is_set() or time.monotonic() >= deadline:
                    raise RuntimeError("peer readiness lost before target release")
                record.update(state="ready", ready_unix_ns=time.time_ns())
                save()
                return
            observer.interrupted.wait(min(0.1, max(0, deadline - time.monotonic())))
    except BaseException as error:
        record.update(state="failed", error=f"{type(error).__name__}: {error}")
        save()
        raise
