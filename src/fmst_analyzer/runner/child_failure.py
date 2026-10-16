"""Correlate guest image failures with Controller-owned TCP probes.

This is a conservative evidence join, not a parser for HTTP bodies or a
firmware-name rule. Raw logs, per-image metadata, and exact request receipts
remain available even when a join is unknown. A fault address is never a PC.
"""

from __future__ import annotations

import json
import ipaddress
from pathlib import Path
import re
from typing import Any

from .budget import ExecutionBudget
from .schema import ScenarioResult


_SIGNAL = re.compile(r"^qemu: uncaught target signal (?P<signal>[0-9]+)(?:\s|\()", re.M)
_EXIT_STATUS = re.compile(r"^guest syscall [0-9]+; status=0x([0-9a-fA-F]+)$")
_POSITIVE_STDOUT = re.compile(r"^operation=write; fd=1; transferred_bytes=([1-9][0-9]*)$")
_MAX_READ_BYTES = 4 * 1024 * 1024


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    try:
        if path.is_symlink():
            return None, f"{path}: symlink evidence is not read"
        size = path.stat().st_size
        if size > _MAX_READ_BYTES:
            return None, f"{path}: {size} bytes exceeds bounded read {_MAX_READ_BYTES}; original retained"
        value = json.loads(path.read_bytes())
        if not isinstance(value, dict):
            return None, f"{path}: expected an object"
        return value, None
    except (OSError, ValueError, UnicodeDecodeError) as error:
        return None, f"{path}: {error}"


def _probe_connections(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        if path.is_symlink():
            return [], [f"{path}: symlink evidence is not read"]
        if path.stat().st_size > _MAX_READ_BYTES:
            return [], [f"{path}: exceeds bounded read {_MAX_READ_BYTES}; original retained"]
        by_id: dict[str, dict[str, Any]] = {}
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            try:
                value = json.loads(line)
                if not isinstance(value, dict) or value.get("schema_version") != 1:
                    raise ValueError("unsupported record")
                connection_id = value.get("connection_id")
                if not isinstance(connection_id, str) or not connection_id:
                    raise ValueError("missing connection ID")
                prior = by_id.get(connection_id)
                if value.get("state") == "requested":
                    if prior is not None:
                        raise ValueError("duplicate requested record")
                    by_id[connection_id] = value
                elif value.get("state") in {"completed", "timeout"} and prior is not None:
                    if any(value.get(key) != prior.get(key) for key in (
                        "step_index", "probe_attempt", "source_port", "destination_host",
                        "destination_port", "request_sha256",
                    )):
                        raise ValueError("connection identity changed")
                    records.append({**prior, "started_unix_ns": prior["unix_ns"],
                                    "finished_unix_ns": value["unix_ns"],
                                    "state": value["state"],
                                    "connected": value.get("connected") is True})
                    del by_id[connection_id]
                else:
                    raise ValueError("orphan or invalid completion")
            except (ValueError, TypeError, KeyError) as error:
                errors.append(f"{path}:{number}: {error}")
        errors.extend(f"{path}: requested connection {key} has no completion" for key in by_id)
    except OSError as error:
        errors.append(f"{path}: {error}")
    return records, errors


def _stdio_peer(record: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    for item in record.get("stdio_at_checkpoint", []):
        if isinstance(item, dict) and item.get("fd") == 0:
            local, peer = item.get("local_socket"), item.get("peer_socket")
            if isinstance(local, dict) and isinstance(peer, dict):
                return local, peer
    return None, None


def _ipv4_address(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        address = address.ipv4_mapped
    return str(address) if isinstance(address, ipaddress.IPv4Address) else None


def _failure_and_output(root: Path, record: dict[str, Any], log_path: Path) -> tuple[int | None, int | None, bool, str | None, str | None]:
    """Return signal, guest exit status, positive stdout, trace path, error."""
    try:
        if log_path.is_symlink():
            return None, None, False, None, f"{log_path}: symlink evidence is not read"
        size = log_path.stat().st_size
        if size > _MAX_READ_BYTES:
            return None, None, False, None, f"{log_path}: {size} bytes exceeds bounded read {_MAX_READ_BYTES}; original retained"
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return None, None, False, None, f"{log_path}: {error}"
    match = _SIGNAL.search(text)
    signal = int(match.group("signal")) if match else None
    trace_name = record.get("trace_path")
    if not isinstance(trace_name, str) or not trace_name:
        return signal, None, False, None, "image trace path missing"
    trace_path = root / Path(trace_name).name
    trace, error = _read_json(trace_path)
    if error or trace is None:
        return signal, None, False, str(trace_path), error
    if trace.get("host_pid") != record.get("pid"):
        return signal, None, False, str(trace_path), f"{trace_path}: process PID mismatch"
    if (trace.get("origin_pid") != record.get("origin_pid")
            or not isinstance(trace.get("started_unix_ns"), int)
            or not isinstance(record.get("image_started_unix_ns"), int)
            or not isinstance(record.get("checkpoint_unix_ns"), int)
            or not record["image_started_unix_ns"] <= trace["started_unix_ns"] <= record["checkpoint_unix_ns"]):
        return signal, None, False, str(trace_path), f"{trace_path}: image-time/origin identity mismatch"
    events = trace.get("events")
    if not isinstance(events, list):
        return signal, None, False, str(trace_path), f"{trace_path}: event list missing"
    output = any(isinstance(event, dict) and event.get("kind") == "stdio_io"
                 and isinstance(event.get("detail"), str)
                 and _POSITIVE_STDOUT.fullmatch(event["detail"])
                 for event in events)
    exit_status = None
    for event in events:
        if isinstance(event, dict) and event.get("kind") == "process_exit":
            detail = event.get("detail")
            result = _EXIT_STATUS.fullmatch(detail) if isinstance(detail, str) else None
            if result is not None:
                exit_status = int(result.group(1), 16) & 255
    return signal, exit_status, output, str(trace_path), None


def assess_child_failures(*, attempt_dir: Path, probe_connections: Path,
                          scenario_result: ScenarioResult | None,
                          budget: ExecutionBudget | None = None) -> dict[str, Any]:
    """Read durable evidence and tighten only a positively related step.

    Caller writes the returned schema-1 object next to full raw artifacts. The
    ScenarioResult is updated in place only for proven associated failures.
    Unrelated and unknown child failures remain visible without a blanket veto.
    """
    connections, errors = _probe_connections(probe_connections)
    failures: list[dict[str, Any]] = []
    metadata_paths = sorted(attempt_dir.glob("diagnostics-*.json"))
    for path in metadata_paths:
        if budget is not None:
            budget.check(cleanup=True)
        record, error = _read_json(path)
        if error:
            errors.append(error)
            continue
        if record is None or record.get("schema_version") != 2 or record.get("kind") != "host_diagnostics":
            errors.append(f"{path}: unsupported diagnostic identity")
            continue
        log_path = path.with_suffix(".log")
        signal, exit_status, output, trace_path, trace_error = _failure_and_output(attempt_dir, record, log_path)
        if signal is None and (exit_status is None or exit_status == 0):
            if trace_error:
                errors.append(f"{path}: failure state unknown: {trace_error}")
            continue
        local, peer = _stdio_peer(record)
        matching = [connection for connection in connections
                    if connection.get("connected") and isinstance(local, dict)
                    and isinstance(peer, dict)
                    and _ipv4_address(local.get("address")) is not None
                    and _ipv4_address(peer.get("address")) is not None
                    and local.get("port") == connection.get("destination_port")
                    and _ipv4_address(local.get("address")) == _ipv4_address(connection.get("destination_host"))
                    and _ipv4_address(peer.get("address")) == _ipv4_address(connection.get("destination_host"))
                    and peer.get("port") == connection.get("source_port")
                    and connection.get("started_unix_ns", 0) <= record.get("checkpoint_unix_ns", -1)
                    and record.get("image_started_unix_ns", 0) <= connection.get("finished_unix_ns", -1)]
        # Multiple matches mean a malformed/reused connection identity, not
        # permission to choose one step by timestamp or image basename.
        identity_ok = isinstance(record.get("process_start_ticks"), int) and not record.get("process_identity_error")
        capture_ok = (record.get("truncated") is False
                      and record.get("write_failures_including_fork_prefix") == 0
                      and trace_error is None)
        if len(matching) == 1 and identity_ok and capture_ok and output:
            relation = "related"
        elif matching or not connections or errors or trace_error:
            relation = "unknown"
        else:
            relation = "unrelated"
        item = {
            "relation":relation, "pid_namespace":record.get("pid_namespace"),
            "pid":record.get("pid"), "process_start_ticks":record.get("process_start_ticks"),
            "parent_pid":record.get("parent_pid"), "origin_pid":record.get("origin_pid"),
            "image_started_unix_ns":record.get("image_started_unix_ns"),
            "binary":record.get("binary"), "signal":signal, "guest_exit_status":exit_status,
            "positive_stdout_observed":output,
            "matched_step":matching[0].get("step_index") if len(matching) == 1 else None,
            "source_port":matching[0].get("source_port") if len(matching) == 1 else None,
            "diagnostic_identity":str(path), "diagnostic_log":str(log_path),
            "trace":trace_path, "uncertainty":trace_error,
        }
        failures.append(item)
        if relation == "related" and scenario_result is not None:
            index = item["matched_step"]
            step = next((step for step in scenario_result.steps if step.index == index), None)
            if step is not None:
                reason = (f"request-associated image {record.get('binary')} pid={record.get('pid')} "
                          f"failed after stdout output: signal={signal}, guest_exit_status={exit_status}; "
                          f"evidence={path}")
                step.passed = False
                step.error = f"{step.error}; {reason}" if step.error else reason
                if scenario_result.status in {"success", "blocked"}:
                    scenario_result.status = "blocked"
                scenario_result.error = (f"{scenario_result.error}; {reason}"
                                         if scenario_result.error else reason)
            else:
                item["relation"] = "unknown"
                item["uncertainty"] = "matched probe step absent from scenario result"
    for log_path in sorted(attempt_dir.glob("diagnostics-*.log")):
        if log_path.with_suffix(".json").is_file():
            continue
        if budget is not None:
            budget.check(cleanup=True)
        errors.append(f"{log_path}: image identity/checkpoint missing")
        try:
            if log_path.is_symlink():
                raise ValueError("symlink evidence is not read")
            size = log_path.stat().st_size
            if size > _MAX_READ_BYTES:
                raise ValueError(f"{size} bytes exceeds bounded read {_MAX_READ_BYTES}; original retained")
            match = _SIGNAL.search(log_path.read_text(encoding="utf-8", errors="replace"))
            signal = int(match.group("signal")) if match else None
            uncertainty = "image identity/checkpoint missing"
        except (OSError, ValueError) as error:
            signal = None
            uncertainty = str(error)
        failures.append({"relation": "unknown", "pid_namespace": None, "pid": None,
                         "process_start_ticks": None, "parent_pid": None, "origin_pid": None,
                         "image_started_unix_ns": None, "binary": None, "signal": signal,
                         "guest_exit_status": None, "positive_stdout_observed": False,
                         "matched_step": None, "source_port": None,
                         "diagnostic_identity": None, "diagnostic_log": str(log_path),
                         "trace": None, "uncertainty": uncertainty})
    return {"schema_version":1, "probe_connections":str(probe_connections),
            "failures":failures, "collection_errors":errors,
            "status":"related_failure" if any(item["relation"] == "related" for item in failures)
            else "unknown" if errors or any(item["relation"] == "unknown" for item in failures)
            else "unrelated_or_no_failure"}
