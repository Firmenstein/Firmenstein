"""Discover process traces without putting their contents in Agent feedback."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def read_trace(path: Path, roots: list[Path], source_sha256: str | None = None):
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not any(resolved.is_relative_to(root.resolve()) for root in roots):
        raise ValueError("trace is outside the current runtime evidence roots")
    raw = resolved.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if source_sha256 is not None and digest != source_sha256:
        raise ValueError("source_changed: live trace checkpoint changed; refresh its inventory")
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get("events"), list):
        raise ValueError("selected file is not a process runtime trace")
    return resolved, digest, value, raw


def trace_inventory(root: Path, *, check=lambda: None, recursive: bool = False) -> dict:
    if recursive and root.is_dir():
        import os
        records, errors = [], []
        for directory, children, _ in os.walk(root, followlinks=False):
            children[:] = [name for name in children if name not in {
                'runtime-trace-views', 'trace-queries', 'core-inspections', 'captured-cores'
            } and not (Path(directory) / name).is_symlink()]
            check()
            inventory = trace_inventory(Path(directory), check=check)
            records.extend(inventory['traces'])
            errors.extend(inventory['errors'])
        return {'schema_version': 1, 'root': str(root.resolve()), 'traces': records, 'errors': errors}
    records, errors = [], []
    if not root.is_dir():
        errors.append({"path": str(root), "error": "runtime evidence directory is not available"})
    diagnostics, transitions = {}, {}
    for pattern in ("diagnostics-*.json", "runtime_trace*.transition.json"):
        for path in sorted(root.glob(pattern)):
            check()
            try:
                if path.is_symlink():
                    raise ValueError("symlink evidence is not read")
                value = json.loads(path.read_bytes())
                if not isinstance(value, dict):
                    raise ValueError("invalid diagnostic/transition record")
                if "trace_path" in value:
                    diagnostics.setdefault(Path(value["trace_path"]).name, []).append(str(path))
                if value.get("child_trace"):
                    transitions.setdefault(Path(value["child_trace"]).name, []).append({
                        "path": str(path), "parent_trace": value.get("parent_trace"),
                        "status": value.get("status"), "error": value.get("error"),
                        "host_pid": value.get('host_pid'),
                        "requested_executable": (value.get('request') or {}).get('pathname')})
            except (OSError, ValueError, TypeError) as error:
                errors.append({"path": str(path), "error": str(error)})
    for path in sorted(root.glob("runtime_trace*.json")):
        check()
        if any(token in path.name for token in (".heartbeat.", ".transition.", "_context")):
            continue
        try:
            resolved, digest, trace, raw = read_trace(path, [root])
            images = {event['detail'] for event in trace.get('image_loads', [])
                      if isinstance(event, dict) and 'detail' in event}
            images.update(event['detail'] for event in trace.get('events', [])
                          if isinstance(event, dict) and event.get('kind') == 'image_load' and 'detail' in event)
            records.append({
                "path": str(resolved), "sha256": digest,
                "bytes": len(raw),
                **{key: trace.get(key) for key in (
                    "host_pid", "origin_pid", "guest_arch", "byte_order", "word_bits", "started_unix_ns", "checkpoint_elapsed_ns",
                    "terminal_reason", "dropped_events", "dropped_image_loads",
                    "dropped_tail_entries", "dropped_focus_tail_entries", "dropped_unique_blocks")},
                "images": sorted(images),
                "event_count": len(trace["events"]),
                "diagnostic_paths": diagnostics.get(path.name, []),
                "exec_transitions": transitions.get(path.name, []),
                "event_kinds": sorted({event.get("kind", "") for event in trace["events"]
                                       if isinstance(event, dict)}),
            })
        except (OSError, ValueError, TypeError) as error:
            errors.append({"path": str(path), "error": str(error)})
    return {"schema_version": 1, "root": str(root.resolve()), "traces": records,
            "errors": errors, "notice": "Separate process/image checkpoints; fork prefixes may overlap. A missing terminal record is not proof of a live process. Syscall names are in syscall_result.detail. Raw hashes bind only this checkpoint."}
