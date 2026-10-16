"""Selective, deterministic navigation views over retained runtime evidence.

These views do not replace the lossless context or infer causes, ABI values,
call/return pairs, per-instruction state, or observations outside capture.
"""
from __future__ import annotations

from pathlib import PurePosixPath

from fmst_analyzer.synthesizer.intervention_generator.shell import unit_module_name

from .schema import RuntimeEventContext, RuntimeSourceLocation, RuntimeTraceContext
from .trace_compaction import compact_trace_context


SNAPSHOT_NOTICE = "Values are omitted from this view, retained in the original event. Uncaptured bytes are unknown, not zero. Decode with the guest architecture, byte order and word width, plus this event's sampling phase; do not assume pointer roles or output writes."


def failure_overview(feedback: dict) -> dict:
    """Select the explicitly identified failed step; retain all facts elsewhere."""
    facts = feedback.get("facts") or {}
    steps = facts.get("steps", [])
    failed = feedback.get("failed_step")
    selected = [step for step in steps if step.get("index") == failed] if failed is not None else []
    assessment = feedback.get("child_failure_assessment")
    dump = feedback.get("runtime_dump")
    if isinstance(assessment, dict):
        assessment = dict(assessment)
        for field in ("failures", "collection_errors"):
            entries = assessment.get(field, [])
            assessment[field] = entries[:4]
            assessment[field + "_extent"] = {"showing": min(4, len(entries)), "total": len(entries)}
    return {
        **{key: feedback.get(key) for key in (
            "scenario_status", "scenario_error", "failed_step", "execution_hashes")},
        "failed_step_facts": selected,
        "step_facts_extent": {"showing": len(selected), "total": len(steps)},
        "step_facts_notice": "Only the explicitly reported failed step is selected; complete facts and wire artifact paths remain in feedback_path. Missing observations remain unknown.",
        "child_failure_association": assessment,
        "runtime_dump": ({key: dump[key] for key in (
            "schema_version", "status", "capture_kind", "source", "guest_arch", "byte_order", "word_bits", "pid", "tid",
            "core_path", "load_map_path", "execution_hashes", "missing", "errors") if key in dump}
            if isinstance(dump, dict) else None),
        "limitations": feedback.get("limitations", []),
        "notice": "Child relations are the Controller's recorded association, not a causal verdict; full assessment remains in feedback_path. A missing dump or last historical event does not establish crash-time state.",
    }


def source_position(location: RuntimeSourceLocation | None, *, assembly: bool) -> dict | None:
    if location is None:
        return None
    result = {key: getattr(location, key) for key in (
        "binary_name", "function_name", "assembly_path", "decompiled_path", "ctree_index",
        "snapshot_hash", "line_number", "column_number")}
    result.update({key: hex(getattr(location, key)) if getattr(location, key) is not None else None
                   for key in ("runtime_pc", "runtime_base", "image_base", "static_ea", "function_ea", "source_ea")})
    if assembly:
        result["assembly_context"] = location.assembly_context
        result["assembly_notice"] = "Static neighboring lines, not a complete basic block/CFG or per-instruction observations. Full function is at assembly_path."
    return {key: value for key, value in result.items() if value is not None}


def execution_view(context: RuntimeTraceContext, *, stream: str, start: int, count: int) -> dict:
    field = "recent_focus_blocks" if stream == "focus" else "recent_blocks"
    items = getattr(context, field)[start:start + count]
    payload = {"events": [], "recent_blocks": [], "recent_focus_blocks": []}
    payload[field] = [item.model_dump(mode="json") for item in items]
    encoded = compact_trace_context(payload)
    records = encoded["streams"][field]
    nodes = {}
    for index, record in enumerate(records["records"]):
        location = (RuntimeSourceLocation.model_validate(encoded["locations"][record["location_ref"]])
                    if "location_ref" in record else None)
        nodes[f"B{index}"] = {
            "runtime_pc": hex(record["runtime_pc"]),
            "consecutive_hits": record["consecutive_hits"],
            "source": source_position(location, assembly=True),
            "source_status": "mapped; inspect image mapping provenance" if location else "unmapped or ambiguous",
        }
    return {
        "stream": field,
        "nodes": nodes,
        "runs": [{"path": [f"B{index}" for index in run["pattern"]], "repeat": run["repeat"]}
                 for run in records["runs"]],
        "original_records": {"section": field, "start": start, "limit": max(1, count)},
        "notice": "Selective execution view. Expand each path repeat times in order to recover this page's retained records. Node names are page-local; counts cover retained records only. Block-entry observations do not prove all displayed instructions completed. Repetition alone does not prove a stuck loop. Source hashes and mapping errors remain in trace_context.metadata.images.",
        "adjacency": ("Focus projection omits other images; adjacent nodes are not necessarily direct control-flow edges."
                      if stream == "focus" else "Ordered tail of captured block entries; not a reconstructed CFG or a complete execution history."),
    }


def snapshot_extent(event: RuntimeEventContext, *, include_notice: bool = True) -> dict:
    return {
        "register_names": [item.name for item in event.registers],
        "memory_ranges": [{"address": hex(item.address), "source_register": item.source_register,
                           "requested_bytes": item.requested_bytes, "captured_bytes": len(item.bytes),
                           "error": item.error} for item in event.memory],
        **({"notice": SNAPSHOT_NOTICE} if include_notice else {}),
    }


def event_sampling(event: RuntimeEventContext) -> str:
    # Exact producer event kinds, not semantic classification of arbitrary text.
    return {
        "iib_hook": "Before invoking the intervention handler; captured state is entry state.",
        "syscall_result": "Post-syscall result event; detail contains the producer-recorded arguments and signed result.",
        "stdio_io": "Successful stdio transfer observation; detail contains operation, fd and transferred byte count.",
    }.get(event.kind, "No additional sampling-phase interpretation for this event kind; inspect producer detail.")


def hook_owner(event: RuntimeEventContext, owners: dict | None) -> dict:
    """Join exact recorded IDs and the frozen generated manifest, never ID substrings."""
    result = {"unit_id": event.unit_id, "hook_id": event.hook_id,
              "status": "unknown"}
    hook_id = event.hook_id
    if not hook_id and event.kind == "iib_hook" and not event.detail_dropped_bytes:
        name, separator, pc = event.detail.rpartition("@")
        try:
            matches_pc = pc.startswith("0x") and int(pc, 16) == event.runtime_pc
        except ValueError:
            matches_pc = False
        if separator and name and matches_pc:
            hook_id = name
            result.update(hook_id=hook_id, hook_id_basis="Exact iib_hook producer detail id@runtime_pc.")
    if owners is None:
        result["reason"] = "Attempt-local owner snapshot unavailable; do not substitute a later workspace or original Plan."
        return result
    try:
        if owners["schema_version"] != 1:
            raise ValueError("unsupported owner snapshot schema")
        units = owners["units"]
        if not isinstance(units, dict):
            raise ValueError("malformed owner units")
        candidates = []
        basis = None
        if hook_id:
            manifest = owners.get("manifest") or {}
            entries = [entry for field in ("callsite_hooks", "function_stubs", "pseudo_files")
                       for entry in manifest.get(field, []) if entry.get("id") == hook_id]
            if len(entries) > 1:
                raise ValueError("ambiguous hook ID in frozen manifest")
            if entries:
                entry = entries[0]
                result["manifest_entry"] = entry
                source = PurePosixPath(entry.get("source_file") or "").parts
                module = source[1] if len(source) >= 3 and source[0] == "src" else None
                candidates = [key for key in units if module == unit_module_name(key)]
                basis = "Exact hook ID -> frozen manifest source_file -> generated Unit module."
        if len(candidates) > 1:
            raise ValueError("ambiguous Unit module in frozen manifest")
        if event.unit_id:
            if candidates and candidates != [event.unit_id]:
                raise ValueError("recorded Unit ID conflicts with frozen manifest")
            candidates = [event.unit_id] if event.unit_id in units else []
            basis = "Recorded Unit ID in attempt-local snapshot."
        if not candidates:
            result["reason"] = "No exact Unit association available in the frozen snapshot."
            return result
        unit_id = candidates[0]
        unit = units[unit_id]
        result.update(unit_id=unit_id, status="associated", basis=basis,
                      configured=unit["configured"], strategy=unit["definition"]["strategy"])
        if not unit["configured"]:
            result["notice"] = "This Unit was disabled in the snapshot; the discrepancy requires investigation."
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        result.update(status="unknown", reason=str(error))
    return result


def api_view(context: RuntimeTraceContext, *, start: int, count: int, owners: dict | None) -> dict:
    return {
        "events": [{
            **{key: getattr(event, key) for key in (
                "sequence", "last_sequence", "repeat_count", "elapsed_ns", "last_elapsed_ns",
                "kind", "detail", "detail_dropped_bytes")},
            "runtime_pc": hex(event.runtime_pc) if event.runtime_pc is not None else None,
            "source": source_position(event.location, assembly=False),
            "sampling_phase": event_sampling(event), "owner": hook_owner(event, owners),
            "snapshot": snapshot_extent(event, include_notice=False),
            "original_event": {"section": "events", "start": index, "limit": 1},
        } for index, event in enumerate(context.events[start:start + count], start=start)],
        "notice": "Selective API/event view; includes lifecycle and unknown event kinds in original order. Producer detail is verbatim. Register and memory values remain in original_event pages or complete_context_path. No ABI argument/result decoding is inferred. Frozen definitions are at runtime_owners.path; configured ownership is not proof of execution success or causality.",
        "pairing": "No call-instance identity or paired return/output snapshot is established by this view. Neighboring events are not paired.",
        "time_scope": "Historical checkpoint; repeated-event ranges retain endpoints, not each inner timestamp. Not crash-time state.",
        "snapshot_notice": SNAPSHOT_NOTICE,
    }
