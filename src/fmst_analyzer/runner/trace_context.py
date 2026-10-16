"""Map bounded QEMU evidence back to stable IDA artifacts.

The raw trace remains the runtime source of truth.  This module derives a
compact, replayable index: aggregate block hits by function, map the bounded
execution tail and low-volume events to assembly/decompiled locations, and
retain event register snapshots.  It performs no decompilation and no Agent
work.
"""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import lief

from fmst_analyzer.analysis.base.report_io import (
    load_model_json,
    write_model_json,
    write_text,
)
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView

from .trace_compaction import compact_trace_context
from .schema import (
    RuntimeEventContext,
    RuntimeMemorySnapshot,
    RuntimeFunctionSummary,
    RuntimeImageMapping,
    RuntimeRecentBlock,
    RuntimeRegister,
    RuntimeSourceLocation,
    RuntimeTraceContext,
)


_IMAGE_LOAD_RE = re.compile(r"^(?P<name>.+)@0x(?P<base>[0-9a-fA-F]+)$")
_CHUNK_RE = re.compile(r"^; chunk: 0x([0-9a-fA-F]+)-0x([0-9a-fA-F]+)$")
_ENTRY_RE = re.compile(r"^; entry_ea: 0x([0-9a-fA-F]+)$")
_INSTRUCTION_RE = re.compile(r"^0x([0-9a-fA-F]+):")


@dataclass(frozen=True)
class _FunctionArtifact:
    binary_name: str
    function_name: str
    function_ea: int
    ranges: tuple[tuple[int, int], ...]
    assembly_path: Path
    decompiled_path: Path | None
    callsites_by_ea: dict[int, object]
    assembly_context_by_ea: dict[int, tuple[str, ...]]


@dataclass(frozen=True)
class _BinarySourceIndex:
    binary_name: str
    binary_path: Path
    image_base: int
    functions: tuple[_FunctionArtifact, ...]


def _source_indexes(view: AnalysisView) -> dict[str, _BinarySourceIndex]:
    indexes: dict[str, _BinarySourceIndex] = {}
    for binary in sorted(view.lib_dep_graph.get_nodes(), key=lambda item: item.name):
        assembly_root = view.global_config.disassembled_code_dir / binary.name
        if not assembly_root.is_dir():
            continue
        try:
            parsed = lief.parse(str(binary.binary_path))
            if parsed is None:
                continue
            image_base = int(parsed.imagebase)
        except (OSError, RuntimeError, ValueError):
            continue
        callgraph = view.lib_dep_graph.get_callgraph_by_name(binary.name)
        functions: list[_FunctionArtifact] = []
        for assembly_path in sorted(assembly_root.glob("*.s")):
            lines = assembly_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            ranges = tuple(
                (int(match.group(1), 16), int(match.group(2), 16))
                for line in lines
                if (match := _CHUNK_RE.match(line)) is not None
            )
            entry = next(
                (
                    int(match.group(1), 16)
                    for line in lines
                    if (match := _ENTRY_RE.match(line)) is not None
                ),
                ranges[0][0] if ranges else None,
            )
            if entry is None or not ranges:
                continue
            callsites_by_ea: dict[int, object] = {}
            if callgraph is not None:
                try:
                    function = callgraph.get_node_by_ea(entry)
                except ValueError:
                    function = None
                if function is not None:
                    for callsite in function.get_callsites().values():
                        source_ea = getattr(callsite, "source_ea", None)
                        if source_ea is not None:
                            callsites_by_ea.setdefault(int(source_ea), callsite)
            instruction_lines = [
                (index, int(match.group(1), 16))
                for index, line in enumerate(lines)
                if (match := _INSTRUCTION_RE.match(line)) is not None
            ]
            assembly_context_by_ea = {
                ea: tuple(
                    lines[context_index]
                    for context_index in range(
                        max(0, line_index - 2),
                        min(len(lines), line_index + 5),
                    )
                    if _INSTRUCTION_RE.match(lines[context_index]) is not None
                )
                for line_index, ea in instruction_lines
            }
            c_path = (
                view.global_config.decompiled_code_dir
                / binary.name
                / f"{assembly_path.stem}.c"
            )
            functions.append(
                _FunctionArtifact(
                    binary_name=binary.name,
                    function_name=assembly_path.stem,
                    function_ea=entry,
                    ranges=ranges,
                    assembly_path=assembly_path.resolve(),
                    decompiled_path=c_path.resolve() if c_path.is_file() else None,
                    callsites_by_ea=callsites_by_ea,
                    assembly_context_by_ea=assembly_context_by_ea,
                )
            )
        # A basename is not a binary identity. Do not pick one of two sources.
        if sum(node.name == binary.name for node in view.lib_dep_graph.get_nodes()) != 1:
            continue
        indexes[binary.name] = _BinarySourceIndex(
            binary_name=binary.name,
            binary_path=Path(binary.binary_path).resolve(),
            image_base=image_base,
            functions=tuple(functions),
        )
    return indexes


def _loaded_images(
    trace: dict[str, object],
    indexes: dict[str, _BinarySourceIndex],
    root_binary: str,
    executed_binary_hashes: dict[str, str] | None = None,
) -> list[RuntimeImageMapping]:
    bases: dict[str, set[int]] = {}
    all_events = [
        event
        for source in ("image_loads", "events")
        for event in trace.get(source, [])
        if isinstance(event, dict)
    ]
    for event in all_events:
        if not isinstance(event, dict) or event.get("kind") != "image_load":
            continue
        match = _IMAGE_LOAD_RE.fullmatch(str(event.get("detail", "")))
        if match is not None:
            bases.setdefault(match.group("name"), set()).add(int(match.group("base"), 16))
    # main_load_address alone does not identify the image (for example after
    # exec). Missing image-load records must not be assigned to the parent.
    images = []
    for name, addresses in sorted(bases.items()):
        source = indexes.get(name)
        error = None
        actual = None
        expected = executed_binary_hashes.get(name) if executed_binary_hashes is not None else None
        basis = "Recorded image name and base; executed ELF content identity unverified."
        if len(addresses) != 1:
            error = "Conflicting load bases for the same image name."
        elif source is None:
            error = "No unique readable ELF/source index for this image name."
        elif executed_binary_hashes is not None:
            try:
                actual = hashlib.sha256(source.binary_path.read_bytes()).hexdigest()
            except OSError:
                pass
            basis = "Image name/base association with source and pre-execution staged ELF digests compared; runtime path and source-cache identity are not independently proven."
            if expected is None or actual != expected:
                error = "Source ELF does not match the pre-execution staged binary identity (or identity is missing)."
        images.append(RuntimeImageMapping(
            binary_name=name,
            runtime_base=min(addresses),
            image_base=(indexes[name].image_base if name in indexes else None),
            binary_path=(str(indexes[name].binary_path) if name in indexes else None),
            source_available=bool(source and source.functions and error is None),
            mapping_basis=basis,
            mapping_error=error,
            source_elf_sha256=actual,
            staged_elf_sha256=expected,
        ))
    return images


def _statement(path: Path | None, line_number: int | None) -> str | None:
    if path is None or line_number is None or line_number < 1:
        return None
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[line_number - 1] if line_number <= len(lines) else None


def _location_for_pc(
    runtime_pc: int,
    images: list[RuntimeImageMapping],
    indexes: dict[str, _BinarySourceIndex],
) -> RuntimeSourceLocation | None:
    matches = []
    for image in images:
        source = indexes.get(image.binary_name)
        if source is None or image.image_base is None or image.mapping_error:
            continue
        static_ea = image.image_base + runtime_pc - image.runtime_base
        if static_ea < 0:
            continue
        for function in source.functions:
            if not any(start <= static_ea < end for start, end in function.ranges):
                continue
            callsite = function.callsites_by_ea.get(static_ea)
            line_number = getattr(callsite, "line_number", None)
            matches.append(RuntimeSourceLocation(
                runtime_pc=runtime_pc,
                binary_name=image.binary_name,
                runtime_base=image.runtime_base,
                image_base=image.image_base,
                static_ea=static_ea,
                function_name=function.function_name,
                function_ea=function.function_ea,
                assembly_path=str(function.assembly_path),
                assembly_context=list(
                    function.assembly_context_by_ea.get(static_ea, ())
                ),
                decompiled_path=(
                    str(function.decompiled_path)
                    if function.decompiled_path is not None
                    else None
                ),
                ctree_index=getattr(callsite, "ctree_index", None),
                snapshot_hash=getattr(callsite, "snapshot_hash", None),
                source_ea=getattr(callsite, "source_ea", None),
                line_number=line_number,
                column_number=getattr(callsite, "column_number", None),
                expression_text=getattr(callsite, "expression_text", None),
                source_statement=_statement(function.decompiled_path, line_number),
            ))
    return matches[0] if len(matches) == 1 else None


def build_runtime_trace_context(
    raw_trace_path: Path,
    view: AnalysisView,
    *, executed_binary_hashes: dict[str, str] | None = None,
) -> RuntimeTraceContext:
    """Build the source-aware view of one complete bounded runtime trace."""
    raw_bytes = raw_trace_path.read_bytes()
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    trace = json.loads(raw_bytes.decode("utf-8"))
    if not isinstance(trace, dict):
        raise ValueError(f"runtime trace is not an object: {raw_trace_path}")
    indexes = _source_indexes(view)
    images = _loaded_images(trace, indexes, view.root.name, executed_binary_hashes)

    aggregate: dict[tuple[str, str, int], list[object]] = {}
    mapped_unique_blocks = 0
    blocks = trace.get("blocks", [])
    if not isinstance(blocks, list):
        raise ValueError("runtime trace blocks must be a list")
    for block in blocks:
        if not isinstance(block, dict):
            continue
        pc = int(block["pc"])
        hit_count = int(block["hit_count"])
        location = _location_for_pc(pc, images, indexes)
        if location is None:
            continue
        mapped_unique_blocks += 1
        key = (
            location.binary_name,
            location.function_name,
            location.function_ea,
        )
        state = aggregate.setdefault(key, [0, 0, location])
        state[0] = int(state[0]) + 1
        state[1] = int(state[1]) + hit_count

    functions = [
        RuntimeFunctionSummary(
            binary_name=key[0],
            function_name=key[1],
            function_ea=key[2],
            unique_blocks=int(state[0]),
            total_hits=int(state[1]),
            assembly_path=state[2].assembly_path,
            decompiled_path=state[2].decompiled_path,
        )
        for key, state in aggregate.items()
    ]
    functions.sort(
        key=lambda item: (-item.total_hits, item.binary_name, item.function_ea)
    )

    def map_tail(name: str) -> list[RuntimeRecentBlock]:
        return [
            RuntimeRecentBlock(
                runtime_pc=int(item["pc"]),
                consecutive_hits=int(item["consecutive_hits"]),
                location=_location_for_pc(int(item["pc"]), images, indexes),
            )
            for item in trace.get(name, [])
            if isinstance(item, dict)
        ]

    recent_focus_blocks = map_tail("recent_focus_blocks")
    recent_blocks = map_tail("recent_blocks")
    events = [
        RuntimeEventContext(
            sequence=int(item["sequence"]),
            last_sequence=int(item.get("last_sequence", item["sequence"])),
            repeat_count=int(item.get("repeat_count", 1)),
            kind=str(item["kind"]),
            detail=str(item["detail"]),
            unit_id=(str(item["unit_id"]) if item.get("unit_id") is not None else None),
            hook_id=(str(item["hook_id"]) if item.get("hook_id") is not None else None),
            elapsed_ns=int(item.get("elapsed_ns", 0)),
            last_elapsed_ns=int(item.get("last_elapsed_ns", item.get("elapsed_ns", 0))),
            detail_dropped_bytes=int(item.get("detail_dropped_bytes", 0)),
            runtime_pc=(int(item["pc"]) if item.get("pc") is not None else None),
            registers=[
                RuntimeRegister(name=str(register["name"]), value=int(register["value"]))
                for register in item.get("registers", [])
                if isinstance(register, dict)
            ],
            memory=[
                RuntimeMemorySnapshot(
                    address=int(memory["address"]),
                    requested_bytes=int(memory.get("requested_bytes", len(memory.get("bytes", [])))),
                    source_register=str(memory.get("source_register", "unknown")),
                    bytes=[int(value) for value in memory.get("bytes", [])],
                    error=(str(memory["error"]) if memory.get("error") is not None else None),
                )
                for memory in item.get("memory", [])
                if isinstance(memory, dict)
            ],
            location=(
                _location_for_pc(int(item["pc"]), images, indexes)
                if item.get("pc") is not None
                else None
            ),
        )
        for item in trace.get("events", [])
        if isinstance(item, dict)
    ]
    return RuntimeTraceContext(
        schema_version=4,
        raw_trace_schema_version=int(trace.get("schema_version", 0)),
        guest_arch=str(trace.get("guest_arch", "unknown")),
        byte_order=str(trace.get("byte_order", "unknown")),
        word_bits=int(trace.get("word_bits", 0)),
        started_unix_ns=int(trace.get("started_unix_ns", 0)),
        host_pid=int(trace.get("host_pid", 0)),
        origin_pid=int(trace.get("origin_pid", 0)),
        checkpoint_elapsed_ns=int(trace.get("checkpoint_elapsed_ns", 0)),
        terminal_reason=(str(trace["terminal_reason"]) if trace.get("terminal_reason") is not None else None),
        raw_trace_bytes=len(raw_bytes),
        raw_trace_sha256=raw_sha256,
        integrity_status=(
            "complete"
            if trace.get("terminal_reason") is not None
            else "partial"
        ),
        dropped_events=int(trace.get("dropped_events", 0)),
        dropped_image_loads=int(trace.get("dropped_image_loads", 0)),
        dropped_tail_entries=int(trace.get("dropped_tail_entries", 0)),
        dropped_focus_tail_entries=int(trace.get("dropped_focus_tail_entries", 0)),
        observed_unique_blocks=int(trace.get("observed_unique_blocks", len(blocks))),
        dropped_unique_blocks=int(trace.get("dropped_unique_blocks", 0)),
        main_load_address=int(trace.get("main_load_address", 0)),
        total_block_executions=int(trace.get("total_block_executions", 0)),
        mapped_unique_blocks=mapped_unique_blocks,
        unmapped_unique_blocks=max(0, len(blocks) - mapped_unique_blocks),
        images=images,
        functions=functions,
        recent_focus_blocks=recent_focus_blocks,
        recent_blocks=recent_blocks,
        events=events,
    )


def render_runtime_trace_context(context: RuntimeTraceContext) -> str:
    """Pure lossless dictionary rendering; raw JSON remains independently readable."""
    return "# Runtime trace context\n\n```json\n" + json.dumps(
        compact_trace_context(context.model_dump(mode="json")),
        ensure_ascii=False, indent=2,
    ) + "\n```\n"


def persist_runtime_trace_context(
    raw_trace_path: Path,
    output_dir: Path,
    view: AnalysisView,
    *, executed_binary_hashes: dict[str, str] | None = None,
) -> tuple[Path, Path]:
    context = build_runtime_trace_context(raw_trace_path, view, executed_binary_hashes=executed_binary_hashes)
    json_path = output_dir / "runtime_trace_context.json"
    markdown_path = output_dir / "runtime_trace_context.md"
    write_model_json(json_path, context)
    context = load_model_json(json_path, RuntimeTraceContext)
    write_text(markdown_path, render_runtime_trace_context(context))
    write_text(json_path.with_suffix(".compact.json"), json.dumps(
        compact_trace_context(context.model_dump(mode="json")), ensure_ascii=False, indent=2) + "\n")
    return json_path, markdown_path


__all__ = [
    "build_runtime_trace_context",
    "persist_runtime_trace_context",
    "render_runtime_trace_context",
]
