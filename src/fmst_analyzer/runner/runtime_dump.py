"""Persist bounded guest crash evidence produced by the embedded harness.

The Controller collects guest ELF cores from the disposable container. This module
only inventories and copies evidence; it never infers a crash from a missing
file and never treats an ELF-loaded byte as captured guest memory.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import time
from pathlib import Path
from typing import Literal

from pydantic import Field

from .budget import ExecutionBudget
from .schema import StrictModel


class RuntimeDumpManifest(StrictModel):
    schema_version: Literal[2] = 2
    session_id: str
    attempt_number: int
    status: Literal["complete", "partial", "unavailable"]
    capture_kind: Literal["crash", "pre_exit", "stall_capture", "last_checkpoint"]
    source: Literal["guest_elf_core", "none"]
    guest_arch: str
    byte_order: str
    word_bits: int
    role: str = "target"
    pid: int | None = None
    tid: int | None = None
    sampled_unix_ns: int
    termination_reason: str
    execution_identity_version: int = 2
    execution_hashes: dict[str, str | None] = Field(default_factory=dict)
    core_candidates: list[dict] = Field(default_factory=list, description="All retained candidates with parsed note identity and explicit target association.")
    core_path: str | None = None
    load_map_path: str | None = None
    files: dict[str, str] = Field(default_factory=dict, description="Relative evidence path to SHA-256.")
    captured_ranges: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    debugger_image: str | None = None
    debugger_command: list[str] = Field(default_factory=list)


def _sha256(path: Path, budget: ExecutionBudget | None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if budget is not None:
                budget.check(cleanup=True)
            digest.update(chunk)
    return digest.hexdigest()


def _capture_kind(termination_reason: str, core_paths: list[Path]) -> str:
    if core_paths:
        return "crash"
    if termination_reason in {"target_exit", "container_exit"}:
        return "pre_exit"
    if termination_reason == "no_progress_watchdog":
        return "stall_capture"
    return "last_checkpoint"


def _valid_guest_core(path: Path, guest_arch: str, byte_order: str, word_bits: int) -> tuple[bool, str | None]:
    """Check only the ELF identity needed before calling a file a guest core."""
    machines = {
        "arm": {40}, "aarch64": {183}, "mips": {8}, "mipsel": {8},
        "mipsbe": {8},
    }
    try:
        with path.open("rb") as stream:
            ident = stream.read(20)
        if len(ident) < 20 or ident[:4] != b"\x7fELF":
            return False, "missing ELF magic"
        expected_class = 1 if word_bits == 32 else 2
        if word_bits in {32, 64} and ident[4] != expected_class:
            return False, f"ELF class {ident[4]} does not match {word_bits}-bit guest"
        expected_data = 1 if byte_order == "little" else 2 if byte_order == "big" else None
        if expected_data is not None and ident[5] != expected_data:
            return False, f"ELF byte order {ident[5]} does not match {byte_order} guest"
        endian = "little" if ident[5] == 1 else "big"
        elf_type = int.from_bytes(ident[16:18], endian)
        machine = int.from_bytes(ident[18:20], endian)
        if elf_type != 4:
            return False, f"ELF type {elf_type} is not ET_CORE"
        allowed = machines.get(guest_arch, set())
        if allowed and machine not in allowed:
            return False, f"ELF machine {machine} does not match guest arch {guest_arch}"
        return True, None
    except (OSError, ValueError) as error:
        return False, str(error)


def _core_identity(path: Path) -> dict:
    """Decode supported Linux/QEMU note layouts; never supply missing identity.

    PRSTATUS IDs are LWPs, not independent process IDs. PRPSINFO owns PID.
    Unknown architectures/layouts remain diagnostic evidence without attribution.
    """
    result = {"pid": None, "tids": [], "executable": None, "errors": []}
    try:
        with path.open("rb") as stream:
            ident = stream.read(16)
            endian = ">" if ident[5] == 2 else "<"
            wide = ident[4] == 2
            header = struct.unpack(endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), stream.read(48 if wide else 36))
            machine = header[1]
            # Explicit ABI layouts, not a search for plausible integer values.
            layout = {(40, False): (12, 28, 44, 24), (183, True): (24, 40, 56, 32), (8, False): (16, 32, 48, 24)}.get((machine, wide))
            if layout is None:
                result["errors"].append("Unsupported core note ABI; process identity is unknown")
                return result
            phoff, phsize, phnum = header[4], header[8], header[9]
            for index in range(phnum):
                stream.seek(phoff + index * phsize)
                ph = struct.unpack(endian + ("IIQQQQQQ" if wide else "IIIIIIII"), stream.read(56 if wide else 32))
                if ph[0] != 4:
                    continue
                offset, size = (ph[2], ph[5]) if wide else (ph[1], ph[4])
                if size > 16 * 1024 * 1024:
                    raise ValueError("Core note segment exceeds 16 MiB")
                stream.seek(offset)
                notes = stream.read(size)
                cursor = 0
                while cursor + 12 <= len(notes):
                    namesz, descsz, kind = struct.unpack_from(endian + "III", notes, cursor)
                    cursor += 12
                    name = notes[cursor:cursor + namesz].rstrip(b"\0")
                    cursor += (namesz + 3) & ~3
                    desc = notes[cursor:cursor + descsz]
                    cursor += (descsz + 3) & ~3
                    if len(desc) != descsz or cursor > len(notes):
                        raise ValueError("Truncated ELF note")
                    if name != b"CORE":
                        continue
                    pid_offset, fname_offset, args_offset, tid_offset = layout
                    if kind == 3 and len(desc) >= args_offset + 80:
                        result["pid"] = struct.unpack_from(endian + "i", desc, pid_offset)[0]
                        result["executable"] = desc[args_offset:args_offset + 80].split(b"\0", 1)[0].decode("utf-8", errors="replace").split(" ", 1)[0]
                    elif kind == 1 and len(desc) >= tid_offset + 4:
                        result["tids"].append(struct.unpack_from(endian + "i", desc, tid_offset)[0])
    except (OSError, ValueError, struct.error, IndexError) as error:
        result["errors"].append(str(error))
    return result

def _trace_metadata(attempt_dir: Path) -> tuple[str, str, int, dict[str, object]]:
    trace = attempt_dir / "runtime_trace.json"
    if not trace.is_file():
        return "unknown", "unknown", 0, {}
    try:
        data = json.loads(trace.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "unknown", "unknown", 0, {}
    if not isinstance(data, dict):
        return "unknown", "unknown", 0, {}
    return (str(data.get("guest_arch", "unknown")), str(data.get("byte_order", "unknown")),
            int(data.get("word_bits", 0) or 0), data)


def _core_ranges(path: Path) -> list[str]:
    """List file-backed PT_LOAD ranges without interpreting memory contents."""
    try:
        with path.open("rb") as stream:
            ident = stream.read(16)
            if ident[:4] != b"\x7fELF":
                return []
            endian = ">" if ident[5] == 2 else "<"
            is_64 = ident[4] == 2
            if is_64:
                header = struct.unpack(endian + "HHIQQQIHHHHHH", stream.read(48))
                phoff, phentsize, phnum = header[4], header[8], header[9]
                fmt, size = endian + "IIQQQQQQ", 56
            else:
                header = struct.unpack(endian + "HHIIIIIHHHHHH", stream.read(36))
                phoff, phentsize, phnum = header[4], header[8], header[9]
                fmt, size = endian + "IIIIIIII", 32
            ranges: list[str] = []
            for index in range(phnum):
                stream.seek(phoff + index * phentsize)
                values = struct.unpack(fmt, stream.read(size))
                if is_64:
                    p_type, _, _, vaddr, _, filesz, _, _ = values
                else:
                    p_type, _, vaddr, _, filesz, _, _, _ = values
                if p_type == 1 and filesz:
                    ranges.append(f"0x{vaddr:x}+0x{filesz:x}")
            return ranges
    except (OSError, struct.error, ValueError):
        return []


def collect_runtime_dump(
    *,
    attempt_dir: Path,
    staged_rootfs: Path | None,
    executable_path: str,
    session_id: str,
    attempt_number: int,
    termination_reason: str,
    budget: ExecutionBudget | None = None,
    debugger_image: str | None = None,
    execution_hashes: dict[str, str | None] | None = None,
) -> Path:
    """Create ``runtime-dump/manifest.json`` before the attempt is cleaned.

    Core files are emitted by the actual LibAFL/QEMU guest harness. The
    manifest remains useful when no core exists: it records the sampling kind,
    missing evidence, and the fact that only a historical checkpoint/trace is
    available.
    """
    attempt_dir = Path(attempt_dir)
    root = attempt_dir / "runtime-dump"
    root.mkdir(parents=True, exist_ok=True)
    if budget is not None:
        budget.check(cleanup=True)
    guest_arch, byte_order, word_bits, trace = _trace_metadata(attempt_dir)
    candidate_cores = sorted(path for pattern in ("*.core", "collected-cores/*.core") for path in attempt_dir.glob(pattern) if path.is_file())
    cores: list[Path] = []
    invalid_cores: list[tuple[Path, str]] = []
    for candidate in candidate_cores:
        valid, reason = _valid_guest_core(candidate, guest_arch, byte_order, word_bits)
        if valid:
            cores.append(candidate)
        else:
            invalid_cores.append((candidate, reason or "invalid ELF core"))
    target_receipt: dict[str, object] = {}
    target_exit = attempt_dir / "target-exit.json"
    if target_exit.is_file():
        try:
            loaded = json.loads(target_exit.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                target_receipt = loaded
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            pass
    kind = _capture_kind(termination_reason, cores)
    manifest = RuntimeDumpManifest(
        session_id=session_id, attempt_number=attempt_number, status="unavailable",
        capture_kind=kind, source="guest_elf_core" if cores else "none",
        guest_arch=guest_arch, byte_order=byte_order, word_bits=word_bits,
        sampled_unix_ns=time.time_ns(), termination_reason=termination_reason,

        debugger_image=debugger_image,
        debugger_command=(
            ["gdb-multiarch", "--nx", "--nh", "-iex", "set auto-load off",
             "-iex", "set debuginfod enabled off", "guest.elf", "guest.core"]
            if debugger_image else []
        ),
        execution_hashes=dict(execution_hashes or {}),
        limitations=[
            "A guest core is a diagnostic snapshot, not a resumable VM/checkpoint.",
            "Uncaptured guest memory is unknown; bytes loaded from an ELF remain static evidence.",
            "This manifest does not claim atomic target/peer/network/fd state.",
            "Copied images are staged static files associated by PID and command notes; their bytes are not captured runtime memory.",
        ],
    )
    collection = attempt_dir / "core-collection.json"
    if collection.is_file():
        shutil.copy2(collection, root / collection.name)
        manifest.files["runtime-dump/" + collection.name] = _sha256(root / collection.name, budget)
        try:
            manifest.errors.extend(json.loads(collection.read_text()).get("errors", []))
        except (ValueError, OSError) as error:
            manifest.errors.append(str(error))
    target_pid = trace.get("host_pid")
    if target_receipt.get("pid") is not None and target_pid != target_receipt["pid"]:
        manifest.errors.append("Primary trace and target exit PID disagree or primary trace is missing")
        target_pid = None
    matched = []
    for index, candidate in enumerate(candidate_cores):
        identity = _core_identity(candidate) if candidate in cores else {"errors": ["Invalid guest ELF core"]}
        destination = root / "cores" / f"{index:04d}.core"
        destination.parent.mkdir(exist_ok=True)
        shutil.copy2(candidate, destination)
        relative = destination.relative_to(attempt_dir).as_posix()
        manifest.files[relative] = _sha256(destination, budget)
        associated = (candidate in cores and isinstance(target_pid, int) and not isinstance(target_pid, bool) and target_pid > 0 and
            identity.get("pid") == target_pid and identity.get("executable") == executable_path and not identity["errors"])
        manifest.core_candidates.append({"source_path": candidate.relative_to(attempt_dir).as_posix(),
            "path": relative, "identity": identity, "association": "target" if associated else "unverified"})
        if associated:
            matched.append((candidate, identity))
    for invalid, reason in invalid_cores:
        manifest.errors.append(f"core candidate {invalid.name} rejected: {reason}")
    if len(matched) != 1 and cores:
        manifest.missing.append(f"Unique target core association unavailable: {len(matched)} matching candidates")
    if len(matched) == 1:
        source_core, identity = matched[0]
        manifest.pid = identity["pid"]
        manifest.tid = None  # PRSTATUS lists LWPs; ordering does not identify the faulting thread.
        target = root / "guest.core"
        shutil.copy2(source_core, target)
        manifest.core_path = str(target.relative_to(attempt_dir))
        manifest.files[manifest.core_path] = _sha256(target, budget)
        manifest.captured_ranges = _core_ranges(target)
        if not manifest.captured_ranges:
            manifest.limitations.append("Core program-header ranges could not be enumerated; captured memory extent is unknown.")
        if staged_rootfs is None or not staged_rootfs.is_dir():
            manifest.errors.append("staged rootfs unavailable while copying matching guest ELF")
        else:
            target_path = (staged_rootfs / executable_path.lstrip("/")).resolve()
            try:
                target_path.relative_to(staged_rootfs.resolve())
                if target_path.is_file():
                    elf = root / "guest.elf"
                    shutil.copy2(target_path, elf)
                    relative = str(elf.relative_to(attempt_dir))
                    manifest.files[relative] = _sha256(elf, budget)
                else:
                    manifest.missing.append(f"target ELF is not a file: {executable_path}")
            except (OSError, ValueError) as error:
                manifest.errors.append(f"target ELF copy failed: {error}")
            # Preserve the concrete load-map facts emitted by runtime_trace.
            load_map = root / "load-map.json"
            load_map.write_text(json.dumps({
                "guest_arch": guest_arch,
                "byte_order": byte_order,
                "word_bits": word_bits,
                "main_load_address": trace.get("main_load_address"),
                "image_loads": trace.get("image_loads", []),
                "images": trace.get("images", []),
                "source": "runtime_trace; not a /proc map and not an atomic snapshot",
            }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            manifest.load_map_path = str(load_map.relative_to(attempt_dir))
            manifest.files[manifest.load_map_path] = _sha256(load_map, budget)
            image_loads = trace.get("image_loads")
            if not isinstance(image_loads, list) or not image_loads:
                manifest.limitations.append("No runtime image-load events were retained; shared-library set is unavailable.")
            else:
                images_root = root / "images"
                images_root.mkdir(parents=True, exist_ok=True)
                for index, item in enumerate(image_loads, start=1):
                    if not isinstance(item, dict):
                        continue
                    detail = str(item.get("detail", ""))
                    guest_name = detail.split("@", 1)[0]
                    if not guest_name or guest_name == executable_path:
                        continue
                    if not guest_name.startswith("/"):
                        manifest.missing.append(f"Runtime image basename has no bound guest path: {guest_name}")
                        continue
                    candidate = (staged_rootfs / guest_name.lstrip("/")).resolve()
                    try:
                        candidate.relative_to(staged_rootfs.resolve())
                    except ValueError:
                        manifest.missing.append(f"image path escapes staged rootfs: {guest_name}")
                        continue
                    if not candidate.is_file():
                        manifest.missing.append(f"loaded image is unavailable in staged rootfs: {guest_name}")
                        continue
                    image = images_root / f"{index:03d}-{candidate.name}"
                    shutil.copy2(candidate, image)
                    relative = str(image.relative_to(attempt_dir))
                    manifest.files[relative] = _sha256(image, budget)
                if not any(path.startswith("runtime-dump/images/") for path in manifest.files):
                    manifest.limitations.append("Runtime image-load events did not resolve to copyable guest libraries.")
    else:
        if not cores:
            manifest.missing.append("guest ELF core was not produced by the harness")
        if not (attempt_dir / "runtime_trace.json").is_file():
            manifest.missing.append("runtime trace is unavailable")
    if manifest.errors:
        manifest.status = "partial" if manifest.files else "unavailable"
    elif cores and manifest.core_path and str((root / "guest.elf").relative_to(attempt_dir)) in manifest.files:
        manifest.status = "complete"
    elif candidate_cores:
        manifest.status = "partial"
    manifest_path = root / "manifest.json"
    manifest_path.write_text(manifest.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return manifest_path


__all__ = ["RuntimeDumpManifest", "collect_runtime_dump"]
