"""Source-bound GNU GDB queries of a captured guest core, without an inferior."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import struct
from typing import Literal
import uuid

from .budget import ExecutionBudget, RunnerStopped, run_process
from .runtime_dump import RuntimeDumpManifest


def _hash(path: Path, budget: ExecutionBudget | None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if budget is not None:
                budget.check()
            digest.update(chunk)
    return digest.hexdigest()


def _query_commands(operation: str, thread_id: int, address: str, count: int) -> list[str]:
    if isinstance(thread_id, bool) or not isinstance(thread_id, int) or thread_id < 0:
        raise ValueError("thread_id is a nonnegative GDB thread index; 0 means all threads")
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 256:
        raise ValueError("count must be between 1 and 256")
    if operation == "threads":
        return ["info threads"]
    if operation == "registers":
        return ["thread apply all info registers"] if thread_id == 0 else [f"thread {thread_id}", "info registers"]
    if operation == "backtrace":
        if count > 32:
            raise ValueError("backtrace count is at most 32 frames")
        return [f"thread apply all bt {count}"] if thread_id == 0 else [f"thread {thread_id}", f"bt {count}"]
    if operation not in {"memory", "disassemble"}:
        raise ValueError("Unknown core query operation")
    if thread_id == 0:
        raise ValueError("memory/disassemble requires a positive GDB thread index")
    if operation == "disassemble" and count > 64:
        raise ValueError("disassemble count is at most 64 instructions")
    # Numeric addresses or a register with one numeric offset only. Never accept
    # arbitrary GDB expressions, function calls, commands, or convenience variables.
    if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|[0-9]+|\$[a-zA-Z][a-zA-Z0-9_]*(?:[+-](?:0[xX][0-9a-fA-F]+|[0-9]+))?)", address):
        raise ValueError("address must be an integer or register with optional integer offset, e.g. 0x4000 or $sp-64")
    return [f"thread {thread_id}", f"x/{count}{'bx' if operation == 'memory' else 'i'} {address}"]


def _captured_load_ranges(path: Path) -> list[tuple[int, int]]:
    """File-backed bytes only; p_memsz can include pages omitted by QEMU."""
    with path.open("rb") as stream:
        ident = stream.read(16)
        if len(ident) != 16 or ident[:4] != b"\x7fELF" or ident[4] not in {1, 2} or ident[5] not in {1, 2}:
            raise ValueError("Invalid ELF core header")
        endian = "<" if ident[5] == 1 else ">"
        wide = ident[4] == 2
        header = struct.unpack(endian + ("HHIQQQIHHHHHH" if wide else "HHIIIIIHHHHHH"), stream.read(48 if wide else 36))
        phoff, phentsize, phnum = header[4], header[8], header[9]
        ranges = []
        size = path.stat().st_size
        for index in range(phnum):
            stream.seek(phoff + index * phentsize)
            values = struct.unpack(endian + ("IIQQQQQQ" if wide else "IIIIIIII"), stream.read(56 if wide else 32))
            kind = values[0]
            offset, address, filesz = (values[2], values[3], values[5]) if wide else (values[1], values[2], values[4])
            if kind == 1 and filesz:
                if offset + filesz > size:
                    raise ValueError("Core PT_LOAD bytes extend beyond captured file")
                ranges.append((address, address + filesz))
        return sorted(ranges)


def inspect_core(
    manifest_path: Path | None, *,
    operation: Literal["threads", "registers", "memory", "disassemble", "backtrace"] = "registers",
    thread_id: int = 0, address: str = "", count: int = 32,
    manifest_sha256: str | None = None, budget: ExecutionBudget | None = None,
    core_path: Path | None = None, core_sha256: str | None = None,
    output_root: Path | None = None,
) -> dict:
    """Inspect only a verified core selected by the latest Controller manifest.

    A private byte snapshot is retained for every query. No staged ELF, library,
    init file, debuginfod, inferior, shell, Python or Agent-supplied command is
    loaded. GDB's output remains evidence, not a crash-thread or cause verdict.
    """
    queries = _query_commands(operation, thread_id, address, count)
    receipt = {
        "schema_version": 1, "status": "unavailable", "request": {
            "operation": operation, "thread_id": thread_id, "address": address, "count": count,
        }, "sources": {}, "command": [], "returncode": None, "stdout": "", "stderr": "",
        "error": None,
        "limitations": [
            "Staged ELF/shared-library bytes are not supplied; memory/disassembly requires file-backed PT_LOAD bytes.",
            "GDB thread indices and its current-thread selection do not establish the faulting thread.",
            "Backtraces and automatic frame descriptions are GDB inference and may include synthesized zeros from uncaptured pages; corroborate them with guarded memory queries.",
            "A register/stack value does not alone identify a cause.",
            "No live guest is resumed; this query cannot measure an uncaptured earlier memory write.",
        ],
    }
    if core_path is None and (manifest_path is None or not Path(manifest_path).is_file()):
        receipt["error"] = "No core manifest is available for the latest attempt"
        return receipt
    manifest_path = Path(manifest_path).resolve() if manifest_path else None
    base = output_root if output_root is not None else (Path(core_path).parent if core_path else manifest_path.parent.parent)
    output = base / "core-inspections" / uuid.uuid4().hex
    output.mkdir(parents=True)
    receipt["receipt_path"] = str(output / "receipt.json")
    try:
        if core_path is not None:
            from .runtime_dump import _valid_guest_core, _core_identity
            source = Path(core_path).resolve(strict=True)
            valid, error = _valid_guest_core(source, 'unknown', 'unknown', 0)
            if not valid:
                raise ValueError(error)
            identity = _core_identity(source)
            receipt['target_pid'] = identity['pid']
            receipt['faulting_tid'] = None
            receipt['association'] = 'Explicit file selection; execution association is not inferred.'
            receipt['core_identity'] = identity
            expected = core_sha256
            guest_arch = 'unknown'
        else:
            raw = manifest_path.read_bytes()
            manifest_hash = hashlib.sha256(raw).hexdigest()
            receipt["sources"]["manifest"] = {"path": str(manifest_path), "sha256": manifest_hash}
            (output / "manifest.json").write_bytes(raw)
            if manifest_sha256 is not None and manifest_sha256 != manifest_hash:
                receipt["status"] = "source_changed"
                raise ValueError("Latest manifest differs from the requested source SHA-256")
            manifest = RuntimeDumpManifest.model_validate_json(raw)
            if manifest.core_path is None or not isinstance(manifest.pid, int) or manifest.pid <= 0:
                raise ValueError("Latest manifest has no verified target core association")
            attempt_root = manifest_path.parent.parent
            source = (attempt_root / manifest.core_path).resolve(strict=True)
            source.relative_to(attempt_root)
            expected = manifest.files.get(manifest.core_path)
            if not expected:
                raise ValueError("Selected core has no bound content SHA-256")
            guest_arch = manifest.guest_arch
            receipt["target_pid"] = manifest.pid
            receipt["faulting_tid"] = manifest.tid
        snapshot = output / "guest.core"
        with source.open("rb") as reader, snapshot.open("wb") as writer:
            while chunk := reader.read(1024 * 1024):
                if budget is not None:
                    budget.check()
                writer.write(chunk)
        actual = _hash(snapshot, budget)
        receipt["sources"]["core"] = {"path": str(source), "snapshot": str(snapshot), "sha256": actual}
        if expected is not None and actual != expected:
            receipt["status"] = "source_changed"
            raise ValueError("Selected core bytes differ from the Controller manifest")
        snapshot.chmod(0o444)
        debugger = shutil.which("gdb-multiarch")
        if debugger is None:
            import platform
            with snapshot.open('rb') as stream:
                header = stream.read(20)
            machine = int.from_bytes(header[18:20], 'little' if header[5] == 1 else 'big')
            native_machine = {'x86_64':62, 'aarch64':183, 'arm64':183, 'i386':3, 'i686':3}.get(platform.machine())
            if machine != native_machine:
                raise RuntimeError('Cross-architecture core inspection needs gdb-multiarch; install it in this task container and retry.')
            debugger = shutil.which("gdb")
        if debugger is None:
            raise RuntimeError("GNU GDB is unavailable; install a GDB build supporting the guest architecture")
        command = [debugger, "--nx", "--nh", "--batch",
            "-iex", "set auto-load off", "-iex", "set debuginfod enabled off",
            "-iex", "set auto-solib-add off", "-iex", f"set sysroot {output / 'no-sysroot'}",
            "-iex", "set trust-readonly-sections off", "--core=" + str(snapshot)]
        for query in queries:
            command += ["-ex", query]
        receipt["command"] = command
        # A local process group shares Runner cancellation/deadline. No Docker
        # daemon or live guest resource is granted to the querying Agent.
        def execute(argv):
            if budget is None:
                return subprocess.run(argv, capture_output=True, text=True, timeout=30)
            return run_process(argv, budget=budget, timeout=30, capture_output=True, text=True)
        if operation in {"memory", "disassemble"}:
            ranges = _captured_load_ranges(snapshot)
            receipt["captured_load_ranges"] = [[hex(start), hex(end)] for start, end in ranges]
            # GDB can synthesize zeros for PT_LOAD memory pages with p_filesz=0.
            # Resolve the address without reading memory, then check the actual
            # file-backed interval before any x command executes.
            address_command = command[:-4] + ["-ex", f"thread {thread_id}", "-ex",
                f'printf "__FMST_ADDRESS__=%#lx\\n", (unsigned long)({address})']
            receipt["address_command"] = address_command
            result = execute(address_command)
            receipt.update(stdout=result.stdout, stderr=result.stderr, returncode=result.returncode)
            match = re.search(r"__FMST_ADDRESS__=(0x[0-9a-fA-F]+|0)\b", result.stdout)
            if result.returncode or match is None:
                receipt["status"] = "query_failed"
                raise ValueError("GDB could not resolve the requested register/address")
            resolved = int(match[1], 0)
            length = count if operation == "memory" else count * (4 if guest_arch in {"arm", "aarch64", "mips", "mipsel", "mipsbe"} else 15)
            end = resolved + length
            covered = resolved
            for start, stop in ranges:
                if start <= covered < stop:
                    covered = stop
                if covered >= end:
                    break
            receipt["requested_range"] = {"start": hex(resolved), "maximum_bytes": length}
            if covered < end:
                receipt["status"] = "unavailable"
                receipt["command"] = []
                raise ValueError("Requested memory/code interval includes uncaptured bytes; GDB zero-filled pages are not evidence")
        result = execute(command)
        receipt.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr,
            status="ok" if result.returncode == 0 else "query_failed")
    except RunnerStopped as error:
        receipt.update(status="stopped", error=str(error),
            stdout=_text(getattr(error, "output", None)), stderr=_text(getattr(error, "stderr", None)))
        raise
    except subprocess.TimeoutExpired as error:
        receipt.update(status="timeout", error=str(error),
            stdout=_text(error.stdout), stderr=_text(error.stderr))
    except (OSError, ValueError, RuntimeError, struct.error) as error:
        receipt["error"] = str(error)
    finally:
        (output / "stdout.txt").write_text(receipt["stdout"])
        (output / "stderr.txt").write_text(receipt["stderr"])
        (output / "receipt.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    return receipt


def _text(value) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""


def render_inspection(receipt: dict) -> str:
    rendered = json.dumps(receipt, ensure_ascii=False)
    if len(rendered) <= 24000:
        return rendered
    return json.dumps({**{k: v for k, v in receipt.items() if k not in {"stdout", "stderr"}},
        "output_notice": "Complete output exceeds the 24000-character transport budget; no bytes were truncated. Read receipt_path or the adjacent stdout.txt/stderr.txt.",
        "complete_output_chars": {k: len(receipt[k]) for k in ("stdout", "stderr")},
    }, ensure_ascii=False)
