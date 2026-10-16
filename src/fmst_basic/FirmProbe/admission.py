"""Read-only content admission, distinct from runtime readiness.

A usable target can be analyzed with missing loader inputs. Such inputs remain
explicit partial findings; directory shape alone cannot establish an ELF source.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import struct
from typing import Literal

from pydantic import BaseModel, Field

from fmst_basic.utils.guest_paths import resolve_guest_file, resolve_guest_path


def is_readable_elf(path: Path) -> bool:
    """Check the complete ELF header without depending on host executability."""
    try:
        if not path.stat().st_mode & 0o444:
            return False
        with path.open("rb") as stream:
            header = stream.read(64)
        if header[:4] != b"\x7fELF" or len(header) < 16 or header[4] not in (1, 2) or header[5] not in (1, 2) or header[6] != 1:
            return False
        length = 52 if header[4] == 1 else 64
        if len(header) < length:
            return False
        endian = "<" if header[5] == 1 else ">"
        kind, machine, version = struct.unpack_from(endian + "HHI", header, 16)
        size = struct.unpack_from(endian + "H", header, 40 if header[4] == 1 else 52)[0]
        return kind in (2, 3) and machine != 0 and version == 1 and size == length
    except OSError:
        return False


def inspect_root_content(rootfs: Path) -> dict:
    """Inventory readable ELF sources and guest-link/I/O limitations."""
    rootfs = Path(rootfs).absolute().resolve()
    elfs, limitations = [], []

    def walk_error(error):
        limitations.append(dict(kind="unreadable_directory", path=str(error.filename), reason=str(error)))

    for directory, dirs, files in os.walk(rootfs, followlinks=False, onerror=walk_error):
        for name in sorted([*dirs, *files]):
            path = Path(directory) / name
            relative = path.relative_to(rootfs).as_posix()
            try:
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    if resolve_guest_path(rootfs, relative) is None:
                        limitations.append(dict(kind="unresolved_guest_link", path=relative, target=os.readlink(path)))
                elif stat.S_ISREG(mode):
                    if not mode & 0o444:
                        limitations.append(dict(kind="unreadable_file", path=relative))
                        continue
                    with path.open("rb") as stream:
                        magic = stream.read(4)
                    if magic == b"\x7fELF":
                        if is_readable_elf(path):
                            elfs.append(relative)
                        else:
                            limitations.append(dict(kind="invalid_elf_header", path=relative))
            except OSError as error:
                limitations.append(dict(kind="input_io_error", path=relative, reason=str(error)))
    return dict(elf_paths=sorted(elfs), limitations=limitations)


class TargetAdmission(BaseModel):
    schema_version: Literal[1] = 1
    target_path: str = Field(description="Requested guest-relative target path.")
    resolved_path: str = Field(description="Selected regular ELF after guest symlink expansion.")
    guest_path_chain: list[str] = Field(description="Guest aliases and expansions, never host symlink targets.")
    status: Literal["complete", "partial"] = Field(description="Static loader closure status under the baseline namespace; never runtime readiness.")
    dependencies: list[dict] = Field(description="Interpreter and transitive DT_NEEDED resolution observations.")
    limitations: list[dict] = Field(description="Missing, unreadable or unresolved baseline loader inputs; preserved for downstream planning.")


def inspect_target_input(rootfs: Path, target: str | Path) -> TargetAdmission:
    """Require a readable parseable selected ELF; retain loader closure gaps.

    Missing/ambiguous DT_NEEDED is a limitation, not a guessed provider. No
    library is chosen by an arbitrary basename when several candidates exist.
    """
    import lief

    rootfs = Path(rootfs).absolute().resolve()
    path = Path(target)
    if path.is_absolute() and (path == rootfs or rootfs in path.parents):
        raw = path.relative_to(rootfs).as_posix()
    elif isinstance(target, str):
        raw = PurePosixPath(target).as_posix().lstrip("/")
    elif path.is_absolute():
        raise ValueError(f"Host target path is outside guest rootfs: {path}")
    else:
        raw = path.as_posix()
    resolution = resolve_guest_file(rootfs, raw)
    if resolution is None or not is_readable_elf(resolution[1]):
        raise ValueError(f"Selected target is not a readable valid ELF inside guest rootfs: {raw}")
    chain, selected = resolution
    limitations, dependencies = [], []
    from fmst_basic.utils.guest_libraries import GuestLibraryResolver
    from fmst_basic.utils.file_utils import AmbiguousBinaryError
    pending, visited = [(selected, ())], set()
    try:
        resolver = GuestLibraryResolver(rootfs, selected)
    except ValueError as error:
        resolver = None
        limitations.append(dict(kind="unresolved_loader_namespace", reason=str(error)))
    while pending:
        current, loader_chain = pending.pop()
        if (current, loader_chain) in visited:
            continue
        visited.add((current, loader_chain))
        parsed = lief.ELF.parse(str(current))
        if parsed is None:
            if current == selected:
                raise ValueError(f"Selected target ELF cannot be parsed: {raw}")
            limitations.append(dict(kind="unparseable_dependency", path=current.relative_to(rootfs).as_posix()))
            continue
        origin = current.relative_to(rootfs).as_posix()
        if parsed.has_interpreter:
            interpreter = parsed.interpreter
            resolved = resolve_guest_file(rootfs, interpreter)
            good = resolved is not None and is_readable_elf(resolved[1])
            dependencies.append(dict(source=origin, kind="interpreter", requested=interpreter,
                                     resolved_path=resolved[0][-1] if good else None))
            if good:
                if resolved[1] not in (*loader_chain, current):
                    pending.append((resolved[1], (current, *loader_chain)))
            else:
                limitations.append(dict(kind="missing_or_invalid_interpreter", source=origin, path=interpreter))
        for name in parsed.libraries:
            if resolver is None:
                dependencies.append(dict(source=origin, kind="DT_NEEDED", requested=name, resolved_path=None))
                continue
            try:
                candidate = resolver.resolve(name, current, loader_chain)
            except (ValueError, AmbiguousBinaryError) as error:
                limitations.append(dict(kind="unresolved_dependency_search", source=origin, requested=name, reason=str(error)))
                candidate = None
            good = candidate is not None and is_readable_elf(candidate)
            dependencies.append(dict(source=origin, kind="DT_NEEDED", requested=name,
                                     resolved_path=candidate.relative_to(rootfs).as_posix() if good else None))
            if good:
                if candidate not in (*loader_chain, current):
                    pending.append((candidate, (current, *loader_chain)))
            else:
                limitations.append(dict(kind="missing_or_invalid_dependency", source=origin, requested=name))
    return TargetAdmission(target_path=raw, resolved_path=chain[-1], guest_path_chain=chain,
                           status="partial" if limitations else "complete",
                           dependencies=dependencies, limitations=limitations)
