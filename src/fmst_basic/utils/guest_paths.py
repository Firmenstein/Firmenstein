"""Read guest paths within a frozen rootfs, independently of host symlink rules."""
from __future__ import annotations

from collections import deque
import os
from pathlib import Path, PurePosixPath
import stat


def resolve_guest_path(
    rootfs: Path,
    raw: str,
    *,
    max_hops: int = 40,
    follow_final_symlink: bool = True,
) -> tuple[list[str], int] | None:
    """Return the guest path chain and final lstat mode.

    Expand each symlink before interpreting later parent components. Absolute
    link targets remain inside rootfs; attempts to leave it return None, as do
    missing components, non-directory parents and link loops. The 40-link
    default follows Linux pathname lookup and is unrelated to Agent retries.
    Permission and other I/O errors propagate as evidence-access failures.

    With follow_final_symlink=False the final link itself is returned, even
    when its target is missing. Callers can then inspect its raw target text.
    """
    guest = PurePosixPath(raw.lstrip("/"))
    if not guest.parts:
        return None
    rootfs = Path(rootfs).absolute().resolve()
    pending = deque(guest.parts)
    resolved: list[str] = []
    chain = [guest.as_posix()]
    links = 0
    while pending:
        part = pending.popleft()
        if part == "..":
            if not resolved:
                return None
            resolved.pop()
            continue
        candidate = rootfs.joinpath(*resolved, part)
        try:
            metadata = candidate.lstat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        if not stat.S_ISLNK(metadata.st_mode) or (not pending and not follow_final_symlink):
            if pending and not stat.S_ISDIR(metadata.st_mode):
                return None
            resolved.append(part)
            continue

        # Keep traversed applet/alias identities after preceding '..' parts
        # have been resolved, before following the next link.
        current = PurePosixPath(*resolved, part, *pending).as_posix()
        if chain[-1] != current:
            chain.append(current)
        links += 1
        if links > max_hops:
            return None
        target = PurePosixPath(os.readlink(candidate))
        if target.is_absolute():
            resolved = []
            target = PurePosixPath(str(target).lstrip("/"))
        pending.extendleft(reversed(target.parts))
        chain.append(PurePosixPath(*resolved, *pending).as_posix())

    endpoint = rootfs.joinpath(*resolved)
    final_mode = endpoint.lstat().st_mode
    final_path = PurePosixPath(*resolved).as_posix()
    if chain[-1] != final_path:
        chain.append(final_path)
    return chain, final_mode


def resolve_guest_file(rootfs: Path, raw: str, *, max_hops: int = 40) -> tuple[list[str], Path] | None:
    """Resolve a regular guest file; preserve the path chain for diagnostics."""
    rootfs = Path(rootfs).absolute().resolve()
    result = resolve_guest_path(rootfs, raw, max_hops=max_hops)
    if result is None or not stat.S_ISREG(result[1]):
        return None
    chain, _ = result
    return chain, rootfs / chain[-1]
