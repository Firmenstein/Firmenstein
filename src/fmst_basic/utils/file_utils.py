from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
from collections import deque
from typing import Iterable, Optional

from loguru import logger


class AmbiguousBinaryError(ValueError):
    """Raised when a basename identifies different ELF contents."""


def index_paths_by_basename(
    paths: Iterable[Path],
) -> dict[str, tuple[Path, ...]]:
    """Build a stable, lossless basename index."""
    grouped: dict[str, list[Path]] = {}
    for path in paths:
        candidate = Path(path).absolute()
        candidates = grouped.setdefault(candidate.name, [])
        if candidate not in candidates:
            candidates.append(candidate)
    return {
        name: tuple(sorted(candidates, key=lambda path: path.as_posix()))
        for name, candidates in grouped.items()
    }


def format_binary_candidates(paths: Iterable[Path], rootfs: Path) -> str:
    """Render every candidate path without truncation."""
    rootfs = Path(rootfs).absolute()
    rendered = []
    for path in paths:
        try:
            rendered.append(path.relative_to(rootfs).as_posix())
        except ValueError:
            rendered.append(path.as_posix())
    return "\n".join(f"  - {path}" for path in rendered)


def resolve_unique_basename(
    binary_name: str,
    paths_by_basename: dict[str, tuple[Path, ...]],
    rootfs: Path,
    *,
    purpose: str,
) -> Path:
    """Resolve a basename or fail with the complete ambiguity set."""
    if Path(binary_name).name != binary_name:
        raise ValueError(
            f"{purpose} must be a binary basename; path-qualified binary "
            f"identity is not supported: {binary_name!r}"
        )
    candidates = paths_by_basename.get(binary_name, ())
    if not candidates:
        raise FileNotFoundError(
            f"{purpose} {binary_name!r} not found in firmware rootfs"
        )
    if len(candidates) > 1:
        raise AmbiguousBinaryError(
            f"Ambiguous {purpose} basename {binary_name!r}; candidates:\n"
            f"{format_binary_candidates(candidates, rootfs)}"
        )
    return candidates[0]


def _resolve_guest_symlink(path: Path, rootfs: Path) -> Optional[Path]:
    """Resolve a symlink using guest-root semantics, without escaping rootfs."""
    rootfs = rootfs.absolute().resolve()
    try:
        pending = deque(path.absolute().relative_to(rootfs).parts)
    except ValueError:
        return None
    resolved: list[str] = []
    links = 0
    while pending:
        part = pending.popleft()
        if part == "..":
            if not resolved:
                return None
            resolved.pop()
            continue
        if part == ".":
            continue
        current = rootfs.joinpath(*resolved, part)
        if current.is_symlink():
            links += 1
            if links > 40:
                return None
            target = PurePosixPath(os.readlink(current))
            if target.is_absolute():
                resolved = []
                target = target.relative_to("/")
            pending.extendleft(reversed(target.parts))
        else:
            resolved.append(part)
    current = rootfs.joinpath(*resolved)
    return current if current.is_file() else None


def _has_elf_magic(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            return stream.read(4) == b"\x7fELF"
    except OSError:
        return False


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_binary_in_rootfs(
    binary_name: str, rootfs_path: Path,
) -> Optional[Path]:
    """Find an ELF by basename without silently choosing different copies.

    Guest symlinks resolving to the same file are collapsed. Multiple
    byte-identical physical copies are equivalent for static onboarding and
    the lexicographically first rootfs-relative path is selected. Different
    contents are ambiguous and fail before IDA can reuse the wrong artifacts.
    """
    rootfs = Path(rootfs_path).absolute().resolve()
    candidates: dict[Path, Path] = {}
    for root, dirnames, filenames in os.walk(rootfs):
        dirnames.sort()
        if binary_name not in filenames:
            continue
        guest_path = Path(root) / binary_name
        resolved = _resolve_guest_symlink(guest_path, rootfs)
        if resolved is None or not _has_elf_magic(resolved):
            continue
        candidates.setdefault(resolved, guest_path)

    if not candidates:
        logger.error(f"Binary {binary_name} not found in rootfs {rootfs}")
        return None

    ordered = sorted(
        candidates.items(),
        key=lambda item: item[1].relative_to(rootfs).as_posix(),
    )
    if len(ordered) == 1:
        return ordered[0][0]

    by_digest: dict[str, list[tuple[Path, Path]]] = {}
    digest_by_path: dict[Path, str] = {}
    for resolved, guest_path in ordered:
        digest = _sha256(resolved)
        digest_by_path[resolved] = digest
        by_digest.setdefault(digest, []).append((resolved, guest_path))
    if len(by_digest) == 1:
        selected = ordered[0][0]
        logger.warning(
            f"Found {len(ordered)} byte-identical copies of {binary_name}; "
            f"using {ordered[0][1].relative_to(rootfs).as_posix()}"
        )
        return selected

    candidate_lines = "\n".join(
        f"  - {guest_path.relative_to(rootfs).as_posix()} "
        f"(sha256={digest_by_path[resolved]})"
        for resolved, guest_path in ordered
    )
    raise AmbiguousBinaryError(
        f"Ambiguous ELF basename {binary_name!r} in rootfs {rootfs}; "
        f"candidates have different contents:\n{candidate_lines}"
    )
