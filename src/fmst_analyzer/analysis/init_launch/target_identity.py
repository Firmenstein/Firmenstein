"""Deterministic target identity preparation for InitLaunchAnalyzer."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import List, Optional, Set

from .analyzer_schema import TargetIdentity
from fmst_analyzer.analysis.base.finding_binding import FindingTarget
from fmst_basic.utils.guest_paths import resolve_guest_path

_INITIALIZATION_ENTRY_CANDIDATES = (
    "init",
    "sbin/init",
    "bin/init",
    "etc/inittab",
    "usr/etc/inittab",
    "etc/rcS",
    "etc/init.d/rcS",
    "etc/preinit",
    "etc/rc.local",
)


def _rootfs_relative(rootfs: Path, path: Path) -> str:
    root = rootfs.resolve()
    candidate = path if path.is_absolute() else root / path
    try:
        # Normalize host aliases such as macOS /var -> /private/var through
        # the parent directory only. Resolving the final component would
        # follow a guest symlink and erase the selected applet identity.
        candidate = candidate.absolute()
        candidate = candidate.parent.resolve(strict=False) / candidate.name
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"target path is outside rootfs: {path}") from exc
    if any(part == ".." for part in relative.parts):
        raise ValueError(f"target path escapes rootfs: {path}")
    return relative.as_posix()


def resolve_symlink_chain_in_rootfs(
    rootfs: Path,
    start_rel: str,
    max_hops: int = 40,
) -> Optional[List[str]]:
    """Resolve all symlinked path components without host-path escape."""
    resolved = resolve_guest_path(rootfs, start_rel, max_hops=max_hops)
    if resolved is None:
        return None
    chain, final_mode = resolved
    return chain if stat.S_ISREG(final_mode) else None


def enumerate_target_identity(
    rootfs: Path,
    selected_target_path: Path,
) -> TargetIdentity:
    """Record the exact selected ELF and symlinks that reach that path."""
    rootfs = rootfs.resolve()
    selected_rel = _rootfs_relative(rootfs, selected_target_path)
    selected_abs = rootfs / selected_rel
    selected_chain = resolve_symlink_chain_in_rootfs(rootfs, selected_rel)
    if selected_chain is None:
        raise ValueError(
            f"selected target is missing, not a regular file, or escapes "
            f"rootfs: {selected_abs}"
        )

    selected_final = selected_chain[-1]
    aliases: Set[str] = set()
    for walk_root, dirs, files in os.walk(rootfs, followlinks=False):
        # Directory symlinks cannot name an executable file and should not be
        # traversed, but inspect them if present in ``dirs`` for completeness.
        entries = [*(Path(walk_root) / name for name in files)]
        entries.extend(
            Path(walk_root) / name
            for name in dirs
            if (Path(walk_root) / name).is_symlink()
        )
        for path in entries:
            if not path.is_symlink():
                continue
            rel = path.relative_to(rootfs).as_posix()
            resolved = resolve_guest_path(rootfs, rel)
            if resolved is None:
                continue
            chain, final_mode = resolved
            candidates = [rel]
            if stat.S_ISDIR(final_mode):
                final_dir = chain[-1].rstrip("/")
                prefix = final_dir + "/"
                if selected_final.startswith(prefix):
                    candidates = [
                        rel.rstrip("/") + "/" + selected_final[len(prefix):]
                    ]
            for candidate in candidates:
                candidate_resolved = resolve_guest_path(rootfs, candidate)
                if candidate_resolved is None:
                    continue
                candidate_chain, candidate_mode = candidate_resolved
                if not stat.S_ISREG(candidate_mode):
                    continue
                same_file = candidate_chain[-1] == selected_final
                same_name = Path(candidate).name == Path(selected_rel).name
                passes_selected = selected_rel in candidate_chain[1:]
                if (
                    candidate != selected_rel
                    and same_file
                    and (same_name or passes_selected)
                ):
                    aliases.add(candidate)

    return TargetIdentity(
        target_basename=Path(selected_rel).name,
        selected_rootfs_path=selected_rel,
        target_aliases=sorted(aliases),
    )


def enumerate_initialization_roots(rootfs: Path) -> List[str]:
    """Return existing firmware initialization entries and exact aliases."""
    rootfs = rootfs.resolve()
    roots: Set[str] = set()
    for candidate in _INITIALIZATION_ENTRY_CANDIDATES:
        resolved = resolve_guest_path(rootfs, candidate)
        if resolved is None:
            continue
        chain, final_mode = resolved
        if not stat.S_ISREG(final_mode):
            continue
        roots.add(candidate)
        roots.add(chain[-1])

    rc_dir = rootfs / "etc/rc.d"
    if rc_dir.is_dir():
        for path in sorted(rc_dir.glob("S*")):
            candidate = path.relative_to(rootfs).as_posix()
            resolved = resolve_guest_path(rootfs, candidate)
            if resolved is None or not stat.S_ISREG(resolved[1]):
                continue
            # The S* link is the boot entry. Its target is evidence in the
            # initialization chain, not an independent root.
            roots.add(candidate)
    return sorted(roots)


def finding_target_for_identity(rootfs: Path, identity: TargetIdentity) -> FindingTarget:
    """Hash the guest-resolved executable while preserving the selected applet path."""
    chain = resolve_symlink_chain_in_rootfs(rootfs, identity.selected_rootfs_path)
    if chain is None:
        raise ValueError("selected target cannot be resolved inside rootfs")
    content = FindingTarget.from_file(rootfs, rootfs / chain[-1])
    return FindingTarget(path=identity.selected_rootfs_path, sha256=content.sha256)


__all__ = [
    "enumerate_initialization_roots",
    "enumerate_target_identity",
    "resolve_symlink_chain_in_rootfs",
]
