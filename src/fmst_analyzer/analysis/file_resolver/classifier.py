"""Pure-Python guest-path classification for FileResolver's Node 4."""
from __future__ import annotations

import os
import posixpath
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .analyzer_schema import FileResourceClass


_PSEUDO_FS_RULES = (
    ("/dev", FileResourceClass.PSEUDO_FS_DEV),
    ("/proc", FileResourceClass.PSEUDO_FS_PROC),
    ("/sys", FileResourceClass.PSEUDO_FS_SYS),
)
_MAX_SYMLINK_HOPS = 16


@dataclass(frozen=True)
class ResourcePathClassification:
    """Deterministic result of resolving one absolute guest path."""

    path_value: Optional[str]
    resource_class: Optional[FileResourceClass]
    symlink_chain: tuple[str, ...] = ()
    error: Optional[str] = None


def _pseudo_class(path: str) -> Optional[FileResourceClass]:
    for prefix, resource_class in _PSEUDO_FS_RULES:
        if path == prefix or path.startswith(prefix + "/"):
            return resource_class
    return None


def resolve_and_classify_resource(
    path_value: str,
    path_kind: str,
    rootfs_path: Path,
    *,
    max_symlink_hops: int = _MAX_SYMLINK_HOPS,
) -> ResourcePathClassification:
    """Resolve and classify one path using firmware-root semantics.

    Relative paths are deliberately rejected: their runtime base directory is
    not a rootfs fact. Concrete absolute paths follow symlinks lexically under
    rootfs_path; absolute symlink targets are guest-absolute, never host
    paths. Pattern paths are classified by their absolute prefix only.
    """
    if not path_value or not posixpath.isabs(path_value):
        return ResourcePathClassification(
            path_value=None,
            resource_class=None,
            error=(
                f"relative or empty path {path_value!r} has no proven runtime "
                "base directory"
            ),
        )

    normalized = posixpath.normpath(path_value)
    direct_pseudo = _pseudo_class(normalized)
    if direct_pseudo is not None:
        return ResourcePathClassification(
            path_value=normalized,
            resource_class=direct_pseudo,
            symlink_chain=(normalized,),
        )

    if path_kind != "concrete":
        return ResourcePathClassification(
            path_value=normalized,
            resource_class=FileResourceClass.MISSING_NON_PSEUDO_FS,
            symlink_chain=(normalized,),
        )

    current = normalized
    chain = [current]
    seen = {current}
    symlink_hops = 0
    while True:
        components = [part for part in current.split("/") if part]
        resolved_parts: list[str] = []
        restarted = False
        for index, component in enumerate(components):
            candidate = rootfs_path.joinpath(*resolved_parts, component)
            guest_component = "/" + "/".join([*resolved_parts, component])
            remaining = components[index + 1:]
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                return ResourcePathClassification(
                    path_value=current,
                    resource_class=(
                        _pseudo_class(current)
                        or FileResourceClass.MISSING_NON_PSEUDO_FS
                    ),
                    symlink_chain=tuple(chain),
                )
            except (OSError, ValueError) as error:
                return ResourcePathClassification(
                    path_value=None,
                    resource_class=None,
                    symlink_chain=tuple(chain),
                    error=f"cannot inspect guest path {guest_component!r}: {error}",
                )

            if not stat.S_ISLNK(metadata.st_mode):
                resolved_parts.append(component)
                continue

            if symlink_hops >= max_symlink_hops:
                return ResourcePathClassification(
                    path_value=None,
                    resource_class=None,
                    symlink_chain=tuple(chain),
                    error=(
                        f"guest symlink chain exceeds {max_symlink_hops} hops "
                        f"from {normalized!r}"
                    ),
                )
            symlink_hops += 1

            try:
                target = os.readlink(candidate)
            except OSError as error:
                return ResourcePathClassification(
                    path_value=None,
                    resource_class=None,
                    symlink_chain=tuple(chain),
                    error=f"cannot read guest symlink {guest_component!r}: {error}",
                )

            target_base = target if posixpath.isabs(target) else posixpath.join(
                posixpath.dirname(guest_component), target,
            )
            following = posixpath.normpath(posixpath.join(
                target_base, *remaining,
            ))
            if not following.startswith("/"):
                following = "/" + following.lstrip("/")
            if following in seen:
                return ResourcePathClassification(
                    path_value=None,
                    resource_class=None,
                    symlink_chain=tuple([*chain, following]),
                    error=f"guest symlink loop at {following!r}",
                )
            seen.add(following)
            chain.append(following)
            current = following
            pseudo_class = _pseudo_class(current)
            if pseudo_class is not None:
                return ResourcePathClassification(
                    path_value=current,
                    resource_class=pseudo_class,
                    symlink_chain=tuple(chain),
                )
            restarted = True
            break

        if restarted:
            continue
        return ResourcePathClassification(
            path_value=current,
            resource_class=FileResourceClass.IN_ROOTFS,
            symlink_chain=tuple(chain),
        )


def classify_resource(
    path_value: str,
    path_kind: str,
    rootfs_path: Path,
) -> FileResourceClass:
    """Compatibility wrapper returning only a successful classification."""
    result = resolve_and_classify_resource(path_value, path_kind, rootfs_path)
    if result.resource_class is None:
        raise ValueError(result.error or f"cannot classify {path_value!r}")
    return result.resource_class


__all__ = [
    "ResourcePathClassification",
    "classify_resource",
    "resolve_and_classify_resource",
]
