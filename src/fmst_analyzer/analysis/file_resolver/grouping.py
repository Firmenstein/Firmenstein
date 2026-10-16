"""Deterministic exact-resource construction for FileResolver.

FileResolver deliberately does not infer resource families. Eligible creating
callsites are grouped only when both ``path_kind`` and ``path_value`` are
identical. This module performs no IO and invokes no Agent.
"""
from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, Set, Tuple

from .analyzer_schema import (
    FileCallsite,
    FileResource,
    FileResourceClass,
    PSEUDO_FS_CLASS_SET,
)


CREATING_APIS: Set[str] = {
    "open", "open64", "openat", "openat64", "openat2",
    "creat", "creat64",
    "fopen", "fopen64", "freopen", "freopen64", "opendir",
    "mkstemp", "mkostemp", "mkstemps",
}


def _path_ext(path: str) -> str:
    """Return the lower-cased extension of the path basename, if any."""
    name = path.rsplit("/", 1)[-1]
    if "." not in name or name.endswith("."):
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _is_eligible_for_agent(
    cs: FileCallsite,
    scope: str,
    ext_allowlist: Iterable[str],
) -> bool:
    """Return whether a creating callsite enters resource analysis."""
    if cs.api_name not in CREATING_APIS:
        return False
    if cs.resource_class in PSEUDO_FS_CLASS_SET:
        return True
    if cs.resource_class is FileResourceClass.MISSING_NON_PSEUDO_FS:
        if scope == "with_allowlist":
            ext = _path_ext(cs.path_value)
            return bool(ext) and ext in ext_allowlist
        if scope == "full":
            return True
    return False


def _resource_id(path_kind: str, path_value: str) -> str:
    """Return a readable, stable id with the identity hash at the end."""
    slug = re.sub(r"[^A-Za-z0-9]+", "_", path_value.strip("/")).strip("_")
    slug = slug.lower() or "root"
    slug = slug[:48].rstrip("_") or "root"
    digest = hashlib.sha256(
        f"{path_kind}\0{path_value}".encode("utf-8")
    ).hexdigest()[:12]
    return f"file_{slug}_{digest}"


def build_file_resources(
    callsites: Dict[str, FileCallsite],
    scope: str,
    ext_allowlist: Iterable[str],
) -> Dict[str, FileResource]:
    """Build one resource per exact ``(path_kind, path_value)`` pair.

    The returned mapping is stable and every included callsite receives its
    ``resource_group_id`` back-link. Different concrete paths and patterns
    are never merged, even when their names look like one device family.
    """
    allowlist = set(ext_allowlist)
    buckets: Dict[Tuple[str, str], list[FileCallsite]] = {}
    for cs in sorted(
        callsites.values(),
        key=lambda item: (item.path_kind, item.path_value, item.profile_key),
    ):
        if not _is_eligible_for_agent(cs, scope, allowlist):
            continue
        buckets.setdefault((cs.path_kind, cs.path_value), []).append(cs)

    resources: Dict[str, FileResource] = {}
    for (path_kind, path_value), callsites in sorted(buckets.items()):
        resource_id = _resource_id(path_kind, path_value)
        if resource_id in resources:
            existing = resources[resource_id]
            raise ValueError(
                "stable resource id collision between "
                f"{existing.path_kind}:{existing.path_value} and "
                f"{path_kind}:{path_value}"
            )
        resource_class = callsites[0].resource_class
        if any(cs.resource_class is not resource_class for cs in callsites):
            raise ValueError(
                f"typed path {path_kind}:{path_value} has inconsistent "
                "resource classes"
            )
        for cs in callsites:
            cs.resource_group_id = resource_id
        resources[resource_id] = FileResource(
            resource_group_id=resource_id,
            path_value=path_value,
            path_kind=path_kind,
            resource_class=resource_class,
            callsites=callsites,
        )
    return resources


__all__ = [
    "CREATING_APIS",
    "_is_eligible_for_agent",
    "_path_ext",
    "_resource_id",
    "build_file_resources",
]
