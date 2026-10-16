"""FileResolver public API.

The analyzer resolves file paths statically when possible, uses one fallback
Agent only for unresolved paths, builds exact typed resources, and analyzes
each resource lifecycle with ``FileResourceAnalysisAgent`` in full phase.
"""
from .analyzer_schema import (
    PSEUDO_FS_CLASS_SET,
    PSEUDO_FS_CLASSES,
    CallSiteReport,
    FileCallsite,
    FilePathCandidate,
    FilePathResolution,
    FileResolverResult,
    FileResource,
    FileResourceClass,
    FileResourceReport,
    UsageReport,
)
from .classifier import classify_resource


def __getattr__(name):
    if name in {"FILE_API_PATH_ARG", "FileResolver"}:
        from . import analyzer
        return getattr(analyzer, name)
    raise AttributeError(name)

__all__ = [
    "FILE_API_PATH_ARG",
    "PSEUDO_FS_CLASSES",
    "PSEUDO_FS_CLASS_SET",
    "CallSiteReport",
    "FileCallsite",
    "FilePathCandidate",
    "FilePathResolution",
    "FileResolver",
    "FileResolverResult",
    "FileResource",
    "FileResourceClass",
    "FileResourceReport",
    "UsageReport",
    "classify_resource",
]
