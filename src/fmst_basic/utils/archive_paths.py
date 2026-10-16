"""Read-only compatibility for absolute paths from the pre-split workspace."""

from __future__ import annotations

from pathlib import Path


def resolve_archived_path(value: Path, *, current_project: Path | None = None) -> Path:
    """Resolve a relocated path only when its current counterpart exists.

    Callers keep the original string for provenance and identity.  This helper
    supplies a filesystem path for old receipts after the Firmenstein/GuestWeave
    split; it never creates a file or treats an unrelated missing path as valid.
    """
    path = Path(value)
    if path.exists():
        return path.resolve()
    project = Path(current_project).resolve() if current_project else Path(__file__).resolve().parents[3]
    for index, component in enumerate(path.parts):
        if component != project.name:
            continue
        candidate = project.joinpath(*path.parts[index + 1:])
        if candidate.exists():
            return candidate.resolve()
    return path.resolve()
