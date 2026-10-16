"""Filesystem-only cache relocation; never fall back to another run's IDB."""
from pathlib import Path
import re


def restored_idb_path(saved_path: Path, requested_dir: Path | None) -> Path:
    relative = Path(saved_path.name)
    if re.fullmatch(r"[0-9a-f]{64}", saved_path.parent.name):
        relative = saved_path.parent.name / relative
    path = saved_path if requested_dir is None else requested_dir / relative
    if not path.is_file():
        raise RuntimeError(f"IDB not found in requested cache location: {path}")
    return path
