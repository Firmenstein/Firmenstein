from __future__ import annotations

from pathlib import Path

from fmst_basic.utils.archive_paths import resolve_archived_path


def test_archived_path_resolution_keeps_unrelated_missing_paths(monkeypatch, tmp_path: Path) -> None:
    current = tmp_path / "Firmenstein"
    current_file = current / "tmp" / "candidate" / "file.py"
    current_file.parent.mkdir(parents=True)
    current_file.write_text("candidate\n", encoding="utf-8")
    archived = Path("/old/work/Firmenstein/tmp/candidate/file.py")
    assert resolve_archived_path(archived, current_project=current) == current_file.resolve()
    missing = Path("/old/work/Firmenstein/tmp/candidate/missing.py")
    assert resolve_archived_path(missing, current_project=current) == missing
