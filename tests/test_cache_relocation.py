"""A copied graph must never reopen the still-existing historical IDB."""
import pytest

from fmst_analyzer.nodes.cache_paths import restored_idb_path


def test_requested_copy_wins_even_while_original_exists(tmp_path):
    original = tmp_path / "history" / "service.i64"
    copied = tmp_path / "new-run" / original.name
    for path in (original, copied):
        path.parent.mkdir()
        path.write_bytes(b"minimal IDB stand-in")
    assert restored_idb_path(original, copied.parent) == copied


def test_missing_copy_rejects_instead_of_writing_history(tmp_path):
    original = tmp_path / "service.i64"
    original.write_bytes(b"historical IDB")
    with pytest.raises(RuntimeError, match="requested cache location"):
        restored_idb_path(original, tmp_path / "new-run")
    assert original.read_bytes() == b"historical IDB"


def test_hashed_idb_relocation_preserves_source_namespace(tmp_path):
    name = "a" * 64
    original = tmp_path / "history" / name / "service.i64"
    requested = tmp_path / "new-run"
    copied = requested / name / original.name
    for path in (original, copied):
        path.parent.mkdir(parents=True)
        path.write_bytes(b"IDB stand-in")
    assert restored_idb_path(original, requested) == copied
    copied.unlink()
    (requested / original.name).write_bytes(b"unrelated same-name IDB")
    with pytest.raises(RuntimeError, match="requested cache location"):
        restored_idb_path(original, requested)
