from pathlib import Path
import os
import subprocess

import pytest

from fmst_analyzer.runner import cargo_cache


def test_cache_mirror_preserves_links_modes_and_removes_stale_entries(tmp_path: Path):
    source, target = tmp_path / "source", tmp_path / "target"
    source.mkdir()
    target.mkdir()
    (source / "worker").write_bytes(b"new executable")
    (source / "worker").chmod(0o755)
    os.utime(source / "worker", ns=(1000000000, 2000000000))
    (source / "worker-link").symlink_to("worker")
    (source / "absent-link").symlink_to("absent")
    (source / "deps").mkdir()
    (source / "deps" / "crate.rmeta").write_bytes(b"metadata")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("unrelated")
    (target / "worker").symlink_to(outside / "keep")
    (target / "deps").symlink_to(outside)
    (target / "obsolete").mkdir()
    (target / "obsolete" / "old.rmeta").write_bytes(b"old")
    for _ in range(2):  # Cached symlinks must also survive the next invocation.
        cargo_cache.sync_tree(source, target)
    assert (target / "worker").read_bytes() == b"new executable"
    assert (target / "worker").stat().st_mode & 0o777 == 0o755
    assert (target / "worker").stat().st_mtime_ns == 2000000000
    assert os.readlink(target / "worker-link") == "worker"
    assert os.readlink(target / "absent-link") == "absent"
    assert not (target / "deps").is_symlink()
    assert (target / "deps" / "crate.rmeta").read_bytes() == b"metadata"
    assert not (target / "obsolete").exists()
    assert (outside / "keep").read_text() == "unrelated"
    assert list(outside.iterdir()) == [outside / "keep"]


@pytest.mark.parametrize("returncode", [0, 101])
def test_cargo_runs_between_cache_transfers_without_retry(tmp_path, monkeypatch, returncode):
    exported, native = tmp_path / "exported", tmp_path / "native"
    exported.mkdir()
    (exported / "previous.rmeta").write_bytes(b"previous")
    calls = []

    def compile_once(command):
        calls.append(command)
        assert (native / "previous.rmeta").read_bytes() == b"previous"
        (native / "previous.rmeta").unlink()
        (native / "new.rmeta").write_bytes(b"complete metadata")
        assert not (exported / "new.rmeta").exists()
        return subprocess.CompletedProcess(command, returncode)

    monkeypatch.setattr(cargo_cache.subprocess, "run", compile_once)
    command = ["cargo", "test", "--", "a literal argument"]
    assert cargo_cache.run(command, native, exported) == returncode
    assert calls == [command]
    assert (exported / "new.rmeta").read_bytes() == b"complete metadata"
    assert not (exported / "previous.rmeta").exists()


@pytest.mark.parametrize("returncode", [0, 101])
@pytest.mark.parametrize("symlink", [False, True])
def test_lock_handoff_preserves_failed_build_and_does_not_follow_links(tmp_path, monkeypatch, returncode, symlink):
    exported, native, crate = (tmp_path / n for n in ("exported", "native", "crate"))
    exported.mkdir(); crate.mkdir()
    lock = crate / "Cargo.lock"
    outside = tmp_path / "outside"
    outside.write_bytes(b"protected")
    calls = []
    def compile_once(command):
        if symlink:
            lock.symlink_to(outside)
        else:
            lock.write_bytes(b"actual dependency lock")
            os.utime(lock, ns=(1000000000, 2000000000))
        return subprocess.CompletedProcess(command, returncode)
    monkeypatch.setattr(cargo_cache.subprocess, "run", compile_once)
    monkeypatch.setattr(cargo_cache.os, "chown", lambda *args, **kwargs: calls.append((args, kwargs)))
    command = ["cargo", "build", "--manifest-path", str(crate / "Cargo.toml")]
    assert cargo_cache.run(command, native, exported, owner=(123, 456)) == returncode
    assert outside.read_bytes() == b"protected"
    if symlink:
        assert not calls
    else:
        assert calls == [((lock, 123, 456), {"follow_symlinks": False})]
        assert lock.read_bytes() == b"actual dependency lock" and lock.stat().st_mtime_ns == 2000000000
