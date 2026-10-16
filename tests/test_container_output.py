"""Container output ownership does not rewrite guest evidence."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess

import pytest

from fmst_analyzer.runner.container_output import handoff_tree, main
from fmst_analyzer.runner.runtime_builder import DockerRuntimeBuilder


def test_handoff_preserves_bytes_modes_times_and_never_follows_links(tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()
    file = output / "trace"
    file.write_bytes(b"unaltered\x00trace")
    file.chmod(0o640)
    os.utime(file, ns=(1234567890, 2345678901))
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "protected").write_bytes(b"not-an-output")
    (output / "link").symlink_to(outside, target_is_directory=True)
    before = file.stat()
    visited = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid, **kw: visited.append((Path(path), kw)))
    records = handoff_tree(output, 123, 456)
    assert file.read_bytes() == b"unaltered\x00trace"
    assert stat.S_IMODE(file.stat().st_mode) == 0o640
    assert file.stat().st_mtime_ns == before.st_mtime_ns
    assert all(path.is_relative_to(output) and kw == {"follow_symlinks": False} for path, kw in visited)
    assert {r["path"] for r in records} == {".", "trace", "link"}
    assert next(r for r in records if r["path"] == "trace")["uid"] == before.st_uid


def test_receipt_replaces_symlink_and_retains_failed_build_status(tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"original")
    (output / ".fmst-output-ownership.json").symlink_to(outside)
    monkeypatch.setattr(os, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(subprocess, "run", lambda argv: subprocess.CompletedProcess(argv, 9))
    assert main([str(output), "123", "456", "failed-build"]) == 9
    assert outside.read_bytes() == b"original"
    receipt = output / ".fmst-output-ownership.json"
    assert not receipt.is_symlink()
    assert json.loads(receipt.read_text())["original_metadata"]


@pytest.mark.external
def test_real_docker_private_outputs_are_readable_and_removable(tmp_path):
    image = os.environ.get("FMST_RUNTIME_BUILDER_IMAGE")
    if not image:
        pytest.skip("requires explicit local FMST_RUNTIME_BUILDER_IMAGE")
    builder = DockerRuntimeBuilder(image=image, project_root=tmp_path,
        workdir=tmp_path / "work", platform_name=os.environ.get("FMST_RUNTIME_BUILDER_PLATFORM"))
    output = builder.workdir / "output"
    output.mkdir(parents=True)
    code = ('import os,pathlib; p=pathlib.Path("/workspace/workdir/output/private");'
        'p.write_bytes(b"exact-container-bytes");os.chmod(p,0o640);'
        'os.utime(p,ns=(1234567890,2345678901));raise SystemExit(7)')
    result = builder._run(["python3", "-c", code], timeout=30, owned_output=output)
    assert result.returncode == 7
    file = output / "private"
    assert file.read_bytes() == b"exact-container-bytes"
    assert file.stat().st_uid == os.getuid()
    assert stat.S_IMODE(file.stat().st_mode) == 0o640
    assert file.stat().st_mtime_ns == 2345678901
    receipt = json.loads((output / ".fmst-output-ownership.json").read_text())
    assert next(r for r in receipt["original_metadata"] if r["path"] == "private")["uid"] == 0
    # Simulate a stopped guest that created an unreadable child artifact.
    code = ('import os,pathlib; p=pathlib.Path("/workspace/workdir/output/child");'
        'p.mkdir();f=p/"trace";f.write_bytes(b"child-bytes");os.chmod(f,0o640)')
    assert builder._run(["python3", "-c", code], timeout=30).returncode == 0
    builder.handoff_output(output)
    assert (output / "child/trace").read_bytes() == b"child-bytes"
    import shutil
    shutil.rmtree(output)
    assert not output.exists()
