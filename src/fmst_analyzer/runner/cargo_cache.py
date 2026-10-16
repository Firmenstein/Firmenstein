"""Run Cargo on a container-native target, then export its reusable cache.

DockerRuntimeBuilder mounts this file in the disposable builder. The two
directories are private to one builder; neither may have another writer.
Cargo never reads metadata while it is being copied across the host mount.
"""

from __future__ import annotations

import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def sync_tree(source: Path, destination: Path) -> None:
    """Mirror an idle cache, preserving modes, timestamps and link targets."""
    destination.mkdir(parents=True, exist_ok=True)
    names = {entry.name for entry in source.iterdir()}
    for entry in destination.iterdir():
        if entry.name not in names:
            _remove(entry)
    for entry in source.iterdir():
        output = destination / entry.name
        if entry.is_dir() and not entry.is_symlink():
            if output.is_symlink() or (output.exists() and not output.is_dir()):
                _remove(output)
            sync_tree(entry, output)
            shutil.copystat(entry, output)
        else:
            if output.is_dir() and not output.is_symlink():
                _remove(output)
            temporary = output.with_name(f".{output.name}.copy-{uuid.uuid4().hex}")
            try:
                if entry.is_symlink():
                    temporary.symlink_to(os.readlink(entry))
                else:
                    shutil.copy2(entry, temporary)
                temporary.replace(output)
            finally:
                if temporary.exists() or temporary.is_symlink():
                    temporary.unlink()


def run(command: list[str], native_target: Path, exported_target: Path,
        *, owner: tuple[int, int] | None = None) -> int:
    # The anonymous Docker volume is empty on entry. Restore only this
    # builder's previous completed export, before starting any compiler.
    sync_tree(exported_target, native_target)
    result = subprocess.run(command)
    # Export failed builds as well; do not retry or erase their evidence.
    sync_tree(native_target, exported_target)
    if owner is not None and "--manifest-path" in command:
        # Cargo creates the lockfile beside the manifest, outside target/. A
        # root-owned lock prevents the host Agent from continuing after a
        # failed build. Change only this build's regular lockfile; keep its
        # original metadata in the private cache, outside authored inputs.
        manifest = Path(command[command.index("--manifest-path") + 1])
        lock = manifest.parent / "Cargo.lock"
        if lock.is_file() and not lock.is_symlink():
            before = lock.stat()
            record = {"path": str(lock), "uid": before.st_uid,
                "gid": before.st_gid, "mode": before.st_mode & 0o777,
                "mtime_ns": before.st_mtime_ns, "owner": list(owner)}
            os.chown(lock, *owner, follow_symlinks=False)
            (exported_target / ".fmst-cargo-lock-ownership.json").write_text(
                json.dumps(record, indent=2) + "\n")
    return result.returncode


if __name__ == "__main__":
    command = sys.argv[3:]
    owner = None
    if command and command[0] == "--host-owner":
        owner = (int(command[1]), int(command[2]))
        command = command[3:]
    raise SystemExit(run(command, Path(sys.argv[1]), Path(sys.argv[2]), owner=owner))
