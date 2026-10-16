"""Hand container-created framework outputs to their host owner.

This helper runs only on an idle, disposable output mount. It does not follow
symlinks or change bytes, modes or timestamps; the receipt retains original
container ownership. Guest rootfs trees and published inputs are excluded.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid


def handoff_tree(root: Path, uid: int, gid: int) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    # The tree has no active writers. lchown never follows links; os.walk
    # leaves directory links in place and never visits their targets.
    paths = [root]
    for directory, dirs, files in os.walk(root, followlinks=False):
        paths.extend(Path(directory) / name for name in dirs + files)
    for path in paths:
        before = path.lstat()
        records.append({"path": path.relative_to(root).as_posix(),
            "uid": before.st_uid, "gid": before.st_gid,
            "mode": stat.S_IMODE(before.st_mode), "size": before.st_size,
            "mtime_ns": before.st_mtime_ns})
        os.chown(path, uid, gid, follow_symlinks=False)
        # chown can clear set-ID bits; restore the original mode on regular
        # files and directories without following a symlink.
        if not stat.S_ISLNK(before.st_mode):
            os.chmod(path, stat.S_IMODE(before.st_mode))
    return records


def main(arguments: list[str]) -> int:
    root, uid, gid, *command = arguments
    result = subprocess.run(command).returncode if command else 0
    records = handoff_tree(Path(root), int(uid), int(gid))
    # Never follow a guest-created receipt symlink. Publish a new inode.
    receipt = Path(root) / ".fmst-output-ownership.json"
    temporary = receipt.with_name(f".fmst-output-ownership-{uuid.uuid4().hex}.tmp")
    with temporary.open("x") as stream:
        json.dump({"schema_version": 1, "uid": int(uid), "gid": int(gid),
            "original_metadata": records}, stream, indent=2)
        stream.write("\n")
    os.chown(temporary, int(uid), int(gid))
    temporary.replace(receipt)
    return result


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
