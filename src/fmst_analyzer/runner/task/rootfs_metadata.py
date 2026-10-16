"""Portable descriptions of a rootfs, without following guest symlinks.

This module is also executed directly in the task container. It uses only the
standard library; manifests describe source attributes, not host inode numbers.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

RUNTIME_TYPES = {"socket", "character", "block"}
TYPES = {stat.S_IFREG: "file", stat.S_IFDIR: "directory", stat.S_IFLNK: "symlink",
         stat.S_IFIFO: "fifo", stat.S_IFSOCK: "socket", stat.S_IFCHR: "character",
         stat.S_IFBLK: "block"}


def manifest(root: Path) -> dict:
    """Read numeric ownership, permissions, links, xattrs (including ACLs), bytes.

    atime/ctime and physical allocation are intentionally not equality fields.
    Security capabilities and ACL bytes are retained, never silently discarded.
    """
    root = Path(root).absolute()
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("Rootfs source must be a directory, not a symlink")
    entries, inodes = {}, {}
    pending = [root]
    while pending:
        path = pending.pop()
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        kind = TYPES[stat.S_IFMT(info.st_mode)]
        item = {"type": kind, "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid, "gid": info.st_gid, "mtime_ns": info.st_mtime_ns,
                "xattrs": {key: os.getxattr(path, key, follow_symlinks=False).hex()
                           for key in sorted(os.listxattr(path, follow_symlinks=False))}}
        if kind == "directory":
            pending.extend(sorted(path.iterdir(), reverse=True))
        elif kind == "symlink":
            item["target"] = os.readlink(path)
        elif kind == "file":
            inode = (info.st_dev, info.st_ino)
            if inode not in inodes:
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    after = os.fstat(stream.fileno())
                fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
                if any(getattr(info, key) != getattr(after, key) for key in fields):
                    raise RuntimeError(f"Rootfs file changed during inspection: {name}")
                inodes[inode] = (name, digest)
            item["hardlink_group"], item["sha256"] = inodes[inode]
            item["size"] = info.st_size
        elif kind in {"character", "block"}:
            item["device"] = [os.major(info.st_rdev), os.minor(info.st_rdev)]
        entries[name] = item
    return {"schema_version": 1, "entries": entries}


def differences(expected: dict, actual: dict) -> list[dict]:
    """Compare static entries; runtime resources must be absent until created.

    Their full source descriptions remain in the source manifest. An unexpected
    placeholder is a difference, not an acceptable recreation of a device/socket.
    """
    before, after = expected["entries"], actual["entries"]
    result = []
    for path in sorted(before.keys() | after.keys()):
        wanted = before.get(path)
        if wanted and wanted["type"] in RUNTIME_TYPES:
            wanted = None
        found = after.get(path)
        if wanted != found:
            result.append({"path": path, "expected": wanted, "actual": found})
    return result


if __name__ == "__main__":
    import sys
    json.dump(manifest(Path(sys.argv[1])), sys.stdout)
    sys.stdout.write("\n")
