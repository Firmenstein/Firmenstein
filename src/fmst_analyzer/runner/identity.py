"""Versioned runtime input identity, shared by execution and frozen replay."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from .budget import ExecutionBudget


def tree_sha256(root: Path, budget: ExecutionBudget | None = None) -> str:
    """Bind paths/types/modes/owners/content/links; exclude timestamps/inodes.

    Guest symlinks are hashed as links, never followed into the host filesystem.
    """
    digest = hashlib.sha256(b"fmst-tree-identity-v2\0")
    for path in [root, *sorted(root.rglob("*"))]:
        if budget is not None:
            budget.check()
        metadata = path.lstat()
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(json.dumps([stat.S_IFMT(metadata.st_mode), stat.S_IMODE(metadata.st_mode),
            metadata.st_uid, metadata.st_gid, metadata.st_rdev], separators=(",", ":")).encode())
        digest.update(b"\0")
        if stat.S_ISLNK(metadata.st_mode):
            digest.update(os.fsencode(os.readlink(path)))
        elif stat.S_ISREG(metadata.st_mode):
            with path.open("rb") as stream:
                while content := stream.read(1024 * 1024):
                    if budget is not None:
                        budget.check()
                    digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def copy_file(source, destination, *, budget: ExecutionBudget):
    """Cooperative file copy, retaining mode/mtime without following tree links."""
    import shutil
    budget.check()
    with open(source, "rb") as reader, open(destination, "wb") as writer:
        while content := reader.read(1024 * 1024):
            budget.check()
            writer.write(content)
    shutil.copystat(source, destination)
    return destination
