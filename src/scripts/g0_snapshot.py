"""Freeze a dirty source tree without resetting it or collecting ignored artifacts.

Usage from the repository root: python src/scripts/g0_snapshot.py tmp/g0/<run>/before
Requires Git; uses no platform-specific shell commands or native analysis SDK.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile


def snapshot(destination: Path) -> dict:
    root = Path(__file__).resolve().parents[2]

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root)

    paths = sorted(set(git("ls-files", "--cached", "--others", "--exclude-standard", "-z").split(b"\0")) - {b""})
    head = git("rev-parse", "HEAD").decode().strip()
    status = git("status", "--short", "--untracked-files=all")
    staged = git("diff", "--binary", "--cached")
    unstaged = git("diff", "--binary")
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "git-status.txt").write_bytes(status)
    (destination / "staged.patch").write_bytes(staged)
    (destination / "unstaged.patch").write_bytes(unstaged)
    records = []
    with tarfile.open(destination / "source.tar.gz", "w:gz") as archive:
        for encoded in paths:
            relative = os.fsdecode(encoded)
            path = root / relative
            if not path.is_symlink() and not path.is_file():
                continue  # Deleted tracked paths remain recorded in the diff.
            symlink = path.is_symlink()
            payload = os.fsencode(os.readlink(path)) if symlink else path.read_bytes()
            records.append({
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "mode": oct(path.lstat().st_mode),
                "symlink": symlink,
            })
            archive.add(path, arcname=relative, recursive=False)
    # Digest includes paths and modes as well as bytes, and excludes timestamps.
    canonical = json.dumps(records, sort_keys=True).encode()
    manifest = {
        "schema_version": 1,
        "head": head,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": records,
        "source_digest": hashlib.sha256(canonical).hexdigest(),
    }
    (destination / "source_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="New snapshot directory; never overwritten")
    args = parser.parse_args()
    manifest = snapshot(args.destination)
    print(f"{len(manifest['files'])} files; source_digest={manifest['source_digest']}")
