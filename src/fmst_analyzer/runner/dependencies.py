"""Bind disposable generated crates to the Controller-selected GuestWeave API."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib


def bind_guestweave_api(roots: list[Path | None], framework: Path, *, check_only: bool = False) -> list[dict[str, str]]:
    """Rewrite only generated inline dependency paths and verify the parsed delta.

    The immutable Generator publication is never a caller of this function.
    Unknown Cargo syntax is rejected rather than rewritten by a broad replacement.
    """
    selected = str((framework / "fmst-iib-api").resolve())
    records = []
    for root in roots:
        if root is None or not (root / "Cargo.toml").is_file():
            continue
        path = root / "Cargo.toml"
        original = path.read_text()
        data = tomllib.loads(original)
        expected = tomllib.loads(original)
        found = False
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dependency = expected.get(section, {}).get("fmst-iib-api")
            if isinstance(dependency, dict) and "path" in dependency:
                found = True
                dependency["path"] = selected
        if not found:
            raise RuntimeError(f"Generated crate has no direct GuestWeave API path dependency: {path}")
        if data == expected:
            continue
        if check_only:
            raise RuntimeError(f"Keep fmst-iib-api bound to the Controller-selected framework: {path}: {selected}")
        updated = re.sub(r'(?m)^(\s*fmst-iib-api\s*=\s*\{[^\n}]*\bpath\s*=\s*)("(?:[^"\\]|\\.)*"|\x27[^\x27]*\x27)',
            lambda match: match[1] + json.dumps(selected), original)
        if tomllib.loads(updated) != expected:
            raise RuntimeError(f"Unsupported generated GuestWeave dependency syntax: {path}")
        records.append({"path": str(path), "before_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "after_sha256": hashlib.sha256(updated.encode()).hexdigest(), "selected_api": selected})
        path.write_text(updated)
    return records
