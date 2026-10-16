"""Prepare Core's pinned GuestWeave checkout without modifying existing trees."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile


def prepare(project: Path) -> Path:
    pin = json.loads((project / "dependencies/guestweave.json").read_text())
    if pin["schema_version"] != 1:
        raise ValueError("Unsupported GuestWeave dependency pin schema")
    checkout = project / pin["checkout"]
    if not checkout.exists():
        checkout.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=checkout.parent, prefix=".prepare-") as tmp:
            staged = Path(tmp) / "GuestWeave"
            subprocess.run(["git", "init", "--quiet", str(staged)], check=True)
            subprocess.run(["git", "-C", str(staged), "remote", "add", "origin", pin["repository"]], check=True)
            subprocess.run(["git", "-C", str(staged), "fetch", "--depth=1", "origin", pin["commit"]], check=True)
            subprocess.run(["git", "-C", str(staged), "checkout", "--quiet", "--detach", "FETCH_HEAD"], check=True)
            staged.rename(checkout)
    head = subprocess.check_output(["git", "-C", str(checkout), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(checkout), "status", "--porcelain"], text=True)
    if head != pin["commit"] or dirty:
        raise ValueError("Existing GuestWeave differs from the pin; preserve it and select a separate checkout")
    subprocess.run([sys.executable, str(checkout / "tools/prepare_dependencies.py")], check=True)
    return checkout.resolve()


if __name__ == "__main__":
    selected = prepare(Path(__file__).resolve().parents[2])
    print(f"FMST_GUESTWEAVE_WORKSPACE={selected}")
