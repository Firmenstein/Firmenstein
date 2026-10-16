"""Compatibility entry point for the GuestWeave runtime bundle builder."""
from __future__ import annotations

import runpy
import shutil
import sys
from pathlib import Path


if __name__ == "__main__":
    framework_script = Path(__file__).resolve().parents[3] / "GuestWeave" / "tools" / "build_runtime_bundle.py"
    netcat = shutil.which("nc")
    if netcat is None:
        raise SystemExit("Firmenstein host bundle requires netcat-openbsd in the builder")
    sys.argv.extend([
        "--binary", f"sh={Path('/bin/sh')}",
        "--binary", f"sleep={Path('/bin/sleep')}",
        "--binary", f"cp={Path('/bin/cp')}",
        "--binary", f"nc={Path(netcat).resolve()}",
    ])
    runpy.run_path(str(framework_script), run_name="__main__")
