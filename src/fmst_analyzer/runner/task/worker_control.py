"""Stop the model worker, preserving services owned by task init."""
import json
import os
import signal
import time
from pathlib import Path
from .common import CONTROL, process_identity


def main():
    marker = CONTROL / "worker.json"
    if not marker.exists():
        return
    worker = json.loads(marker.read_text())
    root = worker["pid"]
    if process_identity(root) != worker["start_ticks"]:
        return
    parents = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            parents[int(entry.name)] = int(fields[1])
        except (OSError, ValueError, IndexError):
            continue
    selected = {root}
    while children := {pid for pid, parent in parents.items() if parent in selected} - selected:
        selected.update(children)
    identities = {pid: process_identity(pid) for pid in selected}
    for sig in (signal.SIGTERM, signal.SIGKILL):
        for pid, start in identities.items():
            if start is not None and process_identity(pid) == start:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass
        if sig == signal.SIGTERM:
            time.sleep(1)


if __name__ == "__main__":
    main()
