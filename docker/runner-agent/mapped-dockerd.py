#!/usr/bin/env python3
"""RootlessKit child entry: provide per-container subordinate IDs privately."""
import os
import subprocess
from pathlib import Path

if subprocess.check_output(['stat', '-c', '%T', '-f', '/etc'], text=True).strip() != 'tmpfs':
    raise SystemExit('This entry must run inside RootlessKit with /etc copy-up')
account = os.environ['FMST_RUNNER_ACCOUNT']
maps = [list(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
count = next((size for inside, outside, size in maps if inside == 1), 0)
if count < 65536:
    raise SystemExit('Rootless Docker requires at least 65536 subordinate IDs')
for name in ('subuid', 'subgid'):
    path = Path('/etc') / name
    # Unlink the copy-up symlink; never write through it to the host file.
    path.unlink(missing_ok=True)
    path.write_text(f'{account}:1:65536\n')
os.execvp('dockerd', ['dockerd', '--userns-remap=' + account + ':' + account, *os.sys.argv[1:]])
