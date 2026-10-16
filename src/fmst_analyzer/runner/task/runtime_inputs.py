"""Match a private image's runtime payload to the selected framework source."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def source_identity(root: Path) -> str:
    if not root.is_dir():
        raise ValueError(f'Runtime source directory is missing: {root}')
    digest = hashlib.sha256()
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in {'.git', 'target', '__pycache__'})
        for name in sorted(files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            value = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
            digest.update(relative.encode() + b'\0' + hashlib.sha256(value).digest())
    return digest.hexdigest()


def prepare_runtime(task, framework: Path, arch: str) -> dict:
    from .host import docker
    from .common import write_json
    metadata = json.loads(docker('exec', task.name, 'cat',
                                '/opt/guestweave/runtime.json', text=True).stdout)
    expected = source_identity(framework)
    if metadata['framework_source_id'] != expected:
        raise ValueError('Runner image runtime does not match selected GuestWeave source; rebuild its runtime payload')
    libafl = source_identity(framework.parent / 'lib/LibAFL')
    if metadata['libafl_source_id'] != libafl:
        raise ValueError('Runner image runtime does not match selected LibAFL source; rebuild its runtime payload')
    selected = {'arm': 'arm', 'mipsel': 'mipsel', 'mipsbe': 'mipsbe', 'x86_64': 'x86_64'}[arch]
    harness = metadata['harnesses'][selected]['path']
    cargo_config = ('[source.crates-io]\nreplace-with = "runner-vendor"\n'
                    '[source.runner-vendor]\ndirectory = "/opt/guestweave/vendor"\n')
    docker('exec', '--user', 'runner', task.name, 'python', '-c',
           "from pathlib import Path;import sys,hashlib;"
           "p=Path('/task/work/.cargo/config.toml');p.parent.mkdir(parents=True,exist_ok=True);"
           "p.write_text(sys.argv[2]);"
           "assert hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()==sys.argv[3], 'Harness identity differs'",
           harness, cargo_config, metadata['harnesses'][selected]['sha256'])
    docker('exec', '--user', 'runner', task.name, 'python', '-c',
           "import sys;from pathlib import Path;"
           "sys.path.insert(0,'/task/work/framework/GuestWeave/tools');from offline import extract;"
           "[extract(Path('/opt/guestweave/sources')/(n+'.tar.gz'),Path('/task/work/native')/n)"
           "for n in ('qemu','libvharness')]")
    record = {'status': 'ready', 'framework_source_id': expected, 'libafl_source_id': libafl,
              'runtime_receipt': '/opt/guestweave/runtime.json', 'harness': harness,
              'vendor': '/opt/guestweave/vendor', 'architecture': selected}
    write_json(task.output / 'image-runtime.json', record)
    task.put_json('/task/evidence/image-runtime.json', record)
    return record
