"""File-based execution identity, independent of Agent and analysis lifetimes."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

from .common import TASK, process_identity, write_json


def file_identity(path: Path) -> dict:
    path = path.resolve(strict=True)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'sha256': digest}


def process_record(pid: int) -> dict:
    result = {'pid': pid, 'start_ticks': process_identity(pid)}
    try:
        result['pid_namespace'] = os.readlink(f'/proc/{pid}/ns/pid')
    except OSError:
        result['pid_namespace'] = None
    return result


def update_execution(path: Path, **changes) -> dict:
    # init, launcher and interactive queries may finish at the same time.
    with path.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = json.loads(path.read_text())
        record.update(changes)
        write_json(path, record)
    return record


def create_execution(config: dict, *, task_root: Path = TASK) -> Path:
    from .cores import core_inventory
    rootfs = Path(config.get('rootfs', task_root / 'work/rootfs')).resolve(strict=True)
    execution_id = uuid.uuid4().hex
    root = task_root / 'evidence/executions' / execution_id
    root.mkdir(parents=True)
    write_json(root / 'launch-config.json', config)
    write_json(root / 'cores-before.json', core_inventory(rootfs))
    path = root / 'execution.json'
    write_json(path, {'schema_version': 1, 'execution_id': execution_id,
        'started_unix_ns': time.time_ns(), 'status': 'preparing', 'rootfs': str(rootfs),
        'config_path': str(root / 'launch-config.json'), 'trace_roots': [str(root / 'runtime')],
        'log_paths': [], 'core_collection': {'status': 'not_collected'},
        'harness': None, 'intervention': None, 'images': [], 'process': None})
    (root / 'runtime').mkdir()
    # Only a firmware launch changes current execution, never a random job.
    write_json(task_root / 'evidence/execution.json', {'schema_version': 1,
        'execution_path': str(path), 'execution_id': execution_id})
    return path


def select_execution(task_root: Path, execution_path: str | None = None) -> tuple[Path | None, dict]:
    if execution_path:
        path = Path(execution_path)
    else:
        pointer = task_root / 'evidence/execution.json'
        if not pointer.is_file():
            return None, {'status': 'unregistered', 'notice': 'No execution is registered; explicit evidence paths remain usable.'}
        value = json.loads(pointer.read_text())
        if 'execution_path' not in value:
            return None, {'status': 'unregistered', 'notice': 'Execution marker has no artifact paths; supply a file path.'}
        path = Path(value['execution_path'])
    record = json.loads(path.read_text())
    if record.get('schema_version') != 1 or 'execution_id' not in record:
        raise ValueError(f'Unsupported execution record: {path}')
    return path, record


def finish_execution(path: Path, returncode: int | None = None) -> None:
    from .cores import collect_cores
    update_execution(path, status='exited', returncode=returncode, ended_unix_ns=time.time_ns())
    try:
        collect_cores(path)
    except Exception as error:
        # Capture failure must not kill init or erase the actual process exit.
        update_execution(path, core_collection={'status': 'collection_failed', 'error': str(error)})
