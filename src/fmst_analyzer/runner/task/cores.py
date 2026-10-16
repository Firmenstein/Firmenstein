"""Collect task-local QEMU core files without Docker or a host core_pattern change."""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import stat
from pathlib import Path

from .common import write_json


def core_inventory(root: Path) -> dict:
    records = {}
    for directory, children, files in os.walk(root, followlinks=False):
        children[:] = [name for name in children if not (Path(directory) / name).is_symlink()
                       and not (Path(directory) == root and name in {'proc', 'sys', 'dev', 'fmst-host', 'fmst-output'})]
        for name in files:
            if name != 'core' and not name.endswith('.core') and not name.startswith('core.'):
                continue
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISREG(info.st_mode):
                records[str(path)] = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
    return records


def collect_cores(execution_path: Path) -> dict:
    from .execution import file_identity, update_execution
    from ..runtime_dump import _valid_guest_core, _core_identity
    from ..trace_files import trace_inventory
    root = execution_path.parent
    with (root / 'core-collection.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        record = json.loads(execution_path.read_text())
        retained = root / 'core-collection.json'
        if retained.is_file():
            previous_collection = json.loads(retained.read_text())
            if previous_collection.get('terminal'):
                return previous_collection
        previous = json.loads((root / 'cores-before.json').read_text())
        candidates = core_inventory(Path(record['rootfs']))
        inventory = [item for folder in record['trace_roots']
                     for item in trace_inventory(Path(folder), recursive=True)['traces']]
        config = json.loads(Path(record['config_path']).read_text())
        records, errors = [], []
        total = 0
        destination = root / 'captured-cores'
        destination.mkdir(exist_ok=True)
        for value, signature in candidates.items():
            if previous.get(value) == signature:
                continue
            source = Path(value)
            valid, error = _valid_guest_core(source, 'unknown', 'unknown', 0)
            if not valid:
                errors.append({'path': value, 'error': error})
                continue
            # This is a diagnostic retention bound, not a ban on Agent tools.
            total += signature[2]
            if total > 64 * 1024**2 or shutil.disk_usage(root).free < signature[2]:
                errors.append({'path': value, 'error': 'Core retention reserve reached; original file remains accessible.'})
                continue
            identity = _core_identity(source)
            expected = file_identity(source)['sha256']
            saved = destination / (expected + '.core')
            if not saved.exists():
                temporary = saved.with_suffix('.partial')
                shutil.copyfile(source, temporary)
                if file_identity(temporary)['sha256'] != expected:
                    temporary.unlink()
                    errors.append({'path': value, 'error': 'Core changed during collection; retry after its writer exits.'})
                    continue
                temporary.replace(saved)
            name = Path(identity.get('executable') or '').name
            matches = []
            for item in inventory:
                if item['host_pid'] != identity.get('pid') or not name:
                    continue
                same_image = any(image.rsplit('@0x', 1)[0] == name for image in item['images'])
                primary_launch = (Path(item['path']) == Path(record['trace_roots'][0]) / 'runtime_trace.json'
                                  and identity.get('executable') == config.get('executable'))
                exec_launch = any(transition.get('status') == 'started'
                    and transition.get('host_pid') == identity.get('pid')
                    and transition.get('requested_executable') == identity.get('executable')
                    for transition in item['exec_transitions'])
                compatible, _ = _valid_guest_core(source, item.get('guest_arch') or 'unknown',
                    item.get('byte_order') or 'unknown', item.get('word_bits') or 0)
                if compatible and (same_image or primary_launch or exec_launch):
                    matches.append(item)
            records.append({'path': str(saved), 'sha256': expected, 'source_path': value,
                'identity': identity, 'association': 'process_trace' if len(matches) == 1 else 'unverified',
                'trace_path': matches[0]['path'] if len(matches) == 1 else None,
                'trace_sha256': matches[0]['sha256'] if len(matches) == 1 else None})
        result = {'status': 'collected' if records else 'no_core_found', 'cores': records, 'errors': errors,
            'terminal': record.get('status') == 'exited',
            'notice': 'Changed task-local core files only. Missing core is not proof of no crash; explicit paths are usable.'}
        if errors:
            result['status'] = 'partial' if records else 'collection_failed'
        write_json(root / 'core-collection.json', result)
        update_execution(execution_path, core_collection=result)
        return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('execution', type=Path)
    args = parser.parse_args()
    print(json.dumps(collect_cores(args.execution)))
