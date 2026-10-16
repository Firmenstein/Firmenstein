"""Actual harness CPU listings and bounded reads of its retained build source."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import uuid

from .budget import ExecutionBudget, RunnerStopped
from .elf_inspection import snapshot_file
from .runtime_builder import RuntimeBuilder


def inspect_emulator(harness: Path | None, output_root: Path, *, builder: RuntimeBuilder,
    operation: str = 'models', name: str = '', source_path: str = '', start: int = 0,
    limit: int = 80, harness_sha256: str | None = None, source_sha256: str | None = None,
    execution_harness_sha256: str | None = None,
    build_source_root: Path | None = None,
    budget: ExecutionBudget | None = None,
) -> dict:
    if operation not in {'models', 'find_source', 'read_source'}:
        raise ValueError('Unsupported emulator inspection operation')
    if isinstance(start, bool) or not isinstance(start, int) or start < 0:
        raise ValueError('start must be a nonnegative entry/line offset')
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError('limit must be between 1 and 200')
    if operation == 'find_source' and (not name or '/' in name or '\x00' in name):
        raise ValueError('name must be an exact source basename')
    output = output_root / 'emulator-inspections' / uuid.uuid4().hex
    output.mkdir(parents=True)
    receipt = {'schema_version': 1, 'status': 'unavailable', 'receipt_path': str(output / 'receipt.json'),
        'request': {'operation': operation, 'name': name, 'source_path': source_path, 'start': start, 'limit': limit},
        'error': None, 'limitations': [
            'CPU listing is output from the actual harness, not a guest execution or feature test.',
            'Retained QEMU build source is source evidence; model names and feature definitions do not prove a firmware scenario succeeds.',
            'The source export is beside this harness build; it is not an independently reproduced binary/source equivalence proof.',
        ]}
    try:
        if budget is not None:
            budget.check()
        if harness is None or not harness.is_file():
            raise ValueError('No actual harness from the latest Controller attempt is available')
        harness = harness.resolve()
        snapshot = output / harness.name
        sha = snapshot_file(harness, snapshot, budget)
        receipt['harness'] = {'path': str(harness), 'snapshot': str(snapshot), 'sha256': sha}
        receipt['execution_harness_sha256'] = execution_harness_sha256
        if execution_harness_sha256 is not None and execution_harness_sha256 != sha:
            receipt['status'] = 'source_changed'
            raise ValueError('Harness differs from the latest executed runtime bundle')
        if harness_sha256 is not None and harness_sha256 != sha:
            receipt['status'] = 'source_changed'
            raise ValueError('Harness differs from the requested SHA-256')
        if operation == 'models':
            snapshot.chmod(0o555)
            result = builder.list_cpu_models(snapshot)
            receipt.update(status='query_completed', command=result.args, returncode=result.returncode,
                stdout=result.stdout, stderr=result.stderr)
        else:
            # This is the source export beside the built LibAFL QEMU harness,
            # not a separately selected checkout or an inferred system QEMU.
            root = build_source_root if build_source_root is not None else harness.parent / 'qemu-libafl-bridge'
            if not root.is_dir() or root.is_symlink():
                raise ValueError('This build has no retained QEMU source export')
            receipt['source_root'] = str(root)
            if operation == 'find_source':
                paths = []
                for entry in root.rglob('*'):
                    if budget is not None:
                        budget.check()
                    if entry.name != name:
                        continue
                    entry.resolve().relative_to(root)
                    if entry.is_file():
                        paths.append(entry.relative_to(root).as_posix())
                paths.sort()
                receipt.update(status='ok', total=len(paths), showing=min(limit, max(0, len(paths) - start)),
                    paths=paths[start:start + limit], next_start=start + limit if start + limit < len(paths) else None)
            else:
                if not source_path or Path(source_path).is_absolute() or '\x00' in source_path:
                    raise ValueError('source_path must be relative to the returned QEMU source root')
                source = (root / source_path).resolve(strict=True)
                source.relative_to(root)
                saved = output / 'source.txt'
                sha = snapshot_file(source, saved, budget)
                receipt['source'] = {'path': str(source), 'snapshot': str(saved), 'sha256': sha}
                if source_sha256 is not None and source_sha256 != sha:
                    receipt['status'] = 'source_changed'
                    raise ValueError('Build source differs from the requested SHA-256')
                lines = []
                total = 0
                with saved.open(encoding='utf-8', errors='replace') as stream:
                    for index, line in enumerate(stream):
                        if budget is not None:
                            budget.check()
                        total += 1
                        if start <= index < start + limit:
                            lines.append({'line': index + 1, 'text': line.rstrip('\n')})
                receipt.update(status='ok', total_lines=total, showing=len(lines), lines=lines,
                    next_start=start + limit if start + limit < total else None)
    except RunnerStopped as error:
        receipt.update(status='stopped', error=str(error))
        raise
    except subprocess.TimeoutExpired as error:
        def as_text(value):
            return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else value or ''
        receipt.update(status='timeout', error=str(error), stdout=as_text(error.stdout), stderr=as_text(error.stderr))
    except (OSError, ValueError, RuntimeError) as error:
        receipt['error'] = str(error)
    finally:
        (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    return receipt
