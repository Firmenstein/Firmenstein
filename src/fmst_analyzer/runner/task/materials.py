"""Package a firmware's analysis material with explicit source/path identities."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .common import write_json
from .host import copy_tree, docker

REPORT_EXCLUDES = ('runner_reports', 'runner_task_reports', 'retained-diagnosis', 'traces', '__pycache__')


def describe(source: Path, destination: str, kind: str, exclude=()) -> dict:
    record = {'source_path': str(source), 'container_path': destination, 'kind': kind}
    if not source.exists():
        return record | {'status': 'missing'}
    digest = hashlib.sha256()
    count = size = 0
    if source.is_file():
        paths = [source]
    else:
        paths = []
        for directory, children, files in os.walk(source, followlinks=False):
            children[:] = sorted(name for name in children if name not in exclude)
            paths.extend(Path(directory) / name for name in sorted(files) if name not in exclude)
            paths.extend(Path(directory) / name for name in children if (Path(directory) / name).is_symlink())
    for path in paths:
        name = path.relative_to(source).as_posix() if path != source else path.name
        if path.is_symlink():
            value = 'symlink:' + os.readlink(path)
        elif path.is_file():
            with path.open('rb') as stream:
                value = hashlib.file_digest(stream, 'sha256').hexdigest()
            size += path.stat().st_size
        else:
            continue
        digest.update((name + '\0' + value + '\n').encode())
        count += 1
    return record | {'status': 'included', 'files': count, 'bytes': size, 'content_index_sha256': digest.hexdigest()}


def package_analysis(task, *, config, view, reports: Path, rootfs: Path, rootfs_sha256: str, candidate: Path | None = None):
    from ..identity import tree_sha256
    source_config = view.global_config if view is not None else config
    workdir = Path(source_config.workdir)
    source_root = Path(source_config.fw_rootfs_path or rootfs).resolve(strict=True)
    if source_root != rootfs and tree_sha256(source_root) != rootfs_sha256:
        raise ValueError('Analysis source belongs to a different firmware rootfs')
    entries = [{'source_path':str(rootfs), 'container_path':'/task/input/rootfs',
                'working_path':'/task/work/rootfs', 'kind':'rootfs', 'status':'included', 'sha256':rootfs_sha256}]
    if candidate is not None:
        entries.append({'source_path':str(candidate), 'container_path':'/task/input/candidate',
            'working_path':'/task/work/candidate', 'kind':'candidate', 'status':'included'})

    def include(source, destination, kind, exclude=()):
        source = Path(source)
        record = describe(source, destination, kind, exclude)
        entries.append(record)
        if record['status'] == 'included':
            copy_tree(task.name, source, destination, exclude=exclude)

    include(reports, '/task/input/reports', 'selected_target_reports', REPORT_EXCLUDES)
    report_paths = {config.current_target: '/task/input/reports'}
    diagnostics = workdir / 'diagnostic_reports'
    if diagnostics.is_dir():
        for source in sorted(diagnostics.iterdir()):
            if not source.is_dir() or source.is_symlink() or source.resolve() == reports.resolve():
                continue
            destination = '/task/input/firmware-reports/' + source.name
            include(source, destination, 'firmware_target_reports', REPORT_EXCLUDES)
            report_paths.setdefault(source.name, destination)
    for name in ('graph_cache', 'decompiled_code', 'disassembled_code'):
        include(workdir / name, '/task/analysis/' + name, name)
    db = Path(source_config.decompiler_db_dir or workdir / 'decompiler_db')
    include(db, '/task/analysis/decompiler_db', 'decompiler_db')
    # A live node can refer to an IDB retained outside the config workdir.
    for binary in view.lib_dep_graph.get_nodes() if view is not None else []:
        value = getattr(binary, 'idb_path', None)
        if value is None:
            continue
        source = Path(value)
        if source.is_relative_to(db):
            continue
        relative = Path(source.parent.name) / source.name if len(source.parent.name) == 64 else Path(source.name)
        include(source, '/task/analysis/decompiler_db/' + relative.as_posix(), 'live_idb')
    result = {'schema_version': 1, 'firmware_rootfs_sha256': rootfs_sha256,
        'analysis_source_rootfs': str(source_root), 'analysis_workdir': str(workdir),
        'report_paths': report_paths, 'materials': entries,
        'notice': 'Historical report paths are provenance. Resolve by these source/container prefixes; reports are observations, not immutable truth.'}
    write_json(task.output / 'materials.json', result)
    task.put_json('/task/input/materials.json', result)
    docker('exec', task.name, 'chmod', '644', '/task/input/materials.json')
    return result


def resolve_material_path(path: str, index_path: Path) -> dict:
    import json
    requested = Path(path)
    index = json.loads(index_path.read_text())
    matches = [item for item in index['materials'] if requested.is_relative_to(item['source_path'])]
    if not matches:
        return {'path':path, 'container_path':path, 'status':'local' if requested.exists() else 'unresolved'}
    selected = max(matches, key=lambda item:len(Path(item['source_path']).parts))
    suffix = requested.relative_to(selected['source_path'])
    result = {'source_path':path, 'status':selected['status'],
              'container_path':str(Path(selected['container_path']) / suffix)}
    if selected.get('working_path'):
        result['working_path'] = str(Path(selected['working_path']) / suffix)
    return result
