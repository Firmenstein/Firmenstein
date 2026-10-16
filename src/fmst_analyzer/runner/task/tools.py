"""Container evidence tools. File access never initializes native analysis."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Literal

from fmst_basic.agent.tool import tool
from .common import TASK, write_json
from .execution import select_execution
from .trace_query import query_trace
from ..trace_files import trace_inventory, read_trace

REPORTS = {
    'ipc': 'ipc_reports/ipc_analysis_result.json', 'file': 'file_reports/file_resolver_result.json',
    'network': 'network_reports/network_analysis_result.json',
    'process': 'process_lifecycle_reports/process_lifecycle_analysis_result.json',
    'launch': 'init_launch_reports/init_launch_analysis_result.json',
    'plan': 'intervention_plan_reports/intervention_plan_result.json',
    'generation': 'intervention_generation_reports/intervention_generation_result.json',
}


def read_lines(path: Path, start: int, end: int) -> str:
    if start < 1 or end < start or end - start >= 400:
        raise ValueError('Request a valid range of at most 400 lines')
    lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    rendered = json.dumps({'source_path': str(path), 'total_lines': len(lines), 'start_line': start,
        'showing': len(lines[start-1:end]), 'lines': lines[start-1:end]}, ensure_ascii=False)
    if len(rendered) > 24000:
        return json.dumps({'status':'oversized','source_path':str(path),'start_line':start,'end_line':end,
            'complete_chars':len(rendered),'notice':'No line was truncated. Read the source file selectively or request a smaller line range.'})
    return rendered


def make_evidence_tools(task: dict, analysis, *, task_root: Path = TASK):
    evidence = task_root / 'evidence'
    rootfs = task_root / 'work/rootfs'

    def inventory(execution_path=None, trace_root=None):
        path, record = select_execution(task_root, execution_path) if not trace_root else (None, {})
        roots = [trace_root] if trace_root else record.get('trace_roots', [])
        inventories = [trace_inventory(Path(root), recursive=True) for root in roots]
        output = evidence / 'runtime-trace-views' / (record.get('execution_id') or 'explicit') / 'inventory.json'
        result = {'execution_path': str(path) if path else None, 'execution_status': record.get('status'),
            'trace_roots': roots, 'traces': [item for inv in inventories for item in inv['traces']],
            'errors': [item for inv in inventories for item in inv['errors']]}
        write_json(output, result)
        return result | {'inventory_path': str(output)}

    def selected_trace(trace_path, execution_path):
        if trace_path:
            return Path(trace_path)
        result = inventory(execution_path)
        if len(result['traces']) != 1:
            raise ValueError(f"Select trace_path from {result['inventory_path']}; found {len(result['traces'])} process traces. Explicit paths also work.")
        return Path(result['traces'][0]['path'])

    async def mapping(path, execution_path, source_sha256=None):
        resolved, digest, _, raw = read_trace(path, [path.parent], source_sha256)
        output = evidence / 'runtime-trace-views' / digest
        output.mkdir(parents=True, exist_ok=True)
        snapshot = output / path.name
        if not snapshot.exists():
            snapshot.write_bytes(raw)
        _, record = select_execution(task_root, execution_path)
        hashes = {Path(item['guest_path']).name: item['sha256'] for item in record.get('images', [])}
        return await analysis.call('map_trace', {'trace_path': str(snapshot), 'output': str(output),
            'executed_binary_hashes': hashes})

    @tool
    def view_executions() -> str:
        """List recorded firmware executions and their evidence paths. Jobs do not change current execution."""
        current, _ = select_execution(task_root)
        records, errors = [], []
        for path in sorted((evidence / 'executions').glob('*/execution.json')):
            try:
                _, record = select_execution(task_root, str(path))
                records.append({key: record.get(key) for key in ('execution_id', 'status', 'started_unix_ns', 'process')} |
                    {'execution_path': str(path), 'current': path == current})
            except (OSError, ValueError) as error:
                errors.append({'path': str(path), 'error': str(error)})
        output = evidence / 'executions/index.json'
        write_json(output, {'executions': records, 'errors': errors})
        return json.dumps({'index_path': str(output), 'count': len(records), 'current': str(current) if current else None})

    @tool
    def view_runtime_trace_files(execution_path: str | None = None, trace_root: str | None = None,
                                 start: int = 0, limit: int = 16, image: str | None = None) -> str:
        """Discover nested process traces for an execution or an explicit output directory.

        Full inventory stays in a file. Select by path/image/PID; separate fork/exec
        checkpoints can overlap. An empty inventory does not establish no execution.
        Args:
            execution_path: execution.json from view_executions; omitted uses the recorded current firmware.
            trace_root: Explicit directory for custom launchers; overrides execution selection.
            start: Zero-based offset after image filtering.
            limit: Process records returned, 1-32.
            image: Optional exact image basename.
        """
        if start < 0 or not 1 <= limit <= 32:
            raise ValueError('start must be nonnegative and limit must be 1-32')
        result = inventory(execution_path, trace_root)
        records = [r for r in result.pop('traces') if image is None or any(i.rsplit('@0x', 1)[0] == image for i in r['images'])]
        return json.dumps(result | {'total': len(records), 'showing': min(limit, max(0, len(records)-start)),
            'traces': records[start:start+limit], 'next_start': start+limit if start+limit < len(records) else None})

    @tool
    async def query_runtime_events(trace_path: str | None = None, execution_path: str | None = None,
        source_sha256: str | None = None, kind: str | None = None, syscall_name: str | None = None,
        runtime_pc: int | None = None, static_ea: int | None = None, unit_id: str | None = None,
        hook_id: str | None = None, sequence_start: int | None = None, sequence_end: int | None = None,
        time_start_ns: int | None = None, time_end_ns: int | None = None, start: int = 0, limit: int = 32) -> str:
        """Save an exact page of retained trace events to a file; raw filters do not need IDA.

        Args:
            trace_path: Actual process trace path, including custom output locations; omit only when selection is unique.
            execution_path: Optional execution.json; otherwise use the current firmware execution.
            source_sha256: Prior checkpoint hash; detects source changes on continuation.
            kind: Exact event kind, for example syscall_result.
            syscall_name: Exact syscall name in detail, for example openat.
            runtime_pc: Exact runtime PC, with no source mapping required.
            static_ea: Exact static address; only this filter requests semantic mapping.
            unit_id: Exact recorded intervention unit.
            hook_id: Exact recorded hook.
            sequence_start: Inclusive sequence lower bound, including overlapping repeated events.
            sequence_end: Inclusive sequence upper bound.
            time_start_ns: Inclusive elapsed-time lower bound.
            time_end_ns: Inclusive elapsed-time upper bound.
            start: Offset within matching retained records.
            limit: Records written per page, 1-64.
        """
        path = selected_trace(trace_path, execution_path)
        mapped = None
        if static_ea is not None:
            context_path = await mapping(path, execution_path, source_sha256)
            from ..schema import RuntimeTraceContext
            context = RuntimeTraceContext.model_validate_json(Path(context_path).read_text())
            mapped = lambda _: (context_path, context)
            # Query the exact snapshot mapped by the backend, never a newer live checkpoint.
            path = Path(context_path).parent / path.name
        return json.dumps(query_trace(path, evidence / 'trace-queries', source_sha256=source_sha256,
            kind=kind, syscall_name=syscall_name, runtime_pc=runtime_pc, static_ea=static_ea,
            unit_id=unit_id, hook_id=hook_id, sequence_start=sequence_start, sequence_end=sequence_end,
            time_start_ns=time_start_ns, time_end_ns=time_end_ns, start=start, limit=limit, mapped=mapped))

    @tool
    async def view_runtime_evidence(execution_path: str | None = None, trace_path: str | None = None,
                                    map_source: bool = False) -> str:
        """Get current execution/evidence routes; optionally map one trace to source.
        Args:
            execution_path: An execution.json path; omitted uses current firmware.
            trace_path: Explicit process trace to map, also supports custom launchers.
            map_source: Request semantic source mapping; otherwise no analysis backend is loaded.
        """
        path, record = select_execution(task_root, execution_path)
        collection = record.get('core_collection', {})
        summary = {key:value for key,value in record.items() if key != 'core_collection'}
        summary['core_collection'] = {'status':collection.get('status'), 'count':len(collection.get('cores', [])),
            'path':str(path.parent / 'core-collection.json') if path else None}
        result = {'execution_path': str(path) if path else None, 'record': summary}
        if map_source:
            result['mapped_context_path'] = await mapping(selected_trace(trace_path, execution_path), execution_path)
        return json.dumps(result)

    @tool
    def view_container_log(path: str | None = None, execution_path: str | None = None,
                           start_line: int = 1, end_line: int = 200) -> str:
        """Read the firmware job log or an explicit log file without analysis initialization.
        Args:
            path: Explicit log path, for companion/custom processes too.
            execution_path: execution.json; omitted uses current firmware.
            start_line: First one-based line.
            end_line: Last line; at most 400 lines per call.
        """
        if path is None:
            _, record = select_execution(task_root, execution_path)
            logs = [item['path'] for item in record.get('log_paths', []) if item['role'] == 'firmware']
            if len(logs) != 1:
                return json.dumps({'status': 'log_selection_required', 'logs': record.get('log_paths', []),
                    'notice': 'No unique firmware log is associated. Supply path; this does not mean the firmware never ran.'})
            path = logs[0]
        return read_lines(Path(path), start_line, end_line)

    @tool
    def view_analyzer_result(analyzer: Literal['ipc','file','network','process','launch','plan','generation'],
        target: str | None = None, mode: Literal['overview','page'] = 'overview', json_pointer: str = '',
        start: int = 0, limit: int = 32, source_sha256: str | None = None) -> str:
        """Read a source report, including other analyzed binaries in the same firmware.
        Args:
            analyzer: Report family.
            target: Binary target name; omitted uses the task's selected target.
            mode: Metadata overview or exact JSON page.
            json_pointer: RFC 6901 pointer into the report.
            start: Page offset.
            limit: Entries per page, 1-128.
            source_sha256: Prior report hash for continuation.
        """
        from ..report_views import view_report
        selected = target or task['target']
        reports = task.get('report_paths', {})
        directory = Path(reports.get(selected, str(task_root / 'input/reports') if selected == task['target']
                                     else str(task_root / 'input/firmware-reports' / selected)))
        return json.dumps(view_report(directory / REPORTS[analyzer], mode=mode, json_pointer=json_pointer,
            start=start, limit=limit, source_sha256=source_sha256))

    @tool
    def resolve_material_path(path: str) -> str:
        """Translate a historical report path to its supplied container copy, preserving provenance.
        Args:
            path: A source path quoted in an Analyzer/Generator report.
        """
        from .materials import resolve_material_path as resolve
        return json.dumps(resolve(path, task_root / 'input/materials.json'))

    @tool
    def read_analysis_artifact(path: str, start_line: int = 1, end_line: int = 200) -> str:
        """Read already exported C, assembly, indexes or reports without IDA.
        Args:
            path: Actual container file path from the materials index or native Glob/Grep.
            start_line: First one-based line.
            end_line: Last line, at most 400 lines per call.
        """
        index = task_root / 'input/materials.json'
        if index.is_file():
            from .materials import resolve_material_path as resolve
            path = resolve(path, index)['container_path']
        return read_lines(Path(path), start_line, end_line)

    @tool
    def find_rootfs_paths(name_or_suffix: str) -> str:
        """Find firmware files by exact basename or path suffix, without IDA.
        Args:
            name_or_suffix: A filename or guest path suffix.
        """
        query = name_or_suffix.strip()
        if not query or '\x00' in query:
            raise ValueError('Supply a nonempty filename/path suffix')
        matches = ['/' + path.relative_to(rootfs).as_posix() for path in rootfs.rglob('*')
                   if (path.name == query if '/' not in query else ('/' + path.relative_to(rootfs).as_posix()).endswith('/' + query.lstrip('/')))]
        output = evidence / 'rootfs-paths.json'
        write_json(output, {'query': query, 'paths': sorted(matches)})
        return json.dumps({'count': len(matches), 'paths_file': str(output)})

    @tool
    def read_rootfs_text(path: str, start_line: int = 1, end_line: int = 200) -> str:
        """Read a firmware text file, resolving absolute symlinks inside its rootfs.
        Args:
            path: Firmware-absolute path.
            start_line: First one-based line.
            end_line: Last line, at most 400 lines.
        """
        from ..rootfs_actions import _guest_host_path
        return read_lines(_guest_host_path(rootfs, path, follow_final_symlink=True), start_line, end_line)

    @tool
    async def inspect_static_elf(path: str, operation: Literal['metadata','bytes','disassemble'] = 'metadata',
        address: str = '', address_space: Literal['virtual','file'] = 'virtual', byte_count: int = 64,
        decoder_mode: str = 'auto', source_sha256: str | None = None) -> str:
        """Inspect firmware ELF bytes and assembly without IDA or executing the binary.
        Args:
            path: Firmware-absolute ELF path.
            operation: metadata, bytes or disassemble.
            address: Numeric static VA or file offset.
            address_space: virtual or file.
            byte_count: Exact bytes, 1-256.
            decoder_mode: auto or an explicit architecture decoder mode.
            source_sha256: Prior ELF hash for continuation.
        """
        from ..elf_inspection import inspect_elf, render_static_inspection
        result = await asyncio.to_thread(inspect_elf, rootfs, evidence, path=path, operation=operation,
            address=address, address_space=address_space, byte_count=byte_count, decoder_mode=decoder_mode,
            source_sha256=source_sha256)
        return render_static_inspection(result)

    @tool
    async def collect_runtime_cores(execution_path: str | None = None) -> str:
        """Collect changed core files for a running or exited execution without stopping its service.

        Useful when a CGI/child crashed while the main service stayed alive.
        Retains up to 64 MiB with disk reserve; originals remain accessible.
        Args:
            execution_path: execution.json; omitted selects the current firmware.
        """
        import os
        import subprocess
        import sys
        from .common import clean_environment
        path, record = select_execution(task_root, execution_path)
        if path is None:
            return json.dumps(record)
        prefix = ['sudo', '--preserve-env=PYTHONPATH'] if os.geteuid() else []
        result = await asyncio.to_thread(subprocess.run,
            [*prefix, sys.executable, '-m', 'fmst_analyzer.runner.task.cores', str(path)],
            env=clean_environment(), capture_output=True, text=True, timeout=60)
        if result.returncode:
            output = evidence / 'core-collection-error.log'
            output.write_text(result.stdout + '\n' + result.stderr)
            return json.dumps({'status':'collection_failed','log_path':str(output)})
        payload = json.loads(result.stdout)
        return json.dumps({'status':payload['status'],'core_count':len(payload.get('cores', [])),
            'collection_path':str(path.parent / 'core-collection.json'),
            'notice':'Read collection_path for core paths and process associations, then inspect_runtime_core.'})

    @tool
    async def inspect_runtime_core(core_path: str | None = None, execution_path: str | None = None,
        operation: Literal['threads','registers','memory','disassemble','backtrace'] = 'registers',
        thread_id: int = 0, address: str = '', count: int = 32, source_sha256: str | None = None) -> str:
        """Inspect a captured core with GDB; missing capture remains explicit, independent of IDA.
        Args:
            core_path: Explicit core file. Its execution association is not assumed.
            execution_path: execution.json; default selects a unique trace-associated core from current execution.
            operation: threads, registers, memory, disassemble or backtrace.
            thread_id: GDB thread index; 0 means all for threads/registers/backtrace.
            address: Numeric address or register with numeric offset for memory/disassemble.
            count: Bytes/instructions/frames, subject to the operation's documented bound.
            source_sha256: Recorded core hash, checked before querying.
        """
        if core_path is None:
            selected_execution, record = select_execution(task_root, execution_path)
            collection = record.get('core_collection', {'status': 'not_collected'})
            cores = [item for item in collection.get('cores', []) if item['association'] == 'process_trace']
            if len(cores) != 1:
                return json.dumps({'status': 'core_selection_required',
                    'collection': {'status':collection['status'],'count':len(collection.get('cores', [])),
                        'path':str(selected_execution.parent / 'core-collection.json') if selected_execution else None},
                    'notice': 'Supply core_path for direct inspection, or call collect_runtime_cores, including while the service remains running.'})
            core_path, source_sha256 = cores[0]['path'], source_sha256 or cores[0]['sha256']
        from ..core_inspection import inspect_core, render_inspection
        receipt = await asyncio.to_thread(inspect_core, None, core_path=Path(core_path), core_sha256=source_sha256,
            output_root=evidence, operation=operation, thread_id=thread_id, address=address, count=count)
        return render_inspection(receipt)

    @tool
    async def inspect_emulator_cpu(harness_path: str | None = None, execution_path: str | None = None,
        operation: Literal['models','find_source','read_source'] = 'models', name: str = '',
        source_path: str = '', source_root: str | None = None, start: int = 0, limit: int = 80,
        harness_sha256: str | None = None, source_sha256: str | None = None) -> str:
        """Query actual QEMU CPU models or build source, not host CPU utilization.
        Args:
            harness_path: Explicit harness; otherwise use the executed bundle from execution.json.
            execution_path: Optional execution.json; defaults to current firmware.
            operation: models, find_source or read_source.
            name: Exact source basename for find_source.
            source_path: Relative source path for read_source.
            source_root: Explicit QEMU source tree; otherwise use recorded build source.
            start: Zero-based result/line offset.
            limit: Complete entries/lines, 1-200.
            harness_sha256: Prior harness hash.
            source_sha256: Prior source file hash.
        """
        from ..emulator_inspection import inspect_emulator
        from ..elf_inspection import render_static_inspection
        from ..runtime_builder import HostRuntimeBuilder
        import subprocess
        _, record = select_execution(task_root, execution_path)
        info = record.get('harness') or {}
        explicit = harness_path is not None
        selected = harness_path or info.get('path')
        if not selected:
            return json.dumps({'status': 'harness_unregistered', 'notice': 'Supply harness_path; no executed harness is associated.'})
        class Builder(HostRuntimeBuilder):
            def list_cpu_models(self, harness):
                if explicit or not info.get('loader'):
                    return super().list_cpu_models(harness)
                return subprocess.run([info['loader'], '--library-path', info['library_path'], str(harness),
                    '--trace-only', '--binary', str(harness), '--rootfs', '/nonexistent'],
                    env={'QEMU_CPU':'help'}, capture_output=True, text=True, timeout=20)
        receipt = await asyncio.to_thread(inspect_emulator, Path(selected), evidence, builder=Builder(),
            operation=operation, name=name, source_path=source_path, start=start, limit=limit,
            harness_sha256=harness_sha256, source_sha256=source_sha256,
            execution_harness_sha256=None if explicit else info.get('sha256'),
            build_source_root=Path(source_root) if source_root else (Path(info['source_root']) if not explicit and info.get('source_root') else None))
        return render_static_inspection(receipt)

    return [view_executions, view_runtime_trace_files, query_runtime_events, view_runtime_evidence,
        view_container_log, view_analyzer_result, resolve_material_path, read_analysis_artifact, find_rootfs_paths, read_rootfs_text,
        inspect_static_elf, collect_runtime_cores, inspect_runtime_core, inspect_emulator_cpu]
