"""Raw process-event queries require files, never IDA or an AnalysisView."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..trace_files import read_trace
from .common import write_json


def query_trace(path: Path, output: Path, *, start: int = 0, limit: int = 32,
                source_sha256: str | None = None, mapped=None, **filters) -> dict:
    if start < 0 or not 1 <= limit <= 64:
        raise ValueError('start must be nonnegative and limit must be 1-64')
    for lower, upper in [('sequence_start', 'sequence_end'), ('time_start_ns', 'time_end_ns')]:
        if any(filters.get(key) is not None and filters[key] < 0 for key in (lower, upper)):
            raise ValueError('sequence/time bounds must be nonnegative')
        if filters.get(lower) is not None and filters.get(upper) is not None and filters[lower] > filters[upper]:
            raise ValueError('start bound exceeds end bound')
    resolved, digest, trace, raw = read_trace(path, [path.parent], source_sha256)
    checkpoint = output / digest / path.name
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    if not checkpoint.exists():
        checkpoint.write_bytes(raw)
    source_events = trace['events']
    mapped_path = None
    mapping_status = None
    if filters.get('static_ea') is not None:
        if mapped is None:
            raise ValueError('Static address selection requires source mapping')
        mapped_path, context = mapped(checkpoint)
        source_events = [event.model_dump(mode='json') for event in context.events]
        mapping_status = {'mapped_events': sum(event.location is not None for event in context.events),
            'unmapped_events': sum(event.runtime_pc is not None and event.location is None for event in context.events),
            'errors': [image.mapping_error for image in context.images if image.mapping_error],
            'notice': 'Unmapped events remain in raw queries; an empty static-address result does not prove no execution.'}
    events = []
    for item in source_events:
        if not isinstance(item, dict):
            continue
        if any(filters.get(key) is not None and item.get(key) != filters[key]
               for key in ('kind', 'unit_id', 'hook_id')):
            continue
        if filters.get('runtime_pc') is not None and item.get('runtime_pc', item.get('pc')) != filters['runtime_pc']:
            continue
        if filters.get('static_ea') is not None and (item.get('location') or {}).get('static_ea') != filters['static_ea']:
            continue
        syscall = filters.get('syscall_name')
        if syscall is not None and (item.get('kind') != 'syscall_result' or not str(item.get('detail', '')).startswith(syscall + '(')):
            continue
        first_seq = item.get('sequence', 0)
        first_time = item.get('elapsed_ns', 0)
        if filters.get('sequence_start') is not None and item.get('last_sequence', first_seq) < filters['sequence_start']:
            continue
        if filters.get('sequence_end') is not None and first_seq > filters['sequence_end']:
            continue
        if filters.get('time_start_ns') is not None and item.get('last_elapsed_ns', first_time) < filters['time_start_ns']:
            continue
        if filters.get('time_end_ns') is not None and first_time > filters['time_end_ns']:
            continue
        events.append(item)
    payload = {'source_path': str(resolved), 'source_sha256': digest, 'checkpoint_path': str(checkpoint),
        'mapped_context_path': str(mapped_path) if mapped_path else None, 'mapping': mapping_status,
        'filters': filters, 'start': start, 'limit': limit, 'total': len(events),
        'showing': min(limit, max(0, len(events) - start)),
        'next_start': start + limit if start + limit < len(events) else None,
        'capture': {key: trace[key] for key in trace if key.startswith('dropped_') or key == 'terminal_reason'},
        'events': events[start:start + limit]}
    encoded = json.dumps(payload, ensure_ascii=False).encode()
    destination = output / digest / (hashlib.sha256(encoded).hexdigest() + '.query.json')
    write_json(destination, payload)
    return {key: value for key, value in payload.items() if key != 'events'} | {
        'query_path': str(destination), 'notice': 'Read query_path for exact retained events. Missing/dropped capture is not proof of absent execution.'}
