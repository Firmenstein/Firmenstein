"""Keep short diagnostics without credentials, native IDs or raw transcripts."""
import os
import json
import re
from pathlib import Path


def scrub(value, limit=4000):
    text = str(value or '')
    for name, secret in os.environ.items():
        if len(secret) >= 8 and any(key in name.upper() for key in ('TOKEN', 'SECRET', 'PASSWORD', 'API_KEY')):
            text = text.replace(secret, '[redacted]')
    text = re.sub(r'(?i)((?:[A-Z0-9_]*API[_-]?KEY|[A-Z0-9_]*TOKEN|PASSWORD|AUTHORIZATION)\s*[:=]\s*)[^\s,;]+', r'\1[redacted]', text)
    text = re.sub(r'(?i)Bearer\s+\S+', 'Bearer [redacted]', text)
    text = re.sub(r'\bsk-[A-Za-z0-9_-]+', '[redacted]', text)
    text = re.sub(r'(https?://)[^\s/@]+:[^\s/@]+@', r'\1[redacted]@', text)
    text = re.sub(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b', '[id-redacted]', text)
    if len(text) > limit:
        text = text[:limit] + f' (truncated, {limit} of {len(text)} chars)'
    return text


def exception_record(error):
    result = {'error_type': type(error).__name__, 'error_message': scrub(error),
              'cause_type': type(error.__cause__).__name__ if error.__cause__ else None,
              'cause_message': scrub(error.__cause__) if error.__cause__ else None}
    for name in ('provider', 'http_status', 'subtype', 'stop_reason', 'terminal_reason', 'code'):
        value = getattr(error, name, None)
        if value is not None:
            result[name] = scrub(value) if isinstance(value, str) else value
    return result


def structured_failures(case_root):
    """Consume actual failure packets before cleanup, without reading transcripts."""
    result = []
    for path in sorted((Path(case_root) / 'pipeline').glob('**/pipeline_failure.json')):
        try:
            packet = json.loads(path.read_text())
        except (OSError, ValueError):
            result.append({'source': str(path), 'packet_status': 'unreadable'})
            continue
        if not isinstance(packet, dict) or packet.get('schema_version') != 1 or not isinstance(packet.get('causes'), list):
            result.append({'source': str(path), 'packet_status': 'unsupported'})
            continue
        def clean(value):
            if isinstance(value, str): return scrub(value)
            if isinstance(value, list): return [clean(item) for item in value]
            if isinstance(value, dict): return {key: clean(item) for key, item in value.items()}
            return value
        result.append({'source': str(path), 'packet_status': 'read', **clean(packet)})
    return result


def dispatch_stop_observed(record):
    """Provider/resource ledger metadata controls dispatch, not log keywords."""
    if record.get('dispatch_blocked') or record.get('provider_failure_observed'):
        return True
    for packet in record.get('pipeline_failures', []):
        if packet.get('dispatch_blocked'):
            return True
        if any(item.get('error_type') == 'AgentProviderError' or item.get('errno') in {12, 23, 24, 28}
               for item in packet.get('causes', [])):
            return True
        tasks = (packet.get('execution') or {}).get('tasks', {})
        if any((item.get('failure') or {}).get('kind') in {'provider', 'cancelled'}
               or (item.get('failure') or {}).get('errno') in {12, 23, 24, 28}
               for item in tasks.values()):
            return True
    return dispatch_stop_observed(record['error_diagnostics']) if isinstance(record.get('error_diagnostics'), dict) else False


def pipeline_diagnostic(case_root, log_path):
    diagnostic = log_record(log_path)
    diagnostic['pipeline_failures'] = structured_failures(case_root)
    diagnostic['dispatch_blocked'] = dispatch_stop_observed(diagnostic)
    if diagnostic['pipeline_failures']:
        readable = [item for item in diagnostic['pipeline_failures'] if item.get('packet_status') == 'read']
        if len(readable) == 1:
            packet = readable[0]
            diagnostic['failure_stage'] = packet.get('failed_stage')
            if packet.get('causes'):
                diagnostic['error_type'] = packet['causes'][0].get('error_type')
                diagnostic['error_message'] = packet['causes'][0].get('reason')
    if not diagnostic.get('error_type'):
        diagnostic['error_message'] = 'Specific exception was not extracted; cause unknown.'
    return diagnostic


def log_record(path):
    path = Path(path)
    if not path.exists():
        return {'source_log': str(path), 'error_type': None, 'error_message': '', 'traceback_observed': False}
    size = path.stat().st_size
    with path.open('rb') as stream:
        stream.seek(max(0, size-128*1024))
        content = stream.read().decode(errors='replace')
    content = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', content)
    found = list(re.finditer(r'(?m)^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Interrupt))(?::\s*(.*))?$', content))
    result = {'source_log': str(path), 'source_log_bytes': size,
              'parsed_tail_bytes': min(size, 128*1024),
              'traceback_observed': 'Traceback (most recent call last)' in content,
              'error_type': found[-1].group(1) if found else None,
              'error_message': scrub(found[-1].group(2)) if found else '',
              'cause_type': found[-2].group(1) if len(found)>1 else None,
              'cause_message': scrub(found[-2].group(2)) if len(found)>1 else None,
              'raw_log_retained_after_case_cleanup': False,
              'ansi_removed_before_parse': True}
    observed_types = {match.group(1).rsplit('.', 1)[-1] for match in found}
    result['provider_failure_observed'] = bool(observed_types & {
        'AgentProviderError', 'APIConnectionError', 'AuthenticationError', 'RateLimitError',
        'ConnectionRefusedError', 'ConnectError', 'CLIConnectionError', 'CLIJSONDecodeError',
    }) or bool(re.search(r'\bAgentProviderError\s*:', content))
    return result
