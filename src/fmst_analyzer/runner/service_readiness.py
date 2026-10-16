"""Observe TCP listeners without connecting to or invoking the guest service."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import time


def tcp_listeners(output: str, port: int, *, ipv6: bool = False) -> list[dict]:
    """Read Linux /proc/net/tcp{,6}; retain exact rows behind decoded facts."""
    rows = output.splitlines()
    remote_column = 'remote_address' if ipv6 else 'rem_address'
    if not rows or rows[0].split()[:4] != ['sl', 'local_address', remote_column, 'st']:
        raise ValueError('Unexpected kernel TCP table header')
    listeners = []
    for row in rows[1:]:
        values = row.split()
        if len(values) < 10:
            raise ValueError('Incomplete kernel TCP table row')
        address, raw_port = values[1].split(':')
        local_port = int(raw_port, 16)
        raw = bytes.fromhex(address)
        if len(raw) != (16 if ipv6 else 4):
            raise ValueError('Unexpected kernel TCP address width')
        # The delivered harness runs on Linux amd64. procfs encodes each
        # address word in host byte order, separately from guest endianness.
        decoded = b''.join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
        if values[3] == '0A' and local_port == port:
            listeners.append({'address': str(ipaddress.ip_address(decoded)), 'port': local_port,
                'inode': int(values[9]), 'family': 'ipv6' if ipv6 else 'ipv4', 'row': row})
    return listeners


def wait_for_service(*, observer, observe_listeners, deadline: float,
                     evidence_path: Path, check_budget) -> dict:
    """Require live target and listeners, retaining a final process observation.

    No request, connection or response assertion is performed. Listener
    ownership and protocol correctness are not inferred; original-scenario
    validation belongs to a separate disposable instance.
    """
    record = {'schema_version': 1, 'state': 'waiting', 'started_unix_ns': time.time_ns(),
        'condition': 'fresh live target process and kernel TCP listener',
        'active_probe_performed': False, 'listeners': [], 'error': None,
        'limitations': ['Point-in-time process/listener readiness does not prove protocol correctness or listener ownership.',
            'No guest application request or TCP connection is sent; native startup and companion activity still occur.']}

    def save():
        evidence_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')

    save()
    try:
        while True:
            check_budget()
            if observer.interrupted.is_set():
                raise RuntimeError(f'Service readiness interrupted: {observer.termination_reason}; {observer.observation_error}')
            if time.monotonic() >= deadline:
                raise RuntimeError('Service process/listener readiness deadline expired')
            fresh = (observer.last_sample_monotonic is not None and observer.observation_error is None
                and time.monotonic() - observer.last_sample_monotonic <= 2.0)
            listeners = observe_listeners() if fresh and observer.target_alive else []
            record.update(listeners=listeners, process_sample_fresh=fresh, sampled_unix_ns=time.time_ns())
            save()
            if listeners:
                observer.stop('service_ready')
                observer.join()
                observer.sample_for_service()
                check_budget()
                final = observer.final_observation
                listeners = observe_listeners()
                if (observer.interrupted.is_set() or not final or final['status'] != 'complete'
                        or not observer.target_alive or not listeners or time.monotonic() >= deadline):
                    raise RuntimeError('Service readiness lost during final observation')
                record.update(state='ready', ready_unix_ns=time.time_ns(), listeners=listeners,
                    process_observation=str(observer.final_process_path))
                save()
                return record
            observer.interrupted.wait(min(0.1, max(0, deadline - time.monotonic())))
    except BaseException as error:
        record.update(state='failed', error=f'{type(error).__name__}: {error}')
        save()
        raise
