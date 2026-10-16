# IPC Analysis

Target process: `/usr/sbin/httpd`.

## Findings

- `/usr/sbin/httpd` depends on `/usr/sbin/peer` being available through Unix domain socket `/var/run/peer.sock`.
  - Impact if the peer is unavailable: the target cannot start or remain ready.
  - Channel evidence: [`channel-uds`](channels/channel-uds.md).

## Unresolved Items

No unresolved analysis boundary was recorded.

## Summary

- `phase`: `full`
- `callsites`: `1`
- `channels`: `1`
- `dependency_assessments`: `1`
- `unresolved_items`: `0`

## Artifacts

- Structured source of truth: [`ipc_analysis_result.json`](ipc_analysis_result.json)
- Callsite evidence: [`callsites/index.md`](callsites/index.md)
- IPC channel and peer evidence: [`channels/index.md`](channels/index.md)
- `schema_version`: `26`
- `firmware_sha256`: `2222222222222222222222222222222222222222222222222222222222222222`
