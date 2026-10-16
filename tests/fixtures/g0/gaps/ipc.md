# IPC Analysis

Target process: `/usr/sbin/httpd`.

## Findings

No verified direct IPC channel was identified within the current analysis scope.

## Unresolved Items

An unresolved item records a specific point where analysis stopped because required evidence was unavailable. It is neither a verified peer nor a distinct IPC channel.

`1` unresolved items were recorded:
- `function`: `1`

See [`unresolved_items.md`](unresolved_items.md) for complete reasons, affected Channels, missing evidence, and runtime evidence requests. The structured source is the `unresolved_items` field in [`ipc_analysis_result.json`](ipc_analysis_result.json).

## Summary

- `phase`: `full`
- `callsites`: `1`
- `channels`: `0`
- `dependency_assessments`: `0`
- `unresolved_items`: `1`

## Artifacts

- Structured source of truth: [`ipc_analysis_result.json`](ipc_analysis_result.json)
- Callsite evidence: [`callsites/index.md`](callsites/index.md)
- IPC channel and peer evidence: [`channels/index.md`](channels/index.md)
- `schema_version`: `26`
- `firmware_sha256`: `2222222222222222222222222222222222222222222222222222222222222222`
