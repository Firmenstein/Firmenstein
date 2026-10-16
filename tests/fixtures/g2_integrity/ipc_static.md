# IPC Analysis

Target process: `/usr/sbin/l2tp-control`.

## Findings

This is the static collection phase; IPC peers and target-side dependencies have not been assessed yet.

## Unresolved Items

An unresolved item records a specific point where analysis stopped because required evidence was unavailable. It is neither a verified peer nor a distinct IPC channel.

`1` unresolved items were recorded:
- `function`: `1`

See [`unresolved_items.md`](unresolved_items.md) for complete reasons, affected Channels, missing evidence, and runtime evidence requests. The structured source is the `unresolved_items` field in [`ipc_analysis_result.json`](ipc_analysis_result.json).

## Summary

- `phase`: `static`
- `callsites`: `1`
- `channels`: `0`
- `dependency_assessments`: `0`
- `unresolved_items`: `1`

## Artifacts

- Structured source of truth: [`ipc_analysis_result.json`](ipc_analysis_result.json)
- Callsite evidence: [`callsites/index.md`](callsites/index.md)
- IPC channel and peer evidence: [`channels/index.md`](channels/index.md)
- `schema_version`: `28`
- `firmware_sha256`: `01785697c51209c9df008ee434a15265a2a8b90f791e2443cac2db5506d48e03`

## target_process

- target_process:
  - executable_path: ` "usr/sbin/l2tp-control" `
  - executable_sha256: ` "63e9f422d199949f817437a16af5b6309f4e91629c2bdfd6b9f56d782e44e817" `
  - argv0: ` "l2tp-control" `

## covered_api_calls

- covered_api_calls: ` [] `

## planning_findings

`{}`


## execution

- tasks: ` {} `
- status: ` "complete" `
