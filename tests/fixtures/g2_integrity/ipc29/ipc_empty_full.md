# IPC Analysis

Target process: `/usr/sbin/l2tp-control`.

## Findings

No verified direct IPC channel was identified within the current analysis scope.

## Unresolved Items

No unresolved analysis boundary was recorded.

## Summary

- `phase`: `full`
- `callsites`: `0`
- `channels`: `0`
- `dependency_assessments`: `0`
- `unresolved_items`: `0`

## Artifacts

- Structured source of truth: [`ipc_analysis_result.json`](ipc_analysis_result.json)
- Callsite evidence: [`callsites/index.md`](callsites/index.md)
- IPC channel and peer evidence: [`channels/index.md`](channels/index.md)
- `schema_version`: `29`
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
