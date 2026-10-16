# IPC Analysis

Target process: `/usr/sbin/l2tp-control`.

## Findings

No direct firmware IPC peer was verified within the current analysis scope.

## Channels Without a Verified Peer

`1` channels do not yet have a verified peer:
- Unix domain socket: `1`

See the [`channels` index](channels/index.md) for every resource identifier, target-side impact, and candidate audit.

## Unresolved Items

An unresolved item records a specific point where analysis stopped because required evidence was unavailable. It is neither a verified peer nor a distinct IPC channel.

`3` unresolved items were recorded:
- `analysis_scope`: `3`

See [`unresolved_items.md`](unresolved_items.md) for complete reasons, affected Channels, missing evidence, and runtime evidence requests. The structured source is the `unresolved_items` field in [`ipc_analysis_result.json`](ipc_analysis_result.json).

## Summary

- `phase`: `full`
- `callsites`: `1`
- `channels`: `1`
- `dependency_assessments`: `1`
- `unresolved_items`: `3`

## Artifacts

- Structured source of truth: [`ipc_analysis_result.json`](ipc_analysis_result.json)
- Callsite evidence: [`callsites/index.md`](callsites/index.md)
- IPC channel and peer evidence: [`channels/index.md`](channels/index.md)
- `schema_version`: `27`
- `firmware_sha256`: `01785697c51209c9df008ee434a15265a2a8b90f791e2443cac2db5506d48e03`

## target_process

- target_process:
  - executable_path: ` "usr/sbin/l2tp-control" `
  - executable_sha256: ` "63e9f422d199949f817437a16af5b6309f4e91629c2bdfd6b9f56d782e44e817" `
  - argv0: ` "l2tp-control" `

## covered_api_calls

- covered_api_calls:
  - [0]:
    - binary_name: ` "l2tp-control" `
    - function_name: ` "sub_4008D0" `
    - api_name: ` "socket" `
    - line_number: ` 14 `
    - column_number: ` 9 `
    - function_ea: ` 4196560 `
    - snapshot_hash: ` "cb4497eb06c3aa29ec80828a3a2f084f5a41900a571d98f72137fba0d2d6ce38" `
    - ctree_index: ` 25 `
    - source_ea: ` 4196780 `
    - reason: ` "IPC uds: Client creates an AF_UNIX SOCK_STREAM socket, connects to /var/run/l2tpctrl, and attempts to write the nonempty input followed by a newline." `
  - [1]:
    - binary_name: ` "l2tp-control" `
    - function_name: ` "sub_4008D0" `
    - api_name: ` "connect" `
    - line_number: ` 17 `
    - column_number: ` 11 `
    - function_ea: ` 4196560 `
    - snapshot_hash: ` "cb4497eb06c3aa29ec80828a3a2f084f5a41900a571d98f72137fba0d2d6ce38" `
    - ctree_index: ` 75 `
    - source_ea: ` 4196884 `
    - reason: ` "IPC uds: Client creates an AF_UNIX SOCK_STREAM socket, connects to /var/run/l2tpctrl, and attempts to write the nonempty input followed by a newline." `

## planning_findings

### finding:ipc:v1:0a31881f16f1f3a5c86b65fc6ecf2dfdcbb5759edb98976141275349aff54107

- finding_ref: ` "finding:ipc:v1:0a31881f16f1f3a5c86b65fc6ecf2dfdcbb5759edb98976141275349aff54107" `
- summary: ` "For nonempty input, the target attempts to send the command followed by a newline after connection; this function does not consume peer data." `
- boundary:
  - kind: ` "resource" `
  - anchors:
    - [0]:
      - kind: ` "ipc_channel" `
      - ref: ` "/channels/0" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "guarantee" `
    - statement: ` "When *a1 is nonzero and socket/connect succeed, the target calls writev with the input buffer length strlen(a1) and a one-byte newline, then returns the connected descriptor." `
    - evidence_refs:
      - ` "/dependency_assessments/0/evidence/1" `
    - unknown_kind: ` null `
  - [1]:
    - kind: ` "fallback" `
    - statement: ` "If *a1 is zero, the helper sets errno to 29 and returns -1. Socket failure calls perror(\"socket\") and returns -1. Connect failure calls perror(\"connect\"), closes the descriptor, and returns -1." `
    - evidence_refs:
      - ` "/dependency_assessments/0/evidence/0" `
    - unknown_kind: ` null `
  - [2]:
    - kind: ` "state" `
    - statement: ` "The helper creates a short-lived client socket, returns its descriptor after the request write attempt, and does not establish persistent state in this function." `
    - evidence_refs:
      - ` "/dependency_assessments/0/evidence/1" `
    - unknown_kind: ` null `
  - [3]:
    - kind: ` "unknown" `
    - statement: ` "Whether writev transfers the complete request, whether the peer returns a response, and how the caller later uses or closes the returned descriptor are not proved because the writev result and subsequent caller behavior are unavailable here." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "external_effects" `
- domain:
  - kind: ` "ipc" `
  - channel_id: ` "channel:4c931a2cbae08236ea3d47b7" `
  - mechanism: ` "uds" `
  - endpoint_ids:
    - ` "endpoint:91d9c28691adcb1bc4310b02" `

