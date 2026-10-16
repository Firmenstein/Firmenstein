# IPC Callsite — `ipc-callsite`

- schema_version: `26`
- phase: `full`
- target_process.executable_path: `usr/sbin/httpd`
- structured_source: [`ipc-callsite_result.json`](ipc-callsite_result.json)
- disposition: `channel_endpoint`
- reason: verified endpoint

## callsite

- callsite_id: `ipc-callsite`
- location:
  - binary_path: `usr/sbin/httpd`
  - binary_sha256: `1111111111111111111111111111111111111111111111111111111111111111`
  - function_name: `main`
  - function_ea: `4096`
  - snapshot_hash: `ipc-snapshot`
  - ctree_index: `3`
  - source_ea: `4128`
  - line_number: `20`
  - column_number: `2`
- api_family: `ipc-v1`
- mechanism_hint: `uds`
- callee_name: `connect`
- call_kind: `direct`
- expression_text: `connect(fd, "/var/run/peer.sock", 16)`
- arguments:
  - item:
    - index: `1`
    - expression: `fd`
- return_expression: null
- api_binding:
  - kind: `dynamic_import`
  - symbol: `connect`
  - binary_path: null
  - binary_sha256: null
  - status: `verified_static`
  - reason: `undefined dynamic symbol`

## callsite_accounting

- callsite_id: `ipc-callsite`
- disposition: `channel_endpoint`
- endpoint_ids:
  - `endpoint-target`
- unresolved_item_ids:
  - (none)
- reason: `verified endpoint`
