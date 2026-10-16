# IPC Callsite — `cs:3c9b56789b831dfecf1a3899`

- schema_version: `27`
- phase: `full`
- target_process.executable_path: `usr/sbin/l2tp-control`
- structured_source: [`cs_3c9b56789b831dfecf1a3899_result.json`](cs_3c9b56789b831dfecf1a3899_result.json)
- disposition: `channel_endpoint`
- reason: Client creates an AF_UNIX SOCK_STREAM socket, connects to /var/run/l2tpctrl, and attempts to write the nonempty input followed by a newline.

## callsite

- callsite_id: `cs:3c9b56789b831dfecf1a3899`
- location:
  - binary_path: `usr/sbin/l2tp-control`
  - binary_sha256: `63e9f422d199949f817437a16af5b6309f4e91629c2bdfd6b9f56d782e44e817`
  - function_name: `sub_4008D0`
  - function_ea: `4196560`
  - snapshot_hash: `cb4497eb06c3aa29ec80828a3a2f084f5a41900a571d98f72137fba0d2d6ce38`
  - ctree_index: `75`
  - source_ea: `4196884`
  - line_number: `17`
  - column_number: `11`
- api_family: `socket_endpoint`
- mechanism_hint: `unknown`
- callee_name: `connect`
- call_kind: `direct`
- expression_text: `connect(fd, &s, 0x6Eu)`
- arguments:
  - item:
    - index: `1`
    - expression: `fd`
  - item:
    - index: `2`
    - expression: `&s`
  - item:
    - index: `3`
    - expression: `0x6Eu`
- return_expression: null
- api_binding:
  - kind: `dynamic_import`
  - symbol: `connect`
  - binary_path: null
  - binary_sha256: null
  - status: `verified_static`
  - reason: `source ELF declares this symbol undefined in its dynamic symbol table; runtime provider intentionally not inferred`

## callsite_accounting

- callsite_id: `cs:3c9b56789b831dfecf1a3899`
- disposition: `channel_endpoint`
- endpoint_ids:
  - `endpoint:91d9c28691adcb1bc4310b02`
- unresolved_item_ids:
  - (none)
- reason: `Client creates an AF_UNIX SOCK_STREAM socket, connects to /var/run/l2tpctrl, and attempts to write the nonempty input followed by a newline.`
