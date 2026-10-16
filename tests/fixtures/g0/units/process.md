# `startup_blocker` — `exit`

- schema_version: `2`
- root_binary: `httpd`

## callsite

- callsite_id: `process-callsite`
- binary_name: `httpd`
- function_name: `main`
- function_ea: `0x1000`
- snapshot_hash: `process-snapshot`
- ctree_index: `5`
- source_ea: `0x1030`
- line_number: `40`
- column_number: `8`
- api_name: `exit`
- event_kind: `termination`

## assessment

- callsite_id: `process-callsite`
- disposition: `startup_blocker`
- summary: Missing nvram device terminates startup.

### trigger_callsites

_None._

### trigger_inputs

- `path` `/dev/nvram` — The failed nvram open reaches startup exit.

### evidence

- `httpd::main:L40::exit` — startup exit

### missing_evidence

_None._
