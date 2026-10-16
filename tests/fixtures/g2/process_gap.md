# Process Lifecycle Analysis — `httpd`

This report classifies reachable termination and process-transition calls by whether they can block target startup. JSON is the source of truth; the pages linked below are deterministic views of the same data.

- Structured source of truth: [`process_lifecycle_analysis_result.json`](process_lifecycle_analysis_result.json)

## Summary

- schema_version: `3`
- phase: `full`
- root_binary: `httpd`
- callsites: 1
- assessments: 1
- skipped: 0
- startup_blocker: 0
- expected_lifecycle: 0
- runtime_only: 0
- unresolved: 1

## assessments

| disposition | event | location | summary | report |
|---|---|---|---|---|
| `unresolved` | `exit` | `httpd::main:L10:C6` | classified process event | [md](unresolved__process-event_abc.md) / [json](unresolved__process-event_abc.json) |

## skipped

_None._

## finding_target

- path: ` "usr/sbin/httpd" `
- sha256: ` "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" `


## callsites

- process-event:abc:
  - callsite_id: ` "process-event:abc" `
  - binary_name: ` "httpd" `
  - function_name: ` "main" `
  - function_ea: ` 4096 `
  - snapshot_hash: ` "snap" `
  - ctree_index: ` 7 `
  - source_ea: ` 4160 `
  - line_number: ` 10 `
  - column_number: ` 6 `
  - api_name: ` "exit" `
  - event_kind: ` "termination" `


## planning_findings

### finding:process:v1:8926cfdf59b75fa9946aeb59ed107f99297c25614a4cfa7c47ff53516dcb3e01

- finding_ref: ` "finding:process:v1:8926cfdf59b75fa9946aeb59ed107f99297c25614a4cfa7c47ff53516dcb3e01" `
- summary: ` "classified process event" `
- boundary:
  - kind: ` "callsite" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/process-event:abc" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "dynamic caller" `
    - evidence_refs:
      - ` "/assessments/process-event:abc/missing_evidence/0" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "process" `
  - callsite_id: ` "process-event:abc" `
  - event_kind: ` "termination" `
