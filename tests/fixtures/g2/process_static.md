# Process Lifecycle Analysis — `nvram`

This report classifies reachable termination and process-transition calls by whether they can block target startup. JSON is the source of truth; the pages linked below are deterministic views of the same data.

- Structured source of truth: [`process_lifecycle_analysis_result.json`](process_lifecycle_analysis_result.json)

## Summary

- schema_version: `3`
- phase: `static`
- root_binary: `nvram`
- callsites: 1
- assessments: 0
- skipped: 0
- startup_blocker: 0
- expected_lifecycle: 0
- runtime_only: 0
- unresolved: 0

## assessments

_None._

## skipped

_None._

## finding_target

- path: ` "usr/sbin/nvram" `
- sha256: ` "690e220908417414f4b4b003811dda7b4f380c14eb9ec0657744bda44913c33d" `


## callsites

- process-event:015ab1793704480029ae30aa:
  - callsite_id: ` "process-event:015ab1793704480029ae30aa" `
  - binary_name: ` "nvram" `
  - function_name: ` "usage" `
  - function_ea: ` 4196624 `
  - snapshot_hash: ` "cf3c99134b9f6c081cdf102d44cfe566a3d8292d6df97ff541fe620bf4bab8cb" `
  - ctree_index: ` 9 `
  - source_ea: ` 4196696 `
  - line_number: ` 4 `
  - column_number: ` 2 `
  - api_name: ` "exit" `
  - event_kind: ` "termination" `


## planning_findings

### finding:process:v1:483f569bbf0cfaa6033b3269e00dba8c1cec04960ac2663eb17a9109319df44b

- finding_ref: ` "finding:process:v1:483f569bbf0cfaa6033b3269e00dba8c1cec04960ac2663eb17a9109319df44b" `
- summary: ` "exit at nvram::usage; lifecycle semantics unassessed." `
- boundary:
  - kind: ` "callsite" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/process-event:015ab1793704480029ae30aa" `
  - reachability_refs: ` [] `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "unknown" `
    - statement: ` "Static call-graph reachability does not establish invocation guards, lifecycle effects or target startup impact." `
    - evidence_refs:
      - ` "/callsites/process-event:015ab1793704480029ae30aa" `
    - unknown_kind: ` "semantics" `
- domain:
  - kind: ` "process" `
  - callsite_id: ` "process-event:015ab1793704480029ae30aa" `
  - event_kind: ` "termination" `
