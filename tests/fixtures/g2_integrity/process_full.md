# Process Lifecycle Analysis — `nvram`

This report classifies reachable termination and process-transition calls by whether they can block target startup. JSON is the source of truth; the pages linked below are deterministic views of the same data.

- Structured source of truth: [`process_lifecycle_analysis_result.json`](process_lifecycle_analysis_result.json)

## Summary

- schema_version: `5`
- phase: `full`
- root_binary: `nvram`
- callsites: 1
- assessments: 1
- startup_blocker: 0
- expected_lifecycle: 1
- runtime_only: 0
- unresolved: 0

## assessments

| disposition | event | location | summary | report |
|---|---|---|---|---|
| `expected_lifecycle` | `exit` | `nvram::usage:L4:C2` | Both reachable calls to usage are deliberate command-line usage/rejection paths. They print the usage text and terminate normally via exit(0), whether no initial command is supplied or an unsupported current command is encountered later in the dispatch loop. No runtime dependency failure guard or startup-blocking propagation is shown. | [md](expected_lifecycle__process-event_015ab1793704480029ae30aa.md) / [json](expected_lifecycle__process-event_015ab1793704480029ae30aa.json) |

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
- summary: ` "usage is expected command-line lifecycle behavior, covering missing-command usage and invalid-command rejection at entry or during later argument dispatch. It is not evidence of a target startup blocker." `
- boundary:
  - kind: ` "callsite" `
  - anchors:
    - [0]:
      - kind: ` "callsite" `
      - ref: ` "/callsites/process-event:015ab1793704480029ae30aa" `
  - reachability_refs:
    - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/4" `
    - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/6" `
  - coverage_refs:
    - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/4" `
    - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/6" `
- claims:
  - [0]:
    - kind: ` "guarantee" `
    - statement: ` "When either proven usage branch is reached, nvram attempts to emit the fixed usage message to stderr and then terminates the process with exit status 0." `
    - evidence_refs:
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/0" `
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/1" `
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/4" `
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/6" `
    - unknown_kind: ` null `
  - [1]:
    - kind: ` "state" `
    - statement: ` "The event represents deliberate normal invocation completion for a missing initial command or an unsupported current command; the latter may occur after earlier dispatch operations in the loop." `
    - evidence_refs:
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/3" `
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/5" `
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/7" `
    - unknown_kind: ` null `
  - [2]:
    - kind: ` "fallback" `
    - statement: ` "No alternate native fallback behavior is shown after these guards: both branches call the custom usage function, whose exit(0) ends the process." `
    - evidence_refs:
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/4" `
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/6" `
      - ` "/assessments/process-event:015ab1793704480029ae30aa/evidence/1" `
    - unknown_kind: ` null `
  - [3]:
    - kind: ` "unknown" `
    - statement: ` "The concrete argv values for the analyzed invocation are not provided, so it is unknown whether this run reaches usage through missing argv[1] or through a later unsupported current command." `
    - evidence_refs: ` [] `
    - unknown_kind: ` "instance_data" `
- domain:
  - kind: ` "process" `
  - callsite_id: ` "process-event:015ab1793704480029ae30aa" `
  - event_kind: ` "termination" `



## execution

- tasks: ` {} `
- status: ` "complete" `
