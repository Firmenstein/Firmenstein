# Process Lifecycle Analysis — `httpd`

This report classifies reachable termination and process-transition calls by whether they can block target startup. JSON is the source of truth; the pages linked below are deterministic views of the same data.

- Structured source of truth: [`process_lifecycle_analysis_result.json`](process_lifecycle_analysis_result.json)

## Summary

- schema_version: `2`
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
| `unresolved` | `exit` | `httpd::main:L40:C8` | The cause of the exit is unknown. | [md](unresolved__process-callsite.md) / [json](unresolved__process-callsite.json) |

## skipped

_None._
