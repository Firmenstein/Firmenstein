# Intervention Generation

- Structured source of truth: [`intervention_generation_result.json`](intervention_generation_result.json)
- Consumed intervention plan: [`intervention_plan_result.json`](../intervention_plan_reports/intervention_plan_result.json)

- schema_version: `16`
- plan_digest: `0000000000000000000000000000000000000000000000000000000000000000`
- completion_status: `complete`
- target_binary: `httpd`
- arch: `arm`
- total_units: `1`
- ok_count: `1`
- not_ready_count: `0`
- skipped_count: `0`
- cargo_build_status: `ok`
- cargo_test_status: `ok`
- intervention_crate_path: `(none)`
- test_crate_path: `(none)`
- environment.status: `not_needed`
- environment.script_path: `(none)`
- environment.reason: No environment units in this synthetic plan.
- environment.handoff: `RUNNER_INPUT_READY` means only that the Environment Agent generated the script; the Generator does not execute or validate it.

## source_artifacts

- catalog: [`planner_input_catalog.json`](../intervention_planner_inputs/planner_input_catalog.json)
- plan: [`intervention_plan_result.json`](../intervention_plan_reports/intervention_plan_result.json)
- ipc: [`ipc_analysis_result.json`](../ipc_reports/ipc_analysis_result.json)
- file: [`file_resolver_result.json`](../file_reports/file_resolver_result.json)
- network: [`network_analysis_result.json`](../network_reports/network_analysis_result.json)
- process: [`process_lifecycle_analysis_result.json`](../process_lifecycle_reports/process_lifecycle_analysis_result.json)
- launch: [`init_launch_analysis_result.json`](../init_launch_reports/init_launch_analysis_result.json)

## cargo_build_failure

(none)

## cargo_test_failure

(none)

## units

| unit_id | strategy | status | review | revisions | runner_handoff | generated_files | rounds | failure_reason | report |
|---|---|---|---|---:|---|---:|---:|---|---|
| `unit-1111111111111111` | `function_stub` | `ok` | `approved` | 1 | `RUNNER_INPUT_READY` | 2 | 2 |  | [md](units/nvram_get.md) / [json](units/nvram_get.json) |

## environment.unit_ids

(none)
