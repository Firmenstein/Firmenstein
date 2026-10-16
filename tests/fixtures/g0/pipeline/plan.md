# Intervention Plan

The plan records behavior contracts for code generation. Each cluster is an independent planning context; each unit identifies one semantic owner and its environment or caller-visible contract. The initial Generator baseline enables every generated execution unit, so each contract must include any required input conditions and native fallback. Later runtime evidence may disable or refine a unit.

- Structured source of truth: [`intervention_plan_result.json`](intervention_plan_result.json)
- Finding clusters: [`finding_clustering_result.json`](finding_clustering_result.json)
- Planning evidence catalog: [`index.md`](../intervention_planner_inputs/index.md) / [`planner_input_catalog.json`](../intervention_planner_inputs/planner_input_catalog.json)

- schema_version: `9`
- clusters: `2`
- units: `1`
- runner_tasks: `1`
- no_interventions: `1`

## launch_choice

- recipe_id: `launch-httpd`
- reason: Validated normal launch command.
- executable_path: `usr/sbin/httpd`
- command_template:

  ```text
  /usr/sbin/httpd -f /etc/httpd.conf
  ```
- launch_site.path: `etc/init.d/httpd`
- launch_site.location: `line 12`
- launch_site.text: `/usr/sbin/httpd -f /etc/httpd.conf &`
- initialization_chain:
  - path: `etc/init.d/httpd`
    - location: `line 12`
    - text: `/usr/sbin/httpd -f /etc/httpd.conf &`
- preparation_actions:
  - (none)
- source_report: [md](../init_launch_reports/recipe_httpd_line_12__launch-httpd.md) / [json](../init_launch_reports/recipe_httpd_line_12__launch-httpd.json) / [index](../init_launch_reports/index.md)

## handoff

### ENVIRONMENT_SETUP

(none)

### EXECUTION_UNITS

- `unit-1111111111111111` (`function_stub`; [cluster report](clusters/nvram__nvram.md))

### RUNNER_TASKS

- `cluster-peer`: `1` ([report](clusters/httpd-startup-requires-the-peer-uds-endpoint__peer.md#runner_tasks))

### CLOSED

- no_intervention: `1`

### AUDIT_ONLY

- analysis_gaps: `0` ([catalog](../intervention_planner_inputs/index.md))

## scope_no_interventions

### `network:network-listener`

- reason: The baseline provides native TCP bind on a free port.
- source_reports: [item_report](../network_reports/listener__network-listener.md) / [analyzer_index](../network_reports/index.md) / [source_json](../network_reports/network_analysis_result.json)

## clusters

### `cluster-nvram`

- cluster_reason: The same nvram resource causes the startup exit.
- finding_refs: `2`
- units: `1`
- runner_tasks: `0`
- no_interventions: `0`
- report: [md](clusters/nvram__nvram.md) / [json](clusters/nvram__nvram.json)
- finding_sources:
  - `file:file_dev_nvram`: [item_report](../file_reports/file_dev_nvram.md) / [analyzer_index](../file_reports/index.md) / [source_json](../file_reports/file_resolver_result.json)
  - `process:process-callsite`: [item_report](../process_lifecycle_reports/startup_blocker__process-callsite.md) / [analyzer_index](../process_lifecycle_reports/index.md) / [source_json](../process_lifecycle_reports/process_lifecycle_analysis_result.json)

#### `unit-1111111111111111`

- strategy: `function_stub`
- finding_refs: `file:file_dev_nvram, process:process-callsite`
- summary: Known key-value semantics allow stable synthetic NVRAM values even when device-specific values are unknown.
- anchors:
  - `function` `libnvram.so::nvram_get` at `0x1000`
- mock_contract:
  - Return a stable guest string for a known key and NULL for an unknown key.
- contract:
  - applicability:
    - claim only the supplied Unit anchors
  - owned_resources:
    - planner anchor 1
  - operations:
    - Return a stable guest string for a known key and NULL for an unknown key.
  - state:
    - preserve state for the declared Unit lifetime
  - native_fallback:
    - fall through when the Unit does not claim the interaction
  - required_iib_capabilities:
    - (none)
  - verification:
    - cover every legacy mock_contract item exactly once
  - allowed_refinement_scope:
    - implementation details inside this Unit
- complete_cluster_report: [md](clusters/nvram__nvram.md) / [json](clusters/nvram__nvram.json)

### `cluster-peer`

- cluster_reason: (singleton)
- finding_refs: `1`
- units: `0`
- runner_tasks: `1`
- no_interventions: `0`
- report: [md](clusters/httpd-startup-requires-the-peer-uds-endpoint__peer.md) / [json](clusters/httpd-startup-requires-the-peer-uds-endpoint__peer.json)
- finding_sources:
  - `ipc:dependency-uds`: [item_report](../ipc_reports/channels/channel-uds.md) / [analyzer_index](../ipc_reports/index.md) / [source_json](../ipc_reports/ipc_analysis_result.json)

#### runner_task

- finding_refs: `ipc:dependency-uds`
- objective: Start the verified peer in the runtime sandbox and observe its endpoint availability.
- complete_cluster_report: [md](clusters/httpd-startup-requires-the-peer-uds-endpoint__peer.md) / [json](clusters/httpd-startup-requires-the-peer-uds-endpoint__peer.json)
