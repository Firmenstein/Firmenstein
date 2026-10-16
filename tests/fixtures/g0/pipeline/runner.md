# Rehosting Runner

- structured_source: [`rehosting_result.json`](rehosting_result.json)
- schema_version: `10`
- target_binary: `httpd`
- guest_arch: `arm`
- selected_recipe_id: `launch-httpd`
- status: `attempts_exhausted`
- success_definition: `connect_and_interact`
- environment_preparation:
  - status: `not_needed`
  - source_script_path: `(none)`
  - application_count: `0`
  - failure_reason: (none)
- generation_baseline_id: `(none)`
- generation_baseline_path: `(none)`
- final_summary: Synthetic failed attempt retained for replay.

## attempts

### attempt 1

- intervention_sha256: `(none)`
- guest_args: `['-f', '/etc/httpd.conf']`
- guest_working_directory: `/`
- guest_environment: `{}`
- companion_processes:
  - (none)
- companion_log_paths: `[]`
- disabled_unit_ids: `[]`
- rootfs_actions:
  - (none)
- intervention_source_path: `(none)`
- intervention_binary_path: `(none)`
- probe.port: `80`
- probe.request_text: `'GET / HTTP/1.0\r\n\r\n'`
- probe.response_contains: `(any non-empty response)`
- probe_result.connected: `False`
- probe_result.interacted: `False`
- probe_result.attempts: `1`
- probe_result.error: Synthetic connection refused: required peer did not start.
- probe_result.response_truncated: `False`
- container_exit_code: `(running at collection)`
- timed_out: `False`
- outcome: `blocked`
- runtime_trace_available: `False`
- runtime_trace_path: `attempts/attempt-01/runtime_trace.json`
- runtime_trace_context_available: `False`
- runtime_trace_context_path: `attempts/attempt-01/runtime_trace_context.json`
- runtime_trace_context_error: (none)
- container_log_path: `attempts/attempt-01/container.log`
- agent_summary: The peer endpoint is unavailable; this fixture records a failed attempt, not successful rehosting.
