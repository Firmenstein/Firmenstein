# Unit Generation: unit-1111111111111111

- schema_version: `15`
- structured_source: [`nvram_get.json`](nvram_get.json)
- consumed_plan: [`intervention_plan_result.json`](../../intervention_plan_reports/intervention_plan_result.json)
- strategy: `function_stub`
- status: `ok`
- contract_digest: `e0b141866c625cb2c178e58f611321bb836e002a205b82210d92b9883ec73fcf`
- revision_count: `1`
- failure_code: `(none)`
- failure_reason: (none)
- summary: Known key-value semantics allow stable synthetic NVRAM values even when device-specific values are unknown.
- runner_handoff: `RUNNER_INPUT_READY`
- finding_refs:
  - `file:file_dev_nvram`
  - `process:process-callsite`
- anchors:
  - kind: `function`
    - binary_name: `libnvram.so`
    - function_name: `nvram_get`
    - function_ea: `0x1000`
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
- generated_files:
  - [`src/unit_nvram/mod.rs`](<src/unit_nvram/mod.rs>)
  - [`tests/unit_nvram/main.rs`](<tests/unit_nvram/main.rs>)
- round_traces:
  - round `1`:
    - generator: [`round-01__generator.md`](<round-01__generator.md>)
    - reviewer: [`round-01__reviewer.md`](<round-01__reviewer.md>)
  - round `2`:
    - generator: [`round-02__generator.md`](<round-02__generator.md>)
    - reviewer: [`round-02__reviewer.md`](<round-02__reviewer.md>)

## review_history

### review_1

- verdict: `revision_required`
- summary: Unknown-key behavior needs a regression case.
- contract_reviews:
  - contract_index: `0`
    - status: `test_gap`
    - evidence: Only known-key behavior was covered in this synthetic round.
    - required_change: Cover NULL for an unknown key.
### review_2

- verdict: `approved`
- summary: Synthetic fixture: both known and unknown keys are covered.
- contract_reviews:
  - contract_index: `0`
    - status: `satisfied`
    - evidence: implementation and test cover this contract item
    - required_change: (none)

## environment_script_path

`(none)`
