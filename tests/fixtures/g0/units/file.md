# File Resource Report — `/dev/nvram`

- `resource_group_id`: `file_dev_nvram`
- `primary_path`: `/dev/nvram`
- `resource_class`: `pseudo_fs_dev`

## summary

The service requires the nvram device during startup.

## contract

- `expectation`: `expected_present`
- `violation_effect`: `fatal_exit`

## observed_apis

_None recorded._

## callsite_reports

### `callsite_id`: `file-callsite`

**containing_function_purpose:** opens nvram

**setup_details:** read-only open

_No usage sites recorded._

#### resource_usage_sites

_None beyond the direct uses listed in `usage_reports`._
