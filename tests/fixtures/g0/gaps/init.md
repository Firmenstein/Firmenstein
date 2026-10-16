# InitLaunchAnalyzer — `httpd`

This report lists rootfs-backed commands with a complete firmware initialization chain to the selected target. It does not rank candidates or prescribe how to launch them.

- Structured source of truth: [`init_launch_analysis_result.json`](init_launch_analysis_result.json)

- schema_version: `4`

## target_identity

- target_basename: `httpd`
- selected_rootfs_path: `usr/sbin/httpd`
- target_aliases:
  - _(none)_

## launch_recipes

_(none)_

## analysis_gaps

### analysis_gaps[1]

- reason: No concrete target invocation is supported by the available init scripts.

#### source

_(none)_
