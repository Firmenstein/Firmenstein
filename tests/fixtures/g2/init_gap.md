# InitLaunchAnalyzer — `httpd`

This report lists rootfs-backed commands with a complete firmware initialization chain to the selected target. It does not rank candidates or prescribe how to launch them.

- Structured source of truth: [`init_launch_analysis_result.json`](init_launch_analysis_result.json)

- schema_version: `5`
- phase: `full`

## target_identity

- target_basename: `httpd`
- selected_rootfs_path: `sbin/httpd`
- target_aliases:
  - `usr/sbin/httpd`

## launch_recipes

_(none)_

## analysis_gaps

### analysis_gaps[1]

- reason: No initialization-reachable target invocation proved.

#### source

_(none)_

## finding_target

- path: ` "sbin/httpd" `
- sha256: ` "3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359" `


## initialization_roots

- initialization_roots:
  - ` "etc/init.d/rcS" `


## planning_findings

`{}`
