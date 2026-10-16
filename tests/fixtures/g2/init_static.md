# InitLaunchAnalyzer — `httpd`

This report lists rootfs-backed commands with a complete firmware initialization chain to the selected target. It does not rank candidates or prescribe how to launch them.

- Structured source of truth: [`init_launch_analysis_result.json`](init_launch_analysis_result.json)

- schema_version: `5`
- phase: `static`

## target_identity

- target_basename: `httpd`
- selected_rootfs_path: `usr/sbin/httpd`
- target_aliases:
  - _(none)_

## launch_recipes

_(none)_

## analysis_gaps

### analysis_gaps[1]

- reason: Static discovery identified initialization entries; target launch chains and preparation semantics have not been analyzed.

#### source

_(none)_

## finding_target

- path: ` "usr/sbin/httpd" `
- sha256: ` "39227120d341932b5d79b7a919593f305ea5ce8f311e97b695a12cada0953fe4" `


## initialization_roots

- initialization_roots:
  - ` "sbin/init" `
  - ` "sbin/rc" `


## planning_findings

`{}`
