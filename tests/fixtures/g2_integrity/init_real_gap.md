# InitLaunchAnalyzer — `httpd`

This report lists rootfs-backed commands with a complete firmware initialization chain to the selected target. It does not rank candidates or prescribe how to launch them.

- Structured source of truth: [`init_launch_analysis_result.json`](init_launch_analysis_result.json)

- schema_version: `7`
- phase: `full`

## target_identity

- target_basename: `httpd`
- selected_rootfs_path: `usr/sbin/httpd`
- target_aliases:
  - _(none)_

## launch_recipes

_(none)_

## analysis_gaps

### analysis_gaps[1]

- kind: `applicability`
- reason: A candidate start_gn_httpd routine passes /usr/sbin/httpd and /tmp/gn-httpd to an unresolved helper, then constructs argv beginning /tmp/gn-httpd, -p, a value obtained through gn_http_port, -G. The launched path is not the selected executable and no alias was supplied; a direct initialization call edge to this routine from the stripped indirect startup dispatch was also not recoverable.

#### source

- path: `sbin/rc`
- location: `0x42a6e8`
- text:

  ```text
  0x42a6e8: lw $s0, -0x7fd8($gp)
  0x42a6ec: lw $a0, -0x7fd8($gp)
  0x42a6f0: lw $t9, -0x7b98($gp)
  0x42a6f4: addiu $a0, $a0, 0x4b58
  0x42a6f8: jalr $t9
  0x42a6fc: addiu $a1, $s0, 0x4b68
  0x42a764: lw $v0, -0x7fd8($gp)
  0x42a76c: addiu $v0, $v0, 0x1f90
  0x42a774: lw $v0, -0x7fd8($gp)
  0x42a778: addiu $v1, $s0, 0x4b68
  0x42a77c: lw $t9, -0x7a18($gp)
  0x42a780: addiu $v0, $v0, 0x4b78
  0x42a784: sw $v1, 0x18($sp)
  0x42a788: sw $a0, 0x20($sp)
  0x42a79c: sw $v0, 0x24($sp)
  0x42a7a0: jalr $t9
  0x42a7a4: sw $zero, 0x28($sp)
  ```

### analysis_gaps[2]

- kind: `applicability`
- reason: A candidate start_wl_warning_httpd routine passes /usr/sbin/httpd and /tmp/wm-httpd to an unresolved helper, then constructs argv beginning /tmp/wm-httpd, -p, a value obtained through warning_http_port, -w. The launched path is not the selected executable and no alias was supplied; a direct initialization call edge to this routine from the stripped indirect startup dispatch was not recoverable.

#### source

- path: `sbin/rc`
- location: `0x438988`
- text:

  ```text
  0x438988: lw $s0, -0x7fd8($gp)
  0x43898c: lw $a0, -0x7fd8($gp)
  0x438990: lw $t9, -0x7b98($gp)
  0x438994: addiu $a1, $s0, 0x7150
  0x438998: jalr $t9
  0x43899c: addiu $a0, $a0, 0x4b58
  0x4389e4: lw $v0, -0x7fd8($gp)
  0x4389ec: addiu $v0, $v0, 0x1f90
  0x4389f4: lw $v0, -0x7fd8($gp)
  0x4389f8: addiu $v1, $s0, 0x7150
  0x4389fc: lw $t9, -0x7a18($gp)
  0x438a00: addiu $v0, $v0, 0x26e4
  0x438a04: sw $v1, 0x18($sp)
  0x438a08: sw $a0, 0x20($sp)
  0x438a1c: sw $v0, 0x24($sp)
  0x438a20: jalr $t9
  0x438a24: sw $zero, 0x28($sp)
  ```


## finding_target

- path: ` "usr/sbin/httpd" `
- sha256: ` "39227120d341932b5d79b7a919593f305ea5ce8f311e97b695a12cada0953fe4" `


## initialization_roots

- initialization_roots:
  - ` "sbin/init" `
  - ` "sbin/rc" `


## planning_findings

`{}`


## execution

- tasks: ` {} `
- status: ` "complete" `


## correction_history
