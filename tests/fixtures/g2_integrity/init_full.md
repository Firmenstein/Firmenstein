# InitLaunchAnalyzer — `httpd`

This report lists rootfs-backed commands with a complete firmware initialization chain to the selected target. It does not rank candidates or prescribe how to launch them.

- Structured source of truth: [`init_launch_analysis_result.json`](init_launch_analysis_result.json)

- schema_version: `7`
- phase: `full`

## target_identity

- target_basename: `httpd`
- selected_rootfs_path: `sbin/httpd`
- target_aliases:
  - `usr/sbin/httpd`

## launch_recipes

### launch_recipes.launch-d72e9735629cbb5c

- recipe_id: `launch-d72e9735629cbb5c`
- executable_path: `/sbin/httpd`
- command_template:
  - `/sbin/httpd`
  - `-f`
  - `/etc/httpd.conf`

#### launch_site

- path: `etc/init.d/rcS`
- location: `line 2`
- text:

  ```text
  /sbin/httpd -f /etc/httpd.conf
  ```

#### context_anchor

- path: `etc/init.d/rcS`
- location: `line 2`
- text:

  ```text
  /sbin/httpd -f /etc/httpd.conf
  ```

#### applicability

The captured initialization entry directly invokes this command after creating /var/run.

#### initialization_chain

##### initialization_chain[1]

- path: `etc/init.d/rcS`
- location: `line 2`
- text:

  ```text
  /sbin/httpd -f /etc/httpd.conf
  ```

#### preparation_actions

##### preparation_actions[1]

- path: `etc/init.d/rcS`
- location: `line 1`
- text:

  ```text
  mkdir -p /var/run
  ```


#### report

- report: [json](recipe_rcS_line_2__launch-d72e9735629cbb5c.json) / [md](recipe_rcS_line_2__launch-d72e9735629cbb5c.md)


## analysis_gaps

_(none)_

## finding_target

- path: ` "sbin/httpd" `
- sha256: ` "3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359" `


## initialization_roots

- initialization_roots:
  - ` "etc/init.d/rcS" `


## planning_findings

### finding:init_launch:v1:b076f7b3a728850dc27bbdf8bd6c46345e268fb55571086bf56918ce9741a1b7

- finding_ref: ` "finding:init_launch:v1:b076f7b3a728850dc27bbdf8bd6c46345e268fb55571086bf56918ce9741a1b7" `
- summary: ` "Initialization contains a source-backed target invocation." `
- boundary:
  - kind: ` "environment" `
  - anchors:
    - [0]:
      - kind: ` "environment" `
      - ref: ` "/launch_recipes/launch-d72e9735629cbb5c/launch_site" `
    - [1]:
      - kind: ` "environment" `
      - ref: ` "/launch_recipes/launch-d72e9735629cbb5c/context_anchor" `
  - reachability_refs:
    - ` "/launch_recipes/launch-d72e9735629cbb5c/initialization_chain/0" `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "guarantee" `
    - statement: ` "The initialization entry attempts the cited target command; readiness is not established." `
    - evidence_refs:
      - ` "/launch_recipes/launch-d72e9735629cbb5c/launch_site" `
    - unknown_kind: ` null `
- domain:
  - kind: ` "init_launch" `
  - recipe_id: ` "launch-d72e9735629cbb5c" `
  - preparation_refs:
    - ` "/launch_recipes/launch-d72e9735629cbb5c/preparation_actions/0" `



## execution

- tasks: ` {} `
- status: ` "complete" `


## correction_history
