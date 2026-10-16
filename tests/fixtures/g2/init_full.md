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

### launch_recipes.launch-3e4547a2ab329cf9

- recipe_id: `launch-3e4547a2ab329cf9`
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

- report: [json](recipe_rcS_line_2__launch-3e4547a2ab329cf9.json) / [md](recipe_rcS_line_2__launch-3e4547a2ab329cf9.md)


## analysis_gaps

_(none)_

## finding_target

- path: ` "sbin/httpd" `
- sha256: ` "3bdbb4fe8397cd2b842430b39ccff01a8663c751945ef5e9a09e267fb8b1d359" `


## initialization_roots

- initialization_roots:
  - ` "etc/init.d/rcS" `


## planning_findings

### finding:init_launch:v1:855c41085301c4bb606bf4fbb1f46b73f0cd9917f8ae1f363082862c93f1b261

- finding_ref: ` "finding:init_launch:v1:855c41085301c4bb606bf4fbb1f46b73f0cd9917f8ae1f363082862c93f1b261" `
- summary: ` "Initialization contains a source-backed target invocation." `
- boundary:
  - kind: ` "environment" `
  - anchors:
    - [0]:
      - kind: ` "environment" `
      - ref: ` "/launch_recipes/launch-3e4547a2ab329cf9/launch_site" `
  - reachability_refs:
    - ` "/launch_recipes/launch-3e4547a2ab329cf9/initialization_chain/0" `
  - coverage_refs: ` [] `
- claims:
  - [0]:
    - kind: ` "guarantee" `
    - statement: ` "The initialization entry attempts the cited target command; readiness is not established." `
    - evidence_refs:
      - ` "/launch_recipes/launch-3e4547a2ab329cf9/launch_site" `
    - unknown_kind: ` null `
- domain:
  - kind: ` "init_launch" `
  - recipe_id: ` "launch-3e4547a2ab329cf9" `
  - preparation_refs:
    - ` "/launch_recipes/launch-3e4547a2ab329cf9/preparation_actions/0" `
