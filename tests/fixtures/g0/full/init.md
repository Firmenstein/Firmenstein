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

### launch_recipes.launch-httpd

- recipe_id: `launch-httpd`
- executable_path: `usr/sbin/httpd`
- command_template:
  - `/usr/sbin/httpd`
  - `-f`
  - `/etc/httpd.conf`

#### launch_site

- path: `etc/init.d/httpd`
- location: `line 12`
- text:

  ```text
  /usr/sbin/httpd -f /etc/httpd.conf &
  ```

#### initialization_chain

##### initialization_chain[1]

- path: `etc/init.d/httpd`
- location: `line 12`
- text:

  ```text
  /usr/sbin/httpd -f /etc/httpd.conf &
  ```

#### preparation_actions

_(none)_

#### report

- report: [json](recipe_httpd_line_12__launch-httpd.json) / [md](recipe_httpd_line_12__launch-httpd.md)


## analysis_gaps

_(none)_
