# Launch recipe `launch-3e4547a2ab329cf9`

- recipe_id: `launch-3e4547a2ab329cf9`
- executable_path: `/sbin/httpd`
- command_template:
  - `/sbin/httpd`
  - `-f`
  - `/etc/httpd.conf`

## launch_site

- path: `etc/init.d/rcS`
- location: `line 2`
- text:

  ```text
  /sbin/httpd -f /etc/httpd.conf
  ```

## initialization_chain

### initialization_chain[1]

- path: `etc/init.d/rcS`
- location: `line 2`
- text:

  ```text
  /sbin/httpd -f /etc/httpd.conf
  ```


## preparation_actions

### preparation_actions[1]

- path: `etc/init.d/rcS`
- location: `line 1`
- text:

  ```text
  mkdir -p /var/run
  ```
