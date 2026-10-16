# Launch recipe `launch-d72e9735629cbb5c`

- recipe_id: `launch-d72e9735629cbb5c`
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

## context_anchor

- path: `etc/init.d/rcS`
- location: `line 2`
- text:

  ```text
  /sbin/httpd -f /etc/httpd.conf
  ```

## applicability

The captured initialization entry directly invokes this command after creating /var/run.

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
