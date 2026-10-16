# Launch recipe `launch-httpd`

- recipe_id: `launch-httpd`
- executable_path: `usr/sbin/httpd`
- command_template:
  - `/usr/sbin/httpd`
  - `-f`
  - `/etc/httpd.conf`

## launch_site

- path: `etc/init.d/httpd`
- location: `line 12`
- text:

  ```text
  /usr/sbin/httpd -f /etc/httpd.conf &
  ```

## initialization_chain

### initialization_chain[1]

- path: `etc/init.d/httpd`
- location: `line 12`
- text:

  ```text
  /usr/sbin/httpd -f /etc/httpd.conf &
  ```


## preparation_actions

_(none)_
