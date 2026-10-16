#!/usr/bin/env python3
"""Start the local rootless task engine without changing the system Docker daemon."""
import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[2]
tools = root / '.fmst/runner-engine/bin'
environment = {**os.environ, 'PATH': str(tools) + ':' + os.environ['PATH']}
if os.geteuid() == 0:
    raise SystemExit('Run this as the normal pipeline user')
runtime = Path(os.environ['XDG_RUNTIME_DIR']) / 'fmst-runner-engine'
endpoint = 'unix://' + str(runtime / 'docker.sock')
current = subprocess.run(['docker', '--host', endpoint, 'info', '--format', '{{json .SecurityOptions}}'],
                         capture_output=True, text=True)
if current.returncode == 0:
    security = json.loads(current.stdout)
    if not {'name=rootless', 'name=userns'} <= set(security):
        raise SystemExit('Existing engine lacks private user namespaces; it was left unchanged')
    print('FMST_RUNNER_DOCKER_HOST=' + endpoint)
    raise SystemExit(0)
for executable in ('rootlesskit', 'slirp4netns', 'newuidmap', 'newgidmap', 'dockerd-rootless.sh'):
    if shutil.which(executable, path=environment['PATH']) is None:
        raise SystemExit(f'Missing rootless Docker prerequisite: {executable}; see README.md')
runtime.mkdir(exist_ok=True)
# The remapped UID must be able to traverse the graph root. Keep it outside
# the user's private 0700 home, without changing home directory permissions.
data = Path('/var/tmp') / f'fmst-runner-engine-{os.getuid()}'
data.mkdir(mode=0o711, exist_ok=True)
wrapper = Path(__file__).with_name('mapped-dockerd.py')
wrapper.chmod(0o755)
args = ['systemd-run', '--user', '--unit=fmst-runner-engine', '--property=Delegate=yes',
        '--property=TasksMax=infinity', '--setenv=PATH=' + environment['PATH'],
        '--setenv=FMST_RUNNER_ACCOUNT=' + pwd.getpwuid(os.getuid()).pw_name,
        '--setenv=DOCKERD=' + str(wrapper),
        '--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns',
        '--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_DISABLE_HOST_LOOPBACK=false',
        '--setenv=DOCKERD_ROOTLESS_ROOTLESSKIT_STATE_DIR=' + str(runtime / 'rootlesskit'),
        shutil.which('dockerd-rootless.sh', path=environment['PATH']),
        '--data-root=' + str(data), '--exec-root=' + str(data / 'exec'),
        '--host=' + endpoint, '--pidfile=' + str(runtime / 'docker.pid')]
subprocess.run(args, check=True, env=environment)
print('FMST_RUNNER_DOCKER_HOST=' + endpoint)
