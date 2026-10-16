"""Enter the task guest network without iproute2's privileged /sys remount."""
import os
import subprocess
import sys
from pathlib import Path


def main():
    namespace, *argv = sys.argv[1:]
    if argv and argv[0] == "--":
        argv.pop(0)
    if not argv:
        raise ValueError("Expected namespace and command")
    with open('/run/netns/' + namespace) as stream:
        os.setns(stream.fileno(), os.CLONE_NEWNET)
    os.unshare(os.CLONE_NEWNS)
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    hosts = Path('/etc/netns') / namespace / 'hosts'
    if hosts.exists():
        subprocess.run(['mount', '--bind', str(hosts), '/etc/hosts'], check=True)
    os.execvp(argv[0], argv)


if __name__ == '__main__':
    main()
