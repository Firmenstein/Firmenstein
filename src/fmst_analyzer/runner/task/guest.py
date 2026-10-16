"""Optional local guest launcher. Agent may freely edit or replace this helper.

build MANIFEST builds a candidate. start CONFIG launches in chroot + private
PID/mount/network namespaces. CONFIG fields: rootfs, harness, executable, args,
cwd, env, intervention_so (optional), addresses (CIDRs), hosts (name -> IP).
"""
from __future__ import annotations
import argparse
import json
import os
import subprocess
import sys
import resource
import time
from pathlib import Path
from .common import TASK, clean_environment, write_json
from .jobs import spawn
from .execution import create_execution, select_execution, update_execution, finish_execution, file_identity, process_record

NS = "fmst-guest"


def limit_guest_core_dumps():
    """Cap diagnostics without raising a caller's smaller or disabled limit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
    cap = 64 * 1024**2
    resource.setrlimit(resource.RLIMIT_CORE, (cap if soft == resource.RLIM_INFINITY else min(soft, cap), hard))


def reap_guest_children(entry_pid: int, output: Path) -> int:
    """Reap the namespace while retaining every status and the entry result."""
    entry_status = None
    while True:
        try:
            pid, status = os.wait()
        except ChildProcessError:
            break
        with (output / 'process-exits.jsonl').open('a') as stream:
            stream.write(json.dumps({'pid': pid, 'wait_status': status, 'at_unix_ns': time.time_ns()}) + '\n')
        if pid == entry_pid:
            entry_status = status
            (output / 'entry-exit.json').write_text(json.dumps({'pid': pid, 'status': status}))
    if entry_status is None:
        raise RuntimeError("Guest entry exit status was not collected; inspect process-exits.jsonl")
    code = os.waitstatus_to_exitcode(entry_status)
    # SystemExit(-signal) wraps to an unrelated code; use shell signal status.
    return 128 - code if code < 0 else code


def net_argv(*argv):
    return [sys.executable, "-m", "fmst_analyzer.runner.task.netns", NS, "--", *argv]


def command(*argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, env=clean_environment(), **kwargs)


def start(config_path: Path):
    config = json.loads(config_path.read_text())
    if os.geteuid() != 0:
        raise RuntimeError("Use sudo for namespace/chroot preparation")
    # Only namespace-local processes are replaced, preserving firmware state.
    existing = subprocess.run(["ip", "netns", "pids", NS], capture_output=True, text=True)
    if existing.returncode == 0:
        for pid in existing.stdout.split():
            subprocess.run(["kill", "-TERM", pid], check=False)
        time.sleep(.3)
        for pid in command("ip", "netns", "pids", NS, capture_output=True, text=True).stdout.split():
            subprocess.run(["kill", "-KILL", pid], check=False)
        command("ip", "netns", "delete", NS)
        previous_path, previous = select_execution(TASK)
        if previous_path and previous.get('namespace') == NS:
            finish_execution(previous_path)
    command("ip", "netns", "add", NS)
    command(*net_argv("ip", "link", "set", "lo", "up"))
    subprocess.run(["ip", "link", "del", "fmst-link"], capture_output=True)
    command("ip", "link", "add", "fmst-link", "type", "veth", "peer", "name", "fmst-peer")
    command("ip", "link", "set", "fmst-peer", "netns", NS)
    command("ip", "addr", "add", "169.254.241.1/30", "dev", "fmst-link")
    command("ip", "link", "set", "fmst-link", "up")
    command(*net_argv("ip", "addr", "add", "169.254.241.2/30", "dev", "fmst-peer"))
    command(*net_argv("ip", "link", "set", "fmst-peer", "up"))
    for address in config.get("addresses", []):
        command(*net_argv("ip", "address", "add", address, "dev", "lo"))
    hosts = Path("/etc/netns") / NS / "hosts"
    hosts.parent.mkdir(parents=True, exist_ok=True)
    hosts.write_text("127.0.0.1 localhost\n" + "".join(f"{ip} {name}\n" for name, ip in config.get("hosts", {}).items()))
    execution_path = create_execution(config)
    update_execution(execution_path, namespace=NS)
    resolved = execution_path.parent / 'launch-config.json'
    result = spawn(net_argv("unshare", "--mount", "--pid", "--fork",
                    "--kill-child", sys.executable, "-m", "fmst_analyzer.runner.task.guest", "enter", str(resolved),
                    '--execution', str(execution_path)), execution_path=execution_path, role='firmware')
    spawn(net_argv(sys.executable, "-m", "fmst_analyzer.runner.task.proxy"), execution_path=execution_path, role='proxy')
    # Reuse the outer relay across guest restarts. The target address is stable
    # inside this task and never shared with another container.
    relay = TASK / "control/relay.json"
    from .common import process_identity
    old_relay = json.loads(relay.read_text()) if relay.exists() else {}
    if process_identity(old_relay.get("pid", -1)) != old_relay.get("start_ticks") or not old_relay:
        write_json(relay, spawn(["socat", "TCP-LISTEN:1080,reuseaddr,fork,bind=0.0.0.0", "TCP:169.254.241.2:1080"]))
    write_json(TASK / "delivery/guest.json", {**result, "namespace": NS, "config": str(resolved)})
    print(json.dumps(result))


def enter(config_path: Path, execution_path: Path | None = None):
    config = json.loads(config_path.read_text())
    rootfs = Path(config.get("rootfs", "/task/work/rootfs")).resolve(strict=True)
    if not rootfs.is_relative_to(TASK / "work"):
        raise ValueError("Guest rootfs must be a task-private work directory")
    harness = Path(config["harness"]).resolve(strict=True)
    from fmst_analyzer.runner.runtime_builder import HostRuntimeBuilder
    from fmst_analyzer.runner.docker_sandbox import _harness_arguments
    execution_path = execution_path or create_execution(config)
    run_dir = execution_path.parent / 'runtime'
    bundle = execution_path.parent / 'host-bundle'
    framework = TASK / "work/framework/GuestWeave"
    HostRuntimeBuilder(framework_root=framework).build_host_bundle(harness, bundle,
        binaries={"sh": Path("/bin/sh"), "sleep": Path("/bin/sleep")})
    intervention = config.get("intervention_so")
    if intervention:
        import shutil
        shutil.copy2(intervention, bundle / "intervention.so")
    from fmst_analyzer.runner.rootfs_actions import _guest_host_path
    executable = _guest_host_path(rootfs, config['executable'], follow_final_symlink=True)
    source_root = Path(config.get('qemu_source_root', harness.parent / 'qemu-libafl-bridge'))
    if not source_root.is_dir() and 'qemu_source_root' not in config:
        source_root = TASK / 'work/native/qemu'
    update_execution(execution_path, status='launching',
        harness={**file_identity(bundle / harness.name), 'build_path': str(harness),
                 'loader': str(bundle / 'ld.so'), 'library_path': str(bundle / 'lib'),
                 'source_root': str(source_root) if source_root.is_dir() else None},
        intervention=file_identity(bundle / 'intervention.so') if intervention else None,
        images=[{**file_identity(executable), 'guest_path': config['executable']}])
    command("mount", "--make-rprivate", "/")

    def inside(name: str) -> Path:
        # Firmware absolute symlinks resolve in its root, never in Ubuntu.
        components = list(Path(name).parts)
        current = rootfs
        followed = 0
        while components:
            component = components.pop(0)
            if component in {"/", "."}:
                continue
            if component == "..":
                current = current.parent if current != rootfs else rootfs
                continue
            current /= component
            if current.is_symlink():
                followed += 1
                if followed > 40:
                    raise ValueError("Firmware symlink loop")
                target = os.readlink(current)
                current = rootfs if target.startswith("/") else current.parent
                components = list(Path(target).parts) + components
        return current

    for name, source in (("/fmst-host", bundle), ("/fmst-output", run_dir), ("/dev", Path("/dev"))):
        destination = inside(name)
        destination.mkdir(parents=True, exist_ok=True)
        command("mount", "--rbind", source, destination)
    proc = inside("/proc")
    proc.mkdir(parents=True, exist_ok=True)
    command("mount", "-t", "proc", "proc", proc)
    interpreter = inside((bundle / "host-interpreter.path").read_text().strip())
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    interpreter.touch(exist_ok=True)
    command("mount", "--bind", bundle / "ld.so", interpreter)
    argv = ["/fmst-host/ld.so", "--library-path", "/fmst-host/lib", *_harness_arguments(
        harness_name=harness.name, intervention_so="/fmst-host/intervention.so" if intervention else None,
        executable_path=config["executable"], trace_output="/fmst-output/runtime_trace.json",
        guest_args=config.get("args", []))]
    write_json(run_dir / "launch.json", {"config": config, "argv": argv})
    os.chroot(rootfs)
    os.chdir(config.get("cwd", "/"))
    environment = {"PATH": "/sbin:/usr/sbin:/bin:/usr/bin", "HOME": "/", **config.get("env", {})}
    limit_guest_core_dumps()
    # Keep namespace PID 1 alive and reap forked/daemonized firmware processes.
    child = subprocess.Popen(argv, env=environment)
    write_json(Path('/fmst-output/process.json'), process_record(child.pid))
    return reap_guest_children(child.pid, Path('/fmst-output'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "start", "enter"])
    parser.add_argument("path", type=Path)
    parser.add_argument('--execution', type=Path)
    args = parser.parse_args()
    if args.action == "build":
        command("cargo", "build", "--release", "--manifest-path", args.path)
    elif args.action == "start":
        start(args.path)
    else:
        raise SystemExit(enter(args.path, args.execution))


if __name__ == "__main__":
    main()
