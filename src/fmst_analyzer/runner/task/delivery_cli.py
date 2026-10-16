#!/usr/bin/env python3
"""Standalone private delivery launcher: requires Python 3.12+ and Docker only."""
import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import socket
import subprocess
import tarfile
import time
import uuid

LABEL = "org.firmenstein.runner-task"


def container_limits(config, engine):
    """Restore explicit captured limits; Docker zero/default values are omitted."""
    arguments = []
    for key, option, capability, divisor in (
        ("Memory", "--memory", "MemoryLimit", 1),
        ("MemorySwap", "--memory-swap", "SwapLimit", 1),
        ("NanoCpus", "--cpus", "CpuCfsQuota", 1000000000),
        ("PidsLimit", "--pids-limit", "PidsLimit", 1),
        ("ShmSize", "--shm-size", None, 1),
    ):
        value = config.get(key)
        if value is None or value == 0:
            continue
        if capability and not engine.get(capability):
            raise RuntimeError(f"Docker does not support captured limit {option}")
        arguments += [option, str(value / divisor if divisor != 1 else value)]
    return arguments


def save(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n")
    tmp.replace(path)


class Delivery:
    def __init__(self, root):
        self.root = root
        self.manifest = json.loads((root / "delivery.json").read_text())
        if self.manifest.get("schema_version") != 1 or self.manifest.get("format") != "fmst-agent-delivery":
            raise ValueError("Unsupported delivery format")
        self.state_path = root / ".state/local.json"
        self.state = json.loads(self.state_path.read_text())

    def docker(self, *args, **kwargs):
        result = subprocess.run(["docker", "--host", self.state["engine"], *args], capture_output=True, **kwargs)
        if result.returncode:
            raise RuntimeError("Docker " + args[0] + " failed: " + result.stderr.decode(errors="replace"))
        return result.stdout

    def info(self, name):
        instance = self.state["instances"][name]
        info = json.loads(self.docker("inspect", instance["id"]))[0]
        if info["Config"]["Labels"].get(LABEL) != instance["task_id"]:
            raise ValueError("Container ownership changed")
        return instance, info

    def service(self, name):
        instance, info = self.info(name)
        if not info["State"]["Running"]:
            return {"container": "stopped", "service": "stopped"}
        script = r'''
import json
from pathlib import Path
def ident(pid):
 try:
  a=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
  return None if a[0]=='Z' else int(a[19])
 except (OSError,ValueError,IndexError):return None
p=Path('/task/delivery/instance.json');v=json.loads(p.read_text()) if p.exists() else json.loads(__import__('sys').argv[1])
print(json.dumps(dict(receipt=v,service_identity=ident(v.get('service_pid')),init_identity=ident(1))))
'''
        fallback = {k: instance[k] for k in ("service_pid", "service_start_ticks") if k in instance}
        observed = json.loads(self.docker("exec", instance["id"], "python", "-c", script, json.dumps(fallback)))
        receipt = observed["receipt"]
        pid, ticks = receipt.get("service_pid"), receipt.get("service_start_ticks")
        live = (type(pid) is int and pid > 1 and type(ticks) is int and ticks > 0
                and observed["service_identity"] == ticks)
        if "init_start_ticks" in receipt:
            init_ticks = receipt["init_start_ticks"]
            live = live and type(init_ticks) is int and init_ticks > 0 and init_ticks == observed["init_identity"]
        status = "running" if live else receipt.get("status", "not_running")
        if not live and status not in {"starting", "startup_error"}:
            status = "not_running"
        return {"container": "running", "service": status, "receipt": receipt}

    def pending(self, container):
        data = self.docker("cp", container + ":/task/control", "-")
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            names = {m.name for m in archive if m.isfile()}
        return [n for n in names if n.startswith("control/requests/") and n.replace("control/requests/", "control/replies/", 1) not in names]

    def create(self, name):
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}", name) or name in self.state["instances"]:
            raise ValueError("Use a new instance name (letters, digits, underscore or dash; <=48 chars)")
        m = self.manifest
        if m["capture"]["status"] != "ready" or m["handoff"]["startup"]["availability"] != "available":
            raise RuntimeError("Snapshot has capture gaps or no startup recipe; use the retained instance")
        self.docker("image", "inspect", m["image"]["id"])
        engine = json.loads(self.docker("info", "--format", "{{json .}}"))
        if "name=userns" not in engine["SecurityOptions"]:
            raise RuntimeError("Delivery requires a userns-remap engine")
        cfg = m["container_config"]
        args = ["create", "--name", "fmst-delivery-" + m["task_id"] + "-" + name,
                "--label", LABEL + "=" + m["task_id"], "--label", "org.firmenstein.delivery-instance=" + name,
                *container_limits(cfg, engine), "--publish", "127.0.0.1::1080",
                "--log-driver", "local", "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
                "--env", "PYTHONPATH=/opt/fmst/src"]
        for cap in cfg["CapAdd"] or []:
            args += ["--cap-add", cap]
        for path, opts in (cfg["Tmpfs"] or {}).items():
            if any(a["destination"] == path for a in m["state_archives"]):
                continue
            args += ["--tmpfs", path + ":" + opts]
        for index, archive in enumerate(m["state_archives"]):
            volume = "fmst-state-" + m["task_id"] + "-" + name + "-" + str(index)
            self.docker("volume", "create", "--label", LABEL + "=" + m["task_id"], volume)
            args += ["--mount", "type=volume,source=" + volume + ",destination=" + archive["destination"]]
        identity = self.docker(*args, m["image"]["id"]).decode().strip()
        self.state["instances"][name] = {"id": identity, "task_id": m["task_id"], "original": False, "prepared": False}
        save(self.state_path, self.state)
        if m["state_archives"]:
            self.restore(identity)
        self.state["instances"][name]["prepared"] = True
        save(self.state_path, self.state)

    def restore(self, identity, archives=None):
        plan = []
        for index, archive in enumerate(self.manifest["state_archives"] if archives is None else archives):
            source = (self.root / archive["file"]).resolve(strict=True)
            if not source.is_relative_to(self.root):
                raise ValueError("Archive path escapes delivery package")
            with source.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != archive["sha256"]:
                    raise ValueError("Archive digest mismatch")
            target = "/opt/fmst-delivery/restore-" + str(index) + ".tar.gz"
            self.docker("cp", str(source), identity + ":" + target)
            plan.append({"source": target, "destination": archive["destination"], "sha256": archive["sha256"]})
        plan_path = self.root / ".state/restore-plan.json"
        save(plan_path, plan)
        self.docker("cp", str(plan_path), identity + ":/opt/fmst-delivery/restores.json")

    def ephemeral_archives(self, instance, info):
        """Named volumes of new instances persist; retained tmpfs data does not."""
        if not instance["original"] or not self.manifest["state_archives"]:
            return []
        path = self.root / self.manifest["capture"]["mount_inventory"]
        mounts = json.loads(path.read_text())
        mounts += [{"path": m["Destination"], "fstype": "tmpfs" if m["Type"] == "tmpfs" else m["Type"]}
                   for m in info["Mounts"]]
        selected = []
        for archive in self.manifest["state_archives"]:
            candidates = [m for m in mounts if PurePosixPath(archive["destination"]).is_relative_to(m["path"])]
            deepest = max((len(PurePosixPath(m["path"]).parts) for m in candidates), default=0)
            if any(m["fstype"] == "tmpfs" and len(PurePosixPath(m["path"]).parts) == deepest for m in candidates):
                selected.append(archive)
        return selected

    def snapshot_ephemeral(self, name, instance, info):
        selected = self.ephemeral_archives(instance, info)
        if not selected:
            return
        stage = self.root / ".state/snapshots" / name / uuid.uuid4().hex
        stage.mkdir(parents=True, mode=0o700)
        archives = []
        for index, archive in enumerate(selected):
            destination = PurePosixPath(archive["destination"])
            paths = sorted({s["path"] for s in self.manifest["handoff"]["state"]
                            if s["persistence"] == "external_mount" and PurePosixPath(s["path"]).is_relative_to(destination)})
            roots = []
            for path in sorted(paths, key=lambda p: (len(PurePosixPath(p).parts), p)):
                if not any(PurePosixPath(path).is_relative_to(root) for root in roots):
                    roots.append(path)
            if not roots:
                raise ValueError("External archive has no declared data paths")
            source = stage / (str(index) + ".tar.gz")
            command = ["docker", "--host", self.state["engine"], "exec", instance["id"],
                       "tar", "--format=pax", "--numeric-owner", "--acls", "--xattrs", "--sparse",
                       *["--exclude=./" + str(PurePosixPath(p).relative_to(destination)) for p in archive["excluded_mounts"]],
                       "-czf", "-", "-C", str(destination), "--no-recursion", ".", "--recursion", "--",
                       *["./" + str(PurePosixPath(p).relative_to(destination)) for p in roots]]
            with source.open("wb") as stream, (stage / (str(index) + "-stderr.txt")).open("wb") as error:
                result = subprocess.run(command, stdout=stream, stderr=error, timeout=7200)
            if result.returncode:
                raise RuntimeError("State snapshot failed; launcher did not stop the container. Inspect " + str(stage))
            with source.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            archives.append({**archive, "file": str(source.relative_to(self.root)),
                             "sha256": digest, "size": source.stat().st_size})
        # Prepare recovery before stopping; an I/O error leaves the live service.
        self.restore(instance["id"], archives)
        snapshot = {"at": time.time(), "consistency": "live_nonatomic", "archives": archives}
        save(stage / "snapshot.json", snapshot)
        instance["state_snapshot"] = snapshot
        save(self.state_path, self.state)

    def up(self, name, new_instance=None):
        if new_instance:
            self.create(new_instance)
            name = new_instance
        instance, info = self.info(name)
        if instance.get("prepared") is False:
            if info["State"]["Running"]:
                raise RuntimeError("Instance started before its state restore was prepared")
            self.restore(instance["id"])
            instance["prepared"] = True
            save(self.state_path, self.state)
        if info["State"]["Running"]:
            state = self.service(name)
            if state["service"] != "running":
                raise RuntimeError("Container is running but service is not; inspect logs before another startup")
            return {"instance": name, **state}
        if self.manifest["handoff"]["startup"]["availability"] != "available":
            raise RuntimeError("No executable startup recipe; stopped instance preserved")
        if self.pending(instance["id"]):
            raise RuntimeError("Pending historical job requests; inspect them before restarting")
        if self.ephemeral_archives(instance, info):
            snapshot = instance.get("state_snapshot")
            if not snapshot or {a["destination"] for a in snapshot["archives"]} != {
                    a["destination"] for a in self.ephemeral_archives(instance, info)}:
                raise RuntimeError("Retained tmpfs state has no down snapshot; preserve the container and inspect recovery evidence")
            self.restore(instance["id"], snapshot["archives"])
        self.docker("start", instance["id"])
        if instance["original"]:
            self.docker("exec", instance["id"], "python", "-c",
                        "import json,os;from pathlib import Path;p=Path('/run/fmst/lifecycle.json');"
                        "p.parent.mkdir(parents=True,exist_ok=True);t=p.with_name(p.name+'.'+str(os.getpid())+'.tmp');"
                        "t.write_text(json.dumps({'status':'serving','agent_phase':'exited'}));t.replace(p)")
            self.docker("exec", instance["id"], "python", "/opt/fmst-delivery/bootstrap.py", "--startup-only", timeout=320)
        deadline = time.monotonic() + 310
        while time.monotonic() < deadline:
            state = self.service(name)
            if state["service"] == "running":
                return {"instance": name, **state}
            if state["service"] == "startup_error":
                raise RuntimeError("Startup failed; inspect ./fmst logs and instance receipt")
            if state["container"] == "stopped":
                raise RuntimeError("Container exited during startup; inspect Docker logs")
            time.sleep(.5)
        raise RuntimeError("Startup did not produce a live service receipt; container preserved")

    def proxy(self, name):
        instance, info = self.info(name)
        if not info["State"]["Running"]:
            raise RuntimeError("Container is stopped")
        entries = info["NetworkSettings"]["Ports"].get("1080/tcp") or []
        if not entries:
            raise RuntimeError("No SOCKS port published")
        entry = entries[0]
        address = (entry["HostIp"], int(entry["HostPort"]))
        with socket.create_connection(address, timeout=3) as stream:
            stream.sendall(b"\x05\x01\x00")
            if stream.recv(2) != b"\x05\x00":
                raise RuntimeError("SOCKS endpoint did not accept handshake")
        return "socks5://" + address[0] + ":" + str(address[1])

    def open(self, name):
        access = self.manifest["handoff"]["access"]
        if self.service(name)["service"] != "running":
            raise RuntimeError("Service is not running")
        if access["transport"] == "container":
            raise RuntimeError("This service needs container browser access: " + access["instructions"])
        browser = next((shutil.which(x) for x in ("chromium", "google-chrome", "google-chrome-stable", "chromium-browser") if shutil.which(x)), None)
        if browser is None:
            raise RuntimeError("Install Chromium/Chrome or follow the native access instructions in README.md")
        profile = self.root / ".state/browser" / name
        args = [browser, "--user-data-dir=" + str(profile), "--no-first-run", "--no-default-browser-check"]
        if access["transport"] == "socks5":
            args += ["--proxy-server=" + self.proxy(name), "--proxy-bypass-list=<-loopback>"]
        else:
            args += ["--no-proxy-server"]
        with (self.root / ".state/browser.log").open("ab") as log:
            subprocess.Popen([*args, access["native_url"]], stdout=log, stderr=log, start_new_session=True)
        return {"browser_started": True, "native_url": access["native_url"]}

    def down(self, name):
        instance, info = self.info(name)
        if info["State"]["Running"]:
            self.snapshot_ephemeral(name, instance, info)
            self.docker("stop", "--time", "10", instance["id"])
        return {"instance": name, "status": "stopped", "data": "retained"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("up", "open", "status", "logs", "down"))
    parser.add_argument("--instance", default="retained")
    parser.add_argument("--new-instance")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    try:
        with (root / ".state/lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            delivery = Delivery(root)
            if args.new_instance and args.action != "up":
                raise ValueError("--new-instance is only valid with up")
            if args.action == "up":
                result = delivery.up(args.instance, args.new_instance)
            elif args.action == "open":
                result = delivery.open(args.instance)
            elif args.action == "down":
                result = delivery.down(args.instance)
            elif args.action == "logs":
                result = {"instance": args.instance, "receipt": delivery.service(args.instance).get("receipt"),
                          "evidence": delivery.manifest["handoff"]["evidence"]}
            else:
                result = {"instance": args.instance, **delivery.service(args.instance),
                          "native_url": delivery.manifest["handoff"]["access"]["native_url"]}
            print(json.dumps(result, ensure_ascii=False, indent=2))
    except Exception as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
