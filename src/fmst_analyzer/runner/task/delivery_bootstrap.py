"""Standalone in-container startup bridge. Copied outside the repaired backend."""
import json
import hashlib
import base64
import os
from pathlib import Path
import shutil
import resource
import signal
import subprocess
import sys
import time
import uuid


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value) + "\n")
    temporary.replace(path)


def identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return None if fields[0] == "Z" else int(fields[19])
    except (OSError, ValueError, IndexError):
        return None


def validate_receipt(receipt):
    pid, ticks = receipt.get("service_pid"), receipt.get("service_start_ticks")
    if type(pid) is not int or pid <= 1 or type(ticks) is not int or ticks <= 0:
        raise ValueError("Startup receipt needs positive service_pid > 1 and service_start_ticks")
    if identity(pid) != ticks:
        raise ValueError("Startup service identity is not live")
    if not isinstance(receipt.get("log_paths"), list) or "execution_path" not in receipt:
        raise ValueError("Startup receipt needs log_paths and execution_path (null if unavailable)")


def limit_automatic_core_dumps(*, include_existing_services=False):
    """Delivery runs indefinitely; diagnostic dumps need explicit re-enabling."""
    limits = []
    required = {os.getpid()}
    # prlimit checks process ownership even for container root without
    # CAP_SYS_RESOURCE. The two task roles limit their own processes.
    if not include_existing_services or Path('/proc/1').stat().st_uid == os.geteuid():
        required.add(1)
    pids = set(required)
    if include_existing_services:
        for path in Path('/proc').iterdir():
            try:
                if path.name.isdigit() and path.stat().st_uid == os.geteuid():
                    pids.add(int(path.name))
            except OSError:
                pass
    errors = []
    for pid in sorted(pids):
        try:
            before = resource.prlimit(pid, resource.RLIMIT_CORE)
            resource.prlimit(pid, resource.RLIMIT_CORE, (0, before[1]))
            limits.append({"pid": pid, "start_ticks": identity(pid), "before": list(before),
                           "after": list(resource.prlimit(pid, resource.RLIMIT_CORE))})
        except OSError as error:
            if pid in required:
                raise
            errors.append({"pid": pid, "errno": error.errno})
    save("/task/evidence/delivery-core-limit-" + uuid.uuid4().hex + ".json",
         {"at": time.time(), "limits": limits, "hard_limits_preserved": True,
          "errors": errors, "scope": "delivered services; original Agent diagnostics remain retained"})


def startup():
    recipe = json.loads(Path("/opt/fmst-delivery/startup.json").read_text())
    if recipe["availability"] != "available":
        raise RuntimeError("No startup recipe: " + recipe["unavailable_reason"])
    receipt_path = Path(recipe["receipt_path"])
    if receipt_path.exists():
        retained = receipt_path.with_name(receipt_path.name + ".previous-" + uuid.uuid4().hex)
        receipt_path.rename(retained)
    command = recipe["command"]
    started = time.time()
    log = Path("/task/evidence/delivery-startup-" + uuid.uuid4().hex + ".log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("wb") as stream:
        child = subprocess.Popen(command["argv"], cwd=command["cwd"],
                                 env={**os.environ, **command["env"]}, stdin=subprocess.DEVNULL,
                                 stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=command["timeout_seconds"])
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            raise RuntimeError("Startup timed out; inspect " + str(log)) from None
    if code:
        raise RuntimeError(f"Startup exited {code}; inspect {log}")
    receipt = json.loads(receipt_path.read_text())
    validate_receipt(receipt)
    # Startup recipes may include older/repaired launchers which raise their
    # own soft core limits. Apply the default after their processes exist.
    limit_automatic_core_dumps(include_existing_services=True)
    subprocess.run(["runuser", "-u", "runner", "--", sys.executable, __file__, "--limit-cores-only"],
                   check=True, timeout=30)
    save("/task/delivery/instance.json", {**receipt, "status": "running", "started_at": started,
                                        "init_start_ticks": identity(1), "startup_log": str(log)})


def restore(*, force=False):
    plan = Path("/opt/fmst-delivery/restores.json")
    marker = Path("/opt/fmst-delivery/restored.json")
    if not plan.exists():
        return
    hostname = os.uname().nodename
    plan_digest = hashlib.sha256(plan.read_bytes()).hexdigest()
    if not force and marker.exists() and json.loads(marker.read_text()).get("hostname") == hostname:
        return
    for item in json.loads(plan.read_text()):
        source = Path(item["source"])
        with source.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != item["sha256"]:
            raise ValueError("State archive digest mismatch")
        destination = Path(item["destination"])
        destination.mkdir(parents=True, exist_ok=True)
        subprocess.run(["tar", "--numeric-owner", "--acls", "--xattrs", "--xattrs-include=*",
                        "--sparse", "-xzpf", str(source), "-C", str(destination)], check=True)
    save(marker, {"restored_at": time.time(), "hostname": hostname, "plan_sha256": plan_digest})


def restore_metadata(root=Path("/opt/fmst-delivery")):
    """Docker commit can omit user/ACL xattrs from a changed layer."""
    marker = root / "metadata-restored.json"
    source = root / "xattrs.json"
    if not source.exists():
        return
    hostname = os.uname().nodename
    if marker.exists() and json.loads(marker.read_text()).get("hostname") == hostname:
        return
    metadata = json.loads(source.read_text())
    for entry in metadata["entries"]:
        for name, value in entry["attributes"].items():
            os.setxattr(entry["path"], name, base64.b64decode(value), follow_symlinks=False)
    # Setting metadata can separately copy up lower-layer aliases on engines
    # without an overlay index. Promote and relink after all attribute writes,
    # including groups which appeared to share a lower inode before copy-up.
    for group in metadata.get("hardlinks", []):
        main, *others = group["paths"]
        for path in others:
            temporary = path + ".fmst-link-" + uuid.uuid4().hex
            os.link(main, temporary)
            os.replace(temporary, path)
    save(marker, {"restored_at": time.time(), "hostname": hostname})


def main():
    if '--limit-cores-only' in sys.argv:
        limit_automatic_core_dumps(include_existing_services=True)
        return
    save("/task/delivery/instance.json", {"status": "starting", "init_start_ticks": identity(1)})
    try:
        limit_automatic_core_dumps()
    except Exception as error:
        save("/task/delivery/instance.json", {"status": "startup_error", "error": str(error),
                                            "init_start_ticks": identity(1)})
        raise
    if "--startup-only" in sys.argv:
        try:
            restore(force=True)
            startup()
        except Exception as error:
            save("/task/delivery/instance.json", {"status": "startup_error", "error": str(error),
                                                "init_start_ticks": identity(1)})
            raise
        return
    # A new image starts with empty control queues. Preserve historical jobs
    # for inspection; do not replay them as requests in the new instance.
    control = Path("/task/control")
    if control.exists():
        dest = Path("/task/control-history") / uuid.uuid4().hex
        dest.parent.mkdir(parents=True, exist_ok=True)
        # OverlayFS can return EXDEV when renaming a directory from an image
        # lower layer. shutil.move preserves it by copying before removal.
        shutil.move(str(control), str(dest))
    for part in ("requests", "replies"):
        path = control / part
        path.mkdir(parents=True, exist_ok=True)
        shutil.chown(path, user="runner", group="runner")
    shutil.chown(control, user="runner", group="runner")
    Path("/run/fmst").mkdir(parents=True, exist_ok=True)
    save("/run/fmst/lifecycle.json", {"status": "serving", "agent_phase": "exited"})
    init = subprocess.Popen(["python", "-m", "fmst_analyzer.runner.task.init"])

    def terminate(*_):
        init.terminate()

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    try:
        restore()
        restore_metadata()
        startup()
    except Exception as error:
        save("/task/delivery/instance.json", {"status": "startup_error", "error": str(error)})
        # Leave the environment and logs available for inspection.
    sys.exit(init.wait())


if __name__ == "__main__":
    main()
