"""Capture a retained task without pausing its service or exporting model history."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import time
import uuid

from .common import write_json
from .delivery_manifest import DeliveryManifestV1, StateArchive, render_readme
from .handoff import HandoffDraftV1, references


CAPTURE_IO_TIMEOUT_SECONDS = 7200


def acquire_capture_lock(lock, deadline: float) -> None:
    """Serialize completed tasks within the I/O budget instead of failing contention."""
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Filesystem capture queue deadline reached; original service retained") from None
            time.sleep(min(0.1, remaining))


def commit_image(docker, *, container: str, task_id: str, engine: str,
                 stage: Path, pending: Path, timeout: float) -> str:
    """Keep unknown daemon work visible and prevent another capture overlapping it."""
    if pending.exists():
        raise RuntimeError(f"A previous image operation has an unknown outcome; inspect {pending}")
    operation = {"status": "started", "started_at": time.time(), "container": container,
                 "task_id": task_id, "engine": engine,
                 "reference": f"firmenstein/delivery:{task_id}-{uuid.uuid4().hex}"}
    receipt = stage / "evidence/image-operation.json"
    write_json(pending, operation)
    write_json(receipt, operation)
    try:
        image = docker("commit", "--pause=false", "--change",
                       'ENTRYPOINT ["python", "/opt/fmst-delivery/bootstrap.py"]',
                       "--change", 'CMD []', container, operation["reference"],
                       text=True, timeout=timeout).stdout.strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise RuntimeError("Image operation returned no exact image identity")
    except BaseException as error:
        response = getattr(error, "process_result", None)
        known_failure = response is not None and response.returncode != 0
        operation.update(status="failed" if known_failure else "outcome_unknown",
                         finished_at=time.time(), error_type=type(error).__name__)
        write_json(receipt, operation)
        write_json(pending, operation)
        if known_failure:
            pending.unlink()
        raise
    operation.update(status="complete", finished_at=time.time(), image=image)
    write_json(receipt, operation)
    pending.unlink()
    return image


INVENTORY = r'''
import hashlib,json,os,re,stat,sys
from pathlib import Path
paths=json.loads(sys.argv[1]); records=[]
for value in paths:
 p=Path(value)
 try:
  st=p.lstat();kind='symlink' if p.is_symlink() else 'file' if p.is_file() else 'directory'
  item=dict(path=value,kind=kind,mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid)
  if kind=='file':
   with p.open('rb') as stream: item.update(sha256=hashlib.file_digest(stream,'sha256').hexdigest(),size=st.st_size)
  if kind=='symlink': item['link']=os.readlink(p)
 except FileNotFoundError:item=dict(path=value,kind='missing')
 records.append(item)
mounts=[];seen=set()
def unescape(s):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),s)
for p in Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:
  ns=os.readlink(p/'ns/mnt');rootview=os.readlink(p/'root');view=(ns,rootview)
  if view in seen:continue
  seen.add(view)
  for line in (p/'mountinfo').read_text().splitlines():
   left,right=line.split(' - ',1);a=left.split();b=right.split()
   visible=unescape(a[4]);path=str(Path(rootview)/visible.lstrip('/'))
   mounts.append(dict(namespace=ns,pid=int(p.name),root=unescape(a[3]),path=path,visible_path=visible,process_root=rootview,options=a[5],fstype=b[0],source=unescape(b[1])))
 except (FileNotFoundError,PermissionError,ProcessLookupError):pass
requests=Path('/task/control/requests');replies=Path('/task/control/replies')
pending=[p.name for p in requests.glob('*.json') if not (replies/p.name).exists()]
print(json.dumps(dict(artifacts=records,mounts=mounts,pending_requests=pending)))
'''


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def apply_archived_artifacts(artifacts: list[dict], archive: StateArchive, stage: Path) -> None:
    """Use external-state bytes for file identities, including tar hardlinks."""
    selected = {item["path"]: item for item in artifacts
                if PurePosixPath(item["path"]).is_relative_to(archive.destination)}
    if not selected:
        return
    with tarfile.open(stage / archive.file, "r:gz") as source:
        for member in source:
            path = str(PurePosixPath(archive.destination) / member.name)
            if path not in selected:
                continue
            item = selected[path]
            item.clear()
            item.update(path=path, kind="file" if member.isfile() or member.islnk() else "symlink" if member.issym() else "directory",
                        mode=member.mode, uid=member.uid, gid=member.gid, storage=archive.file)
            if member.isfile() or member.islnk():
                with source.extractfile(member) as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                    item.update(sha256=digest, size=stream.tell())
            elif member.issym():
                item["link"] = member.linkname


def capture_service_identity(completion: dict, restarted: dict | None, identity) -> dict:
    """Bind capture to a live process without rewriting the original business result."""
    init_ticks = identity(1)
    if type(init_ticks) is not int or init_ticks <= 0:
        raise ValueError("Container init identity is not live")
    for source, receipt in (("original_completion", completion), ("delivery_startup", restarted)):
        if not isinstance(receipt, dict):
            continue
        pid, ticks = receipt.get("service_pid"), receipt.get("service_start_ticks")
        if type(pid) is not int or pid <= 1 or type(ticks) is not int or ticks <= 0:
            continue
        if source == "delivery_startup" and (receipt.get("status") != "running"
                or type(receipt.get("init_start_ticks")) is not int or receipt["init_start_ticks"] != init_ticks):
            continue
        if identity(pid) == ticks:
            return {"source": source, "service_pid": pid, "service_start_ticks": ticks,
                    "init_start_ticks": init_ticks}
    raise ValueError("Neither original service nor a verified delivery restart is live")


def mount_gaps(mounts: list[dict], draft: HandoffDraftV1) -> list[str]:
    """Account for uncaptured writable data, not for business correctness."""
    gaps = set()
    pseudo = {"proc", "sysfs", "devpts", "devtmpfs", "cgroup", "cgroup2", "mqueue", "nsfs"}
    engine_files = {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
    # Translate the guest's actual /proc/PID/root view. These are OS device
    # namespaces, not arbitrary tmpfs application data with a similar name.
    device_mounts = {m["path"] for m in mounts if m["fstype"] == "tmpfs"
                     and PurePosixPath(m.get("visible_path", m["path"])).is_relative_to("/dev")}
    for mount in mounts:
        path = PurePosixPath(mount["path"])
        if path == PurePosixPath("/") or str(path) in engine_files | device_mounts or mount["fstype"] in pseudo:
            continue
        if any(path.is_relative_to(root) for root in ("/proc", "/sys", "/dev", "/run", "/task/sessions")):
            continue
        covered = any((path.is_relative_to(s.path) or
                       (s.persistence == "external_mount" and PurePosixPath(s.path).is_relative_to(path)))
                      and s.persistence in {"recreate", "volatile", "external_mount"}
                      for s in draft.state)
        # Bind mounts on the container's own overlay refer to data already in
        # that filesystem. Namespace mount setup still belongs to the recipe.
        if mount["fstype"] == "overlay":
            continue
        if not covered:
            gaps.add(f"Mount {path} ({mount['fstype']}) has no state archive or recreation declaration")
    return sorted(gaps)


def state_archive_plan(mounts: list[dict], states: list, artifacts: list[dict]) -> tuple[list[dict], list[str]]:
    """Select declared data below a mount; sibling files share a restore directory."""
    kinds = {item["path"]: item["kind"] for item in artifacts}
    groups = []
    gaps = []
    for state in states:
        if state.persistence != "external_mount":
            continue
        path = PurePosixPath(state.path)
        containing = [m for m in mounts if path.is_relative_to(m["path"])]
        mount = max(containing, key=lambda m: len(PurePosixPath(m["path"]).parts), default=None)
        if mount is None or mount["path"] == "/" or mount["fstype"] == "overlay":
            gaps.append(f"External state path {path} is not backed by a known external mount")
            continue
        kind = kinds.get(str(path))
        if kind not in {"file", "directory"}:
            gaps.append(f"External state path {path} must be an existing regular file or directory")
            continue
        destination = path if kind == "directory" else path.parent
        if destination == PurePosixPath("/"):
            gaps.append(f"External state path {path} needs a restoration directory below the container root")
            continue
        groups.append({"destination": str(destination), "mount": mount["path"], "paths": {str(path)}})
    combined = []
    for group in sorted(groups, key=lambda g: (len(PurePosixPath(g["destination"]).parts), g["destination"])):
        parent = next((g for g in combined if g["destination"] == group["destination"] or
                       (g["mount"] == group["mount"]
                        and PurePosixPath(group["destination"]).is_relative_to(g["destination"]))), None)
        if parent is not None:
            parent["paths"].update(group["paths"])
        else:
            combined.append(group)
    plans = []
    for group in combined:
        destination = PurePosixPath(group["destination"])
        selected = sorted(group["paths"], key=lambda p: (len(PurePosixPath(p).parts), p))
        roots = []
        for path in selected:
            if not any(PurePosixPath(path).is_relative_to(p) for p in roots):
                roots.append(path)
        nested = sorted({m["path"] for m in mounts if m["path"] != str(destination)
                         and PurePosixPath(m["path"]).is_relative_to(destination)
                         and not (m["path"] in group["paths"] and kinds.get(m["path"]) == "file")})
        plans.append({"destination": str(destination),
                      "members": ["./" + str(PurePosixPath(p).relative_to(destination)) for p in roots],
                      "excluded_mounts": nested})
    return plans, gaps


def capture(task, *, origin="same_session") -> Path:
    """Publish atomically. On failure the caller retains its service and history."""
    from .host import docker as run_docker, docker_argv, LABEL
    deadline = time.monotonic() + CAPTURE_IO_TIMEOUT_SECONDS

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("Filesystem capture I/O deadline reached; original service retained")
        return value

    def docker(*args, **kwargs):
        kwargs["timeout"] = min(kwargs.get("timeout", CAPTURE_IO_TIMEOUT_SECONDS), remaining())
        return run_docker(*args, **kwargs)

    result = task.result
    if result.status != "serving" or result.completion is None:
        raise ValueError("Capture requires a retained service completion")
    output = task.output / "package"
    if output.exists():
        raise FileExistsError("Delivery package already exists; preserve it")
    lock_path = Path(__file__).resolve().parents[4] / ".fmst/runner-capture.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a") as lock:
        acquire_capture_lock(lock, deadline)
        pending = lock_path.with_suffix(".pending.json")
        if pending.exists():
            raise RuntimeError(f"A previous image operation has an unknown outcome; inspect {pending}")
        draft = HandoffDraftV1.model_validate_json((task.output / "delivery/handoff.json").read_text())
        container = result.container_id
        info = json.loads(docker("inspect", "--size", container, text=True).stdout)[0]
        if info["Config"]["Labels"].get(LABEL) != result.task_id or not info["State"]["Running"]:
            raise ValueError("Task container identity is not live")
        completion_bytes = docker("exec", container, "cat", "/task/delivery/completion.json").stdout
        if json.loads(completion_bytes) != result.completion.model_dump(mode="json"):
            raise ValueError("Retained completion changed before capture")
        # A delivery restart has its own receipt. Original interactions and
        # completion stay immutable and are not relabeled as new observations.
        observed = json.loads(docker("exec", container, "python", "-c", r'''
import json
from pathlib import Path
from fmst_analyzer.runner.task.common import process_identity
p=Path('/task/delivery/instance.json')
receipt=json.loads(p.read_text()) if p.exists() else None
completion=json.loads(Path('/task/delivery/completion.json').read_text())
pids={1,completion['service_pid']}
if isinstance(receipt,dict) and type(receipt.get('service_pid')) is int:pids.add(receipt['service_pid'])
print(json.dumps(dict(restarted=receipt,identities={str(pid):process_identity(pid) for pid in pids})))
''', text=True).stdout)
        service_identity = capture_service_identity(result.completion.model_dump(mode="json"), observed["restarted"],
                                                    lambda pid: observed["identities"].get(str(pid)))
        estimated_layer_bytes = int(info.get("SizeRw") or 0)
        if shutil.disk_usage(task.output).free < 2 * estimated_layer_bytes:
            raise RuntimeError("Insufficient space for the estimated final image layer; original remains available")
        sessions = [m for m in info["Mounts"] if m["Destination"] == "/task/sessions"]
        if not sessions:
            # Old tasks whose sessions were already deleted may be captured;
            # never delete surviving histories merely to permit a commit.
            count = docker("exec", container, "python", "-c",
                           "from pathlib import Path;print(sum(1 for p in Path('/task/sessions').rglob('*') if p.is_file()))",
                           text=True).stdout.strip()
            if count != "0":
                raise RuntimeError("Native history is inside the image filesystem; retain it and move to an excluded recovery volume before capture")
        docker("exec", container, "test", "!", "-e", "/run/fmst/model.json")
        stage = task.output / (".package-" + uuid.uuid4().hex)
        stage.mkdir(mode=0o700)
        (stage / "evidence").mkdir()
        for name in ("completion.json", "evidence.json", "handoff-status.json", "handoff.json"):
            source = task.output / "delivery" / name
            if source.exists():
                shutil.copy2(source, stage / "evidence" / name)
        # Keep helpers independent of any Agent backend repair.
        docker("exec", container, "mkdir", "-p", "/opt/fmst-delivery")
        task.put_file("/opt/fmst-delivery/bootstrap.py", Path(__file__).with_name("delivery_bootstrap.py").read_bytes())
        docker("exec", container, "chmod", "0644", "/opt/fmst-delivery/bootstrap.py")
        task.put_json("/opt/fmst-delivery/startup.json", draft.startup.model_dump(mode="json"))
        changed = [line.split(" ", 1)[1] for line in docker("diff", container, text=True).stdout.splitlines()
                   if line.startswith(("A ", "C "))]
        task.put_json("/run/fmst/capture-paths.json", changed)
        metadata = json.loads(docker("exec", container, "python", "-c", r'''
import os,json,base64,stat
from pathlib import Path
entries=[];errors=[];links={}
for value in json.loads(Path('/run/fmst/capture-paths.json').read_text()):
 p=Path(value)
 if any(p.is_relative_to(root) for root in ('/proc','/sys','/dev','/run','/task/sessions')):continue
 try:
  st=p.lstat()
  if stat.S_ISREG(st.st_mode) and st.st_nlink>1:
   group=links.setdefault((st.st_dev,st.st_ino),dict(paths=[],count=st.st_nlink));group['paths'].append(value)
  attrs={name:base64.b64encode(os.getxattr(p,name,follow_symlinks=False)).decode() for name in os.listxattr(p,follow_symlinks=False)}
  if attrs:entries.append(dict(path=value,attributes=attrs))
 except FileNotFoundError:continue
 except OSError as error:errors.append(dict(path=value,errno=error.errno))
print(json.dumps(dict(entries=entries,errors=errors,hardlinks=list(links.values()))))
''', text=True).stdout)
        task.put_json("/opt/fmst-delivery/xattrs.json", metadata)
        paths = {r.path for r in references(draft)} | {"/opt/fmst-delivery/bootstrap.py", "/opt/fmst-delivery/startup.json", "/opt/fmst-delivery/xattrs.json"}
        paths.update(s.path for s in draft.state if s.persistence == "external_mount")
        execution = json.loads(docker("exec", container, "python", "-c", r'''
import json
from pathlib import Path
p=Path('/task/evidence/execution.json');result={'status':'unregistered','artifacts':[]}
if p.is_file():
 marker=json.loads(p.read_text());path=marker.get('execution_path')
 if path and Path(path).is_file():
  record=json.loads(Path(path).read_text())
  artifacts=[v for v in [record.get('harness'),record.get('intervention'),*record.get('images',[])] if isinstance(v,dict) and 'path' in v and 'sha256' in v]
  result=dict(status='registered',record_path=path,execution_id=record.get('execution_id'),artifacts=artifacts,trace_roots=record.get('trace_roots',[]))
print(json.dumps(result))
''', text=True).stdout)
        if execution["status"] == "registered":
            paths.add(execution["record_path"])
            paths.update(item["path"] for item in execution["artifacts"])
        for operation in result.completion.interactions:
            paths.update(operation.evidence)
        inventory = json.loads(docker("exec", container, "python", "-c", INVENTORY,
                                      json.dumps(sorted(paths)), text=True).stdout)
        write_json(stage / "evidence/mounts.json", inventory["mounts"])
        if inventory["pending_requests"]:
            raise RuntimeError("Task has pending init requests; cannot snapshot a deterministic startup boundary")
        gaps = mount_gaps(inventory["mounts"], draft)
        gaps += [f"Extended attributes could not be read at {entry['path']} (errno {entry['errno']})" for entry in metadata["errors"]]
        gaps += [f"Hardlink group outside captured changed paths: {group['paths']}" for group in metadata["hardlinks"]
                 if len(group["paths"]) != group["count"]]
        archives = []
        plans, state_gaps = state_archive_plan(inventory["mounts"], draft.state, inventory["artifacts"])
        gaps += state_gaps
        for index, plan in enumerate(plans):
            destination, nested = plan["destination"], plan["excluded_mounts"]
            archive = stage / "state-archives" / f"{index}.tar.gz"
            archive.parent.mkdir(exist_ok=True)
            command = docker_argv("exec", container, "timeout", str(max(1, int(remaining()))), "tar", "--format=pax",
                                  "--numeric-owner", "--acls", "--xattrs", "--sparse",
                                  *[f"--exclude=./{PurePosixPath(p).relative_to(destination)}" for p in nested],
                                  "-czf", "-", "-C", destination,
                                  "--no-recursion", ".", "--recursion", "--", *plan["members"])
            with archive.open("wb") as out, (stage / "evidence" / f"state-{index}-stderr.txt").open("wb") as err:
                proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err)
                try:
                    while data := proc.stdout.read(1024 * 1024):
                        if shutil.disk_usage(stage).free < len(data):
                            raise RuntimeError("Insufficient space for the next state archive chunk")
                        out.write(data)
                    if proc.wait() != 0:
                        raise RuntimeError("State archive failed; inspect saved stderr")
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
            archives.append(StateArchive(destination=destination, file=str(archive.relative_to(stage)),
                                          sha256=sha256(archive), size=archive.stat().st_size, excluded_mounts=nested))
        if shutil.disk_usage(task.output).free < 2 * estimated_layer_bytes:
            raise RuntimeError("Disk reserve changed before image capture; original remains available")
        image = commit_image(docker, container=container, task_id=result.task_id,
                             engine=docker_argv()[2], stage=stage, pending=pending, timeout=remaining())
        live_after = docker("exec", container, "python", "-c",
            "from fmst_analyzer.runner.task.common import process_identity;import json,sys;"
            "v=json.loads(sys.argv[1]);print(process_identity(1)==v['init_start_ticks'] and "
            "process_identity(v['service_pid'])==v['service_start_ticks'])", json.dumps(service_identity),
            text=True).stdout.strip()
        if live_after != "True":
            gaps.append("Captured service process stopped or changed during filesystem capture")
        # File hashes describe the committed image, not a previous live read.
        inspector = docker("create", "--network", "none", "--entrypoint", "python", image, "-c", INVENTORY,
            json.dumps(sorted(paths)), text=True).stdout.strip()
        try:
            image_inventory = json.loads(docker("start", "--attach", inspector, text=True).stdout)
        finally:
            # Killing an attached Docker client does not stop its container.
            # This ID belongs only to the offline inventory, never the firmware.
            run_docker("rm", "--force", inspector, timeout=30)
        for archive in archives:
            apply_archived_artifacts(image_inventory["artifacts"], archive, stage)
        for item in image_inventory["artifacts"]:
            if item["kind"] == "missing":
                gaps.append(f"Artifact absent in committed image: {item['path']}")
        captured_hashes = {item["path"]: item.get("sha256") for item in image_inventory["artifacts"]}
        for item in execution["artifacts"]:
            if captured_hashes.get(item["path"]) != item["sha256"]:
                gaps.append(f"Captured file does not match recorded execution identity: {item['path']}")
        cfg = info["HostConfig"]
        config = {key: cfg[key] for key in ("Memory", "MemorySwap", "NanoCpus", "PidsLimit", "ShmSize", "CapAdd", "Tmpfs")}
        inputs_path = task.output / "inputs.json"
        manifest = DeliveryManifestV1(task_id=result.task_id, target=result.target, created_at=time.time(),
            source_result_version=result.schema_version, handoff_origin=origin, completion=result.completion,
            handoff=draft, inputs=json.loads(inputs_path.read_text()) if inputs_path.exists() else {},
            image={"id": image, "base_id": info["Image"], "storage": "local_private_engine", "offline_export": None},
            container_config=config, execution=execution, capture={"status": "incomplete" if gaps else "ready", "consistency": "live_nonatomic",
            "gaps": gaps, "mount_inventory": "evidence/mounts.json", "sessions": "excluded_private_volume" if sessions else "old_history_absent",
            "metadata_overlay": "/opt/fmst-delivery/xattrs.json (restored by bootstrap on first startup)",
            "estimated_layer_bytes": estimated_layer_bytes,
            "service_identity": service_identity,
            "runtime_state": "processes, memory, IPC and namespaces are recreated by startup; not checkpointed"},
            artifacts=image_inventory["artifacts"], state_archives=archives)
        write_json(stage / "delivery.json", manifest.model_dump(mode="json"))
        (stage / "README.md").write_text(render_readme(manifest))
        shutil.copy2(Path(__file__).with_name("delivery_cli.py"), stage / "fmst")
        (stage / "fmst").chmod(0o755)
        (stage / ".state").mkdir(mode=0o700)
        write_json(stage / ".state/local.json", {"engine": docker_argv()[2], "instances": {
            "retained": {"id": container, "task_id": result.task_id, "original": True,
                         "service_pid": service_identity["service_pid"], "service_start_ticks": service_identity["service_start_ticks"]}}})
        write_json(stage / "images.json", manifest.image)
        stage.rename(output)
        return output
