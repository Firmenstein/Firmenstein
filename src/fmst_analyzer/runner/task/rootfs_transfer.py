"""Stream a firmware rootfs through GNU tar and verify both private copies."""
from __future__ import annotations

import json
import os
import subprocess
import uuid
from pathlib import Path

from .common import write_json
from .host import docker, docker_argv
from . import rootfs_metadata

EVIDENCE = "/task/evidence/input-transfer/rootfs"
DESTINATION = "/task/input/rootfs"
WORK = "/task/work/rootfs"


def tar_commands(source: Path, files: Path, container: str, destination: str):
    """Use a NUL-delimited exact inventory: no traversal of symlinks/options."""
    pack = ["tar", "--create", "--file=-", "--format=pax", "--numeric-owner",
            "--acls", "--xattrs", "--xattrs-include=*", "--sparse", "--no-recursion",
            "--directory", str(source), "--null", "--verbatim-files-from",
            "--files-from", str(files)]
    unpack = docker_argv("exec", "-i", container, "env", "TAR_OPTIONS=", "tar", "--extract", "--file=-",
        "--directory", destination, "--numeric-owner", "--same-owner",
        "--same-permissions", "--acls", "--xattrs", "--xattrs-include=*",
        "--delay-directory-restore")
    return pack, unpack


def pipe_tar(pack: list[str], unpack: list[str], output: Path) -> tuple[int, int]:
    """Keep both stderr streams off pipes; a failed receiver cannot deadlock us.

    Closing the parent's pipe copy delivers SIGPIPE to a producer whose receiver
    exits. On cancellation reap both children; neither is left writing a rootfs.
    """
    producer = receiver = None
    with (output / "pack.stderr").open("wb") as pack_log, \
            (output / "unpack.stderr").open("wb") as unpack_log:
        try:
            producer = subprocess.Popen(pack, stdout=subprocess.PIPE, stderr=pack_log,
                                        env={**os.environ, "TAR_OPTIONS": ""})
            try:
                receiver = subprocess.Popen(unpack, stdin=producer.stdout,
                    stdout=subprocess.DEVNULL, stderr=unpack_log)
            finally:
                producer.stdout.close()
            unpack_code = receiver.wait()
            return producer.wait(), unpack_code
        finally:
            for process in (receiver, producer):
                if process is not None and process.poll() is None:
                    process.kill()
                    process.wait()


def _snapshot(container: str, root: str, output: Path) -> dict:
    # Execute this exact metadata implementation, including in verification
    # containers that do not have the rest of Firmenstein copied into them.
    code = Path(rootfs_metadata.__file__).read_text()
    with output.open("wb") as log, output.with_suffix(".stderr").open("wb") as error:
        subprocess.run(docker_argv("exec", container, "python", "-c", code, root),
                       stdout=log, stderr=error, check=True)
    return json.loads(output.read_text())


def transfer_rootfs(task, source: Path) -> dict:
    """Prepare original + working rootfs, preserving attributes the FS supports.

    Device nodes and sockets are described for runtime setup instead of being
    faked as regular files. Static transfer errors/mismatches stop preparation
    with host and Agent-visible receipts; no firmware repair policy is imposed.
    """
    source = Path(source).absolute()
    output = task.output / "input-transfer/rootfs"
    output.mkdir(parents=True, exist_ok=False)
    staging = "/task/input/.rootfs-transfer-" + uuid.uuid4().hex
    receipt = {"schema_version": 1, "status": "preparing", "source": str(source),
               "destination": DESTINATION, "work": WORK, "staging": staging,
               "evidence": EVIDENCE, "pack_exit": None, "unpack_exit": None}
    try:
        original = rootfs_metadata.manifest(source)
        write_json(output / "source.json", original)
        deferred = {name: row for name, row in original["entries"].items()
                    if row["type"] in rootfs_metadata.RUNTIME_TYPES}
        write_json(output / "runtime-entries.json", {"entries": deferred,
            "reason": "Sockets must be created by their service; device nodes require runtime support. No placeholders were created."})
        receipt["runtime_entries"] = len(deferred)
        files = output / "files.nul"
        files.write_bytes(b"".join(os.fsencode("./" + name) + b"\0"
            for name in original["entries"] if name not in deferred))
        # All destinations are trusted framework paths. Refuse symlink parents,
        # stale partial inputs and merges; extract only into a new empty tree.
        docker("exec", task.name, "python", "-c",
            "from pathlib import Path\nimport sys\n"
            "paths=[Path(p) for p in sys.argv[1:]]\n"
            "for p in paths:\n"
            " if p.exists() or p.is_symlink(): raise FileExistsError(str(p))\n"
            " if any(a.is_symlink() for a in p.parents): raise ValueError('Symlink parent: '+str(p))\n"
            "paths[0].mkdir(parents=True)\npaths[2].parent.mkdir(parents=True,exist_ok=True)",
            staging, DESTINATION, WORK)
        pack, unpack = tar_commands(source, files, task.name, staging)
        receipt["pack_exit"], receipt["unpack_exit"] = pipe_tar(pack, unpack, output)
        actual = _snapshot(task.name, staging, output / "received.json")
        mismatch = rootfs_metadata.differences(original, actual)
        write_json(output / "received-differences.json", mismatch)
        if receipt["pack_exit"] or receipt["unpack_exit"] or mismatch:
            raise RuntimeError("Rootfs tar transfer or metadata verification failed")
        docker("exec", task.name, "mv", "--", staging, DESTINATION)
        # GNU cp preserves xattrs/ACLs/hardlinks and sparsity; verify the final
        # runnable copy too, before any Agent or guest modifications.
        with (output / "clone.stderr").open("wb") as log:
            clone = subprocess.run(docker_argv("exec", task.name, "cp", "-a", "--",
                DESTINATION, WORK), stdout=subprocess.DEVNULL, stderr=log)
        receipt["clone_exit"] = clone.returncode
        actual_work = _snapshot(task.name, WORK, output / "work.json")
        mismatch = rootfs_metadata.differences(original, actual_work)
        write_json(output / "work-differences.json", mismatch)
        if clone.returncode or mismatch:
            raise RuntimeError("Rootfs working-copy metadata verification failed")
        receipt["status"] = "verified_with_runtime_entries" if deferred else "verified"
    except BaseException as error:
        receipt.update(status="error", error=str(error))
        if not isinstance(error, Exception):
            raise
        raise RuntimeError(f"Rootfs preparation failed; inspect {output / 'receipt.json'}") from error
    finally:
        receipt["warnings"] = [path.name for path in output.glob("*.stderr") if path.stat().st_size]
        write_json(output / "receipt.json", receipt)
        # Receipts remain on the host even if the container has already stopped.
        try:
            docker("exec", task.name, "mkdir", "-p", EVIDENCE)
            docker("cp", str(output) + "/.", task.name + ":" + EVIDENCE)
        except Exception as error:
            receipt["evidence_copy_error"] = str(error)
            write_json(output / "receipt.json", receipt)
    return {"status": receipt["status"], "receipt": EVIDENCE + "/receipt.json",
            "runtime_entries": EVIDENCE + "/runtime-entries.json"}
