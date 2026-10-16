"""Disposable Docker rootfs sandbox for one Runner session."""

from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path

from fmst_analyzer.analysis.base.report_io import write_model_json

from .rootfs_actions import (
    RootfsAction,
    apply_rootfs_actions,
)

from .probe import MAX_RESPONSE_BYTES, build_probe_result, evaluate_interaction_scenario
from .request_wire import (save_request_bytes, save_response_bytes, response_cookie_values,
                           capture_response_values, substitute_response_values)
from .peer_readiness import unix_listeners, wait_for_peers
from .service_readiness import tcp_listeners, wait_for_service
from .runtime_builder import HostRuntimeBuilder, RuntimeBuilder
from .budget import ExecutionBudget, RunnerStopped, run_process
from .child_failure import assess_child_failures
from .identity import tree_sha256
from .runtime_dump import collect_runtime_dump
from .supervision import TargetProgressWatchdog
from .schema import (
    CompanionProcess,
    InteractionProbe,
    InteractionScenario,
    ProbeResult,
    ScenarioObservation,
    ScenarioResult,
    AttemptExecutionReceipt,
    RuntimeNetwork,
)


_LOADER_RE = re.compile(r"Requesting program interpreter:\s*([^\]]+)")
_LDD_ARROW_RE = re.compile(r"^\s*\S+\s+=>\s+(/\S+)\s+")
_LDD_DIRECT_RE = re.compile(r"^\s*(/\S+)\s+")
_EXPECTED_LIBAFL_VERSION = "0.16.1"
_DEFAULT_HOST_INTERPRETER_PATH = "/lib/ld-linux-aarch64.so.1"
_HOST_INTERPRETER_METADATA = "host-interpreter.path"


@dataclass(frozen=True)
class SandboxAttempt:
    container_exit_code: int | None
    target_exit_code: int | None
    timed_out: bool
    probe_result: ProbeResult
    scenario_result: ScenarioResult | None
    runtime_trace_path: Path
    runtime_trace_paths: tuple[Path, ...]
    container_log_path: Path
    companion_log_paths: tuple[Path, ...]
    rootfs_adaptations: tuple[str, ...]
    heartbeat_paths: tuple[Path, ...]
    watchdog_path: Path
    watchdog_triggered: bool
    termination_reason: str
    runtime_dump_manifest_path: Path | None = None
    runtime_dump_capture_kind: str | None = None
    runtime_dump_available: bool = False


@dataclass(frozen=True)
class ServiceStartup:
    container_name: str
    readiness_path: Path
    readiness: dict




def _checked(command: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, **kwargs)


def _elf_loader(binary: Path) -> Path:
    """Return the ELF interpreter used by a host-side executable."""
    readelf = _checked(["readelf", "-l", str(binary)], capture_output=True).stdout
    match = _LOADER_RE.search(readelf)
    if match is None:
        raise RuntimeError(f"cannot locate host ELF interpreter for {binary}")
    return Path(match.group(1)).resolve(strict=True)


def _collect_host_dependencies(
    binary: Path,
    *,
    loader: Path,
    dependencies: dict[str, Path],
) -> None:
    """Collect dynamic dependencies while rejecting basename collisions."""
    if _elf_loader(binary) != loader:
        raise RuntimeError(
            f"host executable uses a different ELF loader: {binary}"
        )
    ldd = _checked(["ldd", str(binary)], capture_output=True).stdout
    for line in ldd.splitlines():
        match = _LDD_ARROW_RE.match(line) or _LDD_DIRECT_RE.match(line)
        if match is None:
            continue
        path = Path(match.group(1))
        if not path.exists() or path.resolve() == loader:
            continue
        name = path.name
        resolved = path.resolve()
        existing = dependencies.get(name)
        if existing is not None and existing != resolved:
            raise RuntimeError(f"host runtime library basename collision: {name}")
        dependencies[name] = resolved


def _harness_arguments(
    *,
    harness_name: str,
    intervention_so: str | None,
    executable_path: str,
    trace_output: str | None,
    guest_args: list[str],
) -> list[str]:
    """Build the harness argv while keeping guest argv behind ``--``."""
    arguments = [
        f"/fmst-host/{harness_name}",
    ]
    if intervention_so is None:
        arguments.append("--trace-only")
    else:
        arguments.extend(["--intervention-so", intervention_so])
    arguments.extend(["--binary", executable_path, "--rootfs", "/"])
    # Guest execve re-enters the current harness through its host loader;
    # the staged firmware rootfs does not supply host ELF dependencies.
    arguments.extend([
        "--host-loader", "/fmst-host/ld.so",
        "--harness-path", f"/fmst-host/{harness_name}",
    ])
    if trace_output is not None:
        arguments.extend(["--trace-output", trace_output])
    arguments.extend(["--", *guest_args])
    return arguments


def _render_companion_supervisor(
    *,
    harness_name: str,
    companion_processes: list[CompanionProcess],
    target_arguments: list[str],
) -> str:
    """Render a shell wrapper for peers sharing the target's container."""
    lines = ["set -eu"]
    for index, process in enumerate(companion_processes, start=1):
        peer_arguments = _harness_arguments(
            harness_name=harness_name,
            intervention_so=None,
            executable_path=process.executable_path,
            trace_output=f"/fmst-output/runtime_trace.peer-{index:02d}.json",
            guest_args=process.args,
        )
        assignments = " ".join(
            f"{name}={shlex.quote(value)}"
            for name, value in sorted(process.environment.items())
        )
        command = shlex.join([
            "/fmst-host/ld.so",
            "--library-path",
            "/fmst-host/lib",
            *peer_arguments,
        ])
        if assignments:
            command = f"{assignments} {command}"
        lines.extend([
            "(set +e",
            f"(cd {shlex.quote(process.working_directory)} && {command})",
            "peer_rc=$?",
            "printf '{\"exit_code\":%s}\\n' \"$peer_rc\" "
            f"> /fmst-output/peer-{index:02d}-exit.json",
            f") >/fmst-output/companion-{index:02d}.log 2>&1 &",
        ])
    if any(process.readiness is not None for process in companion_processes):
        lines.append('while [ ! -f /fmst-control/target-ready ]; do /fmst-host/ld.so --library-path /fmst-host/lib /fmst-host/sleep 0.05; done')
    lines.extend(_render_target_lifecycle(target_arguments))
    return "\n".join(lines) + "\n"


def _render_target_lifecycle(target_arguments: list[str]) -> list[str]:
    """Keep PID 1 alive when a guest daemon forks its serving child.

    Linux-user QEMU can faithfully emulate ``daemon(3)`` by letting the guest
    parent exit while the child continues in a host child process. If the
    harness itself is PID 1, Docker tears down that child as soon as the
    parent exits, exactly when the service becomes ready. A tiny host-side
    supervisor records the target's own exit and keeps the disposable
    container alive until the Controller's probe deadline; this does not alter
    guest code or suppress daemonization.
    """
    command = shlex.join([
        "/fmst-host/ld.so",
        "--library-path",
        "/fmst-host/lib",
        *target_arguments,
    ])
    return [
        "set +e",
        f"({command}) &",
        "target_pid=$!",
        "wait \"$target_pid\"",
        "target_rc=$?",
        "set -e",
        "printf '{\"pid\":%s,\"tid\":%s,\"exit_code\":%s}\\n' \"$target_pid\" \"$target_pid\" \"$target_rc\" > /fmst-output/target-exit.json",
        "while :; do /fmst-host/ld.so --library-path /fmst-host/lib /fmst-host/sleep 60; done",
    ]


def _container_probe_command(
    container_name: str,
    host: str,
    probe: InteractionProbe,
    source_port: int | None = None,
    wait_seconds: int = 2,
) -> list[str]:
    """Build an argv-only probe command executed inside the target container."""
    return [
        "docker", "exec", "--interactive", container_name,
        "/fmst-host/ld.so", "--library-path", "/fmst-host/lib",
        "/fmst-host/nc", "-n", "-v", "-w", str(wait_seconds),
        *(["-p", str(source_port)] if source_port is not None else []),
        host, str(probe.port),
    ]


def _container_runtime_mounts(
    bundle_dir: Path,
    attempt_dir: Path,
    history_root: Path,
    *,
    host_loader: Path | None = None,
    host_loader_guest_path: str = _DEFAULT_HOST_INTERPRETER_PATH,
) -> list[str]:
    """Return the host mounts used by one runtime attempt.

    The current attempt is writable; all attempts in the same session are
    available separately as read-only history. Keeping the mounts distinct
    prevents guest processes from overwriting previous evidence.
    """
    mounts = [
        "--mount", f"type=bind,src={bundle_dir},dst=/fmst-host,readonly",
        "--mount", f"type=bind,src={attempt_dir},dst=/fmst-output",
        "--mount", f"type=bind,src={history_root},dst=/fmst-history,readonly",
    ]
    if host_loader is not None:
        # The host harness is normally started through /fmst-host/ld.so because
        # the firmware image owns /.  A guest execve re-enters the harness via
        # its ELF PT_INTERP path, so expose the same loader at that exact path
        # without replacing the firmware's MIPS/ARM loader.
        mounts.extend([
            "--mount",
            f"type=bind,src={host_loader},dst={host_loader_guest_path},readonly",
        ])
    return mounts


def _host_loader_guest_path(bundle_dir: Path) -> str:
    """Read the host harness PT_INTERP path recorded in its runtime bundle."""
    metadata = bundle_dir / _HOST_INTERPRETER_METADATA
    if not metadata.is_file():
        # Bundles made before the metadata was introduced were ARM64-only and
        # retain the historical destination.  New bundles always carry the
        # exact path, including for an amd64 builder.
        return _DEFAULT_HOST_INTERPRETER_PATH
    value = metadata.read_text(encoding="utf-8").strip()
    if not value.startswith("/") or "\x00" in value or "\n" in value:
        raise RuntimeError(
            f"invalid host interpreter path in runtime bundle: {metadata}"
        )
    return value


def _docker(*args: str, capture_output: bool = True) -> subprocess.CompletedProcess:
    return _checked(
        ["docker", *args],
        capture_output=capture_output,
    )


def _safe_name(value: str) -> str:
    return re.sub(r"[^a-z0-9_.-]+", "-", value.lower()).strip("-.")


def _remove_disposable_tree(root: Path, budget: ExecutionBudget | None) -> None:
    """Delete a Controller-owned tree cooperatively, without following links.

    Called only after stopping its writers. Each traversal/deletion checks the
    cleanup deadline so an unfinished tree can be recorded and preserved.
    """
    if budget is None:
        shutil.rmtree(root)
        return
    budget.check(cleanup=True)
    if root.is_symlink():
        os.unlink(root)
        return
    with os.scandir(root) as entries:
        for entry in entries:
            budget.check(cleanup=True)
            if entry.is_dir(follow_symlinks=False):
                _remove_disposable_tree(Path(entry.path), budget)
            else:
                os.unlink(entry.path)
    budget.check(cleanup=True)
    os.rmdir(root)


def _restore_executable_mode(rootfs: Path, executable_path: str) -> None:
    """Restore the selected ELF's executable bit in the staged rootfs copy."""
    candidate = (rootfs / executable_path.lstrip("/")).resolve(strict=True)
    candidate.relative_to(rootfs.resolve())
    if not candidate.is_file():
        raise RuntimeError(
            f"selected firmware executable is not an ELF file: {executable_path}"
        )
    with candidate.open("rb") as stream:
        magic = stream.read(4)
    if magic != b"\x7fELF":
        raise RuntimeError(
            f"selected firmware executable is not an ELF file: {executable_path}"
        )
    candidate.chmod(candidate.stat().st_mode | 0o111)


def _staged_guest_owner(member: tarfile.TarInfo) -> tarfile.TarInfo:
    """Import the portable directory baseline as root-owned guest files.

    copytree and host Environment scripts create files as the local developer;
    those UID/GID values are not firmware metadata. The current directory
    handoff has no guest ownership manifest. Its baseline is root:root, with
    content, mode and symlink targets retained. Non-root guest ownership needs
    an explicit metadata contract, not inference from the extraction host.
    """
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    return member


def _materialize_docker_reserved_paths(rootfs: Path) -> list[str]:
    """Materialize aliases Docker replaces with its own container mounts.

    Docker creates ``/etc/hosts`` and related files for every container.  On
    firmware roots where ``/etc`` is a symlink, that setup replaces the alias
    with a directory before the target starts.  Materialize the already
    prepared target tree into a real ``/etc`` directory so the guest sees the
    same files the staged rootfs contained at launch time.  This is a
    Controller adaptation, never an Intervention semantic claim.
    """
    etc = rootfs / "etc"
    if not etc.is_symlink():
        return []
    link_target = etc.readlink()
    target = (
        rootfs / link_target.as_posix().lstrip("/")
        if link_target.is_absolute()
        else etc.parent / link_target
    ).resolve()
    target.relative_to(rootfs.resolve())
    temporary = rootfs / ".fmst-etc-materialized"
    if temporary.exists() or temporary.is_symlink():
        shutil.rmtree(temporary)
    shutil.copytree(target, temporary, symlinks=True)
    etc.unlink()
    temporary.replace(etc)
    return ["materialized /etc symlink for Docker-managed /etc mounts"]


class DockerRootfsSandbox:
    """Import a firmware rootfs as a temporary image and run IIB inside it."""

    def __init__(
        self,
        *,
        rootfs: Path,
        workdir: Path,
        target_binary: str,
        executable_path: str,
        guest_arch: str,
        runtime_workspace: Path,
        env_script: Path | None,
        runtime_builder: RuntimeBuilder | None = None,
        budget: ExecutionBudget | None = None,
        runtime_debugger_image: str | None = None,
        network: RuntimeNetwork | None = None,
        expose_service: bool = False,
    ) -> None:
        self.rootfs = Path(rootfs).resolve()
        self.workdir = Path(workdir).resolve()
        self.target_binary = target_binary
        self.executable_path = executable_path
        self.guest_arch = guest_arch
        self.runtime_workspace = Path(runtime_workspace).resolve()
        self.env_script = Path(env_script).resolve() if env_script else None
        # Tests and low-level rootfs preparation do not need a toolchain. A
        # host builder remains the compatibility default; RehostingRunner
        # supplies the platform-aware builder for full runs.
        self.runtime_builder = runtime_builder or HostRuntimeBuilder()
        self.budget = budget
        self.network = RuntimeNetwork.model_validate((network or RuntimeNetwork()).model_dump())
        self.expose_service = expose_service
        self.runtime_debugger_image = runtime_debugger_image or os.environ.get("FMST_RUNTIME_DEBUGGER_IMAGE")
        self.cleanup_records: list[dict[str, object]] = []
        self.session_id = uuid.uuid4().hex[:12]
        slug = _safe_name(target_binary) or "target"
        self.target_slug = slug
        self.image_tag = f"fmst-runner:{slug}-{self.session_id}"
        self.network_name = f"fmst-runner-{slug}-{self.session_id}"
        self.session_root = self.workdir / "runner_sessions" / slug / self.session_id
        self.preparation_root = self.session_root / "preparation"
        self.bundle_dir = self.session_root / "host_runtime"
        self.harness_path: Path | None = None
        self.output_root = self.session_root / "attempts"
        self._env_script_snapshot: Path | None = None
        self.environment_script_applications = 0
        self.environment_script_failure: str | None = None
        self.staging_adaptations: list[str] = []
        self._active_rootfs: Path | None = None
        self._image_created = False
        self._network_created = False
        self._prepared = False

    def _check_budget(self) -> None:
        if getattr(self, "budget", None) is not None:
            self.budget.check()

    def _process(self, command: list[str], *, timeout: float = 30, cleanup: bool = False, **kwargs):
        if getattr(self, "budget", None) is not None:
            return run_process(command, budget=self.budget, timeout=timeout, cleanup=cleanup, **kwargs)
        return subprocess.run(command, timeout=timeout, **kwargs)

    def _docker(self, *args: str) -> subprocess.CompletedProcess:
        if self.budget is None:
            return _docker(*args)
        return self._process(["docker", *args], check=True, capture_output=True, text=True)

    def _collect_container_cores(self, container_name: str, attempt_dir: Path) -> None:
        """Collect changed core files from the disposable container before removal.

        Docker diff inventories the container layer, including guest chdir paths,
        and excludes bind mounts. Docker cp works while guest writers are frozen.
        Unchanged rootfs files remain historical input, not attempt evidence.
        """
        receipt = {"source": "docker diff + docker cp", "candidates": [], "errors": []}
        try:
            result = self._process(["docker", "diff", container_name],
                capture_output=True, text=True, timeout=10, cleanup=True)
            if result.returncode:
                raise RuntimeError(result.stderr or result.stdout)
            for line in result.stdout.splitlines():
                operation, _, guest_path = line.partition(" ")
                if operation not in {"A", "C"} or not guest_path.endswith(".core"):
                    continue
                destination = attempt_dir / "collected-cores" / f"{len(receipt['candidates']):04d}.core"
                destination.parent.mkdir(exist_ok=True)
                item = {"guest_path": guest_path, "path": destination.relative_to(attempt_dir).as_posix()}
                receipt["candidates"].append(item)
                copied = self._process(["docker", "cp", f"{container_name}:{guest_path}", str(destination)],
                    capture_output=True, text=True, timeout=10, cleanup=True)
                if copied.returncode or not destination.is_file():
                    receipt["errors"].append(f"Core copy failed for {guest_path}: {copied.stderr or copied.stdout}")
        except Exception as error:
            receipt["errors"].append(f"{type(error).__name__}: {error}")
        finally:
            (attempt_dir / "core-collection.json").write_text(json.dumps(receipt, indent=2) + "\n")

    def _copy_file(self, source, destination):
        self._check_budget()
        with open(source, "rb") as reader, open(destination, "wb") as writer:
            while data := reader.read(1024 * 1024):
                self._check_budget()
                writer.write(data)
        shutil.copystat(source, destination)
        return destination

    def configure_network(self, network: RuntimeNetwork) -> None:
        """Apply an attempt's network between executions, never to a live target."""
        self._check_budget()
        network = RuntimeNetwork.model_validate(network.model_dump())
        if network != self.network:
            if self._network_created:
                containers = self._docker("ps", "-aq", "--filter", f"label=fmst.runner.session={self.session_id}").stdout.strip()
                if containers:
                    raise RuntimeError("cannot change network while a session container still exists")
                if ((network.subnet, network.gateway, network.target_address)
                        != (self.network.subnet, self.network.gateway, self.network.target_address)):
                    self._docker("network", "rm", self.network_name)
                    self._network_created = False
                    self.cleanup_records.append({"network": self.network_name, "removed": True, "reason": "attempt network changed"})
            self.network = network
        if self._prepared:
            self._ensure_network()

    def _ensure_network(self) -> None:
        if self._network_created:
            return
        self._docker("network", "create", *([] if self.expose_service else ["--internal"]),
            "--label", "fmst.runner.managed=true",
            "--label", f"fmst.runner.session={self.session_id}",
            "--label", f"fmst.runner.target={self.target_slug}",
            *(["--subnet", self.network.subnet, "--gateway", self.network.gateway] if self.network.subnet else []),
            self.network_name)
        self._network_created = True

    def prepare(
        self,
        rootfs_actions: list[RootfsAction] | None = None,
        companion_processes: list[CompanionProcess] | None = None,
    ) -> None:
        self._check_budget()
        self._docker("version")
        # Preparation can fail before Docker owns a network/image (for
        # example a malformed Environment script). Keep the same session and
        # allow the Controller to feed the exact failure back to RunnerAgent
        # before retrying; never create a second session behind its back.
        self.session_root.mkdir(parents=True, exist_ok=True)
        self.preparation_root.mkdir(exist_ok=True)
        self._snapshot_environment_script()
        harness = self._ensure_harness()
        self.harness_path = harness
        self._build_host_bundle(harness)
        self.update_rootfs_actions(
            rootfs_actions or [], companion_processes or [],
        )
        self._ensure_network()
        self._prepared = True

    def prepare_frozen(self, runtime: Path, *, rootfs_sha256: str, runtime_sha256: str) -> None:
        """Import already-staged immutable inputs, without rebuilding/reapplying edits.

        Used only after a successful configuration is validated. A fresh session
        owns its own copied trees, image and network; it never mounts evidence
        writable or resumes a previous container's overlay.
        """
        self._check_budget()
        if self._prepared or self._image_created or self.env_script is not None:
            raise RuntimeError("frozen preparation requires a new script-free sandbox")
        self._docker("version")
        self.preparation_root.mkdir(parents=True, exist_ok=True)
        staged = self.session_root / "rootfs"
        shutil.copytree(self.rootfs, staged, symlinks=True, copy_function=self._copy_file)
        shutil.copytree(runtime, self.bundle_dir, symlinks=True, copy_function=self._copy_file)
        if tree_sha256(staged, self.budget) != rootfs_sha256 or tree_sha256(self.bundle_dir, self.budget) != runtime_sha256:
            raise ValueError("fresh replay copy changed frozen input identity")
        self._active_rootfs = staged
        self._import_rootfs(staged)
        self._image_created = True
        self._ensure_network()
        self._prepared = True

    def _snapshot_environment_script(self) -> None:
        """Snapshot the generated preparation script for this session.

        The script is a host-side pre-import artifact.  Keeping an immutable
        session copy makes repeated attempts deterministic without mounting the
        script into the firmware runtime container.
        """
        if self.env_script is None:
            return
        if not self.env_script.is_file():
            self.environment_script_failure = (
                "EnvironmentGeneration completed but setup_rootfs.py is missing: "
                f"{self.env_script}"
            )
            raise RuntimeError(
                self.environment_script_failure
            )
        snapshot = self.preparation_root / "setup_rootfs.py"
        shutil.copy2(self.env_script, snapshot)
        self._env_script_snapshot = snapshot

    def refresh_environment_script(self) -> None:
        """Refresh the disposable script after an authorized workspace edit."""
        if self.env_script is None:
            self._env_script_snapshot = None
            self.environment_script_failure = None
            return
        if not self.env_script.is_file():
            self.environment_script_failure = (
                "Environment script disappeared from the disposable workspace: "
                f"{self.env_script}"
            )
            raise RuntimeError(self.environment_script_failure)
        snapshot = self.preparation_root / "setup_rootfs.py"
        shutil.copy2(self.env_script, snapshot)
        self._env_script_snapshot = snapshot
        self.environment_script_failure = None

    def update_rootfs_actions(
        self,
        actions: list[RootfsAction],
        companion_processes: list[CompanionProcess] | None = None,
    ) -> None:
        companion_processes = companion_processes or []
        # Every attempt starts from the immutable original rootfs.  Reapply
        # the static Environment script and the cumulative Runner actions even
        # when their payload is unchanged; this keeps attempts independent and
        # prevents mutations from a previous imported image becoming hidden
        # state for the next attempt.
        staged = self.session_root / "rootfs"
        if staged.exists():
            shutil.rmtree(staged)
        staged.mkdir(parents=True)
        # Use Python's copy implementation so the controller remains
        # portable on macOS.  GNU cp's --reflink option is unavailable in
        # the BSD userland, while symlink preservation is required for a
        # firmware rootfs.
        self._check_budget()
        shutil.copytree(self.rootfs, staged, dirs_exist_ok=True, symlinks=True,
                        copy_function=self._copy_file)
        if self._env_script_snapshot is not None:
            try:
                self._process([
                    sys.executable,
                    str(self._env_script_snapshot),
                    str(staged),
                ], check=True, text=True, timeout=120)
            except BaseException as error:
                self.environment_script_failure = str(error).strip() or repr(error)
                raise
            self.environment_script_applications += 1
            self.environment_script_failure = None
        apply_rootfs_actions(actions, staged)
        self.staging_adaptations = _materialize_docker_reserved_paths(staged)
        # Some extracted datasets do not retain mode bits. The selected target
        # is an authoritative ELF identity and QEMU's loader requires execute
        # permission, so restore it only in this disposable rootfs copy.
        _restore_executable_mode(staged, self.executable_path)
        for process in companion_processes:
            _restore_executable_mode(staged, process.executable_path)
        self._active_rootfs = staged
        if self._image_created:
            self._docker("image", "rm", "--force", self.image_tag)
            self._image_created = False
        self._import_rootfs(staged)
        self._image_created = True

    def _ensure_harness(self) -> Path:
        libafl_manifest = (
            self.runtime_workspace.parent / "lib" / "LibAFL" / "Cargo.toml"
        )
        if not libafl_manifest.is_file():
            raise RuntimeError(
                f"LibAFL checkout is missing: {libafl_manifest}"
            )
        libafl = tomllib.loads(libafl_manifest.read_text(encoding="utf-8"))
        actual_version = libafl.get("workspace", {}).get("package", {}).get(
            "version"
        )
        if actual_version != _EXPECTED_LIBAFL_VERSION:
            raise RuntimeError(
                "Runner requires the official LibAFL "
                f"{_EXPECTED_LIBAFL_VERSION} checkout; found "
                f"{actual_version!r} at {libafl_manifest}"
            )
        return self.runtime_builder.build_harness(
            self.runtime_workspace,
            self.guest_arch,
        )

    def _build_host_bundle(self, harness: Path) -> None:
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        self.runtime_builder.build_host_bundle(
            harness,
            self.bundle_dir,
            # GuestWeave's builder intentionally has no application-specific
            # helper set.  Firmenstein declares the helpers used by its
            # supervisor and probe. Paths belong to the Linux build host;
            # the selected framework supplies the bundle implementation.
            binaries={
                "sh": Path("/bin/sh"), "sleep": Path("/bin/sleep"),
                "cp": Path("/bin/cp"), "nc": Path("/usr/bin/nc"),
            },
        )

    def _import_rootfs(self, rootfs: Path) -> None:
        # Docker can materialize a directory symlink as a stale directory when
        # its target appears later in the tar stream. Emit concrete entries
        # before symlinks so firmware aliases such as /etc -> var/etc survive
        # Environment writes after Docker import.
        tar_path = self.preparation_root / f"rootfs-{uuid.uuid4().hex}.tar"
        entries = sorted(
            rootfs.rglob("*"),
            key=lambda path: (path.is_symlink(), path.relative_to(rootfs).as_posix()),
        )
        with tarfile.open(tar_path, mode="w") as archive:
            for path in entries:
                self._check_budget()
                archive.add(
                    path,
                    arcname=path.relative_to(rootfs).as_posix(),
                    recursive=False,
                    filter=_staged_guest_owner,
                )
        stream = tar_path.open("rb")
        imported = self._process(
            [
                "docker", "import",
                *(["--platform", self.runtime_builder.platform_name]
                  if self.runtime_builder.platform_name else []),
                "--change", "LABEL fmst.runner.managed=true",
                "--change", f"LABEL fmst.runner.session={self.session_id}",
                "--change", f"LABEL fmst.runner.target={self.target_slug}",
                "-", self.image_tag,
            ],
            stdin=stream,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
        stream.close()
        tar_path.unlink(missing_ok=True)
        if imported.returncode != 0:
            raise RuntimeError(
                f"docker import failed ({imported.returncode}): {imported.stderr}"
            )
        ownership = "imported staged directory with guest uid/gid 0:0; source guest ownership unavailable"
        if ownership not in self.staging_adaptations:
            self.staging_adaptations.append(ownership)

    def run_attempt(
        self, *, attempt_number: int, intervention_so: Path | None,
        executable_path: str, guest_args: list[str], guest_working_directory: str,
        guest_environment: dict[str, str], companion_processes: list[CompanionProcess],
        probe: InteractionProbe, timeout_seconds: float,
        scenario: InteractionScenario | None = None, watchdog_stall_seconds: float = 60.0,
    ) -> SandboxAttempt:
        """Validate one disposable instance, retaining evidence before cleanup."""
        return self._run_instance(attempt_number=attempt_number, intervention_so=intervention_so,
            executable_path=executable_path, guest_args=guest_args, guest_working_directory=guest_working_directory,
            guest_environment=guest_environment, companion_processes=companion_processes, probe=probe,
            timeout_seconds=timeout_seconds, scenario=scenario, watchdog_stall_seconds=watchdog_stall_seconds)

    def start_service(
        self, *, intervention_so: Path | None, executable_path: str, guest_args: list[str],
        guest_working_directory: str, guest_environment: dict[str, str],
        companion_processes: list[CompanionProcess], port: int, host_port: int,
        timeout_seconds: float, watchdog_stall_seconds: float = 60.0,
        attempt_number: int = 1,
    ) -> ServiceStartup:
        """Start a fresh user instance; observe readiness without active probes.

        The caller owns interaction and must close this instance on stop.
        Readiness proves only observed
        process/listener availability, never protocol or session semantics.
        """
        return self._run_instance(attempt_number=attempt_number, intervention_so=intervention_so,
            executable_path=executable_path, guest_args=guest_args, guest_working_directory=guest_working_directory,
            guest_environment=guest_environment, companion_processes=companion_processes, probe=None,
            timeout_seconds=timeout_seconds, watchdog_stall_seconds=watchdog_stall_seconds,
            service_port=port, host_port=host_port)

    def stop_service(self, container_name: str, attempt_number: int) -> None:
        """Collect an owned live instance's final output and remove only it."""
        if container_name != f"{self.network_name}-a{attempt_number}":
            raise ValueError("service does not belong to this sandbox instance")
        output = self.output_root / f"attempt-{attempt_number:02d}"
        try:
            with (output / "container.log").open("wb") as log:
                self._process(["docker", "logs", container_name], stdout=log,
                    stderr=subprocess.STDOUT, timeout=5, cleanup=True)
        finally:
            removed = self._process(["docker", "rm", "--force", container_name],
                capture_output=True, text=True, timeout=5, cleanup=True)
            self.cleanup_records.append({"operation": "stop_interaction_service",
                "container": container_name, "remove_returncode": removed.returncode,
                "remove_stderr": removed.stderr})
            handoff = getattr(self.runtime_builder, "handoff_output", None)
            if removed.returncode == 0 and handoff is not None:
                handoff(output, cleanup=True)
            if removed.returncode:
                raise RuntimeError(f"service cleanup failed: {removed.stderr}")

    def _run_instance(
        self,
        *,
        attempt_number: int,
        intervention_so: Path | None,
        executable_path: str,
        guest_args: list[str],
        guest_working_directory: str,
        guest_environment: dict[str, str],
        companion_processes: list[CompanionProcess],
        probe: InteractionProbe | None,
        timeout_seconds: float,
        scenario: InteractionScenario | None = None,
        watchdog_stall_seconds: float = 60.0,
        service_port: int | None = None,
        host_port: int | None = None,
    ) -> SandboxAttempt | ServiceStartup:
        self._check_budget()
        service_mode = service_port is not None
        if service_mode:
            if (not self.expose_service or scenario is not None or probe is not None
                    or type(service_port) is not int or not 1 <= service_port <= 65535
                    or type(host_port) is not int or not 1 <= host_port <= 65535):
                raise ValueError('Service startup requires explicit TCP ports and no active scenario/probe')
        elif host_port is not None or probe is None:
            raise ValueError('Scenario attempts require a probe and cannot publish a user service')
        if not self._prepared:
            raise RuntimeError("sandbox is not prepared")
        assert self._active_rootfs is not None
        guest_cwd = (
            self._active_rootfs / guest_working_directory.lstrip("/")
        ).resolve()
        guest_cwd.relative_to(self._active_rootfs.resolve())
        if not guest_cwd.is_dir():
            raise RuntimeError(
                "selected guest working directory does not exist: "
                f"{guest_working_directory}"
            )
        for process in companion_processes:
            process_cwd = (
                self._active_rootfs / process.working_directory.lstrip("/")
            ).resolve()
            process_cwd.relative_to(self._active_rootfs.resolve())
            if not process_cwd.is_dir():
                raise RuntimeError(
                    "companion working directory does not exist: "
                    f"{process.working_directory}"
                )
        attempt_dir = self.output_root / f"attempt-{attempt_number:02d}"
        attempt_dir.mkdir(parents=True, exist_ok=False)
        # Docker may use user-namespace remapping, so container uid 0 is not
        # the host owner. This directory contains only disposable trace/log
        # output and is removed with the session.
        attempt_dir.chmod(0o777)
        if intervention_so is not None and intervention_so.resolve() != (self.bundle_dir / "intervention.so").resolve():
            shutil.copy2(intervention_so, self.bundle_dir / "intervention.so")
        trace_path = attempt_dir / "runtime_trace.json"
        log_path = attempt_dir / "container.log"
        container_name = f"{self.network_name}-a{attempt_number}"
        harness_name = {
            "arm": "fmst-harness-arm",
            "x86_64": "fmst-harness-x86",
            "mipsel": "fmst-harness-mips",
            "mipsbe": "fmst-harness-mips",
        }[self.guest_arch]
        target_arguments = _harness_arguments(
            harness_name=harness_name,
            intervention_so=(
                "/fmst-host/intervention.so"
                if intervention_so is not None
                else None
            ),
            executable_path=executable_path,
            trace_output="/fmst-output/runtime_trace.json",
            guest_args=guest_args,
        )
        gated = any(process.readiness is not None for process in companion_processes)
        control_dir = self.session_root / "control" / f"attempt-{attempt_number:02d}"
        control_dir.mkdir(parents=True, exist_ok=False)
        # Launch control belongs to this instance, not the immutable runtime
        # bundle. Fresh browser instances must not change the candidate hash.
        supervisor = control_dir / "launch.sh"
        if companion_processes:
            supervisor.write_text(
                _render_companion_supervisor(
                    harness_name=harness_name,
                    companion_processes=companion_processes,
                    target_arguments=target_arguments,
                ),
                encoding="utf-8",
            )
        else:
            process_command = _render_target_lifecycle(target_arguments)
            supervisor.write_text("\n".join(process_command) + "\n", encoding="utf-8")
        shutil.copy2(supervisor, attempt_dir / "launch.sh")
        process_command = [
            "/fmst-host/ld.so", "--library-path", "/fmst-host/lib",
            "/fmst-host/sh", "/fmst-control/launch.sh",
        ]
        command = [
            "docker", "run", "--detach", "--name", container_name,
            *(["--platform", self.runtime_builder.platform_name]
              if self.runtime_builder.platform_name else []),
            "--label", "fmst.runner.managed=true",
            "--label", f"fmst.runner.session={self.session_id}",
            "--label", f"fmst.runner.target={self.target_slug}",
            "--network", self.network_name,
            *(["--publish", f"127.0.0.1:{host_port}:{service_port}"] if service_mode else []),
            *(["--ip", self.network.target_address] if self.network.target_address else []),
            "--cap-drop", "ALL",
            # Firmware web services commonly bind 80/443. Keep the single
            # network capability required for that guest-visible contract.
            # SETGID/SETUID let a root-started service perform its normal
            # one-way privilege drop after binding; without them QEMU forwards
            # setgroups/setuid to a host kernel that rejects the transition.
            "--cap-add", "NET_BIND_SERVICE",
            "--cap-add", "SETGID",
            "--cap-add", "SETUID",
            "--security-opt", "no-new-privileges",
            # The embedded guest harness emits its ELF core through the
            # container's inherited core limit. Keep this bounded and
            # explicit so a missing core is recorded as unavailable evidence.
            "--ulimit", "core=67108864:67108864",
            "--pids-limit", "256",
            "--memory", "1g",
            "--memory-swap", "1g",
            "--cpus", "2",
            "--mount", f"type=bind,src={control_dir},dst=/fmst-control,readonly",
            *_container_runtime_mounts(
                self.bundle_dir,
                attempt_dir,
                self.output_root,
                host_loader=self.bundle_dir / "ld.so",
                host_loader_guest_path=_host_loader_guest_path(self.bundle_dir),
            ),
            "--workdir", guest_working_directory,
            "--env", "RUST_LOG=info",
            # Host programs use ld.so --library-path explicitly. Exporting
            # that path also directs the guest loader to host-architecture
            # libraries (for example MIPS libgcc lookup on an ARM64 host).
            *[
                item
                for name, value in sorted(guest_environment.items())
                for item in ("--env", f"{name}={value}")
            ],
            self.image_tag,
            *process_command,
        ]
        deadline = time.monotonic() + timeout_seconds
        execution_receipt = AttemptExecutionReceipt(
            network=self.network.model_copy(deep=True),
            session_id=self.session_id, attempt_number=attempt_number,
            container_name=container_name, artifact_root=str(attempt_dir), started_unix_ns=time.time_ns(),
            executable_path=executable_path, guest_args=guest_args, guest_working_directory=guest_working_directory,
            guest_environment=guest_environment, companion_processes=companion_processes, scenario=scenario,
        )
        # Controller receipts are outside the writable guest output mount.
        execution_receipt_path = self.session_root / "attempt_receipts" / f"attempt-{attempt_number:02d}.json"
        request_root = execution_receipt_path.parent / f"attempt-{attempt_number:02d}-requests"
        write_model_json(execution_receipt_path, execution_receipt)
        timed_out = False
        exit_code: int | None = None
        target_exit_code: int | None = None
        scenario_result: ScenarioResult | None = None
        watchdog = TargetProgressWatchdog(
            container_name=container_name,
            attempt_dir=attempt_dir,
            stall_seconds=watchdog_stall_seconds,
            peer_count=len(companion_processes),
            budget=self.budget,
        )
        output_handed_off = False
        container_started = False
        scenario_responses: list[ProbeResult] = []
        probe_source_ports: set[int] = set()
        service_ready = False
        try:
            started = self._process(
                command, capture_output=True, text=True, timeout=min(30.0, timeout_seconds),
            )
            if started.returncode != 0:
                raise RuntimeError(f"docker run failed ({started.returncode}): {started.stderr}")
            container_started = True
            execution_receipt.state = "running"
            write_model_json(execution_receipt_path, execution_receipt)
            watchdog.start()
            if gated:
                def observe_endpoint(path: str) -> list[str]:
                    observed = self._process([
                        "docker", "exec", container_name,
                        "/fmst-host/ld.so", "--library-path", "/fmst-host/lib", "/fmst-host/sh", "-c",
                        'test -S "$1" || exit 3; while IFS= read -r line; do printf "%s\\n" "$line"; done < /proc/net/unix',
                        "readiness", path,
                    ], capture_output=True, text=True, timeout=min(2.0, max(0.01, deadline - time.monotonic())))
                    if observed.returncode == 3:
                        return []
                    if observed.returncode:
                        raise RuntimeError(f"peer_readiness_observation_failed: {observed.stderr}")
                    return unix_listeners(observed.stdout, path)
                wait_for_peers(companions=companion_processes, observer=watchdog,
                    observe_endpoint=observe_endpoint, deadline=deadline,
                    evidence_path=attempt_dir / "peer-readiness.json", check_budget=self._check_budget)
                self._check_budget()
                (control_dir / "target-ready").write_text(str(time.time_ns()) + "\n", encoding="ascii")
            if service_mode:
                def observe_listeners():
                    observed = self._process([
                        'docker', 'exec', container_name, '/fmst-host/ld.so', '--library-path', '/fmst-host/lib',
                        '/fmst-host/sh', '-c',
                        'while IFS= read -r line; do printf "%s\\n" "$line"; done < /proc/net/tcp; '
                        'printf "__FMST_TCP6__\\n"; '
                        'if [ -r /proc/net/tcp6 ]; then while IFS= read -r line; do printf "%s\\n" "$line"; done < /proc/net/tcp6; fi',
                    ], capture_output=True, text=True, timeout=min(2.0, max(0.01, deadline - time.monotonic())))
                    if observed.returncode:
                        raise RuntimeError(f'Service listener observation failed: {observed.stderr}')
                    ipv4, separator, ipv6 = observed.stdout.partition('__FMST_TCP6__\n')
                    if not separator:
                        raise RuntimeError('Incomplete service listener observation')
                    listeners = tcp_listeners(ipv4, service_port)
                    if ipv6.strip():
                        listeners.extend(tcp_listeners(ipv6, service_port, ipv6=True))
                    return listeners

                readiness_path = attempt_dir / 'service-readiness.json'
                readiness = wait_for_service(observer=watchdog, observe_listeners=observe_listeners,
                    deadline=deadline, evidence_path=readiness_path, check_budget=self._check_budget)
                service_ready = True
                execution_receipt.state = 'completed'
                return ServiceStartup(container_name=container_name, readiness_path=readiness_path, readiness=readiness)
            if scenario is None:
                save_request_bytes(request_root, 1, probe.request_text)
                watchdog.begin_step(1)
                scenario_responses.append(self._run_tcp_probe_in_container(
                    container_name, probe, deadline=deadline, observer=watchdog,
                    step_index=1, connection_record_path=request_root / "probe-connections.jsonl",
                    used_source_ports=probe_source_ports,
                ))
            else:
                cookies: dict[str, str] = {}
                response_values: dict[str, str] = {}
                for step_index, step in enumerate(scenario.steps, start=1):
                    watchdog.begin_step(step_index)
                    request = step.request_text
                    for name, value in cookies.items():
                        request = request.replace("{{cookie:" + name + "}}", value)
                    try:
                        request = substitute_response_values(request, response_values)
                    except ValueError as error:
                        scenario_responses.append(ProbeResult(connected=False, interacted=False,
                            attempts=0, error=str(error)))
                        break
                    step_probe = InteractionProbe(
                        port=scenario.port,
                        request_text=request,
                        response_contains=step.response_contains,
                    )
                    save_request_bytes(request_root, step_index, request)
                    response = self._run_tcp_probe_in_container(
                        container_name, step_probe, deadline=deadline, observer=watchdog,
                        step_index=step_index, connection_record_path=request_root / "probe-connections.jsonl",
                        used_source_ports=probe_source_ports,
                    )
                    scenario_responses.append(response)
                    try:
                        response_values.update(capture_response_values(step, response))
                    except ValueError:
                        # Evaluation records the same deterministic capture error.
                        # Do not send later requests with stale or absent values.
                        break
                    if step.save_cookies and response.http_response and not response.http_response.error:
                        cookies.update(response_cookie_values(response.http_response.headers_text))
                    if not response.connected or not response.response_text:
                        break
            probe_result = scenario_responses[-1]
            watchdog.stop(
                "probe_satisfied" if probe_result.interacted else "probe_finished"
            )
            watchdog.join()
            watchdog.sample_after_probe()
            if watchdog.triggered and not probe_result.interacted:
                probe_result = probe_result.model_copy(update={
                    "error": (
                        f"Controller stopped waiting: {watchdog.termination_reason}; "
                        f"process evidence: {watchdog.process_path}; "
                        f"observation error: {watchdog.observation_error}"
                    ),
                })
                scenario_responses[-1] = probe_result
            handoff = getattr(self.runtime_builder, "handoff_output", None)
            if handoff is not None:
                # Probes and final lifecycle observation are finished. Freeze
                # all guest writers before handing framework-owned evidence
                # to the host; guest rootfs metadata is never altered.
                self._process(["docker", "pause", container_name], check=True,
                    capture_output=True, text=True, timeout=5)
                self._collect_container_cores(container_name, attempt_dir)
                handoff(attempt_dir)
                output_handed_off = True
            else:
                self._collect_container_cores(container_name, attempt_dir)
            dump_manifest_path = collect_runtime_dump(
                attempt_dir=attempt_dir,
                staged_rootfs=self._active_rootfs,
                executable_path=executable_path,
                session_id=self.session_id,
                attempt_number=attempt_number,
                termination_reason=watchdog.termination_reason if watchdog.triggered else (
                    "probe_satisfied" if probe_result.interacted else "unknown"
                ),
                budget=self.budget,
                debugger_image=self.runtime_debugger_image,
            )
            dump_payload = json.loads(dump_manifest_path.read_text(encoding="utf-8"))
            inspect = self._process(
                ["docker", "inspect", "--format", "{{.State.Running}} {{.State.ExitCode}}", container_name],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            if inspect.returncode == 0:
                state = inspect.stdout.strip().split()
                if state and state[0] == "false" and len(state) > 1:
                    exit_code = int(state[1])
            target_exit_path = attempt_dir / "target-exit.json"
            if target_exit_path.is_file():
                try:
                    target_exit_code = int(
                        json.loads(target_exit_path.read_text(encoding="utf-8"))["exit_code"]
                    )
                except (OSError, ValueError, KeyError, json.JSONDecodeError):
                    target_exit_code = None
            observations = []
            if scenario is not None:
                if self._active_rootfs is not None and self._active_rootfs.is_dir():
                    observations.append(
                        ScenarioObservation(
                            source="container",
                            kind="staged_rootfs",
                            fact="staged_rootfs_ready=true",
                            evidence_path=str(self._active_rootfs),
                        )
                    )
                observations.extend(
                    ScenarioObservation(
                        source="probe",
                        kind="probe_step",
                        fact=(
                            f"step={index} connected={response.connected} "
                            f"response_nonempty={bool(response.response_text)} "
                            f"status_code={response.status_code}"
                        ),
                        evidence_path=str(execution_receipt_path),
                    )
                    for index, response in enumerate(scenario_responses, start=1)
                )
                if len(scenario_responses) == len(scenario.steps) and all(
                    response.interacted for response in scenario_responses
                ):
                    observations.append(
                        ScenarioObservation(
                            source="probe",
                            kind="ordered_response_sequence",
                            fact=f"steps_interacted={len(scenario_responses)}",
                            evidence_path=str(execution_receipt_path),
                        )
                    )
                if watchdog.target_alive_after_probe and all(
                    response.interacted for response in scenario_responses
                ):
                    observations.append(
                        ScenarioObservation(
                            source="lifecycle",
                            kind="target_process_alive",
                            fact="target_process_observed_alive=true",
                            evidence_path=str(watchdog.final_process_path),
                        )
                    )
                observations.append(
                    ScenarioObservation(
                        source="lifecycle",
                        kind="target_lifecycle",
                        fact=(
                            "target_exit_code="
                            + (
                                str(target_exit_code)
                                if target_exit_code is not None
                                else "not_observed"
                            )
                        ),
                        evidence_path=(
                            str(target_exit_path) if target_exit_path.is_file() else None
                        ),
                    )
                )
                observations.append(
                    ScenarioObservation(
                        source="container",
                        kind="probe_step",
                        fact=(
                            "container_exit_code="
                            + (
                                str(exit_code)
                                if exit_code is not None
                                else "running_at_collection"
                            )
                        ),
                        evidence_path=str(log_path),
                    )
                )
                observations.append(
                    ScenarioObservation(
                        source="trace",
                        kind="trace_presence",
                        fact=(
                            "raw_trace_available="
                            + str(trace_path.is_file()).lower()
                        ),
                        evidence_path=(
                            str(trace_path) if trace_path.is_file() else None
                        ),
                    )
                )
                scenario_result = evaluate_interaction_scenario(
                    scenario, scenario_responses, observations
                )
            if not probe_result.interacted and time.monotonic() >= deadline:
                timed_out = True
            execution_receipt.state = "completed"
        except BaseException as error:
            execution_receipt.state = "interrupted" if isinstance(error, (RunnerStopped, KeyboardInterrupt)) else "error"
            execution_receipt.stop_reason = error.reason if isinstance(error, RunnerStopped) else (
                "operation_timeout" if isinstance(error, subprocess.TimeoutExpired) else type(error).__name__)
            execution_receipt.error = str(error)
            raise
        finally:
            watchdog.stop("controller_cleanup")
            # The observer only wakes us. This owner captures logs before
            # removal; a failed collector must not skip resource cleanup.
            cleanup: dict[str, object] = {"container": container_name}
            try:
                watchdog.join()
            except RuntimeError as error:
                cleanup["observer_stop_error"] = str(error)
            try:
                with log_path.open("wb") as log_output:
                    logs = self._process(
                        ["docker", "logs", container_name],
                        stdout=log_output, stderr=subprocess.STDOUT, timeout=10.0, cleanup=True,
                    )
                cleanup["logs_returncode"] = logs.returncode
            except (RunnerStopped, OSError, subprocess.SubprocessError) as error:
                cleanup["logs_error"] = str(error)
            finally:
                if service_ready and execution_receipt.state == "completed":
                    cleanup["retained_for_service"] = True
                else:
                    if container_started and not (attempt_dir / "core-collection.json").is_file():
                        self._collect_container_cores(container_name, attempt_dir)
                    try:
                        removed = self._process(
                            ["docker", "rm", "--force", container_name],
                            capture_output=True, text=True, timeout=5.0, cleanup=True,
                        )
                        cleanup["remove_returncode"] = removed.returncode
                        cleanup["remove_stderr"] = removed.stderr
                    except (RunnerStopped, OSError, subprocess.SubprocessError) as error:
                        cleanup["remove_error"] = str(error)
                if container_started and not output_handed_off:
                    handoff = getattr(self.runtime_builder, "handoff_output", None)
                    if handoff is not None and cleanup.get("remove_returncode") == 0:
                        try:
                            handoff(attempt_dir, cleanup=True)
                            cleanup["output_handoff"] = "complete"
                        except (RunnerStopped, OSError, subprocess.SubprocessError) as error:
                            cleanup["output_handoff_error"] = str(error)
                if (container_started and not service_ready
                        and not (attempt_dir / "runtime-dump/manifest.json").is_file()):
                    try:
                        collect_runtime_dump(attempt_dir=attempt_dir,
                            staged_rootfs=self._active_rootfs, executable_path=executable_path,
                            session_id=self.session_id, attempt_number=attempt_number,
                            termination_reason=watchdog.termination_reason if watchdog.triggered else "unknown",
                            budget=self.budget, debugger_image=self.runtime_debugger_image)
                    except (RunnerStopped, OSError, ValueError) as error:
                        cleanup["runtime_dump_error"] = str(error)
                (attempt_dir / "cleanup.json").write_text(
                    json.dumps(cleanup, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                self.cleanup_records.append(cleanup)
                execution_receipt.finished_unix_ns = time.time_ns()
                execution_receipt.probe_results = scenario_responses
                execution_receipt.cleanup = cleanup
                write_model_json(execution_receipt_path, execution_receipt)
        assessment_path = attempt_dir / "child-failures.json"
        try:
            if self.budget is not None:
                self.budget.check(cleanup=True)
            assessment = assess_child_failures(
                attempt_dir=attempt_dir,
                probe_connections=request_root / "probe-connections.jsonl",
                scenario_result=scenario_result,
                budget=self.budget,
            )
        except (RunnerStopped, OSError, ValueError) as error:
            assessment = {
                "schema_version": 1, "status": "unknown",
                "probe_connections": str(request_root / "probe-connections.jsonl"),
                "failures": [], "collection_errors": [f"child failure assessment unavailable: {error}"],
            }
        assessment_path.write_text(json.dumps(assessment, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if watchdog.triggered:
            termination_reason = watchdog.termination_reason
        elif probe_result.interacted:
            termination_reason = "probe_satisfied"
        elif target_exit_code is not None:
            termination_reason = "target_exit"
        elif timed_out:
            termination_reason = "probe_timeout"
        elif exit_code is not None:
            termination_reason = "container_exit"
        else:
            termination_reason = "unknown"
        return SandboxAttempt(
            container_exit_code=exit_code,
            target_exit_code=target_exit_code,
            timed_out=timed_out,
            probe_result=probe_result,
            scenario_result=scenario_result,
            runtime_trace_path=trace_path,
            runtime_trace_paths=tuple(
                sorted(
                    path for path in attempt_dir.glob("runtime_trace*.json")
                    if not path.name.endswith(".heartbeat.json")
                )
            ),
            container_log_path=log_path,
            companion_log_paths=tuple(
                attempt_dir / f"companion-{index:02d}.log"
                for index in range(1, len(companion_processes) + 1)
                if (attempt_dir / f"companion-{index:02d}.log").is_file()
            ),
            rootfs_adaptations=tuple(self.staging_adaptations),
            heartbeat_paths=tuple(
                sorted(attempt_dir.glob("runtime_trace*.heartbeat.json"))
            ),
            watchdog_path=watchdog.path,
            watchdog_triggered=watchdog.triggered,
            termination_reason=termination_reason,
            runtime_dump_manifest_path=dump_manifest_path,
            runtime_dump_capture_kind=dump_payload.get("capture_kind"),
            runtime_dump_available=dump_payload.get("status") == "complete",
        )

    def _cleanup_owned_resources(self) -> None:
        """Clean only this session, including partially created resources.

        A shared target label is not ownership. Unknown sessions are never
        garbage-collected here, even if they appear stale.
        """
        filters = [
            "--filter", "label=fmst.runner.managed=true",
            "--filter", f"label=fmst.runner.session={self.session_id}",
            "--filter", f"label=fmst.runner.target={self.target_slug}",
        ]
        for listing, removal in (
            (["docker", "ps", "-aq"], ["docker", "rm", "--force"]),
            (["docker", "network", "ls", "-q"], ["docker", "network", "rm"]),
            (["docker", "image", "ls", "-q"], ["docker", "image", "rm", "--force"]),
        ):
            try:
                resources = self._process(
                    [*listing, *filters], capture_output=True, text=True,
                    timeout=5, cleanup=True,
                )
                if resources.returncode:
                    self.cleanup_records.append({"operation": listing, "error": resources.stderr})
                    continue
                for identity in sorted(set(resources.stdout.split())):
                    removed = self._process(
                        [*removal, identity], capture_output=True, text=True,
                        timeout=5, cleanup=True,
                    )
                    self.cleanup_records.append({
                        "operation": removal, "identity": identity,
                        "returncode": removed.returncode, "stderr": removed.stderr,
                    })
            except (RunnerStopped, OSError, subprocess.SubprocessError) as error:
                self.cleanup_records.append({"operation": listing, "error": str(error)})

    def _container_ip(
        self, container_name: str, *, deadline: float, observer: TargetProgressWatchdog,
    ) -> str | None:
        for _ in range(40):
            self._check_budget()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or observer.interrupted.is_set():
                return None
            try:
                result = self._process(
                    [
                        "docker", "inspect", "--format",
                        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                        container_name,
                    ],
                    capture_output=True, text=True, timeout=min(2.0, remaining),
                )
            except subprocess.TimeoutExpired:
                return None
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
            if observer.interrupted.wait(min(0.1, max(0.0, deadline - time.monotonic()))):
                return None
        return None

    def _run_tcp_probe_in_container(
        self,
        container_name: str,
        probe: InteractionProbe,
        *,
        deadline: float,
        observer: TargetProgressWatchdog,
        retry_interval: float = 0.5,
        step_index: int | None = None,
        connection_record_path: Path | None = None,
        used_source_ports: set[int] | None = None,
    ) -> ProbeResult:
        """Probe target networking from inside the target network namespace."""
        attempts = 0
        connected = False
        if used_source_ports is None:
            used_source_ports = set()
        last_result: ProbeResult | None = None
        network = self.network
        container_ip = (self._container_ip(container_name, deadline=deadline, observer=observer)
                        if network.probe_destination != "loopback" else None)
        if network.probe_destination == "interface":
            if container_ip is None or container_ip == "127.0.0.1":
                return build_probe_result(probe, connected=False, attempts=0,
                    error="interface probe requires an observed non-loopback container address")
            if network.target_address and container_ip != network.target_address:
                return build_probe_result(probe, connected=False, attempts=0,
                    error=f"observed container address {container_ip} differs from configured {network.target_address}")
            hosts = [container_ip]
        else:
            hosts = ["127.0.0.1"]
            if network.probe_destination == "auto" and container_ip is not None and container_ip != hosts[0]:
                hosts.append(container_ip)
        while time.monotonic() < deadline:
            self._check_budget()
            if observer.interrupted.is_set():
                return build_probe_result(
                    probe,
                    connected=connected,
                    attempts=attempts,
                    error=(
                        f"Controller stopped waiting: {observer.termination_reason}"
                    ),
                )
            for host in hosts:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or observer.interrupted.is_set():
                    break
                attempts += 1
                observer.probe_attempted()
                source_port = 49152 + secrets.randbelow(16384)
                while source_port in used_source_ports:
                    self._check_budget()
                    if len(used_source_ports) >= 16384:
                        raise RuntimeError("probe source port space exhausted in this attempt")
                    source_port = 49152 + secrets.randbelow(16384)
                used_source_ports.add(source_port)
                # A slow native CGI is still processing this request. Wait within
                # the existing interaction window instead of imposing a shorter
                # transport deadline and starting duplicate CGI trees.
                response_timeout = min(observer.stall_seconds, remaining)
                command = _container_probe_command(container_name, host, probe, source_port,
                    wait_seconds=max(1, int(response_timeout) + 1))
                connection_id = uuid.uuid4().hex
                def record_connection(state: str, **details: object) -> None:
                    if connection_record_path is None:
                        return
                    record = {
                        "schema_version": 1, "connection_id": connection_id,
                        "step_index": step_index, "probe_attempt": attempts,
                        "source_port": source_port, "destination_host": host,
                        "destination_port": probe.port,
                        "request_sha256": hashlib.sha256(probe.request_text.encode("utf-8")).hexdigest(),
                        "state": state, "unix_ns": time.time_ns(), **details,
                    }
                    with connection_record_path.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps(record, sort_keys=True) + "\n")
                record_connection("requested", response_timeout_seconds=response_timeout)
                try:
                    result = self._process(
                        command,
                        input=probe.request_text.encode("utf-8"),
                        capture_output=True,
                        timeout=max(0.1, response_timeout),
                    )
                    stderr = result.stderr.decode("utf-8", errors="replace").strip()
                    connected_attempt = result.returncode == 0
                    record_connection("completed", returncode=result.returncode,
                                      connected=connected_attempt,
                                      response_bytes=len(result.stdout),
                                      response_sha256=hashlib.sha256(result.stdout).hexdigest())
                    connected = connected or connected_attempt
                    last_result = build_probe_result(
                        probe,
                        connected=connected,
                        response=result.stdout,
                        attempts=attempts,
                        error=(stderr or None) if not connected_attempt else None,
                    )
                    if connected_attempt or last_result.response_text:
                        if connection_record_path is not None and step_index is not None:
                            save_response_bytes(connection_record_path.parent, step_index,
                                result.stdout, limit=MAX_RESPONSE_BYTES)
                        # A completed connection with an empty/malformed
                        # response is also execution evidence. The request may
                        # already have changed guest state; do not reissue it.
                        if last_result.response_text:
                            observer.response_received()
                        return last_result
                except subprocess.TimeoutExpired as error:
                    raw = error.stdout or b""
                    if isinstance(raw, str):
                        raw = raw.encode("utf-8")
                    record_connection("timeout", connected=False, response_bytes=len(raw),
                        response_sha256=hashlib.sha256(raw).hexdigest())
                    if connection_record_path is not None and step_index is not None:
                        save_response_bytes(connection_record_path.parent, step_index,
                            raw, limit=MAX_RESPONSE_BYTES)
                    # Timeout is an uncertain executed request, including writes.
                    # Return its evidence; only the Agent may choose a new run.
                    return build_probe_result(
                        probe,
                        connected=connected,
                        response=raw,
                        attempts=attempts,
                        error="in-container probe timed out",
                    )
            remaining = deadline - time.monotonic()
            if remaining > 0:
                observer.interrupted.wait(min(retry_interval, remaining))
        if last_result is not None:
            return last_result
        return build_probe_result(
            probe,
            connected=connected,
            attempts=attempts,
            error="in-container probe deadline expired",
        )

    def close(self) -> None:
        self._cleanup_owned_resources()
        self._network_created = False
        self._image_created = False
        self._prepared = False
        self._active_rootfs = None
        # Preserve attempt and preparation evidence, including partial failures.
        # Only the disposable rootfs and copied host bundle are expendable.
        for directory in (self.session_root / "rootfs", self.bundle_dir):
            if directory.exists():
                try:
                    _remove_disposable_tree(directory, self.budget)
                    self.cleanup_records.append({"path": str(directory), "removed": True})
                except (RunnerStopped, OSError) as error:
                    self.cleanup_records.append({"path": str(directory), "error": str(error)})
        if self.session_root.is_dir():
            (self.session_root / "cleanup.json").write_text(
                json.dumps(self.cleanup_records, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

    def __enter__(self) -> "DockerRootfsSandbox":
        self.prepare()
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()


__all__ = ["DockerRootfsSandbox", "SandboxAttempt"]
