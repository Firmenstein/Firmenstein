"""Build Linux runtime artifacts without coupling them to the IDA host."""

from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Iterable, Mapping

from .budget import ExecutionBudget, RunnerStopped, run_process


class RuntimeBuilder:
    """Interface used by the Runner for Cargo and host-bundle operations."""

    platform_name: str | None = None

    def __init__(
        self,
        *,
        budget: ExecutionBudget | None = None,
        framework_root: Path | None = None,
    ) -> None:
        self.budget = budget
        self.framework_root = Path(framework_root).resolve() if framework_root else None
        self.cleanup_records: list[dict[str, object]] = []

    def _process(self, command: list[str], *, timeout: float, cleanup: bool = False, **kwargs):
        if self.budget is not None:
            return run_process(command, budget=self.budget, timeout=timeout, cleanup=cleanup, **kwargs)
        return subprocess.run(command, timeout=timeout, **kwargs)

    def cargo_target_dir(self, crate_root: Path) -> Path:
        return crate_root / "target"

    def run_cargo(
        self,
        manifest: Path,
        subcommand: str,
        *,
        timeout: int,
        extra_args: Iterable[str] = (),
    ) -> subprocess.CompletedProcess[str]:
        raise NotImplementedError

    def build_harness(self, runtime_workspace: Path, guest_arch: str) -> Path:
        raise NotImplementedError

    def list_cpu_models(self, harness: Path) -> subprocess.CompletedProcess[str]:
        """Query QEMU_CPU=help before guest loading, with no guest environment."""
        return self._process(
            [str(harness), '--trace-only', '--binary', str(harness), '--rootfs', '/nonexistent'],
            env={'QEMU_CPU': 'help'}, capture_output=True, text=True, timeout=20,
        )

    def build_host_bundle(
        self, harness: Path, bundle_dir: Path, *, bundle_script: Path | None = None,
        binaries: Mapping[str, Path] | None = None,
    ) -> None:
        raise NotImplementedError


class HostRuntimeBuilder(RuntimeBuilder):
    """Use the current Linux host toolchain."""

    def run_cargo(
        self,
        manifest: Path,
        subcommand: str,
        *,
        timeout: int,
        extra_args: Iterable[str] = (),
    ) -> subprocess.CompletedProcess[str]:
        return self._process(
            [
                "cargo", subcommand, "--release", "--manifest-path", str(manifest),
                *extra_args,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "CARGO_TERM_COLOR": "never"},
        )

    def build_harness(self, runtime_workspace: Path, guest_arch: str) -> Path:
        package = _harness_package(guest_arch)
        args: list[str] = []
        if guest_arch == "mipsbe":
            args = ["--no-default-features", "--features", "big-endian"]
        self._process(
            ["cargo", "build", "--locked", "--release", "-p", package, *args],
            cwd=runtime_workspace,
            check=True,
            text=True,
            timeout=1800,
        )
        harness = runtime_workspace / "target" / "release" / package
        if not harness.is_file():
            raise RuntimeError(f"built harness is missing: {harness}")
        return harness

    def build_host_bundle(
        self, harness: Path, bundle_dir: Path, *, bundle_script: Path | None = None,
        binaries: Mapping[str, Path] | None = None,
    ) -> None:
        if platform.system() != "Linux":
            raise RuntimeError(
                "LibAFL-QEMU host bundles require Linux; configure "
                "FMST_RUNTIME_BUILDER_IMAGE on non-Linux hosts"
            )
        script = bundle_script or (
            self.framework_root / "tools" / "build_runtime_bundle.py"
            if self.framework_root is not None
            else Path(__file__).resolve().parents[2] / "scripts" / "build_runtime_bundle.py"
        )
        self._process(
            ["python3", str(script), "--harness", str(harness), "--bundle", str(bundle_dir),
                *_binary_args(binaries)],
            check=True,
            text=True,
            timeout=600,
        )


class DockerRuntimeBuilder(RuntimeBuilder):
    """Run Linux-only build operations in a disposable Linux container."""

    def __init__(
        self,
        *,
        image: str,
        project_root: Path,
        workdir: Path,
        platform_name: str | None = None,
        budget: ExecutionBudget | None = None,
        framework_root: Path | None = None,
    ) -> None:
        super().__init__(budget=budget, framework_root=framework_root or project_root / "GuestWeave")
        self.image = image
        self.project_root = Path(project_root).resolve()
        self.workdir = Path(workdir).resolve()
        self.platform_name = platform_name
        self._build_id = uuid.uuid4().hex
        self._cargo_lock = threading.Lock()

    def cargo_target_dir(self, crate_root: Path) -> Path:
        """Return a target directory private to this builder invocation.

        The framework checkout can be shared by independent Runner sessions.
        Keep build output outside the source delivery and isolate separate
        builder instances, including those sharing a consumer work directory.
        Attempts handled by this builder may still reuse its Cargo cache.
        """
        platform_key = (self.platform_name or "image-default").replace("/", "-")
        crate_key = hashlib.sha256(
            str(Path(crate_root).resolve()).encode("utf-8")
        ).hexdigest()[:16]
        return self.workdir / "target" / "runtime-builder" / self._build_id / platform_key / crate_key

    def list_cpu_models(self, harness: Path) -> subprocess.CompletedProcess[str]:
        path = self._container_path(harness)
        return self._run(['env', '-i', 'QEMU_CPU=help', path, '--trace-only',
            '--binary', path, '--rootfs', '/nonexistent'], timeout=20)

    def _container_path(self, path: Path) -> str:
        resolved = Path(path).resolve()
        try:
            relative = resolved.relative_to(self.workdir)
        except ValueError:
            try:
                relative = resolved.relative_to(self.project_root)
            except ValueError as error:
                raise ValueError(
                    f"runtime path is outside builder mounts: {resolved}"
                ) from error
            return "/workspace/project/" + relative.as_posix()
        return "/workspace/workdir/" + relative.as_posix()

    def _run(
        self,
        command: list[str],
        *,
        timeout: int,
        cargo_target: Path | None = None,
        owned_output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if cargo_target is None:
            return self._run_container(command, timeout=timeout, owned_output=owned_output)
        # Cargo's own lock lives in each anonymous volume. Protect the
        # shared export as well when callers reuse this builder concurrently.
        deadline = time.monotonic() + timeout
        while True:
            if self.budget is not None:
                self.budget.check()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            if self._cargo_lock.acquire(timeout=min(0.1, remaining)):
                break
        try:
            return self._run_container(command, timeout=max(0.001, deadline - time.monotonic()),
                cargo_target=cargo_target)
        finally:
            self._cargo_lock.release()

    def _run_container(
        self,
        command: list[str],
        *,
        timeout: float,
        cargo_target: Path | None = None,
        owned_output: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.workdir.mkdir(parents=True, exist_ok=True)
        container_name = f"fmst-builder-{uuid.uuid4().hex}"
        # The daemon runs compilers outside the host Agent's process cgroup.
        # Bound it explicitly, including swap and Cargo's own parallelism.
        memory = os.environ.get("FMST_RUNTIME_BUILDER_MEMORY", "6g")
        docker = ["docker", "run", "--rm", "--name", container_name,
            "--memory", memory, "--memory-swap", memory,
            "--cpus", os.environ.get("FMST_RUNTIME_BUILDER_CPUS", "2"),
            "--pids-limit", "512", "--env",
            "CARGO_BUILD_JOBS=" + os.environ.get("FMST_RUNTIME_BUILD_JOBS", "2")]
        if self.platform_name:
            docker.extend(["--platform", self.platform_name])
        for source, destination in (
            (self.project_root, "/workspace/project"),
            (self.workdir, "/workspace/workdir"),
            # Generation workspaces deliberately contain an absolute symlink
            # to the checkout's src/ directory. Preserve that path inside the
            # builder so Cargo sees the same dependency tree as the host.
            (self.project_root, str(self.project_root)),
        ):
            docker.extend(
                ["--mount", f"type=bind,src={source},dst={destination}"]
            )
        # Published Generator manifests historically contain a relative path
        # calibrated to the source checkout and may resolve to /src when the
        # disposable Runner workspace is mounted at a different depth. Keep
        # that immutable manifest valid by mounting the actual framework at
        # the historical runtime path. Mounting Firmenstein/src at /src would
        # break its relative ../../GuestWeave symlink inside the container.
        if self.framework_root is not None and self.framework_root.is_dir():
            docker.extend([
                "--mount",
                f"type=bind,src={self.framework_root},dst=/src/fmst_iib_runtime,readonly",
            ])
        if cargo_target is not None:
            # On Docker Desktop, distinct bind-mounted targets can still
            # produce transient rustc E0463 metadata failures under parallel
            # builds. Compile on a native anonymous volume, at the same path
            # recorded in Cargo/RPATH, and transfer the cache only while idle.
            cargo_target.mkdir(parents=True, exist_ok=True)
            native_target = self._container_path(cargo_target)
            helper = Path(__file__).with_name("cargo_cache.py")
            docker.extend([
                "--mount", f"type=bind,src={cargo_target},dst=/fmst-cargo-export",
                "--mount", f"type=volume,dst={native_target},volume-nocopy",
                "--mount", f"type=bind,src={helper},dst=/fmst-cargo-cache.py,readonly",
            ])
            command = ["python3", "/fmst-cargo-cache.py", native_target,
                "/fmst-cargo-export", "--host-owner", str(os.getuid()), str(os.getgid()), *command]
        if owned_output is not None:
            owned_output.mkdir(parents=True, exist_ok=True)
            helper = Path(__file__).with_name("container_output.py")
            docker.extend(["--mount", f"type=bind,src={helper},dst=/fmst-output-handoff.py,readonly"])
            command = ["python3", "/fmst-output-handoff.py", self._container_path(owned_output),
                str(os.getuid()), str(os.getgid()), *command]
        docker.extend(["--workdir", "/workspace/project", self.image, *command])
        try:
            return self._process(
                docker,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (RunnerStopped, subprocess.TimeoutExpired, KeyboardInterrupt):
            # Killing the Docker client alone leaves the build running in
            # the daemon. Remove only this invocation's container.
            record: dict[str, object] = {"container": container_name}
            try:
                removed = self._process(
                    ["docker", "rm", "--force", "--volumes", container_name],
                    capture_output=True, text=True, timeout=10, cleanup=True,
                )
                record.update(returncode=removed.returncode, stderr=removed.stderr)
            except (RunnerStopped, OSError, subprocess.SubprocessError) as error:
                record["error"] = str(error)
            self.cleanup_records.append(record)
            raise

    def handoff_output(self, root: Path, *, cleanup: bool = False) -> None:
        """Normalize an idle framework output mount, preserving raw metadata."""
        helper = Path(__file__).with_name("container_output.py")
        name = f"fmst-output-{uuid.uuid4().hex}"
        command = ["docker", "run", "--rm", "--network", "none", "--name", name]
        if self.platform_name:
            command.extend(["--platform", self.platform_name])
        command.extend(["--mount", f"type=bind,src={root.resolve()},dst=/fmst-output",
            "--mount", f"type=bind,src={helper},dst=/fmst-output-handoff.py,readonly",
            self.image, "python3", "/fmst-output-handoff.py", "/fmst-output",
            str(os.getuid()), str(os.getgid())])
        try:
            self._process(command, timeout=10, cleanup=cleanup, check=True,
                capture_output=True, text=True)
        finally:
            self._process(["docker", "rm", "--force", name], timeout=5, cleanup=True,
                capture_output=True, text=True)

    def run_cargo(
        self,
        manifest: Path,
        subcommand: str,
        *,
        timeout: int,
        extra_args: Iterable[str] = (),
    ) -> subprocess.CompletedProcess[str]:
        target_dir = self.cargo_target_dir(manifest.parent)
        return self._run(
            [
                "cargo", subcommand, "--release", "--manifest-path",
                self._container_path(manifest),
                "--target-dir", self._container_path(target_dir),
                *extra_args,
            ],
            timeout=timeout,
            cargo_target=target_dir,
        )

    def build_harness(self, runtime_workspace: Path, guest_arch: str) -> Path:
        package = _harness_package(guest_arch)
        # LibAFL's QEMU source/build cache also depends on the guest CPU.
        target_dir = self.cargo_target_dir(runtime_workspace) / guest_arch
        args: list[str] = []
        if guest_arch == "mipsbe":
            args = ["--no-default-features", "--features", "big-endian"]
        result = self._run(
            [
                "cargo", "build", "--locked", "--release", "-p", package,
                "--manifest-path", self._container_path(runtime_workspace / "Cargo.toml"),
                "--target-dir", self._container_path(target_dir),
                *args,
            ],
            timeout=1800,
            cargo_target=target_dir,
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, result.args, output=result.stdout, stderr=result.stderr
            )
        harness = target_dir / "release" / package
        if not harness.is_file():
            raise RuntimeError(f"built harness is missing: {harness}")
        return harness

    def build_host_bundle(
        self, harness: Path, bundle_dir: Path, *, bundle_script: Path | None = None,
        binaries: Mapping[str, Path] | None = None,
    ) -> None:
        script = bundle_script or (
            self.framework_root / "tools" / "build_runtime_bundle.py"
            if self.framework_root is not None
            else self.project_root / "src" / "scripts" / "build_runtime_bundle.py"
        )
        result = self._run(
            [
                "python3", self._container_path(script),
                "--harness", self._container_path(harness),
                "--bundle", self._container_path(bundle_dir),
                *_binary_args(binaries),
            ],
            timeout=600, owned_output=bundle_dir,
        )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, result.args, output=result.stdout, stderr=result.stderr
            )


def _harness_package(guest_arch: str) -> str:
    package = {
        "arm": "fmst-harness-arm",
        "x86_64": "fmst-harness-x86",
        "mipsel": "fmst-harness-mips",
        "mipsbe": "fmst-harness-mips",
    }.get(guest_arch)
    if package is None:
        raise RuntimeError(f"unsupported Runner guest architecture: {guest_arch}")
    return package


def _binary_args(binaries: Mapping[str, Path] | None) -> list[str]:
    """Helper source paths refer to the Linux build host, not checkout mounts."""
    return [arg for name, path in (binaries or {}).items()
        for arg in ("--binary", f"{name}={path}")]


def create_runtime_builder(
    *,
    runtime_workspace: Path,
    workdir: Path,
    image: str | None = None,
    platform_name: str | None = None,
    budget: ExecutionBudget | None = None,
) -> RuntimeBuilder:
    """Select a Linux-capable backend for the Runner runtime."""
    if image:
        runtime_workspace = Path(runtime_workspace).resolve()
        return DockerRuntimeBuilder(
            image=image,
            project_root=runtime_workspace.parent,
            workdir=workdir,
            platform_name=platform_name,
            budget=budget,
            framework_root=runtime_workspace,
        )
    if platform.system() == "Linux":
        return HostRuntimeBuilder(budget=budget, framework_root=runtime_workspace)
    raise RuntimeError(
        "LibAFL-QEMU runtime builds require Linux. On macOS, set "
        "FMST_RUNTIME_BUILDER_IMAGE to a Linux builder image."
    )


__all__ = [
    "DockerRuntimeBuilder", "HostRuntimeBuilder", "RuntimeBuilder",
    "create_runtime_builder",
]
