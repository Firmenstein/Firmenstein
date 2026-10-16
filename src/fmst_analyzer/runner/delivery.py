"""Export and operate a source-built service package without IDA or Agents."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
import tomllib
import uuid
from urllib.parse import urlsplit
from typing import Literal

from pydantic import Field

from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json, write_text
from .budget import ExecutionBudget, run_process
from .browser_access import BrowserAccess, access_urls, find_browser, freeze_access, start_browser, stop_browser, validate_access
from .docker_sandbox import DockerRootfsSandbox
from .identity import tree_sha256
from .publication import load_frozen_inputs, SuccessfulConfiguration
from .runtime_builder import DockerRuntimeBuilder
from .schema import StrictModel
from .live_client import start_delivery_proxy, stop_delivery_proxy


class EngineeringPackage(StrictModel):
    schema_version: Literal[2] = 2
    package_id: str = Field(description="Identity of the immutable delivered inputs, distinct from a success configuration.")
    configuration_id: str = Field(description="Original successful configuration retained under provenance.")
    target_binary: str = Field(description="Firmware service basename.")
    guest_arch: Literal["arm", "mipsel", "mipsbe", "x86_64"]
    host_platform: Literal["linux/amd64"] = "linux/amd64"
    rootfs_sha256: str = Field(description="Original prepared rootfs tree identity v2, including owners and link targets.")
    runtime_delivery_id: str = Field(description="GuestWeave offline dependency identity; build inputs and builder are verified.")
    builder_image_id: str = Field(description="Exact prepared Docker builder image; no mutable tag resolution during build.")
    builder_archive: str | None = Field(description="Optional relative docker-save archive for loading the exact image.")
    input_identity: dict = Field(description="Complete immutable input inventory: bytes, modes and symlink targets; state is excluded.")
    python_runtime: dict = Field(description="Bundled Linux CPython and exact runtime dependency distributions.")
    dependency_rewrites: list[dict] = Field(description="Recorded relative Cargo API path changes on derived copies only.")
    browser_access: BrowserAccess | None = Field(default=None, description="Optional source-bound native HTTP origin; browse supplies browser-local name resolution without changing firmware filters.")
    limitations: list[str] = Field(description="Verified service scope, host/ownership restrictions and persistence boundary.")


_RUNNER_FILES = (
    "__init__.py", "schema.py", "adaptation_schema.py", "rootfs_actions.py", "probe.py", "request_wire.py",
    "peer_readiness.py", "runtime_builder.py", "cargo_cache.py", "container_output.py", "budget.py",
    "identity.py", "supervision.py", "docker_sandbox.py", "runtime_dump.py", "child_failure.py",
    "publication.py", "delivery.py", "delivery_build.py", "delivery_vendor.py", "browser_access.py", "service_readiness.py", "live_client.py",
)


def _json(path):
    return json.loads(Path(path).read_text())


@contextmanager
def _operation_lock(root):
    """Prevent concurrent CLI writers from losing a package's service/build pointer."""
    (root / "state").mkdir(exist_ok=True)
    with (root / "state/operation.lock").open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another operation is using this package") from error
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def _sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _inventory(root):
    """Hash immutable inputs without following guest symlinks."""
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        if Path(directory) == root:
            dirs[:] = [n for n in dirs if n != "state"]
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == "PACKAGE.json" or "__pycache__" in path.parts:
                continue
            if path.is_symlink():
                result[relative] = {"link": os.readlink(path)}
            elif path.is_file():
                result[relative] = {"sha256": _sha(path), "mode": path.stat().st_mode & 0o7777}
            elif path.is_dir():
                result[relative] = {"directory_mode": path.stat().st_mode & 0o7777}
            else:
                raise ValueError(f"unsupported package input entry: {relative}")
    return result


def _offline_module(delivery):
    tools = delivery / "workspace/GuestWeave/tools"
    sys.path.insert(0, str(tools))
    previous_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location("fmst_delivery_offline", tools / "offline.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.dont_write_bytecode = previous_bytecode
        sys.path.remove(str(tools))


def _rewrite_api(root, framework):
    """Change only the explicit API dependency path in derived Cargo manifests."""
    records = []
    for path in sorted(root.rglob("Cargo.toml")):
        text = path.read_text()
        parsed = tomllib.loads(text)
        relative = os.path.relpath(framework / "fmst-iib-api", path.parent)
        expected = tomllib.loads(text)
        found = False
        for section in ("dependencies", "dev-dependencies", "build-dependencies"):
            dep = expected.get(section, {}).get("fmst-iib-api")
            if isinstance(dep, dict) and "path" in dep:
                dep["path"] = relative
                found = True
        if not found:
            continue
        updated = re.sub(r'(?m)^(\s*fmst-iib-api\s*=\s*\{[^\n}]*\bpath\s*=\s*)("(?:[^"\\]|\\.)*"|\x27[^\x27]*\x27)',
            lambda m: m[1] + json.dumps(relative), text)
        if tomllib.loads(updated) != expected:
            raise ValueError(f"unsupported generated Cargo API path syntax: {path}")
        if parsed != expected:
            records.append({"path": path.relative_to(root).as_posix(), "before_sha256": _sha(path),
                "after_sha256": hashlib.sha256(updated.encode()).hexdigest(), "relative_api": relative})
            path.write_text(updated)
    return records


def _copy_python(destination):
    runtime = Path(sys.base_prefix)
    if sys.version_info[:2] != (3, 12) or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("initial delivery supports Linux amd64 CPython 3.12")
    shutil.copytree(runtime, destination / "python", symlinks=True, ignore=shutil.ignore_patterns("__pycache__"))
    site = destination / "python-packages"
    site.mkdir()
    versions = {}
    for name in ("pydantic", "pydantic_core", "typing_extensions", "annotated_types", "typing_inspection", "python-dotenv"):
        distribution = importlib.metadata.distribution(name)
        versions[name] = distribution.version
        for relative in distribution.files:
            if ".." in relative.parts or "__pycache__" in relative.parts or relative.suffix == ".pyc":
                continue
            source = distribution.locate_file(relative)
            if source.is_file():
                target = site / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
    return {"version": sys.version, "platform": "linux/amd64", "distributions": versions,
            "source": "Local redistributable CPython installation and installed runtime distributions; copied bytes are inventoried."}


def _copy_controller(destination):
    source = Path(__file__).resolve().parents[2]
    target = destination / "controller"
    for relative in ["fmst_analyzer/intervention_contracts.py", "fmst_analyzer/analysis/base/report_io.py",
            "fmst_basic/utils/archive_paths.py", *["fmst_analyzer/runner/" + n for n in _RUNNER_FILES]]:
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, path)
    for name in ("fmst_analyzer", "fmst_analyzer/analysis", "fmst_analyzer/analysis/base", "fmst_basic", "fmst_basic/utils"):
        (target / name / "__init__.py").write_text('"""Delivered service runtime components."""\n')
    write_text(destination / "fmst", '''#!/bin/sh
set -eu
package_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONHOME="$package_root/python"
export PYTHONPATH="$package_root/controller:$package_root/python-packages"
export PYTHONDONTWRITEBYTECODE=1
exec "$package_root/python/bin/python3.12" -m fmst_analyzer.runner.delivery --package "$package_root" "$@"
''')
    (destination / "fmst").chmod(0o755)


def export_package(manifest_path, runtime_inputs, output, registry_cache=None, browser_access=None):
    """Create a new derived package, preserving every original success artifact."""
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError(output)
    manifest_path = Path(manifest_path).resolve(strict=True)
    original = load_frozen_inputs(manifest_path, ExecutionBudget())
    if original.host_platform != "linux/amd64":
        raise ValueError("initial engineering delivery supports linux/amd64 host")
    dependency = _offline_module(Path(runtime_inputs).resolve())
    receipt = dependency.verify(Path(runtime_inputs).resolve())
    output.mkdir(parents=True)
    try:
        shutil.copytree(manifest_path.parent, output / "provenance", symlinks=True)
        access = freeze_access(browser_access, output, original.configuration_id)
        destination = output / "dependencies/runtime"
        shutil.copytree(runtime_inputs, destination, symlinks=True)
        authored = output / "authored"
        authored.mkdir()
        for name in ("interventions", "test_harnesses", "environment", "environments"):
            source = output / "provenance/authored" / name
            if source.is_dir():
                shutil.copytree(source, authored / name, symlinks=True)
        rewrites = _rewrite_api(authored, destination / "workspace/GuestWeave")
        python = _copy_python(output)
        _copy_controller(output)
        if any(authored.rglob("Cargo.toml")):
            name = "fmst-package-vendor-" + uuid.uuid4().hex
            command = ["docker", "run", "--name", name, "--pull=never", "--network=none" if registry_cache else "--network=bridge",
                "--mount", f"type=bind,src={output},dst=/package", "--mount", "type=volume,dst=/build,volume-nocopy"]
            if registry_cache:
                command += ["--mount", f"type=bind,src={Path(registry_cache).resolve(strict=True)},dst=/registry-seed,readonly"]
            command += [receipt["builder"]["image_id"], "python3",
                "/package/controller/fmst_analyzer/runner/container_output.py", "/package/dependencies",
                str(os.getuid()), str(os.getgid()), "python3", "/package/controller/fmst_analyzer/runner/delivery_vendor.py"]
            try:
                with (output / "dependencies/authored-prepare.log").open("wb") as log:
                    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=600)
            finally:
                cleanup = _remove_build_container(name)
                write_text(output / "dependencies/authored-cleanup.json", json.dumps(cleanup, indent=2))
            if result.returncode:
                raise RuntimeError(f"authored source preparation failed ({result.returncode}); see dependencies/authored-prepare.log")
            if _cleanup_failed(cleanup):
                raise RuntimeError("authored preparation cleanup incomplete; see dependencies/authored-cleanup.json")
        readme = render_readme(original, access)
        write_text(output / "README.md", readme)
        value = dict(schema_version=2, host_platform=original.host_platform,
            configuration_id=original.configuration_id, target_binary=original.target_binary,
            guest_arch=original.guest_arch, rootfs_sha256=original.input_trees["rootfs"],
            runtime_delivery_id=receipt["delivery_id"], builder_image_id=receipt["builder"]["image_id"],
            builder_archive="dependencies/runtime/" + receipt["builder"]["archive"] if receipt["builder"].get("archive") else None,
            input_identity=_inventory(output), python_runtime=python, dependency_rewrites=rewrites,
            browser_access=access.model_dump() if access else None,
            limitations=["Linux amd64 Docker and the same source filesystem UID/GID; other hosts/owners need separate validation.",
                "Prepared rootfs and original firmware ELF are inputs; firmware vendor source is not recompiled.",
                "Each up starts a fresh container overlay; configuration persistence across down is not promised.",
                "Acceptance covers the original Runner evidence and declared scope; a new startup/build does not inherit broader business guarantees.",
                "Native dependencies and Cargo sources are bundled; build uses no network, IDA or model."])
        package = EngineeringPackage(package_id=_digest(value), **value)
        write_model_json(output / "PACKAGE.json", package)
        load_package(output)
        return package
    except BaseException as error:
        write_text(output / "EXPORT-FAILED.txt", f"{type(error).__name__}: {error}\n")
        raise


def render_readme(original, access=None):
    return "\n".join(["# Rehosting service engineering package", "",
        f"Target: {original.target_binary}; guest: {original.guest_arch}; host: Linux amd64 with Docker.",
        f"Source configuration: {original.configuration_id}. Its original frozen files are under provenance/.",
        "", "Run from this directory (no development checkout, venv, IDA or model credentials required):", "",
        "```sh", "./fmst build", "./fmst verify", "./fmst up --build --port 8080", "./fmst browse", "./fmst logs", "./fmst down", "```", "",
        "The exact builder can be loaded automatically from its bundled archive. Build uses a new native volume,",
        "locked vendored Cargo/native sources and --network=none. Build logs and identities remain under state/builds/.",
        ("verify checks fresh startup readiness; native business acceptance is retained under provenance/evidence/native-client/." if original.attempt.browser_origin else "verify runs the original scenario in a separate clean instance and removes it afterwards."),
        "Targets with a fixed subnet must be stopped before verify; overlapping subnet instances must run serially.",
        ("up starts a fresh user instance from the browser-accepted inputs without a redundant protocol test." if original.attempt.browser_origin else "up validates the original scenario in a disposable instance, cleans it, then starts a fresh user instance from the same inputs."),
        "The user instance is observed through live target processes and kernel TCP listeners; no application probe or TCP connection is sent.",
        "Readiness is a point observation, separate from protocol acceptance. Native startup and companion activity still occur.",
        "up returns the native browser URL and the localhost transport URL; validation and startup receipts remain separate.",
        *( [f"Native browser hostname: {access.hostname}. {access.rationale}",
            "Use ./fmst browse to supply its name resolution in a dedicated Chrome/Chromium process.",
            "Opening the transport URL alone may fail native origin checks. Supporting files are under access_evidence/."]
            if access else [f"Use ./fmst browse for the native origin {original.attempt.browser_origin}; a private proxy retains native redirects and ports."
                           if original.attempt.browser_origin else "The browser URL uses localhost; open it directly or use ./fmst browse."] ),
        "browse requires Chrome/Chromium on the Linux host; use --browser /path/to/executable when it is not on PATH.",
        "The dedicated profile and proxy/resolver settings affect only this browser. System DNS is unchanged.",
        "down stops the package-owned browser, origin proxy and service, removes its private profile, and retains lifecycle receipts/logs.",
        ("Native startup verification uses a bridge and an ephemeral localhost port; it does not repeat business acceptance."
         if original.attempt.browser_origin else "verify uses an internal Docker network."),
        "up uses a bridge with localhost publication; outbound networking is available.",
        "Each build/up/verify has its own receipts. A source build gets a new identity and never inherits historical success.",
        "The target firmware ELF is preserved; the runtime and intervention, when present, are built from source.",
        "Use the same source file owner on Linux amd64. State persistence and other host platforms are not verified.",
        "", "Original acceptance:", "```json", original.attempt.scenario.model_dump_json(indent=2) if original.attempt.scenario else json.dumps({"browser_origin":original.attempt.browser_origin,"evidence":"provenance/evidence/native-client/"},indent=2), "```", ""])


def load_package(root):
    root = Path(root).resolve(strict=True)
    package = load_model_json(root / "PACKAGE.json", EngineeringPackage)
    actual = _inventory(root)
    if actual != package.input_identity:
        changed = sorted(k for k in actual.keys() | package.input_identity.keys() if actual.get(k) != package.input_identity.get(k))
        raise ValueError("immutable package inputs changed: " + ", ".join(changed))
    value = package.model_dump(exclude={"package_id"})
    if _digest(value) != package.package_id:
        raise ValueError("engineering package identity differs")
    original = load_frozen_inputs(root / "provenance/manifest.json", ExecutionBudget())
    if original.configuration_id != package.configuration_id or original.input_trees["rootfs"] != package.rootfs_sha256:
        raise ValueError("package provenance identity differs")
    validate_access(package.browser_access, root, package.configuration_id)
    receipt = _offline_module(root / "dependencies/runtime").verify(root / "dependencies/runtime")
    if receipt["delivery_id"] != package.runtime_delivery_id:
        raise ValueError("runtime dependency identity differs")
    return package, original


def _process(command, timeout=120):
    return subprocess.run(command, check=True, capture_output=True, text=True, timeout=timeout)


def _ensure_image(root, package):
    try:
        value = json.loads(_process(["docker", "image", "inspect", package.builder_image_id]).stdout)[0]
    except subprocess.CalledProcessError:
        if package.builder_archive is None:
            raise ValueError("load the recorded builder image before building")
        # An unavailable daemon is not evidence that its image is missing.
        _process(["docker", "info", "--format", "{{.ServerVersion}}"])
        _process(["docker", "load", "--input", str(root / package.builder_archive)], timeout=300)
        value = json.loads(_process(["docker", "image", "inspect", package.builder_image_id]).stdout)[0]
    if value["Id"] != package.builder_image_id or value["Architecture"] != "amd64":
        raise ValueError("builder image identity/platform differs")


def _cleanup_failed(record):
    return any((key == 'error' or key.endswith('_error')) and value for key, value in record.items()) or any(
        (key == 'returncode' or key.endswith('_returncode')) and value != 0 for key, value in record.items())


def _remove_build_container(name):
    record = {"container": name}
    try:
        removed = subprocess.run(["docker", "rm", "--force", "--volumes", name], capture_output=True, text=True, timeout=10)
        record.update(returncode=removed.returncode, stderr=removed.stderr)
    except (OSError, subprocess.SubprocessError) as error:
        record["error"] = f"{type(error).__name__}: {error}"
    return record


def build_package(root, package):
    _ensure_image(root, package)
    identifier = uuid.uuid4().hex
    output = root / "state/builds" / identifier
    output.mkdir(parents=True, exist_ok=False)
    name = "fmst-package-build-" + identifier
    command = ["docker", "run", "--pull=never", "--network=none", "--platform", package.host_platform,
        "--name", name, "--mount", f"type=bind,src={root},dst=/package,readonly",
        "--mount", f"type=bind,src={root / 'dependencies/runtime'},dst=/delivery,readonly",
        "--mount", f"type=bind,src={output},dst=/evidence", "--mount", "type=volume,dst=/build,volume-nocopy",
        package.builder_image_id, "python3", "/package/controller/fmst_analyzer/runner/container_output.py",
        "/evidence", str(os.getuid()), str(os.getgid()), "python3",
        "/package/controller/fmst_analyzer/runner/delivery_build.py"]
    receipt = {"schema_version": 1, "package_id": package.package_id, "build_id": identifier,
        "state": "building", "command": command, "network": "none", "fresh_native_volume": True,
        "started_unix_ns": time.time_ns()}
    write_text(output / "receipt.json", json.dumps(receipt, indent=2))
    try:
        with (output / "build.log").open("wb") as log:
            result = run_process(command, budget=ExecutionBudget(7200), timeout=7170, stdout=log, stderr=subprocess.STDOUT)
        receipt["returncode"] = result.returncode
        if result.returncode:
            raise RuntimeError(f"source build failed ({result.returncode}); full log: {output / 'build.log'}")
        receipt.update(runtime_sha256=tree_sha256(output / "runtime"),
            build_complete=_json(output / "build-complete.json"))
    except BaseException as error:
        receipt.update(state="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        cleanup = _remove_build_container(name)
        receipt.update(finished_unix_ns=time.time_ns(), cleanup=cleanup)
        if receipt["state"] != "failed":
            if _cleanup_failed(cleanup):
                receipt.update(state="failed", error="source build cleanup incomplete")
            else:
                receipt["state"] = "built"
        write_text(output / "receipt.json", json.dumps(receipt, indent=2))
    if receipt["state"] != "built":
        raise RuntimeError(f"source build cleanup incomplete; receipt: {output / 'receipt.json'}")
    write_text(root / "state/current-build.json", json.dumps({"build_id": identifier}, indent=2))
    return output


def current_build(root, package):
    pointer = _json(root / "state/current-build.json")
    identifier = pointer["build_id"]
    if not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise ValueError("invalid build pointer")
    output = root / "state/builds" / identifier
    receipt = _json(output / "receipt.json")
    if receipt["package_id"] != package.package_id or receipt["state"] != "built":
        raise ValueError("current build is not a completed build for this package")
    if tree_sha256(output / "runtime") != receipt["runtime_sha256"]:
        raise ValueError("built runtime files changed")
    return output


def _service_urls(package, port, native_origin=None):
    urls = access_urls(package.browser_access, port)
    if native_origin:
        urls.update(url=native_origin, browser_required=True)
    return urls


def _available_service_port():
    import socket
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def run_service(root, package, original, *, persistent=False, port=None):
    if persistent and any((root / "state" / name).exists() for name in ("browser.json", "native-proxy.json")):
        raise ValueError("this package still has a browser receipt; use down first")
    if persistent and (root / "state/service.json").exists():
        raise ValueError("this package already has a service receipt; use logs/down first")
    if not persistent and original.attempt.network.subnet and (root / "state/service.json").exists():
        raise ValueError("this target uses a fixed subnet; run down before verify")
    _ensure_image(root, package)
    build = current_build(root, package)
    budget = ExecutionBudget(300)
    runtime_hash = _json(build / 'receipt.json')['runtime_sha256']
    validation = None
    if persistent and not original.attempt.browser_origin:
        if not original.attempt.browser_origin and (original.attempt.scenario is None or original.attempt.scenario.protocol != 'http'):
            raise ValueError('Published service requires the original HTTP scenario')
        # Arbitrary valid interactions may consume server state. Never expose
        # the validation overlay, memory, process or client session to users.
        validation = _run_service_instance(root, package, original, build=build,
            runtime_hash=runtime_hash, budget=budget, expose_service=True)
    return _run_service_instance(root, package, original, build=build,
        runtime_hash=runtime_hash, budget=budget, persistent=persistent, port=port,
        expose_service=persistent, validation=validation)


def _run_service_instance(root, package, original, *, build, runtime_hash, budget,
                          persistent=False, port=None, expose_service=False, validation=None):
    workdir = root / "state" / ("services" if persistent else "verifications") / uuid.uuid4().hex
    builder = DockerRuntimeBuilder(image=package.builder_image_id, project_root=root, workdir=workdir,
        platform_name=package.host_platform, budget=budget)
    sandbox = DockerRootfsSandbox(rootfs=root / "provenance/rootfs", workdir=workdir,
        target_binary=package.target_binary, executable_path=original.executable_path, guest_arch=package.guest_arch,
        runtime_workspace=root, env_script=None, runtime_builder=builder, budget=budget,
        network=original.attempt.network, expose_service=expose_service or bool(original.attempt.browser_origin))
    record = {"schema_version": 2, "package_id": package.package_id, "build_id": build.name,
        "state": "preparing", "sandbox_session_id": sandbox.session_id, "network": sandbox.network.model_dump(),
        "image_tag": sandbox.image_tag, "target_binary": package.target_binary,
        "target_slug": sandbox.target_slug,
        "network_mode": "bridge_with_localhost_publication" if persistent else "bridge" if expose_service else "internal",
        "purpose": "user_service" if persistent else "startup_verification" if original.attempt.browser_origin else "scenario_validation",
        "input_identity": {"rootfs_sha256": package.rootfs_sha256, "runtime_sha256": runtime_hash},
        "workdir": str(workdir), "session_root": str(sandbox.session_root), "started_unix_ns": time.time_ns()}
    if validation is not None:
        record['validation'] = {'receipt_path': str(Path(validation['workdir']) / 'receipt.json'),
            'receipt_sha256': _sha(Path(validation['workdir']) / 'receipt.json'),
            'sandbox_session_id': validation['sandbox_session_id'], 'state': validation['state'],
            'input_identity': validation['input_identity']}
    receipt_path = workdir / "receipt.json"
    receipt_path.parent.mkdir(parents=True)
    retained = False
    try:
        sandbox.prepare_frozen(build / "runtime", rootfs_sha256=package.rootfs_sha256,
            runtime_sha256=runtime_hash)
        a = original.attempt
        launch = dict(
            intervention_so=build / "runtime/intervention.so" if a.intervention_binary_path else None,
            executable_path=original.executable_path, guest_args=a.guest_args,
            guest_working_directory=a.guest_working_directory, guest_environment=a.guest_environment,
            companion_processes=a.companion_processes,
            timeout_seconds=budget.remaining(), watchdog_stall_seconds=original.watchdog_stall_seconds)
        if a.browser_origin:
            origin = urlsplit(a.browser_origin)
            native_port = origin.port or (443 if origin.scheme == 'https' else 80)
            if not persistent:
                port = _available_service_port()
                sandbox.expose_service = True
            result = sandbox.start_service(**launch, port=native_port, host_port=port)
            record.update(state="running" if persistent else "ready", container_name=result.container_name,
                published_port=port, readiness=result.readiness, readiness_path=str(result.readiness_path),
                verification_scope="startup readiness only; service behavior was assessed by Runner native interaction",
                native_origin=a.browser_origin,
                **_service_urls(package, port, a.browser_origin))
            if persistent:
                write_text(root / "state/service.json", json.dumps(record, indent=2))
                retained = True
        elif persistent:
            result = sandbox.start_service(**launch, port=a.scenario.port, host_port=port)
            record.update(state="running", container_name=result.container_name, published_port=port,
                          readiness=result.readiness, readiness_path=str(result.readiness_path),
                          **access_urls(package.browser_access, port))
            write_text(root / "state/service.json", json.dumps(record, indent=2))
            retained = True
        else:
            result = sandbox.run_attempt(**launch, attempt_number=1, probe=a.probe, scenario=a.scenario)
            record.update(scenario=a.scenario.model_dump(), scenario_result=result.scenario_result.model_dump(),
                state="success" if result.scenario_result.status == "success" else "blocked")
        if record["state"] == "blocked":
            raise RuntimeError(f"original scenario failed; receipt: {receipt_path}")
    except BaseException as error:
        record.update(error=f"{type(error).__name__}: {error}")
        if isinstance(error, subprocess.CalledProcessError):
            record.update(process_stdout=error.stdout, process_stderr=error.stderr)
        raise
    finally:
        if not retained:
            sandbox.close()
        record.update(finished_unix_ns=time.time_ns(), cleanup_records=sandbox.cleanup_records)
        cleanup_failed = not retained and any(_cleanup_failed(r) for r in sandbox.cleanup_records)
        if cleanup_failed:
            record['state'] = 'cleanup_failed'
            record['cleanup_error'] = 'Instance cleanup incomplete; user startup was not admitted'
        write_text(receipt_path, json.dumps(record, indent=2))
        if cleanup_failed and sys.exc_info()[0] is None:
            raise RuntimeError(f'Instance cleanup incomplete; receipt: {receipt_path}')
    return record


def down_service(root, package):
    """Attempt both cleanups even if one fails, retaining their separate errors."""
    errors = {}
    try:
        browser = stop_browser(root, package.package_id)
    except (OSError, ValueError, RuntimeError) as error:
        browser = {"state": "cleanup_failed", "error": f"{type(error).__name__}: {error}"}
        errors["browser"] = browser["error"]
    try:
        proxy = stop_delivery_proxy(root, package.package_id)
    except (OSError, ValueError, RuntimeError) as error:
        proxy = {"state": "cleanup_failed", "error": str(error)}
        errors["proxy"] = proxy["error"]
    try:
        result = _down_service(root, package)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result = {"state": "cleanup_failed"}
        errors["service"] = f"{type(error).__name__}: {error}"
    result["browser_cleanup"] = browser
    result["proxy_cleanup"] = proxy
    if errors:
        path = root / "state/down-failed.json"
        write_text(path, json.dumps({**result, "errors": errors}, indent=2))
        raise RuntimeError(f"package cleanup incomplete; receipt: {path}")
    return result


def _down_service(root, package):
    path = root / "state/service.json"
    if not path.exists():
        return {"state": "absent"}
    record = _json(path)
    if record["package_id"] != package.package_id:
        raise ValueError("service belongs to another package")
    session = record["sandbox_session_id"]
    if not re.fullmatch(r"[0-9a-f]{12}", session):
        raise ValueError("invalid service session")
    workdir = Path(record["workdir"]).resolve()
    if not workdir.is_relative_to(root / "state/services"):
        raise ValueError("service workdir is outside this package")
    original = load_model_json(root / "provenance/manifest.json", SuccessfulConfiguration)
    sandbox = DockerRootfsSandbox(rootfs=root / "provenance/rootfs", workdir=workdir,
        target_binary=package.target_binary, executable_path=original.executable_path,
        guest_arch=package.guest_arch, runtime_workspace=root, env_script=None,
        runtime_builder=DockerRuntimeBuilder(image=package.builder_image_id, project_root=root,
            workdir=workdir, platform_name=package.host_platform))
    sandbox.session_id = session
    sandbox.session_root = Path(record["session_root"]).resolve()
    if sandbox.session_root != workdir / "runner_sessions" / sandbox.target_slug / session:
        raise ValueError("unexpected service session root")
    sandbox.bundle_dir = sandbox.session_root / "host_runtime"
    sandbox.output_root = sandbox.session_root / "attempts"
    try:
        logs = subprocess.run(["docker", "logs", record["container_name"]], capture_output=True, timeout=10)
        record["log_collection"] = {"returncode": logs.returncode}
        (workdir / "service.log").write_bytes(logs.stdout + logs.stderr)
    except (OSError, subprocess.SubprocessError) as error:
        record["log_collection"] = {"error": f"{type(error).__name__}: {error}"}
        if isinstance(error, subprocess.TimeoutExpired):
            (workdir / "service.log").write_bytes((error.output or b"") + (error.stderr or b""))
    finally:
        sandbox.close()
    if not any(_cleanup_failed(r) for r in sandbox.cleanup_records):
        try:
            sandbox.runtime_builder.handoff_output(sandbox.output_root, cleanup=True)
            sandbox.cleanup_records.append({"output_handoff": "complete"})
        except (OSError, subprocess.SubprocessError) as error:
            sandbox.cleanup_records.append({"output_handoff": "failed", "error": str(error)})
    record.update(state="stopped", stopped_unix_ns=time.time_ns(), cleanup_records=sandbox.cleanup_records)
    write_text(workdir / "stopped.json", json.dumps(record, indent=2))
    if any(_cleanup_failed(r) for r in sandbox.cleanup_records):
        raise RuntimeError(f"service cleanup incomplete; receipt: {workdir / 'stopped.json'}")
    path.unlink()
    return record


def browse_service(root, package, *, browser=None, headless=False):
    record = _json(root / "state/service.json")
    if record["package_id"] != package.package_id or record["state"] != "running":
        raise ValueError("service is not running for this package")
    original = load_model_json(root / "provenance/manifest.json", SuccessfulConfiguration)
    urls = _service_urls(package, record["published_port"], original.attempt.browser_origin)
    if any(record[key] != value for key, value in urls.items()):
        raise ValueError("service access URLs differ from the package contract")
    container = json.loads(_process(["docker", "inspect", record["container_name"]]).stdout)[0]
    labels = container["Config"]["Labels"] or {}
    if (not container["State"]["Running"] or labels.get("fmst.runner.managed") != "true"
            or labels.get("fmst.runner.session") != record["sandbox_session_id"]
            or labels.get("fmst.runner.target") != record["target_slug"]):
        raise ValueError("package service process is absent or its identity differs")
    executable = find_browser(browser)
    if not original.attempt.browser_origin:
        return start_browser(root, package.package_id, record, package.browser_access, executable, headless=headless)
    proxy = start_delivery_proxy(root, package.package_id, record)
    try:
        return start_browser(root, package.package_id, record, package.browser_access, executable,
            headless=headless, proxy_url=proxy["proxy_url"])
    except BaseException:
        stop_delivery_proxy(root, package.package_id)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path)
    sub = parser.add_subparsers(dest="action", required=True)
    export = sub.add_parser("export")
    export.add_argument("manifest", type=Path)
    export.add_argument("--runtime-inputs", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--registry-cache", type=Path, help="Optional exact cached crates for offline authored dependency preparation.")
    export.add_argument("--browser-access", type=Path, help="Explicit source-bound BrowserAccess JSON; evidence is frozen with the new package.")
    sub.add_parser("build")
    sub.add_parser("verify")
    up = sub.add_parser("up")
    up.add_argument("--build", action="store_true")
    up.add_argument("--port", type=int, default=8080)
    sub.add_parser("logs")
    sub.add_parser("down")
    browse = sub.add_parser("browse")
    browse.add_argument("--browser", help="Chrome/Chromium executable; otherwise discover it on PATH.")
    browse.add_argument("--headless", action="store_true", help="Expose a localhost CDP port for real browser automation.")
    args = parser.parse_args()
    try:
        if args.action == "export":
            access = load_model_json(args.browser_access, BrowserAccess) if args.browser_access else None
            result = export_package(args.manifest, args.runtime_inputs, args.output, args.registry_cache, access)
            print(json.dumps({"package_id": result.package_id, "output": str(args.output.resolve())}))
            return
        if args.package is None:
            parser.error("--package is required for service operations")
        root = args.package.resolve(strict=True)
        with _operation_lock(root):
            _operate(root, args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)


def _operate(root, args):
    package, original = load_package(root)
    if args.action == "build":
        print(json.dumps({"state": "built", "output": str(build_package(root, package))}))
    elif args.action == "verify":
        result = run_service(root, package, original)
        print(json.dumps({"state": result["state"], "build_id": result["build_id"], "evidence": result["workdir"]}))
    elif args.action == "up":
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if args.build:
            if (root / "state/service.json").exists():
                raise ValueError("this package already has a service receipt; use logs/down first")
            build_package(root, package)
        result = run_service(root, package, original, persistent=True, port=args.port)
        print(json.dumps({"state": result["state"], **{key: result[key] for key in ("url", "transport_url", "browser_required")},
                          "browse_command": "./fmst browse", "evidence": result["workdir"]}))
    elif args.action == "browse":
        result = browse_service(root, package, browser=args.browser, headless=args.headless)
        print(json.dumps({key: result[key] for key in ("state", "url", "transport_url", "log")}
                         | ({"debug_port": result["debug_port"]} if "debug_port" in result else {})))
    elif args.action == "logs":
        record = _json(root / "state/service.json")
        if record["package_id"] != package.package_id:
            raise ValueError("service package identity differs")
        subprocess.run(["docker", "logs", record["container_name"]], check=True)
    else:
        result = down_service(root, package)
        print(json.dumps({"state": result["state"], **({"log_collection": result["log_collection"]} if "log_collection" in result else {})}))


if __name__ == "__main__":
    main()
