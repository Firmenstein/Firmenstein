from __future__ import annotations

from pathlib import Path
import subprocess

import pytest

from fmst_analyzer.runner.runtime_builder import (
    DockerRuntimeBuilder,
    HostRuntimeBuilder,
    _harness_package,
    create_runtime_builder,
)


def test_harness_package_maps_guest_architectures() -> None:
    assert _harness_package("arm") == "fmst-harness-arm"
    assert _harness_package("x86_64") == "fmst-harness-x86"
    assert _harness_package("mipsel") == "fmst-harness-mips"
    assert _harness_package("mipsbe") == "fmst-harness-mips"
    with pytest.raises(RuntimeError, match="unsupported"):
        _harness_package("riscv")


def test_docker_builder_maps_project_and_workdir_paths(tmp_path: Path) -> None:
    project = tmp_path / "project"
    workdir = project / "workdir"
    runtime = project / "src" / "fmst_iib_runtime"
    builder = DockerRuntimeBuilder(
        image="builder:test",
        project_root=project,
        workdir=workdir,
        platform_name="linux/arm64",
    )
    assert builder._container_path(runtime / "Cargo.toml") == (
        "/workspace/project/src/fmst_iib_runtime/Cargo.toml"
    )
    assert builder._container_path(workdir / "runner_workspaces" / "x") == (
        "/workspace/workdir/runner_workspaces/x"
    )


def test_non_linux_requires_explicit_builder_image(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "fmst_analyzer.runner.runtime_builder.platform.system",
        lambda: "Darwin",
    )
    with pytest.raises(RuntimeError, match="FMST_RUNTIME_BUILDER_IMAGE"):
        create_runtime_builder(
            runtime_workspace=Path("/repo/src/fmst_iib_runtime"),
            workdir=Path("/repo/workdir"),
        )


def test_docker_cargo_keeps_linux_artifacts_separate_from_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "checked", "")

    monkeypatch.setattr("fmst_analyzer.runner.runtime_builder.subprocess.run", run)
    builder = DockerRuntimeBuilder(
        image="builder:test", project_root=tmp_path,
        workdir=tmp_path / "work", platform_name="linux/arm64",
    )
    manifest = tmp_path / "work" / "crate" / "Cargo.toml"
    builder.run_cargo(manifest, "test", timeout=600, extra_args=("--test", "unit_a"))
    command = calls[0]
    assert command[:3] == ["docker", "run", "--rm"]
    assert command[command.index("--platform") + 1] == "linux/arm64"
    target = builder.cargo_target_dir(manifest.parent)
    assert target.is_relative_to(builder.workdir / "target")
    assert command[command.index("--target-dir") + 1] == builder._container_path(target)
    mounts = [command[i + 1] for i, arg in enumerate(command) if arg == "--mount"]
    assert f"type=volume,dst={builder._container_path(target)},volume-nocopy" in mounts
    assert f"type=bind,src={target},dst=/fmst-cargo-export" in mounts
    assert command[command.index("builder:test") + 1:][:2] == [
        "python3", "/fmst-cargo-cache.py",
    ]
    assert command[-2:] == ["--test", "unit_a"]
    assert "/var/run/docker.sock" not in " ".join(command)
    assert builder.cargo_target_dir(manifest.parent) != (
        HostRuntimeBuilder().cargo_target_dir(manifest.parent)
    )
    builder.platform_name = "linux/amd64"
    assert builder.cargo_target_dir(manifest.parent).parent.name == "linux-amd64"


def test_docker_build_output_is_owned_by_each_builder(tmp_path: Path) -> None:
    framework = tmp_path / "delivery" / "GuestWeave"
    first = DockerRuntimeBuilder(image="builder:test", project_root=framework.parent,
        framework_root=framework, workdir=tmp_path / "consumer")
    second = DockerRuntimeBuilder(image="builder:test", project_root=framework.parent,
        framework_root=framework, workdir=first.workdir)
    target = first.cargo_target_dir(framework)
    assert target == first.cargo_target_dir(framework)
    assert target != second.cargo_target_dir(framework)
    assert target != first.cargo_target_dir(first.workdir / "intervention")
    assert target.is_relative_to(first.workdir)
    assert not target.is_relative_to(framework)


def test_split_workspace_mounts_framework_at_legacy_dependency_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    framework = tmp_path / "GuestWeave"
    framework.mkdir()
    source = tmp_path / "Firmenstein" / "src"
    source.mkdir(parents=True)
    (source / "fmst_iib_runtime").symlink_to("../../GuestWeave")
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("fmst_analyzer.runner.runtime_builder.subprocess.run", run)
    builder = create_runtime_builder(
        runtime_workspace=source / "fmst_iib_runtime",
        workdir=tmp_path / "work", image="builder:test",
    )
    builder.run_cargo(tmp_path / "work" / "Cargo.toml", "check", timeout=10)
    mounts = [calls[0][i + 1] for i, arg in enumerate(calls[0]) if arg == "--mount"]
    assert f"type=bind,src={framework},dst=/src/fmst_iib_runtime,readonly" in mounts
    assert not any(mount.endswith("dst=/src,readonly") for mount in mounts)
    assert builder._container_path(framework / "Cargo.toml") == (
        "/workspace/project/GuestWeave/Cargo.toml"
    )


def test_builder_timeout_removes_only_its_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if command[1] == "run":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("fmst_analyzer.runner.runtime_builder.subprocess.run", run)
    builder = DockerRuntimeBuilder(
        image="builder:test", project_root=tmp_path, workdir=tmp_path / "work",
    )
    with pytest.raises(subprocess.TimeoutExpired):
        builder.run_cargo(tmp_path / "Cargo.toml", "check", timeout=1)
    name = calls[0][calls[0].index("--name") + 1]
    assert calls[1] == ["docker", "rm", "--force", "--volumes", name]


def test_builder_cache_wait_honors_cancellation(tmp_path, monkeypatch):
    from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped

    budget = ExecutionBudget(60)
    builder = DockerRuntimeBuilder(image="test", project_root=tmp_path,
        workdir=tmp_path / "work", budget=budget)
    builder._cargo_lock.acquire()
    budget.cancelled.set()
    try:
        with pytest.raises(RunnerStopped, match="user_cancelled"):
            builder.run_cargo(tmp_path / "Cargo.toml", "check", timeout=30)
    finally:
        builder._cargo_lock.release()


def test_builder_releases_cache_lock_after_failed_invocation(tmp_path, monkeypatch):
    builder = DockerRuntimeBuilder(image="test", project_root=tmp_path,
        workdir=tmp_path / "work")

    def fail(*args, **kwargs):
        raise OSError("builder unavailable")

    monkeypatch.setattr(builder, "_run_container", fail)
    with pytest.raises(OSError, match="builder unavailable"):
        builder.run_cargo(tmp_path / "Cargo.toml", "check", timeout=30)
    assert builder._cargo_lock.acquire(blocking=False)
    builder._cargo_lock.release()


def test_external_framework_selection_controls_helpers_and_bundle_script(tmp_path, monkeypatch):
    framework = tmp_path / "delivery" / "guestweave-0.1"
    framework.mkdir(parents=True)
    work = tmp_path / "consumer" / "run"
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("fmst_analyzer.runner.runtime_builder.subprocess.run", run)
    builder = create_runtime_builder(runtime_workspace=framework, workdir=work, image="test")
    assert builder.framework_root == framework
    builder.build_host_bundle(framework / "target" / "worker", work / "bundle",
        binaries={"nc": Path("/usr/bin/nc")})
    command = calls[0]
    assert "/workspace/project/guestweave-0.1/tools/build_runtime_bundle.py" in command
    assert command[-2:] == ["--binary", "nc=/usr/bin/nc"]
    assert f"type=bind,src={framework},dst=/src/fmst_iib_runtime,readonly" in command
    assert not any("Firmenstein/src" in value for value in command
                   if "container_output.py" not in value)

    monkeypatch.setattr("fmst_analyzer.runner.runtime_builder.platform.system", lambda: "Linux")
    host = create_runtime_builder(runtime_workspace=framework, workdir=work)
    assert host.framework_root == framework
    host.build_host_bundle(framework / "target" / "worker", work / "host-bundle",
        binaries={"nc": Path("/usr/bin/nc")})
    assert calls[-1][1] == str(framework / "tools/build_runtime_bundle.py")
    assert calls[-1][-2:] == ["--binary", "nc=/usr/bin/nc"]


def test_runner_cargo_check_uses_configured_builder(tmp_path: Path) -> None:
    from fmst_analyzer.runner.agent import RuntimeEvidenceState, make_runner_tools

    calls = []

    class Builder(HostRuntimeBuilder):
        def run_cargo(self, manifest, subcommand, **kwargs):
            calls.append((manifest, subcommand))
            return subprocess.CompletedProcess(["docker"], 0, "Linux check passed", "")

    manifest = tmp_path / "Cargo.toml"
    tools = make_runner_tools(
        view=object(), rootfs=tmp_path, diagnostic_reports_root=tmp_path,
        intervention_manifest=manifest, evidence_state=RuntimeEvidenceState(),
        runtime_builder=Builder(),
    )
    cargo_check = next(tool for tool in tools if tool.name == "cargo_check")
    assert "Linux check passed" in cargo_check.invoke({})
    assert calls == [(manifest, "check")]


def test_runner_locates_cdylib_from_builder_output(tmp_path: Path) -> None:
    from fmst_analyzer.runner.runner import _locate_cdylib

    (tmp_path / "Cargo.toml").write_text('[package]\nname = "sample"\n')
    builder = DockerRuntimeBuilder(
        image="builder:test", project_root=tmp_path, workdir=tmp_path,
        platform_name="linux/arm64",
    )
    artifact = builder.cargo_target_dir(tmp_path) / "release" / "libsample.so"
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"\x7fELF")
    assert _locate_cdylib(tmp_path, builder) == artifact
