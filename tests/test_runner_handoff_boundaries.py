"""Deterministic counterexamples for Generator/Runner handoff boundaries."""

import subprocess
import tarfile
from pathlib import Path

import pytest
from pydantic import ValidationError

import fmst_analyzer.runner.docker_sandbox as sandbox_module
from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
from fmst_analyzer.runner.rootfs_actions import RootfsAction, apply_rootfs_actions
from fmst_analyzer.runner.runner import _run_enabled_tests
from fmst_analyzer.runner.schema import CompanionProcess, InteractionProbe, RunnerDecision
from fmst_analyzer.synthesizer.intervention_generator.shell import (
    unit_test_relative_path,
    unit_test_target,
)


def test_rootfs_import_does_not_expose_staging_host_owners(tmp_path, monkeypatch):
    """A portable staged directory must not import the developer's identity."""
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    (rootfs / "state").write_bytes(b"persisted-state")
    (rootfs / "state").chmod(0o640)
    (rootfs / "alias").symlink_to("/state")
    before = (rootfs / "state").stat()
    sandbox = DockerRootfsSandbox(
        rootfs=rootfs, workdir=tmp_path / "work", target_binary="service",
        executable_path="/service", guest_arch="arm",
        runtime_workspace=tmp_path / "runtime", env_script=None,
    )
    sandbox.preparation_root.mkdir(parents=True)
    imports = []

    def import_image(command, **kwargs):
        assert command[:2] == ["docker", "import"]
        with tarfile.open(fileobj=kwargs["stdin"], mode="r:") as archive:
            imports.append({m.name: (m.uid, m.gid, m.uname, m.gname,
                                    m.mode, m.linkname) for m in archive.getmembers()})
            assert archive.extractfile("state").read() == b"persisted-state"
        return subprocess.CompletedProcess(command, 0, "sha256:image", "")

    monkeypatch.setattr(sandbox, "_process", import_image)
    original = tarfile.TarFile.gettarinfo
    for host_uid, host_gid in [(501, 20), (1001, 1002)]:
        def host_metadata(archive, *args, **kwargs):
            info = original(archive, *args, **kwargs)
            info.uid, info.gid = host_uid, host_gid
            info.uname, info.gname = "developer", "staff"
            return info

        monkeypatch.setattr(tarfile.TarFile, "gettarinfo", host_metadata)
        sandbox._import_rootfs(rootfs)

    assert imports[0] == imports[1]
    assert imports[0]["state"] == (0, 0, "", "", 0o640, "")
    assert imports[0]["alias"][:4] == (0, 0, "", "")
    assert imports[0]["alias"][-1] == "/state"
    after = (rootfs / "state").stat()
    assert (before.st_uid, before.st_gid, before.st_mode) == (
        after.st_uid, after.st_gid, after.st_mode)


def test_runner_consumes_generator_test_layout(tmp_path):
    unit_id = "unit-example"
    source = tmp_path / unit_test_relative_path(unit_id)
    source.parent.mkdir(parents=True)
    source.write_text("#[test] fn caller_visible_behavior() {}\n")
    calls = []

    class Builder:
        def run_cargo(self, manifest, subcommand, **kwargs):
            calls.append((manifest, subcommand, kwargs))
            return subprocess.CompletedProcess([], 0, "test passed", "")

    result = _run_enabled_tests(Builder(), tmp_path, {unit_id}, timeout=30)
    assert result.returncode == 0, result.stderr
    assert calls == [(tmp_path / "Cargo.toml", "test", {
        "timeout": 30, "extra_args": ("--test", unit_test_target(unit_id)),
    })]


@pytest.mark.parametrize("args", [["$PORT", "", "a b", ";", "&&", "|"], ["'quoted'", "a\nb"]])
def test_literal_exec_arguments_are_preserved(args):
    peer = CompanionProcess(
        executable_path="/usr/bin/peer", args=args,
        environment={"TOKEN": "$literal", "EMPTY": ""}, evidence_ref="ipc.json#peer",
    )
    decision = RunnerDecision(
        action="run", probe=InteractionProbe(port=80, request_text="request"),
        guest_args=args, guest_environment=peer.environment,
        companion_processes=[peer], summary="literal argv from launch evidence",
    )
    assert decision.guest_args == args
    assert decision.companion_processes[0].args == args
    assert decision.guest_environment == {"TOKEN": "$literal", "EMPTY": ""}


@pytest.mark.parametrize("is_peer", [True, False])
def test_exec_arguments_reject_nul(is_peer):
    with pytest.raises(ValidationError, match="NUL"):
        if is_peer:
            CompanionProcess(executable_path="/peer", args=["x\x00y"], evidence_ref="ipc")
        else:
            RunnerDecision(action="run", probe=InteractionProbe(port=80, request_text="r"),
                           guest_args=["x\x00y"], summary="invalid exec")


def test_rootfs_actions_validate_sources_at_execution_time(tmp_path):
    actions = [
        RootfsAction(action="write_file", path="/etc/new", content="generated"),
        RootfsAction(action="copy_file", path="/etc/copied", source_path="/etc/new"),
    ]
    assert apply_rootfs_actions(actions, tmp_path) == actions
    assert (tmp_path / "etc/copied").read_text() == "generated"
    with pytest.raises(ValueError, match="does not exist"):
        apply_rootfs_actions([
            RootfsAction(action="copy_file", path="/x", source_path="/missing"),
        ], tmp_path)


def test_rootfs_action_sequence_preserves_repeated_operations(tmp_path):
    actions = [
        RootfsAction(action="write_file", path="/value", content="one"),
        RootfsAction(action="write_file", path="/value", content="two"),
        RootfsAction(action="write_file", path="/value", content="one"),
    ]
    assert apply_rootfs_actions(actions, tmp_path) == actions
    assert (tmp_path / "value").read_text() == "one"


def test_prepare_and_close_only_clean_their_session(tmp_path, monkeypatch):
    """Model Docker label selection, including resources created before failure."""
    a = DockerRootfsSandbox(
        rootfs=tmp_path / "rootfs", workdir=tmp_path, target_binary="httpd",
        executable_path="/httpd", guest_arch="arm",
        runtime_workspace=tmp_path / "runtime", env_script=None,
    )
    b = DockerRootfsSandbox(
        rootfs=a.rootfs, workdir=tmp_path, target_binary="httpd",
        executable_path="/httpd", guest_arch="arm",
        runtime_workspace=tmp_path / "runtime", env_script=None,
    )
    a.session_root.mkdir(parents=True)
    (a.session_root / "evidence").write_text("keep")
    resources = {"container-a": a.session_id, "container-b": b.session_id}
    commands = []

    def docker_run(command, **kwargs):
        commands.append(command)
        if command[:3] == ["docker", "ps", "-aq"]:
            selected = [key for key, owner in resources.items()
                        if f"label=fmst.runner.session={owner}" in command]
            # No session filter means Docker matches all same-target resources.
            if not any("label=fmst.runner.session=" in item for item in command):
                selected = list(resources)
            return subprocess.CompletedProcess(command, 0, "\n".join(selected), "")
        if command[:3] == ["docker", "rm", "--force"]:
            resources.pop(command[-1], None)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(sandbox_module.subprocess, "run", docker_run)
    monkeypatch.setattr(sandbox_module, "_docker", lambda *args: None)
    monkeypatch.setattr(b, "_ensure_harness", lambda: (_ for _ in ()).throw(RuntimeError("build failed")))
    with pytest.raises(RuntimeError, match="build failed"):
        b.prepare()
    b.close()
    b.close()
    assert resources == {"container-a": a.session_id}
    assert (a.session_root / "evidence").read_text() == "keep"
    for command in commands:
        if command[:3] in (["docker", "ps", "-aq"], ["docker", "network", "ls"], ["docker", "image", "ls"]):
            assert f"label=fmst.runner.session={b.session_id}" in command


def test_close_stops_deleting_files_when_cleanup_deadline_expires(tmp_path, monkeypatch):
    """Cleanup must check between filesystem operations, not only before rmtree."""
    import json
    from fmst_analyzer.runner import budget as budget_module
    from fmst_analyzer.runner.budget import ExecutionBudget

    clock = [10.0]
    monkeypatch.setattr(budget_module.time, "monotonic", lambda: clock[0])
    budget = ExecutionBudget(10, cleanup_seconds=5)
    sandbox = DockerRootfsSandbox(rootfs=tmp_path / "source", workdir=tmp_path,
        target_binary="guest", executable_path="/guest", guest_arch="arm",
        runtime_workspace=tmp_path / "runtime", env_script=None, budget=budget)
    monkeypatch.setattr(sandbox, "_cleanup_owned_resources", lambda: None)
    disposable = sandbox.session_root / "rootfs"
    disposable.mkdir(parents=True)
    for index in range(3):
        (disposable / str(index)).write_text("disposable")
    outside = tmp_path / "keep"
    outside.write_text("user data")
    (disposable / "link").symlink_to(outside)
    original_unlink = sandbox_module.os.unlink
    deletions = []

    def elapsed_unlink(path, *args, **kwargs):
        deletions.append(str(path))
        original_unlink(path, *args, **kwargs)
        clock[0] = 21.0

    monkeypatch.setattr(sandbox_module.os, "unlink", elapsed_unlink)
    sandbox.close()
    assert len(deletions) == 1
    assert disposable.is_dir()
    assert outside.read_text() == "user data"
    records = json.loads((sandbox.session_root / "cleanup.json").read_text())
    assert any(record.get("error") == "session_budget_exhausted" for record in records)
