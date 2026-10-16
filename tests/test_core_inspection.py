"""Core queries preserve captured bytes, source identity, and execution bounds."""

import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import struct

import pytest

from fmst_analyzer.runner.core_inspection import inspect_core, render_inspection
from fmst_analyzer.runner.agent import RuntimeEvidenceState, make_runner_tools
from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped
from fmst_analyzer.runner.runtime_dump import RuntimeDumpManifest


def fixture(tmp_path):
    root = tmp_path / "runtime-dump"
    root.mkdir()
    core = root / "guest.core"
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    header = struct.pack("<HHIIIIIHHHHHH", 4, 40, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    segment = struct.pack("<IIIIIIII", 1, 84, 0x4000, 0, 256, 512, 6, 4096)
    core.write_bytes(ident + header + segment + b"x" * 256)
    manifest = RuntimeDumpManifest(session_id="s", attempt_number=1, status="partial",
        capture_kind="crash", source="guest_elf_core", guest_arch="arm", byte_order="little",
        word_bits=32, sampled_unix_ns=1, termination_reason="target_exit", pid=7,
        core_path="runtime-dump/guest.core",
        files={"runtime-dump/guest.core": hashlib.sha256(core.read_bytes()).hexdigest()})
    path = root / "manifest.json"
    path.write_text(manifest.model_dump_json())
    return path, core


def test_source_changed_does_not_launch_debugger(tmp_path, monkeypatch):
    path, core = fixture(tmp_path)
    def forbidden(*args, **kwargs):
        pytest.fail("changed source must not reach a process")
    monkeypatch.setattr("fmst_analyzer.runner.core_inspection.subprocess.run", forbidden)
    core.write_bytes(b"changed input")
    result = inspect_core(path)
    assert result["status"] == "source_changed"
    assert result["command"] == []
    assert json.loads(Path(result["receipt_path"]).read_text())["sources"]["core"]["sha256"] == hashlib.sha256(b"changed input").hexdigest()
    result = inspect_core(path, manifest_sha256="0" * 64)
    assert result["status"] == "source_changed"


@pytest.mark.parametrize("address", ["$sp; shell id", "$sp\nrun", "*(int*)0x10", "foo()", "$sp+foo", "-ex quit"])
def test_queries_reject_commands_and_arbitrary_expressions(tmp_path, address):
    path, _ = fixture(tmp_path)
    with pytest.raises(ValueError, match="address"):
        inspect_core(path, operation="memory", thread_id=1, address=address)
    assert not (tmp_path / "core-inspections").exists()


def test_only_private_core_snapshot_is_loaded_and_full_output_retained(tmp_path, monkeypatch):
    path, core = fixture(tmp_path)
    monkeypatch.setattr("fmst_analyzer.runner.core_inspection.shutil.which", lambda _: "/test/gdb")
    output = "missing captured memory\n" + "x" * 30000
    def process(command, **kwargs):
        snapshot = Path(next(arg.removeprefix("--core=") for arg in command if arg.startswith("--core=")))
        assert snapshot.read_bytes() == core.read_bytes()
        assert snapshot != core
        assert "set auto-load off" in command and "set debuginfod enabled off" in command
        assert not any(arg.endswith("guest.elf") for arg in command)
        if command[-1].startswith('printf "__FMST_ADDRESS__'):
            return subprocess.CompletedProcess(command, 0, "__FMST_ADDRESS__=0x4000\n", "")
        assert command[-1] == "x/16bx $sp-64"
        return subprocess.CompletedProcess(command, 1, output, "Cannot access memory")
    monkeypatch.setattr("fmst_analyzer.runner.core_inspection.subprocess.run", process)
    result = inspect_core(path, operation="memory", thread_id=2, address="$sp-64", count=16)
    assert result["status"] == "query_failed" and result["stdout"] == output
    saved = json.loads(Path(result["receipt_path"]).read_text())
    assert saved == result
    rendered = json.loads(render_inspection(result))
    assert "stdout" not in rendered and rendered["complete_output_chars"]["stdout"] == len(output)
    assert Path(result["receipt_path"]).with_name("stdout.txt").read_text() == output


def test_uncaptured_zero_filled_core_pages_never_become_memory_evidence(tmp_path, monkeypatch):
    path, _ = fixture(tmp_path)
    monkeypatch.setattr("fmst_analyzer.runner.core_inspection.shutil.which", lambda _: "/test/gdb")
    commands = []
    def process(command, **kwargs):
        commands.append(command)
        assert command[-1].startswith('printf "__FMST_ADDRESS__')
        return subprocess.CompletedProcess(command, 0, "__FMST_ADDRESS__=0x4100\n", "")
    monkeypatch.setattr("fmst_analyzer.runner.core_inspection.subprocess.run", process)
    result = inspect_core(path, operation="disassemble", thread_id=1, address="$pc", count=8)
    assert result["status"] == "unavailable" and "uncaptured" in result["error"]
    assert len(commands) == 1 and not result["command"]
    assert result["requested_range"] == {"start": "0x4100", "maximum_bytes": 32}


def test_unverified_core_and_path_escape_do_not_reach_process(tmp_path, monkeypatch):
    path, core = fixture(tmp_path)
    data = json.loads(path.read_text())
    data["core_path"] = "../outside.core"
    data["files"]["../outside.core"] = hashlib.sha256(core.read_bytes()).hexdigest()
    (tmp_path.parent / "outside.core").write_bytes(core.read_bytes())
    path.write_text(json.dumps(data))
    result = inspect_core(path)
    assert result["status"] == "unavailable" and result["command"] == []
    data["core_path"] = None
    path.write_text(json.dumps(data))
    assert "no verified target core" in inspect_core(path)["error"]


def test_cancellation_preserves_receipt_and_uses_shared_budget(tmp_path, monkeypatch):
    path, _ = fixture(tmp_path)
    budget = ExecutionBudget(60)
    monkeypatch.setattr("fmst_analyzer.runner.core_inspection.shutil.which", lambda _: "/test/gdb")
    def process(command, **kwargs):
        assert kwargs["budget"] is budget and kwargs["timeout"] == 30
        raise RunnerStopped("user_cancelled")
    monkeypatch.setattr("fmst_analyzer.runner.core_inspection.run_process", process)
    with pytest.raises(RunnerStopped):
        inspect_core(path, budget=budget)
    receipt = json.loads(next((tmp_path / "core-inspections").glob("*/receipt.json")).read_text())
    assert receipt["status"] == "stopped"


def test_native_runner_tool_routes_latest_attempt_only(tmp_path, monkeypatch):
    state = RuntimeEvidenceState()
    received = []
    def inspect(path, **kwargs):
        received.append(path)
        return {"status": "unavailable", "error": "no captured core"}
    monkeypatch.setattr("fmst_analyzer.runner.agent.inspect_core", inspect)
    tools = make_runner_tools(view=object(), rootfs=tmp_path,
        diagnostic_reports_root=tmp_path, intervention_manifest=tmp_path / "Cargo.toml", evidence_state=state)
    tool = next(t for t in tools if t.name == "inspect_runtime_core")
    state.runtime_dump_manifest = tmp_path / "old.json"
    asyncio.run(tool.ainvoke({}))
    state.reset()
    asyncio.run(tool.ainvoke({}))
    assert received == [tmp_path / "old.json", None]
