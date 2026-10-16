import json
from pathlib import Path
import subprocess
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from fmst_analyzer.synthesizer.intervention_generator import agents as agents_module
from fmst_analyzer.synthesizer.intervention_generator.agents import (
    _make_verify_unit_tool,
)
from fmst_analyzer.synthesizer.intervention_generator.prompts.execution_unit import (
    build_execution_unit_user_message,
)


def test_verify_unit_hides_controller_owned_arguments(tmp_path):
    verify = _make_verify_unit_tool(
        tmp_path / "intervention/Cargo.toml",
        tmp_path / "tests/Cargo.toml",
        "unit_a_test",
    )

    assert verify.args_schema.model_fields == {}
    assert verify.description


def test_verify_unit_serializes_concurrent_cargo_calls(monkeypatch):
    active = 0
    max_active = 0
    lock = threading.Lock()

    def fake_run_cargo(_manifest, _args, *, timeout):
        assert 0 < timeout <= 120
        nonlocal active, max_active
        with lock:
            active += 1
            max_active = max(max_active, active)
        time.sleep(0.02)
        with lock:
            active -= 1
        return subprocess.CompletedProcess([], 0, "ok", "")

    monkeypatch.setattr(agents_module, "_run_cargo", fake_run_cargo)
    first = _make_verify_unit_tool(Path("/a"), Path("/b"), "first")
    second = _make_verify_unit_tool(Path("/c"), Path("/d"), "second")
    threads = [
        threading.Thread(target=tool.invoke, args=({},))
        for tool in (first, second)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert max_active == 1


def test_verify_unit_shares_deadline_between_queue_check_and_test(monkeypatch, tmp_path):
    clock = [0.0]
    lock = Mock()

    def acquire(*, timeout):
        assert timeout == 120
        clock[0] += 10
        return True

    timeouts = []

    def cargo(_manifest, _args, *, timeout):
        timeouts.append(timeout)
        clock[0] += 50
        return subprocess.CompletedProcess([], 0, "ok", "")

    lock.acquire.side_effect = acquire
    monkeypatch.setattr(agents_module, "_VERIFY_UNIT_LOCK", lock)
    monkeypatch.setattr(agents_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(agents_module, "_run_cargo", cargo)
    verify = _make_verify_unit_tool(tmp_path / "a", tmp_path / "b", "unit_test")
    assert verify.timeout_seconds == 120
    assert "unit_test.exit_code=0" in verify.invoke({})
    assert timeouts == [110, 60]
    lock.release.assert_called_once()


def test_expired_verify_worker_does_not_start_cargo(monkeypatch, tmp_path):
    clock = [0.0]
    lock = Mock()

    def acquire(*, timeout):
        clock[0] += 121
        return True

    lock.acquire.side_effect = acquire
    cargo = Mock()
    monkeypatch.setattr(agents_module, "_VERIFY_UNIT_LOCK", lock)
    monkeypatch.setattr(agents_module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(agents_module, "_run_cargo", cargo)
    verify = _make_verify_unit_tool(tmp_path / "a", tmp_path / "b", "unit_test")
    with pytest.raises(TimeoutError, match="tool deadline"):
        verify.invoke({})
    cargo.assert_not_called()
    lock.release.assert_called_once()


def test_execution_unit_message_has_both_outputs_and_no_eager_evidence():
    message = build_execution_unit_user_message(
        target_context={
            "image_name": "firmware",
            "target_binary": "service",
            "architecture": "mipsbe",
            "byte_order": "big",
        },
        unit={"unit_id": "unit-a", "finding_refs": ["file:F1"]},
        related_units=[{"unit_id": "unit-peer"}],
        selected_launch={"recipe_id": "launch-a"},
        intervention_files=[{"path": "/crate/src/unit_a/logic.rs", "current": ""}],
        test_file="/tests/unit_a_test/main.rs",
        target_crate_name="intervention_service",
        import_paths=["intervention_service::state::GlobalState"],
        manifest_global_state_path="intervention_service::state::GlobalState",
        read_only_context_roots=["/decompiled", "/reports"],
    )

    payload = json.loads(message.split("Execution Unit generation input:\n", 1)[1])
    assert payload == {
        "target_context": {
            "image_name": "firmware",
            "target_binary": "service",
            "architecture": "mipsbe",
            "byte_order": "big",
        },
        "unit": {"unit_id": "unit-a", "finding_refs": ["file:F1"]},
        "other_units_in_plan": [{"unit_id": "unit-peer"}],
        "selected_launch_recipe": {"recipe_id": "launch-a"},
        "intervention_files": [{"path": "/crate/src/unit_a/logic.rs", "current": ""}],
        "test_file": "/tests/unit_a_test/main.rs",
        "target_crate_name": "intervention_service",
        "import_paths": ["intervention_service::state::GlobalState"],
        "manifest_global_state_path": "intervention_service::state::GlobalState",
        "read_only_context_roots": ["/decompiled", "/reports"],
    }
