"""Permissions and symlinks are guest inputs even when file bytes stay equal."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped
from fmst_analyzer.runner.runner import _tree_sha256
from fmst_analyzer.runner.schema import RehostingResult, RuntimeAttempt


def test_directory_and_executable_permissions_change_execution_identity(tmp_path):
    directory = tmp_path / "var/run"
    directory.mkdir(parents=True)
    directory.chmod(0o755)
    before = _tree_sha256(tmp_path)
    directory.chmod(0o777)
    assert _tree_sha256(tmp_path) != before
    executable = tmp_path / "target"
    executable.write_bytes(b"unchanged bytes")
    executable.chmod(0o644)
    before = _tree_sha256(tmp_path)
    executable.chmod(0o755)
    assert _tree_sha256(tmp_path) != before


def test_guest_symlink_identity_does_not_follow_host_content(tmp_path):
    guest = tmp_path / "rootfs"
    guest.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("host content")
    link = guest / "absolute-link"
    link.symlink_to(outside)
    before = _tree_sha256(guest)
    outside.write_text("host content must not change the guest link identity")
    assert _tree_sha256(guest) == before
    link.unlink()
    link.symlink_to("/different/guest/path")
    assert _tree_sha256(guest) != before


def test_tree_identity_observes_shared_cancellation(tmp_path):
    (tmp_path / "file").write_bytes(b"fixture")
    budget = ExecutionBudget(10)
    budget.cancelled.set()
    with pytest.raises(RunnerStopped, match="user_cancelled"):
        _tree_sha256(tmp_path, budget)


def test_legacy_content_only_result_is_not_replayed_as_permission_bound():
    fixture = Path(__file__).parent / "fixtures/g4_runtime/runner.json"
    with pytest.raises(ValidationError):
        RehostingResult.model_validate_json(fixture.read_bytes())
    assert RuntimeAttempt.model_fields["tree_identity_version"].is_required()


def test_legacy_result_does_not_claim_launch_and_readiness_contract():
    fixture = Path(__file__).parent / "fixtures/g5_runtime_identity/runner.json"
    with pytest.raises(ValidationError, match="schema_version"):
        RehostingResult.model_validate_json(fixture.read_bytes())
