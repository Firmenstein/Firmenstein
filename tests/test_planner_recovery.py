"""P-25/P-26: real adapter boundaries with portable data-only fixtures."""
import asyncio
import copy
import json
from pathlib import Path
import sys

import pytest

from fmst_basic.agent.codex_agent import _CodexRuntime, _ThreadContext, _permission_profile_config
from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence_runtime import evidence_python_runtime
from fmst_analyzer.synthesizer.intervention_plan_analyzer import evidence_runtime
from fmst_analyzer.synthesizer.intervention_plan_analyzer.plan_agent import make_plan_tools
from fmst_analyzer.synthesizer.intervention_plan_analyzer.draft import PlanDraftStore
from test_plan_draft import setup, unit, scope  # reuse synthetic source/catalog fixtures


def test_explicit_python_runtime_and_read_only_installation_roots():
    context, roots = evidence_python_runtime()
    assert context["command_prefix"][0] == str(Path(sys.executable).resolve())
    assert context["command_prefix"][1:4] == ["-I", "-B", "-c"]
    assert Path(sys.prefix).resolve() in roots
    assert Path(sys.base_prefix).resolve() in roots
    profile = _permission_profile_config("read_shell", readable_roots=roots)
    permissions = profile["permissions"][profile["default_permissions"]]
    assert not permissions["network"]["enabled"]
    assert permissions["filesystem"][":workspace_roots"] == {".": "read"}
    assert all(permissions["filesystem"][str(path)] == {".": "read"} for path in roots)


def test_canonical_python_bootstrap_restores_only_explicit_packages(tmp_path, monkeypatch):
    package_dir = tmp_path / "packages"
    package_dir.mkdir()
    (package_dir / "fixture_evidence_module.py").write_text("value = 41")
    monkeypatch.setattr(evidence_runtime.sysconfig, "get_path", lambda key: str(package_dir))
    context, roots = evidence_python_runtime()
    assert package_dir in roots
    assert tmp_path not in roots
    monkeypatch.setattr(sys, "path", sys.path.copy())
    monkeypatch.setattr(sys, "argv", ["-c", "import fixture_evidence_module; result = fixture_evidence_module.value"])
    namespace = {}
    try:
        exec(context["command_prefix"][4], namespace)
        assert namespace["result"] == 41
    finally:
        sys.modules.pop("fixture_evidence_module", None)


async def dispatch(tools, arguments):
    runtime = _CodexRuntime()
    runtime._contexts["fixture"] = _ThreadContext(tools=tools, loop=asyncio.get_running_loop())
    try:
        return await asyncio.to_thread(runtime._handle_server_request, "item/tool/call", {
            "threadId": "fixture", "tool": "apply_plan_batch", "arguments": arguments})
    finally:
        runtime.close()


def tool_map(store):
    return {item.name: item for item in make_plan_tools(store)}


@pytest.mark.parametrize("envelope", ["object", "string", "proxy"])
def test_nested_rejection_recovers_exact_input_then_accepts_corrected_batch(setup, envelope):
    store, catalog, resolver, context, _ = setup
    tools = tool_map(store)
    contract = unit(scope()).model_dump(mode="json")
    # Reproduce rejection before apply_plan_batch executes. Preserve long facts.
    contract["behavior_scopes"] = []
    contract["contract"]["operations"] = [("verified synthetic value; " * 2000).rstrip()]
    batch = {"expected_revision": 0, "reason": "Keep previously established facts", "units": {"config": contract}}
    original = {"batch": batch}
    raw = original if envelope == "object" else json.dumps(original, ensure_ascii=False)
    if envelope == "proxy":
        raw = {"arguments": raw}
    before = store.path.read_bytes()
    response = asyncio.run(dispatch(tools, raw))
    assert response["success"] is False
    message = response["contentItems"][0]["text"]
    assert "batch.units.config.behavior_scopes" in message
    listing = tools["read_failed_batches"].invoke({})
    assert listing["total"] == listing["showing"] == 1
    batch_id = listing["failures"][0]["failed_batch_id"]
    assert batch_id in message
    assert store.path.read_bytes() == before and store.state.revision == 0
    # Recreate store/tools as after resumption; failure is still retrievable.
    loaded = PlanDraftStore(store.path, catalog, resolver, context, service_goal=store.state.service_goal,
                            resolve_unit=store.resolve_unit)
    recovered = tool_map(loaded)["read_failed_batches"].invoke({"batch_ids": [batch_id]})["records"][batch_id]
    assert recovered["arguments"] == raw
    assert "behavior_scopes" in recovered["error"]
    corrected = copy.deepcopy(original)
    corrected["batch"]["units"]["config"]["behavior_scopes"] = [scope().model_dump(mode="json")]
    result = asyncio.run(dispatch(tools, corrected))
    assert result["success"] is True
    assert store.state.units["config"].contract.operations == contract["contract"]["operations"]
    assert tools["read_failed_batches"].invoke({})["total"] == 1


@pytest.mark.parametrize("raw,expected", [
    ('{\n "batch":\n}', "line 3 column 1"),
    ({"arguments": '{\n "batch":\n}'}, "line 3 column 1"),
    ({"batch": {"expected_revision": 17, "reason": "Stale revision fixture"}}, "current revision=0"),
])
def test_wire_and_contract_failures_have_full_recoverable_inputs(setup, raw, expected):
    store, *_ = setup
    tools = tool_map(store)
    response = asyncio.run(dispatch(tools, raw))
    assert not response["success"]
    assert expected in response["contentItems"][0]["text"]
    listing = tools["read_failed_batches"].invoke({})
    batch_id = listing["failures"][0]["failed_batch_id"]
    assert tools["read_failed_batches"].invoke({"batch_ids": [batch_id]})["records"][batch_id]["arguments"] == raw
    assert store.state.revision == 0


def test_failure_pagination_and_identity_isolation(setup):
    store, catalog, resolver, context, _ = setup
    tools = tool_map(store)
    for number in range(5):
        tools["apply_plan_batch"].error_feedback({"attempt": number}, ValueError("fixture rejection"))
    first = tools["read_failed_batches"].invoke({"limit": 2})
    assert (first["showing"], first["total"], first["next_offset"]) == (2, 5, 2)
    second = tools["read_failed_batches"].invoke({"offset": 2, "limit": 3})
    assert second["next_offset"] is None and second["showing"] == 3
    all_ids = [item["failed_batch_id"] for item in first["failures"] + second["failures"]]
    assert len(set(all_ids)) == 5
    for invalid in ("../draft", "/tmp/elsewhere", "a" * 32):
        with pytest.raises(ValueError, match="unknown failed_batch_id"):
            tools["read_failed_batches"].invoke({"batch_ids": [invalid]})
    store.path.unlink()
    other = PlanDraftStore(store.path, catalog, resolver, context, service_goal="A different service goal")
    other_tools = tool_map(other)
    assert other_tools["read_failed_batches"].invoke({})["total"] == 0
    with pytest.raises(ValueError, match="unknown failed_batch_id"):
        other_tools["read_failed_batches"].invoke({"batch_ids": [all_ids[0]]})


def test_failure_storage_error_preserves_original_diagnostic(setup, monkeypatch):
    tools = tool_map(setup[0])
    def fail(*args):
        raise OSError("read-only storage fixture")
    tools["apply_plan_batch"].error_context = fail
    message = tools["apply_plan_batch"].error_feedback({}, ValueError("original location"))
    assert "ValueError: original location" in message
    assert "could not be saved" in message and "read-only storage fixture" in message
