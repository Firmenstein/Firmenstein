"""Single-session draft tools, uncapped corrections and publication boundaries."""
import asyncio
import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_basic.agent import AgentResult
from fmst_analyzer.framework import runtime_workspace
from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.synthesizer.intervention_plan_analyzer import plan_agent as module
from fmst_analyzer.synthesizer.intervention_plan_analyzer.draft import PlanDraftStore
from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import build_planning_context
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import LaunchChoice, NoIntervention
from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import _catalog, _Resolver, scopes_for_test


@pytest.fixture
def case(tmp_path, monkeypatch):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    code, assembly = tmp_path / "code", tmp_path / "assembly"
    code.mkdir()
    assembly.mkdir()
    config = SimpleNamespace(planner_model="fixture-model", planner_reasoning_effort="max", agent_provider="codex",
        fw_rootfs_path=rootfs, decompiled_code_dir=code, disassembled_code_dir=assembly)
    catalog, resolver = _catalog(), _Resolver()
    store = PlanDraftStore(tmp_path / "plan_draft.json", catalog, resolver, build_planning_context(), service_goal="Serve the fixture protocol")
    monkeypatch.setattr(module, "make_analyzer_tools", lambda view: [])
    return config, catalog, resolver, store, tmp_path


class FakeAgent:
    def __init__(self, callbacks, kwargs):
        self.callbacks, self.kwargs = list(callbacks), kwargs
        self.tools = {tool.name: tool for tool in kwargs["tools"]}
        self.messages = []
        self.closed = False
        self.reasoning_effort = kwargs["reasoning_effort"]

    async def ainvoke(self, message, trace):
        self.messages.append(message)
        item = self.callbacks.pop(0)
        if isinstance(item, BaseException):
            raise item
        completion = item(self)
        return AgentResult(text=completion.model_dump_json(), structured_response=completion,
            provider="codex", session_id="one-session", turn_id=f"turn-{len(self.messages)}", status="completed")

    async def aclose(self):
        self.closed = True


def _close_claim(fake, *, choice="launch-test"):
    scope = scopes_for_test(["file:F1"])[0]
    result = fake.tools["apply_plan_batch"].invoke({"batch": {
        "expected_revision": 0, "reason": "Frozen evidence-backed decision",
        "launch_choice": {"recipe_id": choice, "reason": "The direct command is supported, without assuming the boot chain ran"},
        "no_interventions": {"native": NoIntervention(**scope.model_dump(), reason="The baseline preserves the required fixture interaction").model_dump()}}})
    assert result["decided_claims"] == 1
    return module.PlanCompletion(revision=result["revision"], summary="Fixture accounted for")


def _elf_view(case, machine=8, byte_order=1):
    path = case[0].fw_rootfs_path / "target.elf"
    ident = b"\x7fELF" + bytes([1, byte_order, 1]) + bytes(9)
    path.write_bytes(struct.pack(
        ("<" if byte_order == 1 else ">") + "16sHHIIIIIHHHHHH",
        ident, 2, machine, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0,
    ))
    # The ELF node may differ from the selected applet/launch basename.
    binary = SimpleNamespace(name="actual-elf", binary_path=path)
    graph = SimpleNamespace(get_node_by_name=lambda name: binary if name == binary.name else None)
    return AnalysisView(SimpleNamespace(lib_dep_graph=graph, analysis_level="semantic", root=binary))


def _run(case, monkeypatch, callbacks, *, view=None):
    config, catalog, resolver, store, root = case
    if view is None:
        view = _elf_view(case)
    instances = []
    def create(**kwargs):
        fake = FakeAgent(callbacks, kwargs)
        instances.append(fake)
        return fake
    monkeypatch.setattr(module, "create_analysis_agent", create)
    async def run():
        return await module.PlanAgent(config).run(catalog, resolver, view, store, trace_root=root / "trace")
    return run, instances


@pytest.mark.parametrize("choice", ["launch-test", None])
def test_single_agent_assesses_launch_and_completes_draft(case, monkeypatch, choice):
    run, instances = _run(case, monkeypatch, [lambda fake: _close_claim(fake, choice=choice)])
    plan = asyncio.run(run())
    assert len(instances) == 1 and instances[0].closed
    fake = instances[0]
    assert fake.kwargs["developer_instructions"] == ""
    assert fake.messages[0].startswith(module.PLAN_TASK_PROMPT + "\n\n")
    assert fake.messages[0].count(module.PLAN_TASK_PROMPT) == 1
    assert fake.kwargs["filesystem_access"] == "read_shell"
    runtime, roots = module.evidence_python_runtime()
    assert fake.kwargs["readable_roots"] == [case[0].decompiled_code_dir, case[0].disassembled_code_dir] + roots
    assert fake.kwargs["reasoning_effort"] == "max"
    assert fake.kwargs.get("max_tool_calls_per_turn") is None
    assert fake.kwargs["output_format"] is module.PlanCompletion
    assert plan.launch_choice.recipe_id == choice
    assert plan.service_goal == case[3].state.service_goal
    assert plan.producer.session_id == "one-session"
    assert plan.draft_revision == 1
    payload = json.loads((case[4] / "trace/input.json").read_text())
    assert payload["service_goal"] == plan.service_goal
    assert payload["filesystem_context"]["python_runtime"] == runtime
    assert payload["planning_context"]["runtime_observations"] == []
    sources = plan.planning_context.implementation_sources
    assert payload["planning_context"]["implementation_sources"] == {
        key: source.model_dump(exclude={"text"}) for key, source in sources.items()
    }
    assert fake.tools["read_baseline"].invoke({"source_keys": list(sources)}) == {
        "sources": {key: source.model_dump() for key, source in sources.items()}
    }


@pytest.mark.parametrize("machine,name,order,endian", [
    (8, "MIPS", 1, "LSB"), (8, "MIPS", 2, "MSB"), (40, "ARM", 1, "LSB"),
])
def test_planner_receives_actual_guest_elf_identity(case, monkeypatch, machine, name, order, endian):
    run, instances = _run(case, monkeypatch, [_close_claim], view=_elf_view(case, machine, order))
    asyncio.run(run())
    supplied = json.loads(instances[0].messages[0].split("Target planning input:\n", 1)[1])
    saved = json.loads((case[4] / "trace/input.json").read_text())
    assert supplied == saved
    assert supplied["guest_elf_identity"] == {
        "machine": name, "class": "ELF32", "byte_order": endian, "processor_flags": "0x0",
    }


@pytest.mark.parametrize("failure", ["missing", "not-elf"])
def test_invalid_guest_elf_stops_before_agent_creation(case, monkeypatch, failure):
    view = _elf_view(case)
    if failure == "missing":
        view.root.binary_path.unlink()
    else:
        view.root.binary_path.write_text("not an ELF")
    run, instances = _run(case, monkeypatch, [], view=view)
    with pytest.raises(ValueError, match="Cannot parse ELF identity"):
        asyncio.run(run())
    assert not instances
    assert case[3].state.revision == 0
    assert not (case[4] / "trace/input.json").exists()


def test_completion_feedback_corrects_only_missing_work_in_same_session(case, monkeypatch):
    def premature(fake):
        return module.PlanCompletion(revision=0, summary="Premature completion")
    run, instances = _run(case, monkeypatch, [premature, _close_claim])
    result = asyncio.run(run())
    fake = instances[0]
    assert len(instances) == 1 and len(fake.messages) == 2 and fake.closed
    assert "unprocessed claims" in fake.messages[1] and "file:F1" in fake.messages[1]
    assert "Target planning input" not in fake.messages[1]
    assert result.draft_revision == 1


def _format_error():
    error = ValueError("final response is not valid JSON at line 1 column 1")
    error.code = "structured_output_error"
    return error


def test_adapter_format_error_keeps_accepted_draft_and_corrects_in_same_session(case, monkeypatch):
    accepted = []

    def malformed(fake):
        _close_claim(fake)
        accepted.append(case[3].path.read_bytes())
        raise _format_error()

    def correct(fake):
        assert case[3].path.read_bytes() == accepted[0]
        assert "line 1 column 1" in fake.messages[-1]
        progress = fake.tools["read_plan"].invoke({})
        return module.PlanCompletion(revision=progress["revision"], summary="Accepted draft retained")

    run, instances = _run(case, monkeypatch, [malformed, correct])
    plan = asyncio.run(run())
    assert len(instances) == 1 and len(instances[0].messages) == 2 and instances[0].closed
    assert plan.draft_revision == 1 and case[3].path.read_bytes() == accepted[0]


def test_repeated_format_errors_preserve_complete_draft_without_publication(case, monkeypatch):
    def malformed(fake):
        _close_claim(fake)
        raise _format_error()

    run, instances = _run(case, monkeypatch, [malformed, *[_format_error() for _ in range(7)], asyncio.CancelledError()])
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())
    assert len(instances[0].messages) == 9 and instances[0].closed
    assert case[3].validate_complete().revision == 1
    assert not (case[4] / "intervention_plan_result.json").exists()


@pytest.mark.parametrize("failure", [RuntimeError("provider disconnected"), ValueError("SDK rejected effort")])
def test_provider_errors_are_not_output_correction_or_semantic_unknown(case, monkeypatch, failure):
    run, instances = _run(case, monkeypatch, [failure])
    with pytest.raises(type(failure), match=str(failure)):
        asyncio.run(run())
    assert instances[0].closed and len(instances[0].messages) == 1
    assert case[3].state.revision == 0 and not case[3].state.unresolved
    assert not (case[4] / "intervention_plan_result.json").exists()


def test_cancellation_retains_partial_state_and_never_publishes(case, monkeypatch):
    def incomplete(fake):
        return module.PlanCompletion(revision=0, summary="Still incomplete")
    run, instances = _run(case, monkeypatch, [incomplete] * 7 + [asyncio.CancelledError()])
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run())
    assert instances[0].closed and len(instances[0].messages) == 8
    assert case[3].path.is_file()


def test_read_plan_paginates_and_failed_tool_batch_preserves_state(case):
    store = case[3]
    tools = {tool.name: tool for tool in module.make_plan_tools(store)}
    page = tools["read_plan"].invoke({"remaining_only": True, "limit": 1})
    assert page["showing"] == page["total"] == 1 and page["next_offset"] is None
    before = store.path.read_bytes()
    with pytest.raises(ValueError, match="unknown finding"):
        tools["apply_plan_batch"].invoke({"batch": {"expected_revision": 0, "reason": "invalid source",
            "no_interventions": {"bad": {"finding_ref": "invented", "claim_indices": [0], "applicability": "fixture", "reason": "bad"}}}})
    assert store.path.read_bytes() == before
    with pytest.raises(ValueError, match="unknown decision IDs"):
        tools["read_plan"].invoke({"decision_ids": ["invented"]})


def test_baseline_public_api_is_complete_frozen_source_evidence(case):
    import hashlib

    store = case[3]
    tool = next(t for t in module.make_plan_tools(store) if t.name == "read_baseline")
    keys = ["iib_context_api", "iib_pseudo_file_api", "iib_capability_identifiers",
            "iib_native_call_implementation"]
    records = tool.invoke({"source_keys": keys})["sources"]
    for record in records.values():
        relative = Path(record["relative_path"]).relative_to("fmst_iib_runtime")
        raw = (runtime_workspace() / relative).read_bytes()
        assert record["file_sha256"] == hashlib.sha256(raw).hexdigest()
        assert record["text"] == raw.decode("utf-8")
    frozen = store.state.model_dump_json()
    with pytest.raises(ValueError, match="unknown baseline source keys.*invented"):
        tool.invoke({"source_keys": [keys[0], "invented"]})
    assert store.state.model_dump_json() == frozen
    # Returned payloads must not let a consumer mutate the persisted evidence.
    records[keys[0]]["text"] = "not the source"
    assert tool.invoke({"source_keys": [keys[0]]})["sources"][keys[0]]["text"] != "not the source"
