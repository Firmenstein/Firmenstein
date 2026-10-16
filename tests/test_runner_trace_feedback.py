"""Counterexamples for retained trace fidelity, mapping and Agent presentation."""
import hashlib
import json
import random
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner.agent import RuntimeEvidenceState, make_runner_tools
from fmst_analyzer.runner.owner_context import persist_runtime_owners, read_runtime_owners
from fmst_analyzer.runner.schema import RuntimeTraceContext, RuntimeEventContext
from fmst_analyzer.runner.trace_compaction import compact_trace_context, expand_trace_context
from fmst_analyzer.runner.evidence_views import failure_overview, hook_owner
from fmst_analyzer.runner.schema import RuntimeMemorySnapshot, RuntimeRecentBlock, RuntimeRegister, RuntimeSourceLocation
from fmst_analyzer.runner.trace_context import (
    _BinarySourceIndex, _FunctionArtifact, _loaded_images, _location_for_pc,
    render_runtime_trace_context,
)


def context(**kwargs):
    return RuntimeTraceContext(raw_trace_schema_version=5, main_load_address=0,
        total_block_executions=10000, mapped_unique_blocks=0, unmapped_unique_blocks=0,
        images=[], functions=[], recent_blocks=[], recent_focus_blocks=[], events=[], **kwargs)


def tool_for(tmp_path, value, name):
    path = tmp_path / "context.json"
    path.write_text(value.model_dump_json())
    state = RuntimeEvidenceState()
    state.trace_context_json = path
    state.attempt_json = tmp_path / "attempt.json"
    state.attempt_json.write_text('{"execution_hashes":{"fixture":"unchanged"}}')
    tools = make_runner_tools(view=object(), rootfs=tmp_path,
        diagnostic_reports_root=tmp_path, intervention_manifest=tmp_path / "Cargo.toml", evidence_state=state)
    return next(item for item in tools if item.name == name)


def test_lossless_loops_keep_exit_order_counts_and_changed_memory():
    original = context(dropped_focus_tail_entries=7123).model_dump(mode="json")
    a = {"runtime_pc": 10, "consecutive_hits": 1, "location": {"assembly_context": ["same assembly"]}}
    b = {"runtime_pc": 20, "consecutive_hits": 2, "location": None}
    original["recent_blocks"] = [a, b] * 256 + [{**a, "consecutive_hits": 3}]
    original["events"] = [{"sequence": n, "elapsed_ns": n * 10, "memory": [n % 3],
                           "location": a["location"]} for n in range(100)]
    encoded = compact_trace_context(original)
    assert expand_trace_context(encoded) == original
    assert encoded["streams"]["recent_blocks"]["runs"][0] == {"pattern": [0, 1], "repeat": 256}
    assert len(json.dumps(encoded)) < len(json.dumps(original)) / 2
    assert encoded["metadata"]["dropped_focus_tail_entries"] == 7123
    # Encoding is not permitted to mutate the independent evidence.
    assert original["recent_blocks"][0] == a


def test_random_and_nested_patterns_round_trip_with_exact_types():
    rng = random.Random(1729)
    for length in (0, 1, 2, 64, 513):
        value = context().model_dump(mode="json")
        value["recent_focus_blocks"] = [{"pc": rng.randrange(7), "extra": [None, False, "0", 0]}
                                        for _ in range(length)]
        assert expand_trace_context(compact_trace_context(value)) == value
    bad = compact_trace_context(value)
    bad["encoding"] = "unknown"
    with pytest.raises(ValueError, match="unsupported"):
        expand_trace_context(bad)


def test_agent_and_markdown_keep_identity_missing_capture_and_all_records(tmp_path):
    value = context(host_pid=19, origin_pid=3, started_unix_ns=100,
        checkpoint_elapsed_ns=90, dropped_events=8, dropped_tail_entries=900,
        dropped_image_loads=2, integrity_status="partial", word_bits=32)
    value.events = [RuntimeEventContext(sequence=7, last_sequence=9, repeat_count=3,
        kind="hook", detail="partial", elapsed_ns=10, last_elapsed_ns=20,
        detail_dropped_bytes=99, unit_id="runtime-owner")]
    output = json.loads(tool_for(tmp_path, value, "view_runtime_evidence").invoke({}))
    assert output["trace_context"]["metadata"]["dropped_events"] == 8
    page = json.loads(tool_for(tmp_path, value, "view_runtime_evidence").invoke({"section": "events"}))
    assert expand_trace_context(page["page"]["lossless_context"]) == value.model_dump(mode="json")
    assert "error" in output["runtime_owners"]
    markdown = render_runtime_trace_context(value)
    assert expand_trace_context(json.loads(markdown.split("```json\n")[1].split("\n```")[0])) == value.model_dump(mode="json")


def test_repeated_event_query_intersects_interval_not_only_first_timestamp(tmp_path):
    value = context()
    value.events = [RuntimeEventContext(sequence=1, last_sequence=4, repeat_count=4,
        kind="hook", detail="same", elapsed_ns=10, last_elapsed_ns=40)]
    tool = tool_for(tmp_path, value, "query_runtime_events")
    result = json.loads(tool.invoke({"time_start_ns": 20, "time_end_ns": 25}))
    assert "events" not in result
    assert len(json.loads(Path(result["query_path"]).read_text())["events"]) == 1
    result = json.loads(tool.invoke({"time_start_ns": 41}))
    assert not json.loads(Path(result["query_path"]).read_text())["events"]


def test_truncated_context_keeps_attempt_and_original_pointer(tmp_path):
    tool = tool_for(tmp_path, context(), "view_runtime_evidence")
    (tmp_path / "context.json").write_text('{"events":[')
    output = json.loads(tool.invoke({}))
    assert json.loads((tmp_path / "attempt.json").read_text())["execution_hashes"]["fixture"] == "unchanged"
    assert output["attempt_path"] == str(tmp_path / "attempt.json")
    assert output["trace_context_error"]
    assert output["complete_context_path"] == str(tmp_path / "context.json")
    assert "trace_context" not in output


def test_trace_pages_fit_transport_and_reconstruct_every_event(tmp_path):
    value = context()
    value.events = [RuntimeEventContext(sequence=n + 1, last_sequence=n + 1, repeat_count=1,
        kind="hook", detail="x" * 1300, elapsed_ns=n, last_elapsed_ns=n) for n in range(90)]
    tool = tool_for(tmp_path, value, "view_runtime_evidence")
    start, restored = 0, []
    while start is not None:
        text = tool.invoke({"section": "events", "start": start, "limit": 512})
        assert len(text) <= 24000
        page = json.loads(text)["page"]
        restored.extend(expand_trace_context(page["lossless_context"])["events"])
        start = page["next_start"]
    assert restored == [item.model_dump(mode="json") for item in value.events]


def test_oversized_single_record_returns_exact_pointer_not_cut_json(tmp_path):
    value = context()
    value.events = [RuntimeEventContext(sequence=1, last_sequence=1, repeat_count=1,
        kind="hook", detail="x" * 25000)]
    result = json.loads(tool_for(tmp_path, value, "view_runtime_evidence").invoke({"section": "events"}))
    assert "no record was truncated" in result["notice"]
    assert result["requested_start"] == 0
    assert RuntimeTraceContext.model_validate_json((tmp_path / "context.json").read_text()) == value


def index(tmp_path, name="service"):
    path = tmp_path / name
    path.write_bytes(b"source-ELF-identity")
    function = _FunctionArtifact(name, "main", 0x100, ((0x100, 0x120),),
        tmp_path / "main.s", None, {}, {})
    return _BinarySourceIndex(name, path, 0, (function,))


def test_wrong_elf_identity_and_conflicting_load_base_do_not_map(tmp_path):
    source = index(tmp_path)
    trace = {"image_loads": [{"kind": "image_load", "detail": "service@0x4000"}]}
    images = _loaded_images(trace, {"service": source}, "service", {"service": "wrong"})
    assert "does not match" in images[0].mapping_error
    assert _location_for_pc(0x4100, images, {"service": source}) is None
    good = {"service": hashlib.sha256(source.binary_path.read_bytes()).hexdigest()}
    images = _loaded_images(trace, {"service": source}, "service", good)
    assert _location_for_pc(0x4100, images, {"service": source}).static_ea == 0x100
    assert _location_for_pc(0x5100, images, {"service": source}) is None
    trace["image_loads"].append({"kind": "image_load", "detail": "service@0x5000"})
    images = _loaded_images(trace, {"service": source}, "service", good)
    assert "Conflicting" in images[0].mapping_error
    assert _location_for_pc(0x4100, images, {"service": source}) is None


def test_missing_child_image_identity_and_overlapping_images_are_not_guessed(tmp_path):
    a, b = index(tmp_path), index(tmp_path, "child")
    indexes = {"service": a, "child": b}
    assert not _loaded_images({"main_load_address": 0x4000}, indexes, "service")
    images = _loaded_images({"events": [{"kind": "image_load", "detail": f"{name}@0x4000"}
                                       for name in indexes]}, indexes, "service")
    assert _location_for_pc(0x4100, images, indexes) is None


def test_runtime_owner_snapshot_uses_revised_definition_and_disabled_status(tmp_path):
    path = tmp_path / "runtime-owners.json"
    definition = {"strategy": "function_stub", "contract": {"state": ["runtime revision"]}}
    persist_runtime_owners(path, units={"revised": SimpleNamespace(model_dump=lambda **_: definition)},
        enabled_ids=set(), manifest=tmp_path / "absent", adaptation_ids=["admitted-change"], environment_script=None)
    snapshot = read_runtime_owners(path)
    assert snapshot["units"] == [{"unit_id": "revised", "configured": False, "strategy": "function_stub"}]
    assert snapshot["adaptation_ids"] == ["admitted-change"]
    assert json.loads(path.read_text())["units"]["revised"]["definition"] == definition
    assert snapshot["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_text('{"schema_version":2}')
    assert "unsupported" in read_runtime_owners(path)["error"]


def mapped_position():
    return RuntimeSourceLocation(runtime_pc=0x4100, binary_name="service", runtime_base=0x4000,
        image_base=0, static_ea=0x100, function_name="poll", function_ea=0x100,
        assembly_path="/source/service/poll.s", assembly_context=["0x100: jal close", "0x104: nop"])


def hook_event(**changes):
    return RuntimeEventContext(sequence=7, last_sequence=7, repeat_count=1,
        kind="iib_hook", detail="opaque-hook@0x4100", runtime_pc=0x4100,
        **changes)


def owners_snapshot(*, configured=True, units=None):
    return {"schema_version": 1, "notice": "configured", "adaptation_ids": [], "environment_script": None,
        "units": units or {"unit-state": {"configured": configured,
            "definition": {"strategy": "function_stub", "contract": "current revision"}}},
        "manifest": {"function_stubs": [{"id": "opaque-hook", "source_file": "src/unit_state/function_stubs/read.rs"}]}}


def test_execution_nodes_show_asm_and_keep_projection_and_hit_counts(tmp_path):
    value = context(dropped_focus_tail_entries=91)
    a = RuntimeRecentBlock(runtime_pc=0x4100, consecutive_hits=1, location=mapped_position())
    b = RuntimeRecentBlock(runtime_pc=0x4200, consecutive_hits=3)
    value.recent_focus_blocks = [a, b] * 12 + [a.model_copy(update={"consecutive_hits": 2})]
    value.recent_blocks = [b]
    tool = tool_for(tmp_path, value, "view_runtime_evidence")
    output = json.loads(tool.invoke({"section": "execution", "limit": 512}))
    page = output["page"]
    view = page["view"]
    assert page["total"] == 25 and page["next_start"] is None
    assert view["nodes"]["B0"]["source"]["static_ea"] == "0x100"
    assert view["nodes"]["B0"]["source"]["assembly_context"] == mapped_position().assembly_context
    assert view["runs"][0] == {"path": ["B0", "B1"], "repeat": 12}
    expanded = [view["nodes"][key] for run in view["runs"] for _ in range(run["repeat"]) for key in run["path"]]
    assert [(item["runtime_pc"], item["consecutive_hits"]) for item in expanded] == [
        (hex(item.runtime_pc), item.consecutive_hits) for item in value.recent_focus_blocks]
    assert expanded[-1]["consecutive_hits"] == 2
    assert "not necessarily direct" in view["adjacency"]
    assert "do not prove all" in view["notice"]
    assert output["trace_context"]["metadata"]["dropped_focus_tail_entries"] == 91
    full = json.loads(tool.invoke({"section": "execution", "stream": "all"}))["page"]
    assert full["total"] == 1 and full["view"]["stream"] == "recent_blocks"
    assert full["view"]["nodes"]["B0"]["source"] is None


def test_api_view_separates_entry_capture_from_output_and_preserves_raw_changes(tmp_path):
    value = context(guest_arch="mips", word_bits=32, byte_order="big")
    value.events = [hook_event(elapsed_ns=11, last_elapsed_ns=11, location=mapped_position(),
        registers=[RuntimeRegister(name="a0", value=0x12345678)],
        memory=[RuntimeMemorySnapshot(address=0x2000, requested_bytes=8, source_register="a0", bytes=[17, 34], error="partial")])]
    value.events.append(value.events[0].model_copy(deep=True))
    value.events[1].sequence = value.events[1].last_sequence = 8
    value.events[1].memory[0].bytes[1] = 35
    (tmp_path / "runtime-owners.json").write_text(json.dumps(owners_snapshot(configured=False)))
    tool = tool_for(tmp_path, value, "view_runtime_evidence")
    rendered = tool.invoke({"section": "api"})
    view = json.loads(rendered)["page"]["view"]
    events = view["events"]
    assert "305419896" not in rendered and "0x12345678" not in rendered
    assert events[0]["snapshot"]["memory_ranges"] == [{"address": "0x2000", "source_register": "a0",
        "requested_bytes": 8, "captured_bytes": 2, "error": "partial"}]
    assert "Before invoking" in events[0]["sampling_phase"]
    assert "No call-instance" in view["pairing"]
    assert events[0]["owner"]["unit_id"] == "unit-state"
    assert events[0]["owner"]["configured"] is False
    assert "disabled" in events[0]["owner"]["notice"]
    for event, original in zip(events, value.events, strict=True):
        raw = json.loads(tool.invoke(event["original_event"]))["page"]["lossless_context"]
        assert expand_trace_context(raw)["events"] == [original.model_dump(mode="json")]


@pytest.mark.parametrize("change,reason", [
    (lambda owners: owners["manifest"]["function_stubs"].append(owners["manifest"]["function_stubs"][0]), "ambiguous hook"),
    (lambda owners: owners["units"].update({"unit-State": owners["units"]["unit-state"]}), "ambiguous Unit"),
    (lambda owners: owners.update(schema_version=99), "unsupported"),
    (lambda owners: owners.update(units=[]), "malformed"),
])
def test_owner_join_rejects_ambiguity_without_guessing(change, reason):
    owners = owners_snapshot()
    change(owners)
    result = hook_owner(hook_event(), owners)
    assert result["status"] == "unknown" and reason in result["reason"]


def test_owner_join_does_not_guess_from_hook_substrings_or_truncated_detail():
    event = hook_event()
    assert hook_owner(event, None)["status"] == "unknown"
    owners = owners_snapshot()
    event.detail = "unit-state@0x4100"
    assert hook_owner(event, owners)["status"] == "unknown"
    event.detail = "opaque-hook@0x4200"  # Producer PC must agree.
    assert hook_owner(event, owners)["hook_id"] is None
    event.detail = "opaque-hook@0x4100"
    event.detail_dropped_bytes = 1
    assert hook_owner(event, owners)["hook_id"] is None
    event.detail_dropped_bytes = 0
    event.unit_id = "unit-other"
    assert "conflicts" in hook_owner(event, owners)["reason"]


def test_api_pagination_preserves_unknown_events_order_and_original_offsets(tmp_path):
    value = context()
    value.events = [RuntimeEventContext(sequence=index + 1, last_sequence=index + 1, repeat_count=1,
        kind="new-producer-event", detail="z" * 2200) for index in range(30)]
    tool = tool_for(tmp_path, value, "view_runtime_evidence")
    start, indices = 0, []
    while start is not None:
        text = tool.invoke({"section": "api", "start": start, "limit": 512})
        assert len(text) <= 24000
        page = json.loads(text)["page"]
        for event in page["view"]["events"]:
            indices.append(event["original_event"]["start"])
            assert event["kind"] == "new-producer-event"
            assert "No additional" in event["sampling_phase"]
        start = page["next_start"]
    assert indices == list(range(30))


def test_malformed_owner_snapshot_does_not_hide_other_evidence(tmp_path):
    value = context()
    value.events = [hook_event()]
    (tmp_path / "runtime-owners.json").write_text('{"schema_version":1,"units":[]}')
    tool = tool_for(tmp_path, value, "view_runtime_evidence")
    output = json.loads(tool.invoke({"section": "api"}))
    assert "error" in output["runtime_owners"]
    event = output["page"]["view"]["events"][0]
    assert event["sequence"] == 7
    assert event["owner"]["status"] == "unknown"
    assert "malformed owner units" in event["owner"]["reason"]


def test_failure_overview_selects_explicit_step_and_keeps_unknown_child_relation(tmp_path):
    value = {"scenario_status": "blocked", "failed_step": 2,
        "facts": {"steps": [{"index": 1, "passed": True},
                            {"index": 2, "expected_status": 200, "actual_status": None}]},
        "child_failure_assessment": {"status": "unknown", "failures": [{"relation": "unrelated", "signal": 11}], "collection_errors": []},
        "limitations": ["No persisted guest snapshot"]}
    (tmp_path / "feedback.json").write_text(json.dumps(value))
    output = json.loads(tool_for(tmp_path, context(), "view_runtime_evidence").invoke({}))
    failure = output["failure"]
    assert failure["failed_step_facts"] == [value["facts"]["steps"][1]]
    assert failure["step_facts_extent"] == {"showing": 1, "total": 2}
    assert failure["child_failure_association"]["status"] == "unknown"
    assert failure["child_failure_association"]["failures"][0]["relation"] == "unrelated"
    assert failure["runtime_dump"] is None
    assert failure["limitations"] == value["limitations"]
    value["failed_step"] = None
    assert failure_overview(value)["failed_step_facts"] == []
    assert "not root causes" in output["trace_context"]["notice"]


def test_execution_pages_keep_distinct_source_observations_at_same_pc(tmp_path):
    value = context()
    for index in range(40):
        location = mapped_position().model_copy(update={"assembly_context": ["x" * 900, f"observation {index}"]})
        value.recent_focus_blocks.append(RuntimeRecentBlock(runtime_pc=0x4100, consecutive_hits=1, location=location))
    tool = tool_for(tmp_path, value, "view_runtime_evidence")
    start, observed = 0, []
    while start is not None:
        text = tool.invoke({"section": "execution", "start": start, "limit": 512})
        assert len(text) <= 24000
        page = json.loads(text)["page"]
        view = page["view"]
        observed.extend(view["nodes"][node]["source"]["assembly_context"]
            for run in view["runs"] for _ in range(run["repeat"]) for node in run["path"])
        start = page["next_start"]
    assert observed == [item.location.assembly_context for item in value.recent_focus_blocks]


def test_empty_execution_view_retains_a_valid_original_query(tmp_path):
    tool = tool_for(tmp_path, context(), "view_runtime_evidence")
    page = json.loads(tool.invoke({"section": "execution"}))["page"]
    assert page["count"] == page["total"] == 0
    assert page["next_start"] is None and page["view"]["nodes"] == {}
    assert page["view"]["runs"] == []
    raw = json.loads(tool.invoke(page["view"]["original_records"]))["page"]
    assert expand_trace_context(raw["lossless_context"])["recent_focus_blocks"] == []
