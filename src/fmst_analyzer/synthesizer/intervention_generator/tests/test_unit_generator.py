from __future__ import annotations

from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import scopes_for_test, finding_resolver_for_test

from fmst_analyzer.analysis.base.report_io import model_content_sha256

from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import build_planning_context

from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import contract_for_test

import asyncio
import json
import re
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from fmst_analyzer.synthesizer.intervention_generator.environment import (
    EnvironmentGenerationResult,
)
from fmst_analyzer.runner.rootfs_actions import (
    RootfsAction,
    apply_rootfs_actions,
    normalize_rootfs_actions,
)
from fmst_analyzer.synthesizer.intervention_generator import generator as generator_module
from fmst_analyzer.synthesizer.intervention_generator import agents as agents_module
from fmst_analyzer.synthesizer.intervention_generator.generator import (
    InterventionGenerator,
    _UnitState,
    _generated_source_blockers,
    _import_paths,
    _reset_trace_root,
)
from fmst_basic.agent.config import configured_codex_model
from fmst_analyzer.framework import runtime_workspace
from fmst_analyzer.synthesizer.intervention_generator.review_schema import (
    normalize_unit_review,
)
from fmst_analyzer.synthesizer.intervention_generator.agents import (
    GenerationAgentOutcome,
)
from fmst_analyzer.synthesizer.intervention_generator.cargo import (
    classify_file_path,
    parse_build_errors,
)
from fmst_analyzer.synthesizer.intervention_generator.architecture import (
    detect_generator_arch,
    manifest_arch,
)
from fmst_analyzer.synthesizer.intervention_generator.reports import (
    load_persisted_intervention_generation,
    persist_generation,
    render_index,
    render_unit,
)
from fmst_analyzer.synthesizer.intervention_generator.resolve import (
    AnchorResolutionError,
    resolve_unit,
    resolve_units,
)
from fmst_analyzer.synthesizer.intervention_generator.schema import (
    ContractReview,
    FailureSignal,
    InterventionGenerationResult,
    UnitReviewOutcome,
    UnitGenerationReport,
    UnitGenerationResult,
    UnitRoundTrace,
)
from fmst_analyzer.synthesizer.intervention_generator.shell import (
    configure_active_units,
    generate_shell,
    unit_module_name,
    unit_test_relative_path,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionUnit,
    InterventionPlanResult,
    LaunchChoice,
    ResolvedCallsiteAnchor,
    ResolvedFunctionAnchor,
    ResourceAnchor,
)


class _View:
    def get_binary_image_base(self, binary_name):
        return {"libnvram.so": 0, "httpd": 0x1000}.get(binary_name, 0)

    def get_decompiled_name(self, binary_name, function_ea):
        if (binary_name, function_ea) == ("libnvram.so", 0x1000):
            return "nvram_get"
        if (binary_name, function_ea) == ("httpd", 0x2000):
            return "main"
        return None

    def get_callsite_resume_ea(self, binary_name, function_ea, source_ea):
        assert (binary_name, function_ea) == ("httpd", 0x2000)
        return source_ea + 4


def _function_unit() -> InterventionUnit:
    return InterventionUnit(
        unit_id="unit-1111111111111111",
        behavior_scopes=scopes_for_test(["file:F1"]),
        strategy="function_stub",
        anchors=[ResolvedFunctionAnchor(
            binary_name="libnvram.so",
            function_name="nvram_get",
            function_ea=0x1000,
        )],
        contract=contract_for_test(["return stable key-value data"]),
        summary="Mock NVRAM wrapper",
    )


def _callsite_unit(source_ea=0x2010) -> InterventionUnit:
    return InterventionUnit(
        unit_id="unit-2222222222222222",
        behavior_scopes=scopes_for_test(["network:F1"]),
        strategy="callsite_hook",
        anchors=[ResolvedCallsiteAnchor(
            callsite_id="network-cs:1",
            binary_name="httpd",
            function_name="main",
            function_ea=0x2000,
            snapshot_hash="a" * 64,
            ctree_index=7,
            source_ea=source_ea,
            line_number=4,
            column_number=8,
            api_name="ioctl",
        )],
        contract=contract_for_test(["write the expected output field"]),
        summary="Mock one ioctl output",
    )


def _pseudo_unit(kind="path") -> InterventionUnit:
    return InterventionUnit(
        unit_id="unit-3333333333333333",
        behavior_scopes=scopes_for_test(["file:F2"]),
        strategy="pseudo_file",
        anchors=[ResourceAnchor(
            resource_kind=kind,
            value="/dev/null" if kind == "path" else "/dev/mtd*",
            source_ref="file:F2",
        )],
        contract=contract_for_test(["open allocates a descriptor and read returns EOF"]),
        summary="Provide pseudo-file behavior",
    )


def _approved_review(unit: InterventionUnit) -> UnitReviewOutcome:
    return UnitReviewOutcome(
        verdict="approved",
        contract_reviews=[
            ContractReview(
                contract_index=index,
                status="satisfied",
                evidence="implementation and test cover this contract item",
            )
            for index, _item in enumerate(unit.contract.operations)
        ],
        summary="The Unit is approved.",
    )


def _minimal_elf(*, machine: int, byteorder: str, elf_class: int = 1) -> bytes:
    data = 1 if byteorder == "<" else 2
    ident = b"\x7fELF" + bytes([elf_class, data, 1, 0, 0]) + b"\0" * 7
    fmt = byteorder + (
        "HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH"
    )
    header_size = 52 if elf_class == 1 else 64
    fields = (2, machine, 1, 0, 0, 0, 0, header_size, 0, 0, 0, 0, 0)
    return ident + struct.pack(fmt, *fields)


def test_execution_generator_uses_configured_model_for_codex_units():
    codex = InterventionGenerator(SimpleNamespace(
        agent_concurrency_limit=10,
        synthesizer_model="gpt-5.6-luna",
        agent_provider="codex",
    ))
    claude = InterventionGenerator(SimpleNamespace(
        agent_concurrency_limit=5,
        synthesizer_model="deepseek-flash[1m]",
        agent_provider="claude",
    ))

    assert codex.model == configured_codex_model()
    assert codex._sem._value == 10
    assert claude.model == "deepseek-flash[1m]"
    assert claude._sem._value == 5


def test_execution_agent_writes_only_unit_and_unit_test_directory(
    tmp_path, monkeypatch
):
    unit_dir = tmp_path / "intervention" / "src" / "unit_a"
    test_file = tmp_path / "tests" / "tests" / "unit_a_test" / "main.rs"
    reports = tmp_path / "reports"
    for path in (unit_dir, test_file.parent, reports):
        path.mkdir(parents=True, exist_ok=True)
    test_file.touch()
    captured = {}

    class FakeAgent:
        async def aclose(self):
            pass

    monkeypatch.setattr(agents_module, "make_analyzer_tools", lambda _view: [])
    monkeypatch.setattr(
        agents_module,
        "create_analysis_agent",
        lambda **kwargs: captured.update(kwargs) or FakeAgent(),
    )
    handle = agents_module.build_execution_unit_agent(
        unit_id="unit-a",
        provider="codex",
        model="gpt-5.6-terra",
        workdir=unit_dir,
        intervention_cargo_toml=tmp_path / "intervention" / "Cargo.toml",
        test_cargo_toml=tmp_path / "tests" / "Cargo.toml",
        test_target="unit_a_test",
        test_file=test_file,
        view=object(),
        trace_dir=tmp_path / "traces",
        readable_roots=[reports],
    )

    assert captured["workdir"] == unit_dir
    from fmst_analyzer.synthesizer.intervention_skill import application_guidance
    assert captured["developer_instructions"] == application_guidance("generation")
    assert captured["filesystem_access"] == "write"
    from fmst_analyzer.synthesizer.intervention_skill import APPLICATION_READ_ROOTS
    assert captured["readable_roots"] == [reports, *APPLICATION_READ_ROOTS]
    assert captured["writable_roots"] == [test_file.parent]
    assert captured["model"] == "gpt-5.6-terra"
    assert captured["turn_timeout_seconds"] is None
    assert captured["default_tool_timeout_seconds"] == 120
    assert captured.get("max_tool_calls_per_turn") is None
    assert [tool.name for tool in captured["tools"]] == ["verify_unit"]
    assert handle.trace_for_round(1).md_path.name == "round-01__generator.md"


def test_execution_units_do_not_use_cluster_serialization():
    """Unit scheduling is flat; there is no mutable peer-file handoff."""
    assert not hasattr(InterventionGenerator, "_run_cluster")


@pytest.mark.parametrize("allow_runtime_edits", [True, False])
def test_execution_agent_receives_unit_scoped_evidence_without_capability_gate(
    tmp_path, monkeypatch, allow_runtime_edits
):
    unit = _function_unit()
    unit.contract.required_iib_capabilities = ["unlisted_capability"]
    if not allow_runtime_edits:
        unit.contract.allowed_refinement_scope = []
    module = tmp_path / "crate" / "src" / unit_module_name(unit.unit_id)
    module.mkdir(parents=True)
    (module / "logic.rs").write_text("// shell\n", encoding="utf-8")
    captured = []
    messages = []

    class Resolver:
        def read_finding(self, finding_ref, record_refs=None):
            return self.finding_evidence(finding_ref)

        def finding_evidence(self, finding_ref):
            return {"finding_ref": finding_ref, "complete": "evidence"}

    def fake_builder(**kwargs):
        captured.append(("implementation", kwargs))
        return SimpleNamespace(role="implementation")

    async def fake_invoke(handle, message):
        payload = json.loads(message.split("Execution Unit generation input:\n", 1)[1])
        messages.append((handle.role, payload))
        return SimpleNamespace(structured_response=GenerationAgentOutcome(
            status="completed",
            reason="Implemented the supplied contract.",
        ))

    monkeypatch.setattr(generator_module, "build_execution_unit_agent", fake_builder)
    monkeypatch.setattr(generator_module, "invoke_agent", fake_invoke)
    generator = InterventionGenerator(SimpleNamespace(
        agent_concurrency_limit=2,
        synthesizer_model="test",
        agent_provider="codex",
    ))
    state = _UnitState(unit)

    test_file = (
        tmp_path / "tests" / unit_test_relative_path(unit.unit_id)
    )
    test_file.parent.mkdir(parents=True)
    test_file.write_text("// shell\n", encoding="utf-8")
    asyncio.run(generator._run_unit(
        state=state,
        unit=unit,
        related_units=[],
        selected_launch=None,
        launch_choice={"recipe_id": None, "reason": "launch gap"},
        runtime_tasks={"task-fixture": {"summary": "verify peer"}},
        resolver=Resolver(),
        view=_View(),
        crate_root=tmp_path / "crate",
        test_root=tmp_path / "tests",
        trace_root=tmp_path / "traces",
        target_binary="httpd",
        image_name="firmware",
        arch="arm",
        readable_roots=[tmp_path / "reports"],
    ))

    assert [role for role, _kwargs in captured] == ["implementation"]
    kwargs = captured[0][1]
    assert [tool.name for tool in kwargs["extra_tools"]] == [
        "view_finding_evidence"
    ]
    payload = json.loads(kwargs["extra_tools"][0].invoke({
        "finding_refs": ["file:F1"],
    }))
    assert payload == {"file:F1": {"finding_ref": "file:F1", "complete": "evidence"}}
    assert kwargs["test_file"] == test_file
    assert kwargs["workdir"] == module
    assert kwargs["readable_roots"] == [tmp_path / "reports"]
    assert kwargs.get("turn_timeout_seconds") is None
    assert len(messages) == 1
    assert messages[0][0] == "implementation"
    payload = messages[0][1]
    assert "finding_evidence" not in payload
    assert payload["unit"]["finding_refs"] == ["file:F1"]
    assert payload["target_context"]["launch_choice"]["reason"] == "launch gap"
    assert payload["target_context"]["runtime_tasks"] == {"task-fixture": {"summary": "verify peer"}}
    assert payload["unit"]["contract"]["operations"] == unit.contract.operations
    assert payload["unit"]["contract"]["required_iib_capabilities"] == ["unlisted_capability"]
    assert payload["unit"]["contract"]["allowed_refinement_scope"] == unit.contract.allowed_refinement_scope
    assert state.status == "pending"
    assert state.agent_outcome.status == "completed"
    assert len(state.round_traces) == 1
    assert state.round_traces[0].reviewer_trace_path is None


def test_legacy_review_replay_requires_exact_contract_accounting():
    unit = _function_unit().model_copy(update={
        "contract": contract_for_test(["first", "second"]),
    })
    review = UnitReviewOutcome(
        verdict="approved",
        contract_reviews=[ContractReview(
            contract_index=0,
            status="satisfied",
            evidence="only the first item was reviewed",
        )],
        summary="Incomplete review.",
    )

    _normalized, error = normalize_unit_review(review, len(unit.contract.operations))

    assert error == (
        "independent review must cover each contract.operations item exactly once; "
        "expected indexes [0, 1], received [0]"
    )


def test_semantic_agent_inability_fails_only_its_execution_unit() -> None:
    state = _UnitState(_pseudo_unit())
    outcome = InterventionGenerator._record_agent_response(
        state,
        SimpleNamespace(structured_response=GenerationAgentOutcome(
            status="unable",
            reason="native file bytes are unavailable to this pseudo-file",
        )),
    )

    assert outcome is not None
    assert outcome.status == "unable"
    assert state.status == "generation_failed"
    assert state.failure_reason == "native file bytes are unavailable to this pseudo-file"
    assert state.failure_code == "no_candidate"
    assert state.last_failure is not None


def test_failed_unit_does_not_block_independent_unit_activation(
    tmp_path, monkeypatch
) -> None:
    owner = _function_unit()
    consumer = _callsite_unit()
    states = {
        owner.unit_id: _UnitState(owner),
        consumer.unit_id: _UnitState(consumer, status="generation_failed"),
    }
    configured = []

    monkeypatch.setattr(
        generator_module,
        "configure_active_units",
        lambda **kwargs: configured.extend(kwargs["units"]),
    )
    active = InterventionGenerator._configure_active_units(
        execution_units=[owner, consumer],
        states=states,
        view=_View(),
        target_binary="httpd",
        image_name="firmware",
        arch="arm",
        crate_root=tmp_path / "crate",
        eligible_statuses={"pending"},
    )

    assert active == [owner]
    assert configured == [owner]
    assert states[owner.unit_id].status == "pending"
    assert states[consumer.unit_id].failure_reason is None


def test_final_build_drops_only_attributed_failed_unit(tmp_path, monkeypatch):
    first = _function_unit()
    second = _callsite_unit()
    states = {
        first.unit_id: _UnitState(first, status="pending"),
        second.unit_id: _UnitState(second, status="pending"),
    }
    configured: list[list[str]] = []
    results = iter([
        subprocess.CompletedProcess(
            [],
            101,
            "",
            "error[E0308]: mismatch\n"
            "  --> src/unit_1111111111111111/logic.rs:4:2\n\n",
        ),
        subprocess.CompletedProcess([], 0, "built", ""),
    ])

    monkeypatch.setattr(
        generator_module,
        "configure_active_units",
        lambda **kwargs: configured.append([
            unit.unit_id for unit in kwargs["units"]
        ]),
    )
    monkeypatch.setattr(
        generator_module,
        "_run_cargo",
        lambda *_args, **_kwargs: next(results),
    )
    generator = InterventionGenerator(SimpleNamespace(
        synthesizer_model="test",
        agent_concurrency_limit=2,
        agent_provider="codex",
    ))

    status, _result = generator._build_generated_units(
        execution_units=[first, second],
        states=states,
        view=_View(),
        target_binary="httpd",
        image_name="firmware",
        arch="arm",
        crate_root=tmp_path / "crate",
    )

    assert status == "ok"
    assert configured == [
        [first.unit_id, second.unit_id],
        [second.unit_id],
    ]
    assert states[first.unit_id].status == "build_failed"
    assert states[second.unit_id].status == "pending"


def test_completed_outcome_does_not_require_template_changes(tmp_path):
    unit = _function_unit()
    state = _UnitState(unit)
    crate_root = tmp_path / "crate"
    test_root = tmp_path / "tests"
    module_root = crate_root / "src" / unit_module_name(unit.unit_id)
    test_file = test_root / unit_test_relative_path(unit.unit_id)
    module_root.mkdir(parents=True)
    test_file.parent.mkdir(parents=True)
    logic = module_root / "logic.rs"
    logic.write_text("// shell\n", encoding="utf-8")
    test_file.write_text("// shell\n", encoding="utf-8")
    InterventionGenerator._record_agent_response(
        state,
        SimpleNamespace(structured_response=GenerationAgentOutcome(
            status="completed",
            reason="verify_unit passed",
        )),
    )
    InterventionGenerator._mark_inactive(
        {unit.unit_id: state}, crate_root, test_root
    )

    assert state.status == "pending"


def test_unexpected_file_in_unit_test_directory_is_rejected(tmp_path):
    unit = _function_unit()
    crate_root = tmp_path / "crate"
    test_root = tmp_path / "tests"
    module_root = crate_root / "src" / unit_module_name(unit.unit_id)
    test_file = test_root / unit_test_relative_path(unit.unit_id)
    module_root.mkdir(parents=True)
    test_file.parent.mkdir(parents=True)
    (module_root / "logic.rs").write_text("pub fn implemented() {}\n")
    test_file.write_text("#[test] fn contract() {}\n")
    unexpected = test_file.parent / "helper.rs"
    unexpected.write_text("// outside the supplied test file\n")

    blockers = _generated_source_blockers(unit, crate_root, test_root)

    assert (unexpected, "Unit Agent may only edit the supplied test file") in blockers


def test_old_generation_schema_is_rejected() -> None:
    result = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="httpd",
        arch="arm",
        total_units=0,
        ok_count=0,
        not_ready_count=0,
        skipped_count=0,
        cargo_build_status="not_run",
        cargo_test_status="not_run",
        environment=EnvironmentGenerationResult(),
    )
    payload = result.model_dump(mode="json")
    payload["schema_version"] = 11
    with pytest.raises(ValidationError):
        InterventionGenerationResult.model_validate(payload)


def test_persisted_generation_is_validated_against_complete_plan_unit(tmp_path: Path):
    unit = _pseudo_unit()
    plan = InterventionPlanResult(planning_context=build_planning_context(), catalog_digest="0" * 64,
        launch_choice=LaunchChoice(recipe_id=None, reason="Offline contract fixture"),
        draft_revision=1, claim_counts={ref: 1 for ref in unit.finding_refs}, units={unit.unit_id: unit})

    generated = tmp_path / "generated" / "unit.rs"
    generated.parent.mkdir(parents=True)
    generated.write_text("// generated", encoding="utf-8")
    generator_trace = tmp_path / "traces" / "round-01__generator.md"
    generator_trace.parent.mkdir(parents=True, exist_ok=True)
    generator_trace.write_text("# generator trace\n", encoding="utf-8")
    reviewer_trace = tmp_path / "traces" / "round-01__reviewer.md"
    reviewer_trace.parent.mkdir(parents=True, exist_ok=True)
    reviewer_trace.write_text("# reviewer trace\n", encoding="utf-8")
    result = InterventionGenerationResult(plan_digest=model_content_sha256(plan),
        intervention_crate_path=str(generated.parent),
        target_binary="httpd",
        arch="arm",
        total_units=1,
        ok_count=1,
        not_ready_count=0,
        skipped_count=0,
        units=[UnitGenerationResult(
            unit_id=unit.unit_id,
            report_stem="dev-null__3333333333",
            strategy=unit.strategy,
            status="ok",
            generated_files=[str(generated)],
            round_traces=[UnitRoundTrace(
                round_index=1,
                generator_trace_path=str(generator_trace),
                reviewer_trace_path=str(reviewer_trace),
            )],
            review_history=[_approved_review(unit)],
        )],
        cargo_build_status="ok",
        cargo_test_status="ok",
        environment=EnvironmentGenerationResult(),
    )

    persisted = persist_generation(tmp_path, result, plan)
    assert load_persisted_intervention_generation(tmp_path, plan) == persisted
    assert load_persisted_intervention_generation(
        tmp_path, plan, require_complete=True
    ) == persisted

    report_path = next(
        (tmp_path / "intervention_generation_reports" / "units").glob("*.json")
    )
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    payload["unit"]["summary"] = "stale plan payload"
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="differs from Plan"):
        load_persisted_intervention_generation(tmp_path, plan)


@pytest.mark.parametrize(
    ("machine", "byteorder", "elf_class", "expected"),
    [
        (40, "<", 1, "arm"),
        (62, "<", 2, "x86_64"),
        (8, "<", 1, "mipsel"),
        (8, ">", 1, "mipsbe"),
    ],
)
def test_generator_architecture_comes_from_target_elf(
    tmp_path, machine, byteorder, elf_class, expected
):
    elf = tmp_path / f"{expected}.elf"
    elf.write_bytes(_minimal_elf(
        machine=machine, byteorder=byteorder, elf_class=elf_class
    ))

    arch = detect_generator_arch(elf)
    assert arch == expected
    assert manifest_arch(arch) == ("mips" if expected.startswith("mips") else expected)


def test_resolved_anchors_use_binary_relative_offsets():
    function = resolve_unit(_function_unit(), _View()).entries[0]
    assert function.binary == "libnvram.so"
    assert function.offset == 0x1000
    callsite = resolve_unit(_callsite_unit(), _View()).entries[0]
    assert callsite.binary == "httpd"
    assert callsite.offset == 0x1010
    assert callsite.resume_offset == 0x1014


def test_missing_source_ea_unknown_binary_and_pattern_are_blocked():
    with pytest.raises(AnchorResolutionError, match="missing source_ea"):
        resolve_unit(_callsite_unit(None), _View())
    bad = _function_unit().model_copy(update={
        "anchors": [ResolvedFunctionAnchor(
            binary_name="missing.so", function_name="nvram_get", function_ea=0x1000
        )]
    })
    with pytest.raises(AnchorResolutionError, match="unknown function"):
        resolve_unit(bad, _View())
    with pytest.raises(ValidationError, match="pseudo_file requires exact path"):
        _pseudo_unit("path_pattern")


@pytest.mark.external
def test_shell_uses_unit_modules_and_manifest_binary(tmp_path):
    unit = _function_unit()
    callsite_unit = _callsite_unit()
    units = [unit, callsite_unit]
    manifest = resolve_units(units, _View())
    generate_shell(
        target_binary="httpd",
        image_name="firmware",
        arch="arm",
        units=units,
        resolved_manifest=manifest,
        interventions_root=tmp_path / "interventions",
        test_harnesses_root=tmp_path / "tests",
        iib_api_abspath=runtime_workspace() / "fmst-iib-api",
    )
    module = unit_module_name(unit.unit_id)
    crate = tmp_path / "interventions" / "httpd"
    payload = json.loads((crate / "manifest.json").read_text())
    api_source = (runtime_workspace() / "fmst-iib-api/src/manifest.rs").read_text()
    declared_abi = int(re.search(r"pub const CURRENT_ABI_VERSION: u32 = (\d+);", api_source)[1])
    assert payload["manifest_abi_version"] == declared_abi
    assert payload["function_stubs"][0]["target"]["binary"] == "libnvram.so"
    assert payload["function_stubs"][0]["target"]["offset"] == "0x00001000"
    assert payload["callsite_hooks"][0]["target"]["offset"] == "0x00001010"
    assert payload["callsite_hooks"][0]["resume_offset"] == "0x00001014"
    assert (crate / "src" / module / "logic.rs").is_file()
    assert (
        tmp_path / "tests" / "httpd" / unit_test_relative_path(unit.unit_id)
    ).is_file()
    test_cargo = (tmp_path / "tests" / "httpd" / "Cargo.toml").read_text()
    assert f'name = "{module}_test"' in test_cargo
    assert f'path = "tests/{module}_test/main.rs"' in test_cargo
    checked = subprocess.run(
        ["cargo", "check", "--manifest-path", str(crate / "Cargo.toml")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert checked.returncode == 0, checked.stderr


@pytest.mark.external
def test_pseudo_file_manifest_uses_path_aware_factory_for_all_exact_paths(tmp_path):
    unit = _pseudo_unit().model_copy(update={
        "anchors": [
            ResourceAnchor(
                resource_kind="path",
                value="/dev/mtd2",
                source_ref="file:F2",
            ),
            ResourceAnchor(
                resource_kind="path",
                value="/dev/mtd3",
                source_ref="file:F2",
            ),
        ],
    })
    crate = tmp_path / "interventions" / "httpd"
    generate_shell(
        target_binary="httpd",
        image_name="firmware",
        arch="arm",
        units=[unit],
        resolved_manifest=resolve_units([unit], _View()),
        interventions_root=tmp_path / "interventions",
        test_harnesses_root=tmp_path / "tests",
        iib_api_abspath=runtime_workspace() / "fmst-iib-api",
    )
    manifest = json.loads((crate / "manifest.json").read_text())
    assert manifest["pseudo_files"] == [{
        "id": f"pf_{unit.unit_id}",
        "paths": ["/dev/mtd2", "/dev/mtd3"],
        "impl_type_path": (
            "crate::unit_3333333333333333::pseudo_files::PseudoFileImpl"
        ),
        "factory_path": (
            "crate::unit_3333333333333333::pseudo_files::factory"
        ),
        "source_file": "src/unit_3333333333333333/pseudo_files/mod.rs",
    }]
    source = (crate / "src/unit_3333333333333333/pseudo_files/mod.rs").read_text()
    assert "pub fn for_path(path: &str)" in source
    assert "pub fn factory(path: &str, flags: i64)" in source
    checked = subprocess.run(
        ["cargo", "check", "--manifest-path", str(crate / "Cargo.toml")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert checked.returncode == 0, checked.stderr


def test_mipsbe_test_harness_uses_big_endian_mock(tmp_path):
    unit = _function_unit()
    api = tmp_path / "api"
    (api / "src").mkdir(parents=True)
    (api / "src/manifest.rs").write_text("pub const CURRENT_ABI_VERSION: u32 = 3;\n")
    generate_shell(
        target_binary="httpd",
        image_name="firmware",
        arch="mipsbe",
        units=[unit],
        resolved_manifest=resolve_units([unit], _View()),
        interventions_root=tmp_path / "interventions",
        test_harnesses_root=tmp_path / "tests",
        iib_api_abspath=api,
    )

    cargo_toml = (tmp_path / "tests/httpd/Cargo.toml").read_text()
    assert 'features = ["mock", "mock-big-endian"]' in cargo_toml


@pytest.mark.external
def test_blocked_unit_is_removed_from_shared_indexes_but_source_is_retained(
    tmp_path,
):
    active = _function_unit()
    blocked = _callsite_unit()
    units = [active, blocked]
    crate = tmp_path / "interventions" / "httpd"
    generate_shell(
        target_binary="httpd",
        image_name="firmware",
        arch="arm",
        units=units,
        resolved_manifest=resolve_units(units, _View()),
        interventions_root=tmp_path / "interventions",
        test_harnesses_root=tmp_path / "tests",
        iib_api_abspath=runtime_workspace() / "fmst-iib-api",
    )

    configure_active_units(
        target_binary="httpd",
        image_name="firmware",
        arch="arm",
        units=[active],
        resolved_manifest=resolve_units([active], _View()),
        crate_root=crate,
    )

    active_module = unit_module_name(active.unit_id)
    blocked_module = unit_module_name(blocked.unit_id)
    lib_rs = (crate / "src/lib.rs").read_text()
    state_rs = (crate / "src/state.rs").read_text()
    manifest = json.loads((crate / "manifest.json").read_text())
    assert active_module in lib_rs and active_module in state_rs
    assert blocked_module not in lib_rs and blocked_module not in state_rs
    assert (crate / "src" / blocked_module / "logic.rs").is_file()
    assert {entry["id"].split("_")[1] for entry in manifest["function_stubs"]} == {
        active.unit_id
    }
    assert manifest["callsite_hooks"] == []

    # Retained blocked source is diagnostic evidence, not part of the active
    # crate. Even invalid Rust in that directory must not poison valid Units.
    (crate / "src" / blocked_module / "logic.rs").write_text(
        "this is intentionally invalid Rust",
        encoding="utf-8",
    )
    checked = subprocess.run(
        ["cargo", "check", "--manifest-path", str(crate / "Cargo.toml")],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert checked.returncode == 0, checked.stderr


def test_runner_rootfs_actions_are_idempotent_and_cannot_escape(tmp_path):
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir()
    actions = [
        RootfsAction(action="mkdir", path="/var/run"),
        RootfsAction(
            action="write_file", path="/etc/app.conf",
            content="enabled=1\n", mode=0o600,
        ),
        RootfsAction(
            action="symlink", path="/var/run/app.conf",
            target="/etc/app.conf",
        ),
    ]
    for _ in range(2):
        apply_rootfs_actions(actions, rootfs)
    assert (rootfs / "etc/app.conf").read_text() == "enabled=1\n"
    assert (rootfs / "var/run/app.conf").is_symlink()

    with pytest.raises(ValueError, match="absolute"):
        normalize_rootfs_actions(
            [RootfsAction(
                action="mkdir",
                path="relative/path",
            )],
            rootfs,
        )

    outside = tmp_path / "outside"
    outside.mkdir()
    (rootfs / "escape").symlink_to(outside, target_is_directory=True)
    # Absolute links are guest paths, even when their spelling also names an
    # existing host directory. Prove the host remains untouched.
    apply_rootfs_actions(
        [RootfsAction(action="write_file", path="/escape/host-file",
                      content="must stay in rootfs")], rootfs,
    )
    assert not (outside / "host-file").exists()
    assert (rootfs / outside.as_posix().lstrip("/") / "host-file").read_text() == "must stay in rootfs"

    dynamic_parent_actions = [
        RootfsAction(action="symlink", path="/dynamic", target="/outside"),
        RootfsAction(
            action="write_file",
            path="/dynamic/host-file",
            content="must stay in rootfs",
        ),
    ]
    apply_rootfs_actions(dynamic_parent_actions, rootfs)
    assert (rootfs / "outside/host-file").read_text() == "must stay in rootfs"

    (rootfs / "relative_escape").symlink_to("../outside", target_is_directory=True)
    with pytest.raises(ValueError, match="escapes rootfs through symlink"):
        apply_rootfs_actions([
            RootfsAction(action="write_file", path="/relative_escape/host-file", content="bad"),
        ], rootfs)
    assert not (outside / "host-file").exists()


def test_cargo_parser_and_result_report_use_unit_identity():
    assert classify_file_path("src/unit_abc/logic.rs") == "unit-abc"
    assert classify_file_path("tests/unit_abc_test/main.rs") == "unit-abc"
    errors = parse_build_errors(
        "error[E0308]: mismatch\n  --> src/unit_abc/logic.rs:4:2\n\n"
    )
    assert errors[0].unit_id == "unit-abc"
    result = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="httpd",
        arch="arm",
        total_units=1,
        ok_count=1,
        not_ready_count=0,
        skipped_count=0,
        units=[UnitGenerationResult(
            unit_id="unit-abc",
            report_stem="nvram__abc",
            strategy="function_stub",
            status="ok",
        )],
        cargo_build_status="ok",
        cargo_test_status="ok",
        environment=EnvironmentGenerationResult(),
    )
    assert InterventionGenerationResult.model_validate_json(
        result.model_dump_json()
    ) == result
    rendered = render_index(result)
    assert "unit_id" in rendered
    assert "RUNNER_INPUT_READY" in rendered
    assert "RUNNER_READY" not in rendered
    assert "[md](units/nvram__abc.md)" in rendered
    assert "../intervention_plan_reports/intervention_plan_result.json" in rendered


def test_generation_index_preserves_global_cargo_failure():
    failure = FailureSignal(
        phase="build",
        file_path="/generated/Cargo.toml",
        message="target toolchain is unavailable\ncomplete diagnostic",
    )
    result = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="thttpd",
        arch="mipsbe",
        total_units=0,
        ok_count=0,
        not_ready_count=0,
        skipped_count=0,
        cargo_build_status="failed",
        cargo_test_status="not_run",
        cargo_build_failure=failure,
        environment=EnvironmentGenerationResult(),
    )

    rendered = render_index(result)
    assert "## cargo_build_failure" in rendered
    assert "target toolchain is unavailable\ncomplete diagnostic" in rendered


def test_generation_index_escapes_multiline_table_failures():
    result = InterventionGenerationResult(plan_digest="0" * 64,
        target_binary="httpd",
        arch="arm",
        total_units=1,
        ok_count=0,
        not_ready_count=1,
        skipped_count=0,
        units=[UnitGenerationResult(
            unit_id="unit-abc",
            report_stem="device__abc",
            strategy="pseudo_file",
            status="generation_failed",
            failure_reason="missing read | ioctl contract\nfull detail",
        )],
        cargo_build_status="not_run",
        cargo_test_status="not_run",
        environment=EnvironmentGenerationResult(),
    )

    rendered = render_index(result)
    assert "missing read \\| ioctl contract<br>full detail" in rendered


def test_unit_report_renders_typed_anchor_and_complete_contract():
    generation = UnitGenerationResult(
        unit_id="unit-1111111111111111",
        report_stem="nvram__1111111111",
        strategy="function_stub",
        status="ok",
        round_traces=[UnitRoundTrace(
            round_index=1,
            generator_trace_path="/trace/round-01__generator.md",
            reviewer_trace_path="/trace/round-01__reviewer.md",
        )],
        revision_count=1,
        review_history=[UnitReviewOutcome(
            verdict="approved",
            contract_reviews=[ContractReview(
                contract_index=0,
                status="satisfied",
                evidence="the wrapper result and assertion agree",
            )],
            summary="Contract approved.",
        )],
    )
    report = UnitGenerationReport(
        unit=_function_unit(),
        generation=generation,
    )

    rendered = render_unit(report)

    assert "- kind: `function`" in rendered
    assert "    - binary_name: `libnvram.so`" in rendered
    assert "    - function_name: `nvram_get`" in rendered
    assert "    - function_ea: `0x1000`" in rendered
    assert "- contract:" in rendered
    assert "return stable key-value data" in rendered
    assert "runner_handoff: `RUNNER_INPUT_READY`" in rendered
    assert "revision_count: `1`" in rendered
    assert "round-01__reviewer.md" not in rendered
    assert "## review_history" not in rendered
    assert '`{"kind"' not in rendered
    assert "nvram__1111111111.json" in rendered


def test_test_agent_imports_manifest_global_state():
    assert _import_paths(_callsite_unit(), "httpd")[0] == (
        "intervention_httpd::state::GlobalState"
    )


def test_generated_source_blockers_only_check_file_ownership(tmp_path):
    unit = _callsite_unit()
    module = unit_module_name(unit.unit_id)
    source = tmp_path / "crate" / "src" / module / "hook.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "// TODO(arch-escape): missing callee\n"
        "const ORIGINAL: u64 = 0;\n"
        "fn hook(ctx: &mut C) {\n"
        "    let _ = std::fs::read(\"/guest/path\");\n"
        "    ctx.native_call(ORIGINAL, &[]);\n"
        "    ctx.native_call(0x2010, &[]);\n"
        "}\n",
        encoding="utf-8",
    )
    test_file = tmp_path / "tests" / unit_test_relative_path(unit.unit_id)
    test_file.parent.mkdir(parents=True)
    test_file.write_text("#[test] fn contract() {}\n", encoding="utf-8")

    blockers = _generated_source_blockers(
        unit, tmp_path / "crate", tmp_path / "tests"
    )

    assert blockers == []


def test_generated_source_blockers_do_not_guess_guest_errno_semantics(tmp_path):
    unit = _callsite_unit().model_copy(update={
        "contract": contract_for_test(["Return -1 with EAGAIN when no stream is available"]),
    })
    module = unit_module_name(unit.unit_id)
    source = tmp_path / "crate" / "src" / module / "hook.rs"
    source.parent.mkdir(parents=True)
    source.write_text(
        "fn hook(ctx: &mut C) { let _ = ctx.set_return_value(u64::MAX); }\n",
        encoding="utf-8",
    )
    test_file = tmp_path / "tests" / unit_test_relative_path(unit.unit_id)
    test_file.parent.mkdir(parents=True)
    test_file.write_text("#[test] fn contract() {}\n", encoding="utf-8")

    blockers = _generated_source_blockers(
        unit, tmp_path / "crate", tmp_path / "tests"
    )
    assert blockers == []


def test_generator_trace_root_is_replaced_not_merged(tmp_path):
    trace_root = tmp_path / "intervention_generator"
    stale = trace_root / "units" / "unit-stale" / "trace.md"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale", encoding="utf-8")

    _reset_trace_root(trace_root)

    assert trace_root.is_dir()
    assert list(trace_root.iterdir()) == []


def test_one_unit_test_failure_does_not_block_other_units(monkeypatch, tmp_path):
    first = _function_unit()
    second = _callsite_unit()
    states = {
        first.unit_id: _UnitState(unit=first, status="pending"),
        second.unit_id: _UnitState(unit=second, status="pending"),
    }
    invoked_targets: list[str] = []

    def fake_run_cargo(_manifest, subcommand, *, extra_args=None, timeout):
        assert subcommand == "test"
        assert timeout > 0
        target = (extra_args or [None, ""])[1]
        invoked_targets.append(target)
        if target == "unit_1111111111111111_test":
            return subprocess.CompletedProcess([], 0, "1 passed", "")
        failure = (
            "running 1 test\n"
            "test fails ... FAILED\n\n"
            "---- fails stdout ----\n"
            "thread 'fails' panicked at "
            "tests/unit_2222222222222222_test/main.rs:7:5:\nboom\n"
        )
        return subprocess.CompletedProcess([], 101, failure, "")

    monkeypatch.setattr(generator_module, "_run_cargo", fake_run_cargo)
    generator = InterventionGenerator(SimpleNamespace(
        synthesizer_model="test",
        agent_concurrency_limit=1,
        agent_provider="codex",
    ))

    status, results = generator._test_generated_units(
        states,
        tmp_path,
    )

    assert status == "failed"
    assert set(results) == {first.unit_id, second.unit_id}
    assert states[first.unit_id].status == "ok"
    assert states[second.unit_id].status == "test_failed"
    assert states[second.unit_id].last_failure is not None
    assert (
        "thread 'fails' panicked at "
        "tests/unit_2222222222222222_test/main.rs:7:5:\nboom"
    ) in states[second.unit_id].last_failure.message
    assert invoked_targets == [
        "unit_1111111111111111_test",
        "unit_2222222222222222_test",
    ]


def test_controller_returns_full_failure_to_same_author_and_keeps_candidate(tmp_path, monkeypatch):
    import time
    unit = _function_unit()
    crate, tests = tmp_path / 'crate', tmp_path / 'tests'
    source = crate / 'src' / unit_module_name(unit.unit_id) / 'logic.rs'
    source.parent.mkdir(parents=True)
    source.write_text('broken candidate')
    test = tests / unit_test_relative_path(unit.unit_id)
    test.parent.mkdir(parents=True)
    test.write_text('original test')
    handle = SimpleNamespace(trace_dir=tmp_path / 'traces')
    state = _UnitState(unit, status='build_failed', agent_handle=handle, failure_code='build',
        last_failure=FailureSignal(code='build', phase='build', message='exit_code=101\nCOMPLETE stdout\nCOMPLETE stderr'))
    calls = []
    async def correct(same_handle, message, **kwargs):
        assert same_handle is handle and 'COMPLETE stdout\nCOMPLETE stderr' in message
        calls.append(message)
        source.write_text('repaired candidate')
        return SimpleNamespace(structured_response=GenerationAgentOutcome(status='completed', reason='corrected'))
    monkeypatch.setattr(generator_module, 'invoke_agent', correct)
    generator = InterventionGenerator(SimpleNamespace(synthesizer_model='test', agent_concurrency_limit=1, agent_provider='claude'))
    changed = asyncio.run(generator._correct_failed_units({unit.unit_id: state}, crate, tests, set(), deadline=time.monotonic() + 30))
    assert changed and state.status == 'pending' and state.revision_count == 1
    assert len(calls) == 1
    assert (handle.trace_dir / 'round-01__feedback/candidate/src' / unit_module_name(unit.unit_id) / 'logic.rs').read_text() == 'broken candidate'
    assert (handle.trace_dir / 'round-01__feedback/failure.json').is_file()


def test_controller_stops_author_correction_without_source_progress(tmp_path, monkeypatch):
    import time
    unit = _function_unit()
    handle = SimpleNamespace(trace_dir=tmp_path / 'traces')
    state = _UnitState(unit, status='test_failed', agent_handle=handle, failure_code='test',
        last_failure=FailureSignal(code='test', phase='test_runtime', message='assertion failed'))
    calls = []
    async def no_change(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(structured_response=GenerationAgentOutcome(status='completed', reason='claims repaired'))
    monkeypatch.setattr(generator_module, 'invoke_agent', no_change)
    generator = InterventionGenerator(SimpleNamespace(synthesizer_model='test', agent_concurrency_limit=1, agent_provider='claude'))
    seen = set()
    for _ in range(2):
        assert not asyncio.run(generator._correct_failed_units({unit.unit_id: state}, tmp_path / 'crate', tmp_path / 'tests', seen, deadline=time.monotonic() + 30))
    assert len(calls) == 1 and 'no source change' in state.failure_reason


def test_cargo_feedback_binds_named_unit_from_actual_owner_table():
    errors = parse_build_errors('error[E0425]: missing value\n --> src/unit_named_seed/logic.rs:1:1\n', owner_modules={'unit_named_seed': 'named-seed'})
    assert errors[0].unit_id == 'named-seed'
    assert not parse_build_errors('error[E0425]: missing value\n --> src/unit_other/logic.rs:1:1\n', owner_modules={'unit_named_seed': 'named-seed'})


def test_execution_envelope_feedback_can_complete_without_changing_valid_source(tmp_path, monkeypatch):
    import time
    unit = _function_unit()
    handle = SimpleNamespace(trace_dir=tmp_path / 'traces')
    state = _UnitState(unit, agent_handle=handle, failure_code='structured_output_error',
        last_failure=FailureSignal(code='structured_output_error', phase='input_validation', message='invalid envelope'))
    async def envelope(*args, **kwargs):
        return SimpleNamespace(structured_response=GenerationAgentOutcome(status='completed', reason='valid envelope'))
    monkeypatch.setattr(generator_module, 'invoke_agent', envelope)
    generator = InterventionGenerator(SimpleNamespace(synthesizer_model='test', agent_concurrency_limit=1, agent_provider='claude'))
    assert asyncio.run(generator._correct_failed_units({unit.unit_id: state}, tmp_path / 'crate', tmp_path / 'tests', set(), deadline=time.monotonic() + 30))
    assert state.status == 'pending' and state.failure_code is None


@pytest.mark.parametrize("version", [3, 4])
def test_manifest_uses_linked_api_abi_including_retained_release(tmp_path, version):
    from fmst_analyzer.synthesizer.intervention_generator.shell import configure_active_units, ResolvedManifest
    api = tmp_path / "api"
    (api / "src").mkdir(parents=True)
    (api / "src/manifest.rs").write_text(f"pub const CURRENT_ABI_VERSION: u32 = {version};\n")
    crate = tmp_path / "crate"
    crate.mkdir()
    (crate / "Cargo.toml").write_text('[dependencies]\nfmst-iib-api={path="../api"}\n')
    configure_active_units(target_binary="guest", image_name="firmware", arch="arm", units=[],
                           resolved_manifest=ResolvedManifest(), crate_root=crate)
    assert json.loads((crate / "manifest.json").read_text())["manifest_abi_version"] == version
