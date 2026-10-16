"""Focused checks for the single-Agent Generator control flow."""

import hashlib
from types import SimpleNamespace

from fmst_analyzer.synthesizer.intervention_generator.agents import (
    AgentHandle,
    GenerationAgentOutcome,
)
from fmst_analyzer.synthesizer.intervention_generator.generator import (
    InterventionGenerator,
    _UnitState,
)
from fmst_analyzer.synthesizer.intervention_generator.reports import unit_report_stem
from fmst_analyzer.synthesizer.intervention_generator.shell import (
    unit_module_name,
    unit_test_relative_path,
)
from fmst_analyzer.synthesizer.intervention_generator.tests.test_unit_generator import (
    _function_unit,
)


def test_completed_agent_candidate_stays_pending_for_controller_checks():
    state = _UnitState(unit=_function_unit())
    outcome = InterventionGenerator._record_agent_response(
        state,
        SimpleNamespace(
            structured_response=GenerationAgentOutcome(
                status="completed",
                reason="wrote implementation and test candidate",
            )
        ),
    )
    assert outcome is not None
    assert state.status == "pending"
    assert state.failure_code is None


def test_unable_means_no_candidate_and_is_not_a_plan_mismatch():
    state = _UnitState(unit=_function_unit())
    outcome = InterventionGenerator._record_agent_response(
        state,
        SimpleNamespace(
            structured_response=GenerationAgentOutcome(
                status="unable",
                reason="required target input is absent",
            )
        ),
    )
    assert outcome is not None
    assert state.status == "generation_failed"
    assert state.failure_code == "no_candidate"
    assert state.last_failure is not None
    assert state.last_failure.code == "no_candidate"


def test_agent_trace_has_one_role(tmp_path):
    handle = AgentHandle(
        agent=SimpleNamespace(),
        trace_dir=tmp_path / "traces",
        agent_name="execution-unit-unit-a",
        title="unit-a",
        model="test-model",
    )
    assert handle.trace_for_round(1).md_path.name == "round-01__generator.md"


def test_invalid_envelope_keeps_existing_candidate_for_controller_checks(tmp_path):
    state = _UnitState(unit=_function_unit())
    crate_root, test_root = tmp_path / "crate", tmp_path / "tests"
    module = crate_root / "src" / unit_module_name(state.unit.unit_id)
    module.mkdir(parents=True)
    (module / "logic.rs").write_text("pub fn candidate() {}\n")
    test_file = test_root / unit_test_relative_path(state.unit.unit_id)
    test_file.parent.mkdir(parents=True)
    test_file.write_text("#[test] fn candidate() {}\n")

    outcome = InterventionGenerator._record_agent_response(
        state,
        SimpleNamespace(structured_response=None),
        crate_root=crate_root,
        test_root=test_root,
    )

    assert outcome is None
    assert state.status == "pending"
    assert state.failure_code == "structured_output_error"


def test_provider_failure_never_promotes_leftover_candidate(tmp_path):
    state = _UnitState(unit=_function_unit())
    crate_root, test_root = tmp_path / "crate", tmp_path / "tests"
    module = crate_root / "src" / unit_module_name(state.unit.unit_id)
    module.mkdir(parents=True)
    (module / "logic.rs").write_text("pub fn stale() {}\n")
    test_file = test_root / unit_test_relative_path(state.unit.unit_id)
    test_file.parent.mkdir(parents=True)
    test_file.write_text("#[test] fn stale() {}\n")

    outcome = InterventionGenerator._record_agent_response(
        state,
        RuntimeError("stream disconnected before completion"),
        crate_root=crate_root,
        test_root=test_root,
    )

    assert outcome is None
    assert state.status == "generation_failed"
    assert state.failure_code == "provider_error"


def test_structured_error_never_promotes_unchanged_template(tmp_path):
    state = _UnitState(unit=_function_unit())
    crate_root, test_root = tmp_path / "crate", tmp_path / "tests"
    module = crate_root / "src" / unit_module_name(state.unit.unit_id)
    module.mkdir(parents=True)
    (module / "logic.rs").write_text("pub fn template() {}\n")
    test_file = test_root / unit_test_relative_path(state.unit.unit_id)
    test_file.parent.mkdir(parents=True)
    test_file.write_text("#[test] fn template() {}\n")
    snapshot = {
        str(path): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in (module / "logic.rs", test_file)
    }

    InterventionGenerator._record_agent_response(
        state,
        SimpleNamespace(structured_response=None),
        crate_root=crate_root,
        test_root=test_root,
        source_snapshot=snapshot,
    )

    assert state.status == "generation_failed"
    assert state.failure_code == "structured_output_error"


def test_report_stem_bounds_model_authored_summary():
    stem = unit_report_stem("a very long finding summary " * 40, "unit-1234567890abcdef")
    assert len(stem) <= 92
    assert stem.endswith("__1234567890")
