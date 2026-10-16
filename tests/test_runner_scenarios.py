from fmst_analyzer.runner.probe import evaluate_interaction_scenario
from fmst_analyzer.runner.runner import _scenario_weakening
from fmst_analyzer.runner.schema import (
    InteractionScenario,
    InteractionStep,
    InteractionProbe,
    ObservationAssertion,
    ProbeResult,
    RunnerDecision,
    ScenarioObservation,
)


def _scenario(**kwargs):
    values = dict(
        protocol="http",
        port=80,
        steps=[InteractionStep(request_text="GET / HTTP/1.0\r\n\r\n", expected_status_code=200)],
        evidence_refs=["network.finding:svc-1"],
    )
    values.update(kwargs)
    return InteractionScenario(**values)


def test_scenario_requires_decidable_evidence_and_accepts_expected_response():
    result = evaluate_interaction_scenario(
        _scenario(),
        [ProbeResult(connected=True, interacted=True, attempts=1,
                     response_text="HTTP/1.0 200 OK\r\n\r\nhello", status_code=200)],
    )
    assert result.status == "success"
    assert result.steps[0].passed


def test_business_readback_and_protected_continuity_are_required_after_write():
    scenario = _scenario(steps=[
        InteractionStep(request_text="GET /device HTTP/1.0\r\n\r\n",
                        expected_status_code=200, response_contains='"model":"fixture"'),
        InteractionStep(request_text="POST /label HTTP/1.0\r\n\r\nlabel=after",
                        expected_status_code=200, response_contains='"saved":true'),
        InteractionStep(request_text="GET /label HTTP/1.0\r\n\r\n",
                        expected_status_code=200, response_contains='"label":"after"'),
        InteractionStep(request_text="GET /protected/status HTTP/1.0\r\n\r\n",
                        expected_status_code=200, response_contains='"ready":true',
                        response_not_contains=['"login_required":true']),
    ])

    def response(body):
        return ProbeResult(connected=True, interacted=True, attempts=1,
                           response_text="HTTP/1.0 200 OK\r\n\r\n" + body,
                           status_code=200)

    good = [response('{"model":"fixture"}'), response('{"saved":true}'),
            response('{"label":"after"}'), response('{"ready":true}')]
    assert evaluate_interaction_scenario(scenario, good).status == "success"
    stale = [*good[:2], response('{"label":"before"}'), good[3]]
    result = evaluate_interaction_scenario(scenario, stale)
    assert result.status == "blocked" and not result.steps[2].passed
    lost_session = [*good[:3], response('{"login_required":true}')]
    result = evaluate_interaction_scenario(scenario, lost_session)
    assert result.status == "blocked" and not result.steps[3].passed
    assert len(result.steps) == len(scenario.steps)


def test_early_exit_retains_failed_step_and_process_observation():
    scenario = _scenario(steps=[InteractionStep(request_text="first", expected_status_code=200),
                                InteractionStep(request_text="second", expected_status_code=200)])
    observation = ScenarioObservation(source="lifecycle", kind="target_lifecycle", fact="target_exit_code=42")
    result = evaluate_interaction_scenario(scenario,
        [ProbeResult(connected=False, interacted=False, attempts=1, error="target exited")], [observation])
    assert result.status == "unsupported"
    assert len(result.steps) == 1 and result.steps[0].index == 1 and not result.steps[0].passed
    assert result.observations == [observation]


def test_scenario_result_can_carry_machine_observation_facts_without_claiming_state():
    result = evaluate_interaction_scenario(
        _scenario(),
        [ProbeResult(connected=True, interacted=True, attempts=1,
                     response_text="HTTP/1.0 200 OK\r\n\r\nhello", status_code=200)],
    )
    result.observations.append(
        ScenarioObservation(
            source="probe",
            fact="step=1 connected=true response_nonempty=true status_code=200",
        )
    )
    assert result.state_changes_observed == []
    assert result.observations[0].source == "probe"


def test_required_state_change_uses_controller_verified_observation_channels():
    scenario = _scenario(
        required_state_changes=["ordered caller-visible response sequence completed"],
        observation_requirements=["ordered_response_sequence"],
        observation_assertions=[ObservationAssertion(
            target="state_change", target_index=1,
            predicate="ordered_response_sequence_complete",
        )],
    )
    result = evaluate_interaction_scenario(
        scenario,
        [ProbeResult(connected=True, interacted=True, attempts=1,
                     response_text="HTTP/1.0 200 OK\r\n\r\nhello", status_code=200)],
        [ScenarioObservation(
            source="probe", kind="ordered_response_sequence",
            fact="steps_interacted=1",
        )],
    )
    assert result.status == "success"
    assert result.state_changes_observed


def test_required_state_change_without_typed_observation_remains_blocked():
    scenario = _scenario(required_state_changes=["same process served the request"])
    result = evaluate_interaction_scenario(
        scenario,
        [ProbeResult(connected=True, interacted=True, attempts=1,
                     response_text="HTTP/1.0 200 OK\r\n\r\nhello", status_code=200)],
    )
    assert result.status == "blocked"
    assert "unbound claims" in (result.error or "")


def test_precondition_can_use_staged_rootfs_observation_channel():
    scenario = _scenario(
        preconditions=["staged rootfs is ready"],
        observation_requirements=["staged_rootfs"],
        observation_assertions=[ObservationAssertion(
            target="precondition", target_index=1,
            predicate="staged_rootfs_ready",
        )],
    )
    result = evaluate_interaction_scenario(
        scenario,
        [ProbeResult(connected=True, interacted=True, attempts=1,
                     response_text="HTTP/1.0 200 OK\r\n\r\nhello", status_code=200)],
        [ScenarioObservation(
            source="container", kind="staged_rootfs",
            fact="staged_rootfs_ready=true",
        )],
    )
    assert result.status == "success"


def test_generic_observation_channel_cannot_prove_arbitrary_state_change():
    scenario = _scenario(
        required_state_changes=["configuration persisted to nonvolatile storage"],
        observation_requirements=["ordered_response_sequence"],
        observation_assertions=[ObservationAssertion(
            target="state_change", target_index=1,
            predicate="ordered_response_sequence_complete",
        )],
    )
    result = evaluate_interaction_scenario(
        scenario,
        [ProbeResult(connected=True, interacted=True, attempts=1,
                     response_text="HTTP/1.0 200 OK\r\n\r\nhello", status_code=200)],
        [ScenarioObservation(
            source="probe", kind="ordered_response_sequence",
            fact="steps_interacted=1",
        )],
    )
    # The machine fact is real, but it is not proof of the unrelated semantic
    # claim. The Controller needs a dedicated owner or trace predicate first.
    assert result.status == "blocked"
    assert "canonical predicate" in (result.error or "")


def test_scenario_rejects_wrong_status_and_forbidden_body():
    scenario = _scenario(
        steps=[InteractionStep(request_text="GET / HTTP/1.0\r\n\r\n",
                               expected_status_code=200,
                               response_not_contains=["Internal Server Error"])],
    )
    result = evaluate_interaction_scenario(
        scenario,
        [ProbeResult(connected=True, interacted=True, attempts=1,
                     response_text="HTTP/1.0 500 Internal Server Error\r\n\r\nInternal Server Error",
                     status_code=500)],
    )
    assert result.status == "blocked"
    assert not result.steps[0].passed


def test_scenario_gap_can_be_recorded_but_never_succeeds():
    scenario = InteractionScenario(
        protocol="tcp", port=1234,
        steps=[InteractionStep(request_text="ping")],
        specification_gap=True,
        gap_reason="No caller-visible protocol contract was recovered.",
    )
    result = evaluate_interaction_scenario(
        scenario,
        [ProbeResult(connected=True, interacted=True, attempts=1, response_text="pong")],
    )
    assert result.status == "specification_gap"


def test_omitted_runner_scenario_is_explicit_gap():
    decision = RunnerDecision(
        action="run",
        probe=InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n"),
        summary="legacy probe",
    )
    assert decision.scenario is not None
    assert decision.scenario.specification_gap


def test_new_evidence_can_resolve_gap_without_erasing_previous_scenario():
    gap = _scenario(specification_gap=True, gap_reason="Protocol response expectation unknown")
    resolved = _scenario(steps=[InteractionStep(request_text=gap.steps[0].request_text,
        expected_status_code=200, response_contains="source-backed business result")])
    assert "reason" in _scenario_weakening(gap, resolved)
    assert _scenario_weakening(gap, resolved,
        scenario_resolution_reason="Inspected native handler and recovered the expected business response") is None
    assert gap.specification_gap and gap.gap_reason
    resolved.steps[0].request_text = "GET /easy HTTP/1.0\r\n\r\n"
    assert "request was changed" in _scenario_weakening(gap, resolved, scenario_resolution_reason="new evidence")


def test_completion_schema_does_not_infer_business_coverage_from_request_counts():
    import pytest
    from pydantic import ValidationError
    from fmst_analyzer.runner.schema import RehostingResult
    with pytest.raises(ValidationError, match="complete requires"):
        RunnerDecision(action="complete", summary="unsupported success")
    with pytest.raises(ValidationError, match="evidence-bound completion"):
        RehostingResult(target_binary="service", guest_arch="arm", selected_recipe_id=None,
            status="success", final_summary="scenario only")


def test_nonempty_response_without_positive_assertion_is_a_gap():
    scenario = InteractionScenario(
        protocol="tcp", port=1234,
        steps=[InteractionStep(request_text="ping")],
        evidence_refs=["ipc.finding:peer-1"],
    )
    assert scenario.specification_gap
    result = evaluate_interaction_scenario(
        scenario,
        [ProbeResult(connected=True, interacted=True, attempts=1, response_text="pong")],
    )
    assert result.status == "specification_gap"


def test_later_runner_decision_cannot_remove_bootstrap_assertions():
    floor = _scenario(
        preconditions=["config staged"],
        required_state_changes=["listener accepted request"],
        rejection_conditions=["generic error"],
    )
    weakened = _scenario()
    assert _scenario_weakening(floor, weakened) == "precondition assertion was removed"


def test_later_runner_decision_may_add_stronger_assertions():
    floor = _scenario()
    stronger = _scenario(
        steps=[
            InteractionStep(
                request_text="GET / HTTP/1.0\r\n\r\n",
                expected_status_code=200,
                response_contains="hello",
            ),
            InteractionStep(request_text="GET /health HTTP/1.0\r\n\r\n", expected_status_code=200),
        ],
    )
    assert _scenario_weakening(floor, stronger) is None
