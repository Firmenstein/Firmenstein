"""Offline Controller wiring checks, explicitly not real Agent/guest evidence."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import fmst_analyzer.runner.runner as controller
from fmst_analyzer.runner.docker_sandbox import SandboxAttempt
from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario, InteractionStep, ProbeResult, RunnerCompletion, RunnerDecision, ScenarioResult
from fmst_analyzer.synthesizer.intervention_generator.schema import InterventionGenerationResult


@pytest.fixture
def wired_controller(tmp_path, monkeypatch):
    rootfs, workspace, reports = (tmp_path / p for p in ("rootfs", "workspace", "reports"))
    for path in (rootfs, workspace, reports):
        path.mkdir()
    (rootfs / "guest").write_bytes(b"controlled-identity-not-an-ELF")
    generation = InterventionGenerationResult(target_binary="guest", arch="arm", total_units=0,
        plan_digest="0" * 64, environment={"status": "not_needed", "unit_ids": [], "reason": "No environment units"},
        ok_count=0, not_ready_count=0, skipped_count=0, units=[], cargo_build_status="not_run", cargo_test_status="not_run")
    recipe = SimpleNamespace(recipe_id="recipe", executable_path="/guest", model_dump_json=lambda **kwargs: '{"recipe_id":"recipe","executable_path":"/guest"}')
    plan = SimpleNamespace(launch_choice=SimpleNamespace(recipe_id="recipe"), service_goal="controlled protocol interaction", units={}, runner_tasks={})
    monkeypatch.setattr(controller, "archive_stage_outputs", lambda *args: None)
    monkeypatch.setattr(controller, "load_persisted_intervention_plan", lambda *a, **kw: (SimpleNamespace(launch_candidates={"recipe": recipe}), plan))
    monkeypatch.setattr(controller, "load_persisted_intervention_generation", lambda *a, **kw: generation)
    monkeypatch.setattr(controller, "validate_generation_publication", lambda *a: SimpleNamespace(baseline_id="baseline", root=tmp_path / "baseline"))
    monkeypatch.setattr(controller, "materialize_generation_workspace", lambda *a, **kw:
        SimpleNamespace(intervention_root=workspace, test_harness_root=None, root=workspace, environment_script=None))
    monkeypatch.setattr(controller, "create_runtime_builder", lambda **kw: SimpleNamespace(cleanup_records=[]))

    state = SimpleNamespace(agent_instances=0, messages=[], attempts=[], closed=False, success_at=2, invalid_bootstraps=0,
                            wait_on_feedback=False, feedback_started=asyncio.Event(), start_failure=False, publications=[],
                            latest_success=False)
    def publish(**kwargs):
        # Publication has separate real-copy/tampering tests. This fixture only
        # proves Controller wiring and does not claim a real guest or snapshot.
        state.publications.append(kwargs)
        return tmp_path / "frozen-success/manifest.json"
    monkeypatch.setattr(controller, "publish_success", publish)
    scenario = InteractionScenario(protocol="http", port=8080, evidence_refs=["controlled-test-fixture"],
        steps=[InteractionStep(request_text="GET / HTTP/1.0\r\n\r\n", expected_status_code=200, response_contains="controlled-response")])

    class Agent:
        def __init__(self, **kwargs):
            state.agent_instances += 1
            state.evidence = kwargs['evidence_state']
            state.framework = kwargs['runtime_workspace']

        async def invoke(self, message):
            state.messages.append(message)
            if state.attempts and state.wait_on_feedback:
                state.feedback_started.set()
                await asyncio.Event().wait()
            index = len(state.messages)
            invalid = index <= state.invalid_bootstraps
            if state.latest_success:
                path = state.evidence.attempt_json
                number = json.loads(path.read_text())["attempt_number"]
                decision = RunnerDecision(action="complete", completion=RunnerCompletion(
                    attempt_number=number, attempt_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    coverage="Controlled single-operation service; only the fixture's declared goal is covered."),
                    summary="controlled evidence-bound completion")
            else:
                decision = RunnerDecision(action="complete" if invalid else "run",
                    completion=RunnerCompletion(attempt_number=1, attempt_sha256="0"*64, coverage="premature") if invalid else None,
                    probe=None if invalid else InteractionProbe(port=8080, request_text="GET / HTTP/1.0\r\n\r\n"),
                    scenario=None if invalid else scenario.model_copy(deep=True),
                    guest_args=[f"revision-{index}"], summary="controlled offline response")
            return decision, SimpleNamespace(provider="test-double", session_id="same-test-session", turn_id=str(index), status="completed", text=decision.model_dump_json())

        async def aclose(self):
            state.closed = True

    class Sandbox:
        harness_path = None
        def __init__(self, **kwargs):
            self.target_slug = "guest"
            self.session_root = tmp_path / "sandbox"
            self.session_root.mkdir()
            self.bundle_dir = self.session_root / "bundle"
            self.bundle_dir.mkdir()
            self._active_rootfs = rootfs
            self.environment_script_failure = None
            self.environment_script_applications = 0
            self.cleanup_records = []

        def prepare(self, *a): pass
        def configure_network(self, network):
            self.network = network
        def refresh_environment_script(self): pass
        def update_rootfs_actions(self, *a): pass

        def run_attempt(self, **kwargs):
            kwargs["network"] = self.network
            state.attempts.append(kwargs)
            number = kwargs["attempt_number"]
            output = self.session_root / f"attempt-{number}"
            output.mkdir()
            if state.start_failure and number == 1:
                raise RuntimeError("controlled Docker startup failure")
            (output / "container.log").write_text("controlled failure" if number < state.success_at else "controlled response")
            passed = number >= state.success_at
            state.latest_success = passed
            return SandboxAttempt(container_exit_code=None, target_exit_code=None if passed else 42,
                timed_out=False, probe_result=ProbeResult(connected=passed, interacted=passed, attempts=1),
                scenario_result=ScenarioResult(status="success" if passed else "blocked", error=None if passed else "target exited"),
                runtime_trace_path=output / "trace.json", runtime_trace_paths=(), container_log_path=output / "container.log",
                companion_log_paths=(), rootfs_adaptations=(), heartbeat_paths=(), watchdog_path=output / "watchdog.json",
                watchdog_triggered=not passed, termination_reason="probe_satisfied" if passed else "target_exit")

        def close(self):
            self.cleanup_records.append({"operation": "offline sandbox close", "success": True})

    monkeypatch.setattr(controller, "RunnerAgentSession", Agent)
    monkeypatch.setattr(controller, "DockerRootfsSandbox", Sandbox)
    config = SimpleNamespace(workdir=tmp_path, target_diagnostic_reports_dir=lambda: reports,
        target_agent_debug_dir=lambda: tmp_path / "debug")
    runner = controller.RehostingRunner(config)
    view = SimpleNamespace(lib_dep_graph=SimpleNamespace(get_nodes=lambda: []))
    api_source = tmp_path / "runtime/fmst-iib-api/src/manifest.rs"
    api_source.parent.mkdir(parents=True)
    api_source.write_text("pub const CURRENT_ABI_VERSION: u32 = 4;\n")
    return runner, state, dict(view=view, rootfs=rootfs, runtime_workspace=tmp_path / "runtime"), tmp_path


def test_actual_controller_wires_failure_message_response_and_next_attempt(wired_controller):
    runner, state, args, root = wired_controller
    result = asyncio.run(runner.run(**args))
    assert result.status == "success"
    assert state.agent_instances == 1 and state.closed
    assert state.framework == args['runtime_workspace']
    assert len(state.attempts) == 2
    assert "termination_reason=target_exit" in state.messages[1]
    assert "target_exit_code=42" in state.messages[1]
    assert 'network=' in state.messages[1]
    assert 'Configured runtime owners=' in state.messages[1]
    for number in (1, 2):
        path = root / f"reports/runner_reports/attempts/attempt-{number:02d}/runtime-owners.json"
        assert json.loads(path.read_text())["schema_version"] == 1
    assert result.attempts[-1].network == state.attempts[-1]["network"]
    receipt = json.loads(Path(result.session_receipt_path).read_text())
    exchanges = [json.loads(p.read_text()) for p in sorted(Path(receipt["feedback_root"]).glob("exchange-*.json"))]
    assert [r["response_metadata"]["session_id"] for r in exchanges] == ["same-test-session"] * 3
    assert exchanges[1]["source_attempt_path"] == str(root / "reports/runner_reports/attempts/attempt-01/attempt.json")
    assert exchanges[1]["admission"] == "accepted"
    assert exchanges[1]["executions"][-1]["attempt_number"] == 2
    assert exchanges[1]["executions"][-1]["status"] == "completed"
    assert state.publications[0]["attempt"].attempt_number == 2
    assert result.success_configuration_path == str(root / "frozen-success/manifest.json")
    assert result.decision_history[-1].action == "complete"
    assert result.completion.attempt_number == 2
    assert "not automatic task completion" in state.messages[2]
    assert exchanges[2]["source_attempt_path"].endswith("attempt-02/attempt.json")


def test_caller_goal_reaches_bootstrap_and_all_feedback_without_changing_plan(wired_controller):
    runner, state, args, root = wired_controller
    runner.service_goal = "Native management login, stateful configuration reads and reversible write/readback"
    result = asyncio.run(runner.run(**args))
    assert result.status == "success"
    assert all("Service goal: " + runner.service_goal in message for message in state.messages)
    goal_path = Path(result.session_receipt_path).parent / "input-goal.json"
    assert json.loads(goal_path.read_text()) == {"service_goal": runner.service_goal, "source": "caller"}


def test_invalid_staged_rootfs_action_returns_feedback_and_can_recover(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    original = controller.DockerRootfsSandbox.update_rootfs_actions
    rejected = False

    def apply(self, *values):
        nonlocal rejected
        if not rejected:
            rejected = True
            raise ValueError("action would follow an existing symlink: /lib/guest-loader")
        return original(self, *values)

    monkeypatch.setattr(controller.DockerRootfsSandbox, "update_rootfs_actions", apply)
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and len(state.attempts) == 2
    assert state.agent_instances == 1
    assert any("action would follow an existing symlink" in m for m in state.messages)
    exchanges = [json.loads(p.read_text()) for p in (Path(result.session_receipt_path).parent / "feedback").glob("exchange-*.json")]
    assert any(e["status"] == "failed" and e["phase"] == "prepare"
               for x in exchanges for e in x["executions"])


@pytest.mark.parametrize("defect", ["wrong_hash", "old_attempt", "unverified", "source_edit", "configuration"])
def test_completion_rejection_returns_to_same_agent_without_publication(wired_controller, monkeypatch, defect):
    runner, state, args, root = wired_controller
    state.success_at = 1
    original = controller.RunnerAgentSession.invoke

    async def premature(self, message):
        if len(state.messages) == 2:
            assert not state.publications
        decision, response = await original(self, message)
        if len(state.messages) == 2:
            assert decision.action == "complete"
            if defect == "wrong_hash":
                decision.completion.attempt_sha256 = "0" * 64
            elif defect == "old_attempt":
                decision.completion.attempt_number = 999
            elif defect == "unverified":
                decision.completion.unverified_requirements = ["required write/readback remains untested"]
            elif defect == "source_edit":
                (root / "workspace/unverified.txt").write_text("changed after test")
            else:
                decision.guest_args = ["different-launch"]
        return decision, response

    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", premature)
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and len(state.attempts) == 1
    assert len(state.messages) == 3 and state.agent_instances == 1
    assert "Controller rejected" in state.messages[2]
    assert len(state.publications) == 1
    assert not (root / "workspace/unverified.txt").exists()


def test_success_can_be_followed_by_more_checks_and_failure_repair(wired_controller, monkeypatch):
    from dataclasses import replace
    runner, state, args, root = wired_controller
    state.success_at = 1
    original = controller.RunnerAgentSession.invoke
    run = controller.DockerRootfsSandbox.run_attempt
    expanded = None

    async def add_checks(self, message):
        nonlocal expanded
        decision, response = await original(self, message)
        if len(state.messages) in (2, 3, 4):
            if expanded is None:
                expanded = InteractionScenario.model_validate(json.loads(state.evidence.attempt_json.read_text())["scenario"])
                expanded.steps.append(InteractionStep(request_text="GET /config HTTP/1.0\r\n\r\n",
                    expected_status_code=200, response_contains='"value":"expected"'))
            selected = expanded.model_copy(deep=True)
            if len(state.messages) == 3:
                selected.steps.pop()  # Must not lose the addition after it fails.
            decision = RunnerDecision(action="run", probe=InteractionProbe(port=8080, request_text=expanded.steps[0].request_text),
                scenario=selected, summary="additional required config read; retain original test")
        return decision, response

    def fail_added_check(self, **kwargs):
        result = run(self, **kwargs)
        if kwargs["attempt_number"] == 2:
            state.latest_success = False
            return replace(result, scenario_result=ScenarioResult(status="blocked", error="configuration not initialized"))
        return result

    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", add_checks)
    monkeypatch.setattr(controller.DockerRootfsSandbox, "run_attempt", fail_added_check)
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and len(state.attempts) == 4
    assert [a.scenario_result.status for a in result.attempts] == ["success", "blocked", "success", "success"]
    assert len(result.attempts[-1].scenario.steps) == 2
    assert "configuration not initialized" in state.messages[2]
    assert not any("steps were removed" in m for m in state.messages)
    assert state.publications[0]["attempt"].attempt_number == 4


def test_agent_can_revise_tests_after_failure_with_original_version_retained(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    state.success_at = 2
    original = controller.RunnerAgentSession.invoke

    async def drop(self, message):
        decision, response = await original(self, message)
        if len(state.messages) == 1:
            decision.scenario.steps.append(InteractionStep(request_text="GET /config HTTP/1.0\r\n\r\n", expected_status_code=200))
        elif len(state.messages) == 3:
            decision.scenario = result_scene.model_copy(deep=True)
        return decision, response

    result_scene = InteractionScenario(protocol="http", port=8080, evidence_refs=["controlled-test-fixture"], steps=[
        InteractionStep(request_text="GET / HTTP/1.0\r\n\r\n", expected_status_code=200, response_contains="controlled-response"),
        InteractionStep(request_text="GET /config HTTP/1.0\r\n\r\n", expected_status_code=200)])
    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", drop)
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and not any("steps were removed" in m for m in state.messages)
    assert len(result.attempts[0].scenario.steps) == 2
    assert len(result.attempts[-1].scenario.steps) == 1
    assert result.attempts[-1].request_revisions[0].before == result.attempts[0].scenario


def test_external_input_request_retains_unfinished_goal_after_protocol_success(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    runner.max_attempts, state.success_at = 1, 1
    original = controller.RunnerAgentSession.invoke

    async def stop_after_pass(self, message):
        decision, response = await original(self, message)
        if state.latest_success:
            decision = RunnerDecision(action="request_input", input_request={"required_input":"Caller-owned enrollment credential", "evidence_refs":[str(state.evidence.attempt_json)], "unavailable_reason":"Credential is issued by external tenant, unavailable in this fixture"}, summary="Enrollment requires caller input")
        return decision, response

    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", stop_after_pass)
    result = asyncio.run(runner.run(**args))
    assert result.status == "waiting_for_input" and result.attempts[0].outcome == "success"
    receipt = json.loads(Path(result.session_receipt_path).read_text())
    assert receipt["state"] == "waiting_for_input" and receipt["input_request"] == result.input_request.model_dump()
    assert not state.publications and result.completion is None


@pytest.mark.parametrize("edit_turn, action", [(1, "run"), (2, "run"), (2, "continue")])
def test_source_diff_requires_edit_action_before_admission(
    wired_controller, monkeypatch, edit_turn, action
):
    runner, state, args, root = wired_controller
    original = controller.RunnerAgentSession.invoke
    lock = root / "workspace/Cargo.lock"

    async def create_lock(self, message):
        decision, response = await original(self, message)
        if len(state.messages) == edit_turn:
            lock.write_text("generated during tool check\n")
            if action == "continue":
                decision = RunnerDecision(action="continue", summary="work in progress")
            response.text = decision.model_dump_json()
        elif len(state.messages) == edit_turn + 1:
            assert not lock.exists(), "Rejected workspace changes must be restored"
        return decision, response

    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", create_lock)
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and len(state.attempts) == 2
    assert len(state.messages) == 4
    assert not lock.exists() and result.revision_history == []
    assert all(d.action in {"run", "complete"} and not d.changed_paths for d in result.decision_history)
    receipt = json.loads(Path(result.session_receipt_path).read_text())
    exchanges = [json.loads(p.read_text()) for p in sorted(Path(receipt["feedback_root"]).glob("exchange-*.json"))]
    rejected = exchanges[edit_turn - 1]
    assert rejected["admission"] == "rejected" and rejected["response"]["action"] == action
    assert rejected["response"]["changed_paths"] == []
    assert "intervention/Cargo.lock" in rejected["error"]
    assert not rejected["executions"]


def test_owned_workspace_edit_keeps_canonical_decision_and_revision(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    original = controller.RunnerAgentSession.invoke

    async def edit_lock(self, message):
        decision, response = await original(self, message)
        if len(state.messages) == 2:
            (root / "workspace/Cargo.lock").write_text("declared workspace change\n")
            decision = RunnerDecision(**{
                **decision.model_dump(), "action": "edit_workspace",
                "changed_paths": ["intervention/workspace/Cargo.lock"],
            })
            response.text = decision.model_dump_json()
        return decision, response

    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", edit_lock)
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and len(state.attempts) == 2
    assert result.decision_history[0].changed_paths == []
    assert result.decision_history[1].action == "edit_workspace"
    assert result.decision_history[1].changed_paths == ["intervention/Cargo.lock"]
    assert result.revision_history[0].changed_paths == ["intervention/Cargo.lock"]


def test_missing_launch_is_resolved_by_same_agent_before_guest(wired_controller, monkeypatch):
    import hashlib
    from fmst_analyzer.runner.schema import LaunchEvidence, RuntimeLaunchProposal
    runner, state, args, root = wired_controller
    guest = args['rootfs'] / 'guest'
    guest.write_bytes(b'\x7fELFcontrolled-fixture')
    source = args['rootfs'] / 'rc'
    source.write_text('/guest --serve\n')
    identity = SimpleNamespace(selected_rootfs_path='guest', executable_sha256=hashlib.sha256(guest.read_bytes()).hexdigest(),
        model_dump_json=lambda **kw: '{"selected_rootfs_path":"guest"}')
    plan = SimpleNamespace(launch_choice=SimpleNamespace(recipe_id=None, model_dump_json=lambda **kw: '{"recipe_id":null}'),
        service_goal='controlled protocol', units={}, runner_tasks={})
    monkeypatch.setattr(controller, 'load_persisted_intervention_plan', lambda *a, **kw: (SimpleNamespace(launch_candidates={}, target_identity=identity), plan))
    original = controller.RunnerAgentSession.invoke
    async def propose(self, message):
        decision, response = await original(self, message)
        if decision.action == 'complete':
            return decision, response
        decision.guest_args = ['--serve']
        # First response lacks a launch; same-session correction must occur
        # before any preparation or actual guest attempt.
        if len(state.messages) > 1:
            decision.launch_proposal = RuntimeLaunchProposal(executable_path='/guest', args=['--serve'], working_directory='/', environment={},
                evidence=[LaunchEvidence(path=str(source), sha256=hashlib.sha256(source.read_bytes()).hexdigest(), excerpt='/guest --serve')],
                rationale='controlled launch', limitations=['service unproved'])
        return decision, response
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', propose)
    state.success_at = 1
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and len(state.attempts) == 1
    assert state.agent_instances == 1 and len(state.messages) == 3
    assert 'submit a source-backed launch_proposal' in state.messages[1]
    assert result.launch_resolution == result.attempts[0].launch_resolution
    assert plan.launch_choice.recipe_id is None


def test_supplied_scenario_is_not_regenerated_on_new_session(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    runner.scenario_floor = InteractionScenario(protocol='http', port=8080, evidence_refs=['original'],
        steps=[InteractionStep(request_text=r'GET /original HTTP/1.0\r\n\r\n', expected_status_code=200, response_contains='controlled-response')])
    original = controller.RunnerAgentSession.invoke
    async def correct(self, message):
        decision, response = await original(self, message)
        if len(state.messages) > 1 and decision.action != 'complete':
            decision.scenario = runner.scenario_floor.model_copy(deep=True)
            decision.scenario.steps[0].request_text = 'GET /original HTTP/1.0\r\n\r\n'
            decision.request_representation_reason = 'Correct header separators; retain resource and assertions'
        return decision, response
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', correct)
    state.success_at = 1
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and len(state.attempts) == 1
    assert not any('request was changed' in m for m in state.messages)
    revision = result.attempts[0].request_revisions[0]
    assert revision.before == runner.scenario_floor
    assert revision.after == result.attempts[0].scenario
    assert revision.parent_sha256 != revision.result_sha256


def test_supplied_scenario_retains_original_evidence_when_agent_revises_it(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    runner.scenario_floor = InteractionScenario(protocol='http', port=8080,
        evidence_refs=['original producer', 'original consumer'],
        steps=[InteractionStep(request_text='GET / HTTP/1.0\r\n\r\n',
            expected_status_code=200, response_contains='controlled-response')])
    state.success_at = 1
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success'
    assert result.attempts[0].scenario.evidence_refs == [
        'original producer', 'original consumer', 'controlled-test-fixture']
    assert runner.scenario_floor.evidence_refs == ['original producer', 'original consumer']
    assert len(state.messages) == 2


def test_unresolved_launch_requests_specific_external_input(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    identity = SimpleNamespace(selected_rootfs_path='guest', model_dump_json=lambda **kw: '{}')
    plan = SimpleNamespace(launch_choice=SimpleNamespace(recipe_id=None, model_dump_json=lambda **kw: '{}'),
        service_goal='controlled protocol', units={}, runner_tasks={})
    monkeypatch.setattr(controller, 'load_persisted_intervention_plan', lambda *a, **kw:
        (SimpleNamespace(launch_candidates={}, target_identity=identity), plan))
    async def ask(self, message):
        decision = RunnerDecision(action="request_input", summary="Need caller's encrypted input",
            input_request={"required_input":"Decryption key", "evidence_refs":[str(root / "rootfs/guest")],
                           "unavailable_reason":"No key in supplied environment"})
        return decision, SimpleNamespace(text=decision.model_dump_json())
    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", ask)
    result = asyncio.run(runner.run(**args))
    assert result.status == 'waiting_for_input' and result.stop_reason == 'external_input_required'
    assert not state.attempts and not state.publications
    assert result.input_request.required_input == "Decryption key"


def test_controller_has_no_default_eight_attempt_or_sixteen_correction_stop(wired_controller):
    runner, state, args, root = wired_controller
    state.success_at, state.invalid_bootstraps = 10, 18
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and len(result.attempts) == 10
    assert len(state.messages) == 29 and state.agent_instances == 1
    receipt = json.loads(Path(result.session_receipt_path).read_text())
    records = [json.loads(p.read_text()) for p in Path(receipt["feedback_root"]).glob("exchange-*.json")]
    assert sum(r["admission"] == "rejected" for r in records) == 18
    assert sum(r["admission"] == "accepted" for r in records) == 11


@pytest.mark.parametrize("successful_attempt", [False, True])
def test_cancel_during_feedback_keeps_attempt_and_unknown_delivery(wired_controller, successful_attempt):
    runner, state, args, root = wired_controller
    if successful_attempt:
        state.success_at = 1
    state.wait_on_feedback = True
    async def cancel_feedback():
        task = asyncio.create_task(runner.run(**args))
        await asyncio.wait_for(state.feedback_started.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    asyncio.run(cancel_feedback())
    assert len(state.attempts) == 1 and state.closed
    assert not state.publications
    receipt = json.loads(next(root.glob("runner_controller_sessions/*/session.json")).read_text())
    assert receipt["state"] == "cancelled" and receipt["stop_reason"] == "user_cancelled"
    assert receipt["cleanup_records"]
    exchange = json.loads((Path(receipt["feedback_root"]) / "exchange-0002.json").read_text())
    assert exchange["delivery"] == "interrupted_delivery_unknown" and exchange["admission"] == "not_received"
    result = json.loads((root / "reports/runner_reports/rehosting_result.json").read_text())
    assert len(result["attempts"]) == 1 and result["status"] == "stopped"


def test_execution_error_can_retry_without_reusing_attempt_directory(wired_controller):
    runner, state, args, root = wired_controller
    state.start_failure = True
    result = asyncio.run(runner.run(**args))
    assert result.status == "success"
    assert [a["attempt_number"] for a in state.attempts] == [1, 2]
    assert [a.attempt_number for a in result.attempts] == [2]
    assert "controlled Docker startup failure" in state.messages[1]
    assert "do not assume the guest started" in state.messages[1]


def test_partial_peer_failure_is_readable_by_same_agent(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    original = controller.DockerRootfsSandbox.run_attempt
    def peer_failure(self, **kwargs):
        if kwargs['attempt_number'] == 1:
            state.attempts.append(kwargs)
            output = self.session_root / 'attempts/attempt-01'
            output.mkdir(parents=True)
            (output / 'companion-01.log').write_text('bind EACCES: Permission denied')
            (output / 'peer-readiness.json').write_text('{"state":"failed","error":"peer_exit"}')
            (output / 'runtime-dump').mkdir()
            (output / 'runtime-dump/manifest.json').write_text('{"status":"partial"}')
            harness = self.bundle_dir / 'fmst-harness-arm'
            harness.write_bytes(b'controlled-harness')
            self.harness_path = harness
            receipt = self.session_root / 'attempt_receipts/attempt-01.json'
            receipt.parent.mkdir()
            receipt.write_text('{"state":"error","stop_reason":"peer_exit"}')
            raise RuntimeError('peer readiness interrupted: peer_exit')
        return original(self, **kwargs)
    monkeypatch.setattr(controller.DockerRootfsSandbox, 'run_attempt', peer_failure)
    original_invoke = controller.RunnerAgentSession.invoke
    async def inspect(self, message):
        if len(state.attempts) == 1:
            assert 'bind EACCES: Permission denied' not in message
            assert str(state.evidence.attempt_json) in message
            assert state.evidence.attempt_json.is_relative_to(root / 'reports')
            assert json.loads(state.evidence.attempt_json.read_text())['kind'] == 'partial_execution'
            assert json.loads(state.evidence.runtime_dump_manifest.read_text())['status'] == 'partial'
            assert state.evidence.emulator_harness.name == 'fmst-harness-arm'
            assert state.evidence.emulator_harness_sha256 == hashlib.sha256(b'controlled-harness').hexdigest()
            assert state.evidence.companion_logs[0].read_text() == 'bind EACCES: Permission denied'
            assert state.evidence.trace_context_json is None
        return await original_invoke(self, message)
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', inspect)
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and state.agent_instances == 1
    assert [a.attempt_number for a in result.attempts] == [2]
    assert (root / 'reports/runner_reports/attempts/attempt-01/execution-receipt.json').is_file()


def test_partial_startup_admits_new_owner_then_builds_and_runs(wired_controller, monkeypatch):
    import subprocess
    from fmst_analyzer.runner.adaptation_schema import RuntimeUnitProposal, AdaptationEvidence
    from test_runner_adaptation import unit
    runner, state, args, root = wired_controller
    candidate = root / 'partial-repair'
    intervention = candidate / 'interventions/guest'
    monkeypatch.setattr(controller, 'materialize_generation_workspace', lambda *a, **kw:
        SimpleNamespace(intervention_root=intervention, test_harness_root=None,
                        root=candidate, environment_script=None))
    state.start_failure = True
    builds = []
    def build(*args, **kwargs):
        builds.append(args)
        return subprocess.CompletedProcess([], 0, '', '')
    monkeypatch.setattr(controller, '_run_cargo', build)
    binary = root / 'controlled.so'
    binary.write_bytes(b'controlled-runtime')
    monkeypatch.setattr(controller, '_locate_cdylib', lambda *a: binary)
    original = controller.RunnerAgentSession.invoke
    async def repair(self, message):
        decision, response = await original(self, message)
        turn = len(state.messages)
        if turn == 2:
            path = state.evidence.attempt_json
            assert path.name == 'partial-feedback.json'
            assert json.loads(path.read_text())['kind'] == 'partial_execution'
            assert not list((root / 'reports').glob('runner_reports/attempts/*/attempt.json'))
            decision.action = 'propose_unit'
            decision.unit_proposal = RuntimeUnitProposal(operation='upsert', unit=unit(),
                evidence=[AdaptationEvidence(path=str(path),
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest(), excerpt='partial_execution')],
                rationale='Observed startup dependency failure supports an owner experiment',
                limitations=['Controlled offline wiring only'])
        elif turn == 3:
            path = intervention / 'src/unit_runtime_status/logic.rs'
            assert path.is_file()
            path.write_text(path.read_text() + '\n// implement observed dependency\n')
            decision.action = 'edit_unit'
            decision.changed_unit_ids = ['runtime-status']
            decision.changed_paths = ['intervention/src/unit_runtime_status/logic.rs']
        return decision, response
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', repair)
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and state.agent_instances == 1
    assert len(state.attempts) == 2 and builds
    assert len(result.attempts) == 1 and result.attempts[0].attempt_number == 2
    assert len(result.adaptation_history) == 1
    assert result.attempts[0].adaptation_ids == [result.adaptation_history[0].adaptation_id]
    assert state.attempts[1]['intervention_so'] == binary


def test_publication_failure_retains_successful_execution_but_not_session_success(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    state.success_at = 1
    def broken_publication(**kwargs):
        raise OSError("controlled frozen input copy failure")
    monkeypatch.setattr(controller, "publish_success", broken_publication)
    result = asyncio.run(runner.run(**args))
    assert result.status == "error"
    assert result.attempts[0].outcome == "success"
    assert result.success_configuration_path is None
    assert "copy failure" in result.final_summary
    assert state.closed


@pytest.mark.parametrize("cancel_after_admission", [False, True])
def test_controller_preserves_owner_lifecycle_on_rollback_or_cancel(wired_controller, monkeypatch, cancel_after_admission):
    import hashlib
    import subprocess
    from fmst_analyzer.runner.adaptation_schema import RuntimeUnitProposal, AdaptationEvidence
    from test_runner_adaptation import unit
    runner, state, args, root = wired_controller
    candidate = root / 'derived-candidate'
    intervention, tests = candidate / 'interventions/guest', candidate / 'test_harnesses/guest'
    monkeypatch.setattr(controller, 'materialize_generation_workspace', lambda *a, **kw:
        SimpleNamespace(intervention_root=intervention, test_harness_root=tests, root=candidate, environment_script=None))
    state.success_at = 3
    state.unit_checks = []
    cancellation_ready = asyncio.Event()
    monkeypatch.setattr(controller, '_run_cargo', lambda *a, **kw: subprocess.CompletedProcess([], 0, '', ''))
    def check(builder, test_root, enabled, **kw):
        state.unit_checks.append(set(enabled))
        assert (test_root / 'tests/unit_runtime_status_test/main.rs').is_file()
        return subprocess.CompletedProcess([], 0, '', '')
    monkeypatch.setattr(controller, '_run_enabled_tests', check)
    binary = root / 'intervention.so'
    binary.write_bytes(b'controlled-shared-library')
    monkeypatch.setattr(controller, '_locate_cdylib', lambda *a: binary)
    original = controller.RunnerAgentSession.invoke
    async def propose(self, message):
        decision, response = await original(self, message)
        turn = len(state.messages)
        if turn == 4 and cancel_after_admission:
            cancellation_ready.set()
            await asyncio.Event().wait()
        if turn in (2, 4):
            attempt = root / f'reports/runner_reports/attempts/attempt-{len(state.attempts):02d}/attempt.json'
            evidence = AdaptationEvidence(path=str(attempt), sha256=hashlib.sha256(attempt.read_bytes()).hexdigest(), excerpt='blocked')
            active = sorted((candidate / 'runtime_adaptations').glob('*.json'))
            records = [json.loads(p.read_text()) for p in active if p.name != 'guestweave-api-binding.json']
            decision.action = 'propose_unit'
            decision.unit_proposal = RuntimeUnitProposal(operation='upsert' if turn == 2 else 'rollback',
                unit=unit() if turn == 2 else None, parent_adaptation_id=None if turn == 2 else records[0]['adaptation_id'],
                evidence=[evidence], rationale='controlled source-bound owner experiment', limitations=['Offline wiring fixture only'])
        elif turn == 3:
            source = intervention / 'src/unit_runtime_status/logic.rs'
            assert source.is_file()
            source.write_text(source.read_text() + '\n// controlled implementation edit\n')
            test = tests / 'tests/unit_runtime_status_test/main.rs'
            test.parent.mkdir(parents=True)
            test.write_text('// controlled test artifact; execution replaced at the boundary\n')
            decision.action = 'edit_unit'
            decision.changed_unit_ids = ['runtime-status']
            decision.changed_paths = ['intervention/src/unit_runtime_status/logic.rs', 'test_harness/tests/unit_runtime_status_test/main.rs']
        return decision, response
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', propose)
    if cancel_after_admission:
        async def cancel_after_two_attempts():
            task = asyncio.create_task(runner.run(**args))
            await asyncio.wait_for(cancellation_ready.wait(), timeout=5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        asyncio.run(cancel_after_two_attempts())
        result_path = root / 'reports/runner_reports/rehosting_result.json'
        result = json.loads(result_path.read_text())
        assert result['status'] == 'stopped' and result['stop_reason'] == 'user_cancelled'
        assert len(result['attempts']) == 2 and state.closed
        assert len(result['adaptation_history']) == 1
        owner = result['adaptation_history'][0]
        assert owner['proposal']['operation'] == 'upsert'
        assert result['attempts'][1]['adaptation_ids'] == [owner['adaptation_id']]
        assert 'controlled implementation edit' in (intervention / 'src/unit_runtime_status/logic.rs').read_text()
        receipt = json.loads(Path(result['session_receipt_path']).read_text())
        assert receipt['state'] == 'cancelled' and receipt['result_path'] == str(result_path)
        assert receipt['cleanup_records']
        exchange = json.loads((Path(receipt['feedback_root']) / 'exchange-0004.json').read_text())
        assert exchange['delivery'] == 'interrupted_delivery_unknown'
        assert exchange['admission'] == 'not_received'
        return
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and state.agent_instances == 1
    assert len(state.messages) == 6 and len(state.attempts) == 3
    assert state.unit_checks == []  # Runtime verifies through actual interaction, without a separate self-test phase.
    assert [len(attempt.adaptation_ids) for attempt in result.attempts] == [0, 1, 0]
    snapshots = [json.loads((root / f'reports/runner_reports/attempts/attempt-{n:02d}/runtime-owners.json').read_text())
                 for n in (1, 2, 3)]
    assert [set(item['units']) for item in snapshots] == [set(), {'runtime-status'}, set()]
    assert snapshots[1]['units']['runtime-status']['configured'] is True
    assert [len(item['adaptation_ids']) for item in snapshots] == [0, 1, 0]
    assert [record.proposal.operation for record in result.adaptation_history] == ['upsert', 'rollback']
    assert result.adaptation_history[0].before is None
    assert result.adaptation_history[1].after is None
    assert not (intervention / 'Cargo.toml').exists()
    assert not (intervention / 'src/unit_runtime_status/logic.rs').exists()
    receipt = json.loads(Path(result.session_receipt_path).read_text())
    exchanges = [json.loads(p.read_text()) for p in sorted(Path(receipt['feedback_root']).glob('exchange-*.json'))]
    assert {e['response_metadata']['session_id'] for e in exchanges} == {'same-test-session'}
    assert [e['admission'] for e in exchanges] == ['accepted'] * 6


def test_controller_admits_cookie_repair_and_carries_network_and_proof(wired_controller, monkeypatch):
    from dataclasses import replace
    from fmst_analyzer.runner.probe import build_probe_result, evaluate_interaction_scenario
    from fmst_analyzer.runner.request_wire import save_response_bytes
    from fmst_analyzer.runner.schema import RuntimeNetwork
    runner, state, args, root = wired_controller
    floor = InteractionScenario(protocol='http', port=8080, evidence_refs=['controlled evidence'], steps=[
        InteractionStep(request_text='GET / HTTP/1.0\r\n\r\n', expected_status_code=401),
        InteractionStep(request_text='GET /auth HTTP/1.0\r\nAuthorization: Basic right\r\n\r\n', expected_status_code=200)])
    runner.scenario_floor = floor
    agent_invoke = controller.RunnerAgentSession.invoke
    async def invoke(self, message):
        decision, response = await agent_invoke(self, message)
        if decision.action == 'complete':
            return decision, response
        decision.scenario = floor.model_copy(deep=True)
        if state.attempts:
            decision.cookie_continuity_reason = 'Return the previous server-issued session cookie'
            decision.scenario.steps[0].save_cookies = True
            decision.scenario.steps[1].request_text = decision.scenario.steps[1].request_text.replace(
                '\r\n\r\n', '\r\nCookie: sid={{cookie:sid}}\r\n\r\n')
            decision.network = RuntimeNetwork(probe_destination='interface')
        return decision, response
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', invoke)
    run = controller.DockerRootfsSandbox.run_attempt
    def attempt(self, **kwargs):
        result = run(self, **kwargs)
        responses = []
        raw_root = self.session_root / 'attempt_receipts' / f"attempt-{kwargs['attempt_number']:02d}-requests"
        raw_root.mkdir(parents=True)
        for index, step in enumerate(kwargs['scenario'].steps, 1):
            status = 200 if kwargs['attempt_number'] == 2 and index == 2 else 401
            raw = f'HTTP/1.0 {status} Fixture\r\nSet-Cookie: sid=opaque; Path=/\r\nContent-Length: 0\r\n\r\n'.encode()
            save_response_bytes(raw_root, index, raw, limit=1024)
            responses.append(build_probe_result(InteractionProbe(port=8080, request_text=step.request_text), connected=True, response=raw, attempts=1))
        return replace(result, scenario_result=evaluate_interaction_scenario(kwargs['scenario'], responses))
    monkeypatch.setattr(controller.DockerRootfsSandbox, 'run_attempt', attempt)
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and len(result.attempts) == 2
    revision = result.attempts[1].request_revisions[0]
    assert revision.kind == 'scenario_revision' and revision.before == floor
    assert [step.expected_status_code for step in revision.after.steps] == [401, 200]
    assert revision.after.steps[0].save_cookies
    assert result.attempts[1].network.probe_destination == 'interface'
    assert state.attempts[1]['network'] == result.attempts[1].network
    assert state.publications[0]['attempt'].request_revisions == [revision]
    assert not result.attempts[0].request_revisions


def test_environment_admission_edit_and_rollback_preserve_owner_and_script(wired_controller, monkeypatch):
    import hashlib
    from fmst_analyzer.runner.adaptation_schema import RuntimeUnitProposal, AdaptationEvidence
    from test_runner_adaptation import unit
    runner, state, args, root = wired_controller
    candidate = root / 'environment-candidate'
    intervention = candidate / 'intervention'
    environment = candidate / 'environment'
    environment.mkdir(parents=True)
    script = environment / 'setup_rootfs.py'
    script.write_text('original source script\n')
    original_unit = unit('seed', '/vendor/state')
    original_unit.strategy = 'environment_setup'
    revised = original_unit.model_copy(deep=True)
    revised.contract.state = ['Restore source-derived state after the observed failure']
    plan = SimpleNamespace(launch_choice=SimpleNamespace(recipe_id='recipe'), service_goal='controlled protocol interaction',
        units={'seed': original_unit}, runner_tasks={})
    recipe = SimpleNamespace(recipe_id='recipe', executable_path='/guest', model_dump_json=lambda **kw: '{}')
    monkeypatch.setattr(controller, 'load_persisted_intervention_plan', lambda *a, **kw: (SimpleNamespace(launch_candidates={'recipe': recipe}), plan))
    monkeypatch.setattr(controller, 'materialize_generation_workspace', lambda *a, **kw:
        SimpleNamespace(intervention_root=intervention, test_harness_root=None, root=candidate, environment_script=script))
    source = root / 'rootfs/init.sh'
    source.write_text('source supplied state')
    state.success_at = 3
    original = controller.RunnerAgentSession.invoke
    async def revise(self, message):
        decision, response = await original(self, message)
        turn = len(state.messages)
        if turn in (2, 4):
            attempt = root / f'reports/runner_reports/attempts/attempt-{len(state.attempts):02d}/attempt.json'
            evidence = [AdaptationEvidence(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest(), excerpt=excerpt)
                        for p, excerpt in [(attempt, 'blocked'), (source, 'source supplied state')]]
            records = [json.loads(p.read_text()) for p in (candidate / 'runtime_adaptations').glob('*.json') if p.name != 'guestweave-api-binding.json']
            decision.action = 'propose_unit'
            decision.unit_proposal = RuntimeUnitProposal(operation='upsert' if turn == 2 else 'rollback',
                unit=revised if turn == 2 else None, parent_adaptation_id=None if turn == 2 else records[0]['adaptation_id'],
                evidence=evidence, rationale='source bound environment correction', limitations=['Offline wiring only'])
        elif turn == 3:
            assert script.read_text() == 'original source script\n'
            assert not (intervention / 'Cargo.toml').exists()
            script.write_text('revised source script\n')
            decision.action = 'edit_workspace'
            decision.changed_paths = ['environment/setup_rootfs.py']
        return decision, response
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', revise)
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and len(state.messages) == 6
    assert script.read_text() == 'original source script\n'
    assert not (intervention / 'Cargo.toml').exists()
    assert original_unit.contract.state != revised.contract.state
    snapshots = [json.loads((root / f'reports/runner_reports/attempts/attempt-{n:02d}/runtime-owners.json').read_text()) for n in (1, 2, 3)]
    assert [s['units']['seed']['definition']['contract']['state'] for s in snapshots] == [original_unit.contract.state, revised.contract.state, original_unit.contract.state]
    assert [len(s['adaptation_ids']) for s in snapshots] == [0, 1, 0]


@pytest.mark.parametrize('primary_present', [False, True])
def test_primary_trace_is_explicit_even_when_descendant_sorts_first(wired_controller, monkeypatch, primary_present):
    runner, state, args, root = wired_controller
    state.success_at = 1
    run = controller.DockerRootfsSandbox.run_attempt
    def traces(self, **kwargs):
        from dataclasses import replace
        result = run(self, **kwargs)
        child = result.container_log_path.parent / 'runtime_trace.child-15.json'
        child.write_text('{"host_pid":15}')
        primary = result.container_log_path.parent / 'runtime_trace.json'
        paths = [child]
        if primary_present:
            primary.write_text('{"host_pid":7}')
            paths.append(primary)
        return replace(result, runtime_trace_path=primary, runtime_trace_paths=tuple(paths))
    monkeypatch.setattr(controller.DockerRootfsSandbox, 'run_attempt', traces)
    mapped = []
    def mapping(path, artifact_dir, *a, **kw):
        mapped.append(path.name)
        out = artifact_dir / 'runtime_trace_context.json'
        out.write_text('{}')
        return out, None
    monkeypatch.setattr(controller, 'persist_runtime_trace_context', mapping)
    result = asyncio.run(runner.run(**args))
    attempt = result.attempts[0]
    assert Path(attempt.runtime_trace_path).name == 'runtime_trace.json'
    assert attempt.runtime_trace_available is primary_present
    assert mapped == (['runtime_trace.json'] if primary_present else [])
    assert len(attempt.runtime_trace_paths) == (2 if primary_present else 1)
    assert state.evidence.trace_json == (Path(attempt.runtime_trace_path) if primary_present else None)
    if not primary_present:
        assert 'primary' in attempt.runtime_trace_context_error


def test_source_bound_client_correction_returns_to_same_agent_and_executes_again(wired_controller, monkeypatch):
    from fmst_analyzer.runner.schema import ScenarioRequestCorrection
    runner,state,args,root=wired_controller
    source=args['rootfs']/'native-ui.js';source.write_text('fetch("/native?form=login")')
    original=controller.RunnerAgentSession.invoke
    async def respond(self,message):
        decision,response=await original(self,message)
        if len(state.messages)==2:
            prior=state.evidence.attempt_json
            old=controller.RuntimeAttempt.model_validate_json(prior.read_text())
            decision.scenario=old.scenario.model_copy(deep=True)
            decision.scenario.steps[0].request_text='GET /native?form=login HTTP/1.0\r\n\r\n'
            decision.probe=InteractionProbe(port=8080,request_text=decision.scenario.steps[0].request_text)
            decision.request_correction=ScenarioRequestCorrection(
                parent_sha256=hashlib.sha256(old.scenario.model_dump_json().encode()).hexdigest(),step_indices=[1],
                reason='Native UI route corrects the earlier client request',evidence=[
                    dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),excerpt=p.read_text())
                    for p in [prior,source]])
        return decision,response
    monkeypatch.setattr(controller.RunnerAgentSession,'invoke',respond)
    result=asyncio.run(runner.run(**args))
    assert result.status=='success' and len(state.attempts)==2 and state.agent_instances==1
    revision=result.attempts[-1].request_revisions[0]
    assert revision.kind=='scenario_revision' and revision.before==result.attempts[0].scenario
    assert state.attempts[1]['scenario'].steps[0].request_text==revision.after.steps[0].request_text
    assert result.completion.attempt_number==2


def test_native_client_failure_and_completion_stay_in_one_agent_session(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    state.success_at = 1
    captured = {}
    original_init = controller.RunnerAgentSession.__init__
    original_invoke = controller.RunnerAgentSession.invoke

    def init(self, **kwargs):
        original_init(self, **kwargs)
        captured['client'] = kwargs['live_client']

    async def interact(self, message):
        decision, response = await original_invoke(self, message)
        if decision.action == 'complete':
            client = captured['client']
            candidate = client.start_candidate()
            assert candidate['attempt_sha256'] == decision.completion.attempt_sha256
            instance = root / ('native-first' if len(state.messages) == 2 else 'native-fresh')
            instance.mkdir()
            receipt = dict(path=str(instance), state='running', commands=['command-0000.json'],
                attempt_sha256=candidate['attempt_sha256'], workspace_sha256=candidate['workspace_sha256'])
            client.current = receipt
            (instance/'receipt.json').write_text(json.dumps(receipt))
            (instance/'command-0000.json').write_text(json.dumps({'stdout': 'native entry failed' if len(state.messages)==2 else 'write/readback restored'}))
            if len(state.messages) == 2:
                scenario = candidate['attempt'].scenario.model_copy(deep=True)
                scenario.steps[0].expected_status_code = None
                scenario.steps[0].response_contains = 'native corrected oracle'
                decision = RunnerDecision(action='run', probe=candidate['attempt'].probe,
                    scenario=scenario, scenario_revision_reason='Native interaction exposed an incorrect test expectation',
                    summary='Continue after browser failure; revise the oracle and rerun')
            else:
                decision.completion.client_receipt = str(instance/'receipt.json')
        return decision, response

    monkeypatch.setattr(controller.RunnerAgentSession, '__init__', init)
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', interact)
    result = asyncio.run(runner.run(**args))
    assert result.status == 'success' and state.agent_instances == 1
    assert len(result.attempts) == 2
    assert result.attempts[0].scenario.steps[0].expected_status_code == 200
    assert result.attempts[1].scenario.steps[0].expected_status_code is None
    assert result.attempts[1].request_revisions[0].reason.startswith('Native interaction')
    assert (root/'reports/runner_reports/attempts/attempt-02/native-client/command-0000.json').is_file()


def test_direct_browser_path_runs_without_protocol_tests(wired_controller, monkeypatch):
    runner, state, args, root = wired_controller
    from fmst_analyzer.runner.docker_sandbox import ServiceStartup
    monkeypatch.setattr(controller, '_local_service_port', lambda: 19080)
    captured = {}
    original_init = controller.RunnerAgentSession.__init__

    def init(self, **kwargs):
        original_init(self, **kwargs)
        captured['client'] = kwargs['live_client']

    async def invoke(self, message):
        state.messages.append(message)
        if len(state.messages) == 1:
            decision = RunnerDecision(action='run', browser_origin='http://native.router/', summary='Start native UI directly')
        else:
            path = state.evidence.attempt_json
            decision = RunnerDecision(action='complete', completion=RunnerCompletion(
                attempt_number=1, attempt_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                client_receipt=str(Path(captured['client'].current['path'])/'receipt.json'),
                coverage='Native config write, independent readback and restore'), summary='Native interactions complete')
        return decision, SimpleNamespace(provider='test-double', session_id='one-session', turn_id=str(len(state.messages)), status='completed', text=decision.model_dump_json())

    def start_service(self, **kwargs):
        state.attempts.append(kwargs)
        output = self.output_root / f"attempt-{kwargs['attempt_number']:02d}"
        output.mkdir(parents=True)
        (output/'container.log').write_text('controlled native runtime')
        return ServiceStartup(container_name='owned-native', readiness_path=output/'readiness.json', readiness={'state':'ready'})

    def start(self, origin):
        candidate = self.start_candidate()
        assert candidate['attempt'].probe is None and candidate['attempt'].scenario is None
        output = root/'native-instance'; output.mkdir()
        self.current = dict(path=str(output), commands=['command.json'],
            attempt_sha256=candidate['attempt_sha256'], workspace_sha256=candidate['workspace_sha256'])
        (output/'receipt.json').write_text(json.dumps(self.current))
        (output/'command.json').write_text('native interaction evidence')
        self.pending_service = None
        return 'native page snapshot'

    monkeypatch.setattr(controller.RunnerAgentSession, '__init__', init)
    monkeypatch.setattr(controller.RunnerAgentSession, 'invoke', invoke)
    monkeypatch.setattr(controller.DockerRootfsSandbox, 'start_service', start_service, raising=False)
    monkeypatch.setattr(controller.RunnerLiveClient, 'start', start)
    # The fixture's sandbox only models protocol attempts by default.
    original_sandbox = controller.DockerRootfsSandbox.__init__
    def sandbox_init(self, **kwargs):
        original_sandbox(self, **kwargs)
        self.output_root=self.session_root/'attempts'; self.staging_adaptations=[]
    monkeypatch.setattr(controller.DockerRootfsSandbox, '__init__', sandbox_init)
    result=asyncio.run(runner.run(**args))
    assert result.status=='success' and state.agent_instances==1
    assert len(result.attempts)==1 and result.attempts[0].probe is None
    assert result.attempts[0].scenario is None and result.attempts[0].browser_origin=='http://native.router/'
    assert 'No protocol scenario was executed' in state.messages[1]


@pytest.mark.parametrize("at_bootstrap", [True, False])
def test_progress_replies_continue_same_goal_without_rerun(wired_controller, monkeypatch, at_bootstrap):
    runner, state, args, root = wired_controller
    original = controller.RunnerAgentSession.invoke
    replies = []
    async def progress(self, message):
        if len(replies) < 3 and (at_bootstrap or state.latest_success):
            replies.append(message)
            decision = RunnerDecision(action="continue", summary="Diagnosis identifies another useful observation")
            return decision, SimpleNamespace(text=decision.model_dump_json())
        return await original(self, message)
    monkeypatch.setattr(controller.RunnerAgentSession, "invoke", progress)
    result = asyncio.run(runner.run(**args))
    assert result.status == "success" and len(replies) == 3
    assert state.agent_instances == 1 and len(state.attempts) == 2
    receipt = json.loads(Path(result.session_receipt_path).read_text())
    exchanges = [json.loads(p.read_text()) for p in Path(receipt["feedback_root"]).glob("exchange-*.json")]
    ongoing = [e for e in exchanges if (e["response"] or {}).get("action") == "continue"]
    assert len(ongoing) == 3 and all(e["admission"] == "accepted" and e["decision_index"] is None for e in ongoing)
    assert len(result.decision_history) == 3  # run, run, complete; progress never invalidates executed identity


def test_plain_reply_keeps_agent_session_and_pending_edits():
    from fmst_analyzer.runner.agent import RunnerAgentSession
    calls = []
    decision = RunnerDecision(action="continue", summary="Continuing the next observation")
    class Agent:
        async def ainvoke(self, message, trace):
            calls.append((message, trace))
            return SimpleNamespace(structured_response=None if len(calls) == 1 else decision)
    session = RunnerAgentSession.__new__(RunnerAgentSession)
    session.agent, session.trace = Agent(), object()
    actual, _ = asyncio.run(session.invoke("Investigate"))
    assert actual is decision and len(calls) == 2
    assert calls[0][1] is calls[1][1]
    assert "goal remains active" in calls[1][0] and "workspace edits" in calls[1][0]
