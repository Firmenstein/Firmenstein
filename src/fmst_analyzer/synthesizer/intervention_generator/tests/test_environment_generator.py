from __future__ import annotations

from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import scopes_for_test, finding_resolver_for_test

from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import build_planning_context

from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.fixtures import contract_for_test

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from fmst_analyzer.analysis.init_launch.analyzer_schema import (
    LaunchRecipe,
    SourceSnippet,
)
from fmst_analyzer.synthesizer.intervention_generator.agents import (
    GenerationAgentOutcome,
)
from fmst_analyzer.synthesizer.intervention_generator.environment import (
    EnvironmentGenerator,
)
from fmst_analyzer.synthesizer.intervention_generator.environment import (
    generator as environment_generator_module,
)
from fmst_analyzer.synthesizer.intervention_generator.generator import (
    InterventionGenerator,
)
from fmst_analyzer.synthesizer.intervention_generator import (
    generator as intervention_generator_module,
)
from fmst_analyzer.analysis.base.finding_binding import pointer
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    PlanningEvidenceCatalog,
    FindingIndexEntry,
    PlanningTargetIdentity,
    SourceArtifact,
    SourceKind,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    NoIntervention,
    InterventionPlanResult,
    InterventionUnit,
    LaunchChoice,
    ResourceAnchor,
    RunnerTask,
)
from fmst_analyzer.synthesizer.intervention_skill import (
    REHOSTING_PLANNING_SKILL,
)


class _FakeEvidenceResolver:
    def __init__(self, _reports_root: Path, _catalog: PlanningEvidenceCatalog) -> None:
        pass

    def read_finding(self, finding_ref, record_refs=None):
        return self.finding_evidence(finding_ref)

    def finding_evidence(self, finding_ref: str) -> dict[str, str]:
        return {"finding_ref": finding_ref, "complete": "evidence"}


class _FakeAgent:
    def __init__(self, outcome: GenerationAgentOutcome) -> None:
        self.outcome = outcome
        self.prompts: list[str] = []
        self.closed = False

    async def ainvoke(self, prompt: str, *, trace=None):
        self.prompts.append(prompt)
        return SimpleNamespace(
            structured_response=self.outcome,
            text=self.outcome.reason,
        )

    async def aclose(self) -> None:
        self.closed = True


class _StructuredOutputFailure(ValueError):
    code = "structured_output_error"


def _catalog() -> PlanningEvidenceCatalog:
    launch_site = SourceSnippet(
        path="etc/init.d/S50service",
        location="line 8",
        text="/usr/sbin/service -C /etc/service.conf",
    )
    recipe = LaunchRecipe(
        recipe_id="launch-service",
        launch_site=launch_site,
        context_anchor=launch_site,
        applicability="The initialization entry directly invokes the selected target.",
        executable_path="/usr/sbin/service",
        command_template=[
            "/usr/sbin/service",
            "-C",
            "/etc/service.conf",
        ],
        initialization_chain=[launch_site],
    )
    findings = {
        ref: FindingIndexEntry(
                 source_kind=SourceKind.FILE,
                 source_id=f"resource-{index}",
                 summary=f"Prepare {path}",
                 finding_ref=ref,
                 boundary_kind="resource",
                 anchor_keys=[],
                 evidence_refs=[],
                 source_locator=pointer("planning_findings", ref),
             )
        for index, (ref, path) in enumerate(
            (("file:F1", "/etc/service.conf"), ("file:F2", "/var/run/service")),
            1,
        )
    }
    artifacts = {
        kind: SourceArtifact(
                  source_kind=kind,
                  relative_path=f"{kind.value}.json",
                  schema_version=1,
                  phase="full",
                  content_sha256="0" * 64, provenance_sha256="0" * 64,
              )
        for kind in SourceKind
    }
    return PlanningEvidenceCatalog(
        target_identity=PlanningTargetIdentity(
            target_basename="service",
            selected_rootfs_path="usr/sbin/service",
            executable_sha256="a" * 64,
            argv0="service",
            firmware_sha256="b" * 64,
        ),
        source_artifacts=artifacts,
        finding_index=findings,
        launch_candidates={recipe.recipe_id: recipe},
    )


def _environment_unit(unit_id: str, finding_ref: str, path: str) -> InterventionUnit:
    return InterventionUnit(
        unit_id=unit_id,
        behavior_scopes=scopes_for_test([finding_ref]),
        strategy="environment_setup",
        anchors=[ResourceAnchor(
            resource_kind="path",
            value=path,
            source_ref=finding_ref,
        )],
        contract=contract_for_test([f"Make {path} available before launch"]),
        summary=f"Prepare {path}",
    )


def _plan(*, include_environment_units: bool = True) -> InterventionPlanResult:
    if include_environment_units:
        units = {
            "unit-1111111111111111": _environment_unit(
                "unit-1111111111111111", "file:F1", "/etc/service.conf"
            ),
            "unit-2222222222222222": _environment_unit(
                "unit-2222222222222222", "file:F2", "/var/run/service"
            ),
        }
        runner_tasks = []
    else:
        units = {}
        runner_tasks = [RunnerTask(
            behavior_scopes=scopes_for_test(["file:F1", "file:F2"]),
            objective="Observe the runtime environment before choosing an action.",
        )]
    return InterventionPlanResult(planning_context=build_planning_context(), catalog_digest="0" * 64,
        launch_choice=LaunchChoice(recipe_id="launch-service", reason="Only validated launch recipe."),
        draft_revision=1, claim_counts={"file:F1": 1, "file:F2": 1}, units=units,
        runner_tasks={f"task-{i}": task for i, task in enumerate(runner_tasks)},
        no_interventions={} if units else {f"native-{i}": NoIntervention(
            **scope.model_dump(), reason="Fixture baseline provides this behavior.")
            for i, scope in enumerate(scopes_for_test(["file:F1", "file:F2"]))})


def _config(tmp_path: Path):
    return SimpleNamespace(
        agent_provider="codex",
        synthesizer_model="test-model",
        agent_concurrency_limit=2,
        workdir=tmp_path,
    )


def _rootfs(tmp_path: Path) -> Path:
    rootfs = tmp_path / "rootfs"
    rootfs.mkdir(exist_ok=True)
    return rootfs


def test_environment_units_use_one_agent_and_validate_script(
    tmp_path, monkeypatch
):
    catalog = _catalog()
    plan = _plan()
    outcome = GenerationAgentOutcome(
        status="completed",
        reason="Implemented the complete staged-rootfs preparation.",
    )
    fake_agent = _FakeAgent(outcome)
    factory_calls = []

    def fake_factory(**kwargs):
        factory_calls.append(kwargs)
        kwargs["workdir"].joinpath("setup_rootfs.py").write_text(
            "from pathlib import Path\n\n"
            "def prepare(root):\n"
            "    Path(root, 'etc').mkdir(parents=True, exist_ok=True)\n",
            encoding="utf-8",
        )
        return fake_agent

    monkeypatch.setattr(
        environment_generator_module,
        "FindingEvidenceResolver",
        _FakeEvidenceResolver,
    )
    monkeypatch.setattr(
        environment_generator_module,
        "create_analysis_agent",
        fake_factory,
    )

    env_root = tmp_path / "env_scripts"
    rootfs = _rootfs(tmp_path)
    result = asyncio.run(EnvironmentGenerator(_config(tmp_path)).run(
        plan=plan,
        catalog=catalog,
        diagnostic_reports_root=tmp_path / "reports",
        env_scripts_root=env_root,
        rootfs_path=rootfs,
        trace_root=tmp_path / "traces",
    ))

    expected_script = env_root / "service" / "setup_rootfs.py"
    assert result.status == "completed"
    assert result.unit_ids == [
        "unit-1111111111111111",
        "unit-2222222222222222",
    ]
    assert result.script_path == str(expected_script)
    assert expected_script.is_file()
    assert len(factory_calls) == 1
    from fmst_analyzer.synthesizer.intervention_skill import application_guidance
    assert factory_calls[0]["developer_instructions"] == application_guidance("environment-generation")
    assert fake_agent.prompts[0].startswith(
        environment_generator_module.ENVIRONMENT_TASK_PROMPT + "\n\n"
    )
    assert factory_calls[0]["filesystem_access"] == "write"
    assert factory_calls[0]["workdir"] == expected_script.parent
    from fmst_analyzer.synthesizer.intervention_skill import APPLICATION_READ_ROOTS, APPLICATION_CONTRACT
    assert factory_calls[0]["readable_roots"] == [rootfs.resolve(), *APPLICATION_READ_ROOTS]
    assert str(APPLICATION_CONTRACT) in factory_calls[0]["developer_instructions"]
    assert factory_calls[0]["output_format"] is GenerationAgentOutcome
    assert factory_calls[0]["skills"] == []
    assert [tool.name for tool in factory_calls[0]["tools"]] == [
        "view_finding_evidence"
    ]
    assert json.loads(factory_calls[0]["tools"][0].invoke({
        "finding_refs": ["file:F1"],
    }))["file:F1"]["finding_ref"] == "file:F1"
    assert fake_agent.closed

    payload = json.loads(
        fake_agent.prompts[0].split("Environment generation input:\n", 1)[1]
    )
    assert payload["output_file"] == "setup_rootfs.py"
    assert payload["output_path"] == str(
        (env_root / "service" / "setup_rootfs.py").resolve()
    )
    assert payload["rootfs_path"] == str(rootfs.resolve())
    assert payload["selected_launch_recipe"]["recipe_id"] == "launch-service"
    assert payload["launch_choice"] == plan.launch_choice.model_dump(mode="json")
    assert payload["runtime_tasks"] == {key: task.model_dump(mode="json") for key, task in plan.runner_tasks.items()}
    assert payload["service_goal"] == plan.service_goal
    assert {unit["unit_id"] for unit in payload["units"]} == set(result.unit_ids)
    assert set(payload["finding_evidence"]) == {"file:F1", "file:F2"}


def test_environment_unable_preserves_reason_for_all_units(tmp_path, monkeypatch):
    reason = "The required file contents are not present in the supplied evidence."
    fake_agent = _FakeAgent(
        GenerationAgentOutcome(status="unable", reason=reason)
    )
    monkeypatch.setattr(
        environment_generator_module,
        "FindingEvidenceResolver",
        _FakeEvidenceResolver,
    )
    monkeypatch.setattr(
        environment_generator_module,
        "create_analysis_agent",
        lambda **_kwargs: fake_agent,
    )

    result = asyncio.run(EnvironmentGenerator(_config(tmp_path)).run(
        plan=_plan(),
        catalog=_catalog(),
        diagnostic_reports_root=tmp_path / "reports",
        env_scripts_root=tmp_path / "env_scripts",
        rootfs_path=_rootfs(tmp_path),
        trace_root=tmp_path / "traces",
    ))

    assert result.status == "unable"
    assert result.script_path is None
    assert result.reason == reason
    assert result.unit_ids == [
        "unit-1111111111111111",
        "unit-2222222222222222",
    ]


def test_environment_static_gate_allows_runtime_names_and_checks_compilation(
    tmp_path, monkeypatch
):
    fake_agent = _FakeAgent(GenerationAgentOutcome(
        status="completed",
        reason="done",
    ))

    monkeypatch.setattr(
        environment_generator_module,
        "FindingEvidenceResolver",
        _FakeEvidenceResolver,
    )

    def fake_factory(**kwargs):
        kwargs["workdir"].joinpath("setup_rootfs.py").write_text(
            "class Config:\n"
            "    def system(self):\n"
            "        return 'value'\n"
            "\n"
            "Config().system()\n",
            encoding="utf-8",
        )
        return fake_agent

    monkeypatch.setattr(
        environment_generator_module,
        "create_analysis_agent",
        fake_factory,
    )
    result = asyncio.run(EnvironmentGenerator(_config(tmp_path)).run(
        plan=_plan(),
        catalog=_catalog(),
        diagnostic_reports_root=tmp_path / "reports",
        env_scripts_root=tmp_path / "env_scripts",
        rootfs_path=_rootfs(tmp_path),
        trace_root=tmp_path / "traces",
    ))

    assert result.status == "completed"
    assert result.script_path is not None


def test_environment_preserves_script_when_envelope_decoder_fails(
    tmp_path, monkeypatch
):
    fake_agent = _FakeAgent(GenerationAgentOutcome(
        status="completed", reason="candidate was written"
    ))

    monkeypatch.setattr(
        environment_generator_module,
        "FindingEvidenceResolver",
        _FakeEvidenceResolver,
    )

    def fake_factory(**kwargs):
        kwargs["workdir"].joinpath("setup_rootfs.py").write_text(
            "def prepare(root):\n    return root\n",
            encoding="utf-8",
        )

        async def fail_after_write(prompt, *, trace=None):
            raise _StructuredOutputFailure("decoder rejected the final envelope")

        fake_agent.ainvoke = fail_after_write
        return fake_agent

    monkeypatch.setattr(
        environment_generator_module,
        "create_analysis_agent",
        fake_factory,
    )
    result = asyncio.run(EnvironmentGenerator(_config(tmp_path)).run(
        plan=_plan(),
        catalog=_catalog(),
        diagnostic_reports_root=tmp_path / "reports",
        env_scripts_root=tmp_path / "env_scripts",
        rootfs_path=_rootfs(tmp_path),
        trace_root=tmp_path / "traces",
    ))

    assert result.status == "completed"
    assert result.script_path is not None
    assert "invalid structured envelope" in result.reason


def test_environment_static_gate_rejects_script_that_cannot_compile(
    tmp_path, monkeypatch
):
    fake_agent = _FakeAgent(GenerationAgentOutcome(
        status="completed",
        reason="done",
    ))
    monkeypatch.setattr(
        environment_generator_module,
        "FindingEvidenceResolver",
        _FakeEvidenceResolver,
    )

    def fake_factory(**kwargs):
        kwargs["workdir"].joinpath("setup_rootfs.py").write_text(
            "return\n",
            encoding="utf-8",
        )
        return fake_agent

    monkeypatch.setattr(
        environment_generator_module,
        "create_analysis_agent",
        fake_factory,
    )
    result = asyncio.run(EnvironmentGenerator(_config(tmp_path)).run(
        plan=_plan(),
        catalog=_catalog(),
        diagnostic_reports_root=tmp_path / "reports",
        env_scripts_root=tmp_path / "env_scripts",
        rootfs_path=_rootfs(tmp_path),
        trace_root=tmp_path / "traces",
    ))

    assert result.status == "failed"
    assert "failed static compilation" in result.reason
    assert Path(result.script_path).read_text() == "return\n"
    assert result.failure_code == "static_compilation"


def test_no_environment_units_start_no_agent_and_leave_no_script(
    tmp_path, monkeypatch
):
    out_dir = tmp_path / "env_scripts" / "service"
    out_dir.mkdir(parents=True)
    stale = out_dir / "setup_rootfs.py"
    stale.write_text("stale", encoding="utf-8")

    def unexpected_factory(**_kwargs):
        raise AssertionError("no Environment Agent should be constructed")

    monkeypatch.setattr(
        environment_generator_module,
        "create_analysis_agent",
        unexpected_factory,
    )
    result = asyncio.run(EnvironmentGenerator(_config(tmp_path)).run(
        plan=_plan(include_environment_units=False),
        catalog=_catalog(),
        diagnostic_reports_root=tmp_path / "reports",
        env_scripts_root=tmp_path / "env_scripts",
        rootfs_path=None,
        trace_root=tmp_path / "traces",
    ))

    assert result.status == "not_needed"
    assert result.unit_ids == []
    assert result.script_path is None
    assert not stale.exists()


def test_missing_rootfs_starts_no_agent_and_marks_units_failed(
    tmp_path, monkeypatch
):
    def unexpected_factory(**_kwargs):
        raise AssertionError("invalid rootfs must fail before Agent construction")

    monkeypatch.setattr(
        environment_generator_module,
        "create_analysis_agent",
        unexpected_factory,
    )
    monkeypatch.setattr(
        intervention_generator_module,
        "_persist_generation_with_baseline",
        lambda **_kwargs: None,
    )
    config = _config(tmp_path)
    config.fw_rootfs_path = tmp_path / "missing-rootfs"
    result = asyncio.run(InterventionGenerator(config)._run_impl(
        plan=_plan(),
        catalog=_catalog(),
        view=SimpleNamespace(),
        image_name="firmware",
        arch="arm",
        diagnostic_reports_root=tmp_path / "reports",
        trace_root=tmp_path / "traces",
        interventions_root=tmp_path / "interventions",
        test_harnesses_root=tmp_path / "tests",
        env_scripts_root=tmp_path / "env_scripts",
        iib_api_abspath=tmp_path / "fmst-iib-api",
    ))

    expected = (
        "Environment Generation rootfs is not a directory: "
        f"{config.fw_rootfs_path.resolve()}"
    )
    assert result.environment.status == "unable"
    assert result.environment.reason == expected
    assert result.not_ready_count == 2
    assert {unit.failure_reason for unit in result.units} == {expected}


def test_environment_sdk_error_marks_all_environment_units_failed(
    tmp_path, monkeypatch
):
    official_reason = "429 account rate limit exceeded"

    async def fail_environment(self, **_kwargs):
        raise RuntimeError(official_reason)

    monkeypatch.setattr(
        intervention_generator_module.EnvironmentGenerator,
        "run",
        fail_environment,
    )
    monkeypatch.setattr(
        intervention_generator_module,
        "_persist_generation_with_baseline",
        lambda **_kwargs: None,
    )
    result = asyncio.run(InterventionGenerator(_config(tmp_path))._run_impl(
        plan=_plan(),
        catalog=_catalog(),
        view=SimpleNamespace(),
        image_name="firmware",
        arch="arm",
        diagnostic_reports_root=tmp_path / "reports",
        trace_root=tmp_path / "traces",
        interventions_root=tmp_path / "interventions",
        test_harnesses_root=tmp_path / "tests",
        env_scripts_root=tmp_path / "env_scripts",
        iib_api_abspath=tmp_path / "fmst-iib-api",
    ))

    assert result.environment.status == "unable"
    assert result.environment.reason == official_reason
    assert result.not_ready_count == 2
    assert {unit.status for unit in result.units} == {"generation_failed"}
    assert {unit.failure_reason for unit in result.units} == {official_reason}


def test_environment_corrects_syntax_in_original_session_and_retains_bad_source(tmp_path, monkeypatch):
    fake_agent = _FakeAgent(GenerationAgentOutcome(status='completed', reason='repaired'))
    monkeypatch.setattr(environment_generator_module, 'FindingEvidenceResolver', _FakeEvidenceResolver)
    def factory(**kwargs):
        script = kwargs['workdir'] / 'setup_rootfs.py'
        async def invoke(message, *, trace=None):
            assert not fake_agent.closed
            fake_agent.prompts.append(message)
            script.write_text('return\n' if len(fake_agent.prompts) == 1 else 'def prepare(root):\n    return root\n')
            return SimpleNamespace(structured_response=fake_agent.outcome, text='candidate')
        fake_agent.ainvoke = invoke
        return fake_agent
    monkeypatch.setattr(environment_generator_module, 'create_analysis_agent', factory)
    result = asyncio.run(EnvironmentGenerator(_config(tmp_path)).run(plan=_plan(), catalog=_catalog(),
        diagnostic_reports_root=tmp_path / 'reports', env_scripts_root=tmp_path / 'env', rootfs_path=_rootfs(tmp_path), trace_root=tmp_path / 'traces'))
    assert result.status == 'completed' and fake_agent.closed and len(fake_agent.prompts) == 2
    assert 'failed static compilation' in fake_agent.prompts[1]
    assert (tmp_path / 'traces/environment-feedback-01/candidate/setup_rootfs.py').read_text() == 'return\n'
