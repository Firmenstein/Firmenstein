"""Guidance transport and reference identity, without asserting prose policy."""
import asyncio
import hashlib
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from claude_agent_sdk import ResultMessage

from fmst_analyzer.synthesizer.intervention_skill import (
    APPLICATION_CONTRACT, APPLICATION_REFERENCES, CANDIDATE_ENGINEERING,
    application_guidance,
)
from fmst_analyzer.runner.task import inputs, worker


@pytest.mark.parametrize('stage,engineering', [
    ('generation', True), ('runtime-refinement', True), ('environment-generation', False),
])
def test_stage_references_resolve_to_current_sources(stage, engineering):
    records = json.loads(application_guidance(stage).split('\n', 1)[1])
    expected = [APPLICATION_CONTRACT]
    if engineering:
        expected.append(CANDIDATE_ENGINEERING)
    expected.append(APPLICATION_REFERENCES / f'{stage}.md')
    assert [Path(record['path']) for record in records] == expected
    for record in records:
        assert record['sha256'] == hashlib.sha256(Path(record['path']).read_bytes()).hexdigest()


@pytest.fixture
def prepared_task(tmp_path, monkeypatch, request):
    from fmst_analyzer.runner.task import materials
    from fmst_analyzer.synthesizer import intervention_plan_analyzer
    from fmst_analyzer.synthesizer.intervention_generator import reports, publication

    rootfs = tmp_path / 'rootfs'
    rootfs.mkdir()
    baseline = tmp_path / 'baseline'
    baseline.mkdir()
    framework = tmp_path / 'framework'
    skill = framework / 'skills/intervention-engineering/SKILL.md'
    skill.parent.mkdir(parents=True)
    skill.write_text('---\nname: guestweave-intervention-engineering\n'
                     'description: Selected library fixture.\n---\nLibrary fixture instructions.\n')
    goals = getattr(request, 'param', {})
    config = SimpleNamespace(current_target='service', target_diagnostic_reports_dir=lambda: tmp_path,
                             rehosting_goal=goals.get('configuration'))
    plan = SimpleNamespace(launch_choice=SimpleNamespace(recipe_id='native'),
                           service_goal=goals.get('plan', 'Restore the supplied native service.'))
    catalog = SimpleNamespace(launch_candidates={})
    monkeypatch.setattr(intervention_plan_analyzer, 'load_persisted_intervention_plan',
                        lambda *args, **kwargs: (catalog, plan))
    monkeypatch.setattr(reports, 'load_persisted_intervention_generation',
                        lambda *args, **kwargs: SimpleNamespace(arch='arm'))
    monkeypatch.setattr(publication, 'validate_generation_publication',
                        lambda *args: SimpleNamespace(root=baseline, baseline_id='fixture'))
    monkeypatch.setattr(inputs, 'image_analysis_environment', lambda task: {})
    from fmst_analyzer.runner.task import runtime_inputs
    monkeypatch.setattr(runtime_inputs, 'prepare_runtime', lambda *args:
                        {'status': 'ready', 'harness': '/opt/guestweave/runtime/arm/fmst-harness-arm'})
    monkeypatch.setattr(inputs, 'transfer_rootfs', lambda *args: {})
    monkeypatch.setattr(materials, 'package_analysis', lambda *args, **kwargs:
                        {'analysis_source_rootfs': str(rootfs), 'report_paths': {}})
    monkeypatch.setattr(inputs, 'docker', lambda *args, **kwargs: None)
    monkeypatch.delenv('FMST_RUNNER_RUNTIME_INPUTS', raising=False)
    copied = []

    def copy(container, source, destination, **kwargs):
        source = Path(source)
        target = tmp_path / 'container' / destination.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
        copied.append((source, target))

    monkeypatch.setattr(inputs, 'copy_tree', copy)
    task = SimpleNamespace(name='fixture', output=tmp_path, delivery_mode=goals.get('delivery_mode', 'full'), resource_limits=None)
    result = inputs.prepare(task, config=config, view=None, rootfs=rootfs, framework=framework,
                            service_goal=goals.get('caller'))
    return result, tmp_path / 'container', copied


@pytest.mark.parametrize('prepared_task,source,expected_goal', [
    ({'caller': '  caller scope  ', 'configuration': 'current scope', 'plan': 'old scope'}, 'caller', 'caller scope'),
    ({'configuration': '  current scope  ', 'plan': 'old scope'}, 'configuration', 'current scope'),
    ({'plan': '  retained scope  '}, 'plan', 'retained scope'),
    ({'caller': ' ', 'configuration': '\n', 'plan': 'retained scope'}, 'plan', 'retained scope'),
    ({'plan': None}, 'default', None),
    ({'plan': ' \n'}, 'default', None),
], indirect=['prepared_task'])
def test_goal_selection_reaches_user_message(prepared_task, source, expected_goal):
    task, _, _ = prepared_task
    message = worker.initial_message(task)
    assert isinstance(task['goal'], str) and task['goal'].strip()
    if expected_goal is not None:
        assert task['goal'] == expected_goal
    assert task['goal_source'] == source
    assert 'Goal source: ' + source in message
    assert message.endswith('Goal:\n' + task['goal'])


def test_task_supplies_engineering_reference_without_stage_acceptance_policy(prepared_task):
    task, root, copied = prepared_task
    expected = {'candidate_engineering': CANDIDATE_ENGINEERING}
    for key, source in expected.items():
        supplied = root / task['paths'][key].lstrip('/')
        assert supplied.read_bytes() == source.read_bytes()
        assert (source, supplied) in copied
    assert 'application_contract' not in task['paths']
    assert not any(source.name in {'application-contract.md', 'generation.md', 'runtime-refinement.md', 'planning.md'}
                   for source, _ in copied)


def test_container_message_reaches_sdk_with_selected_skill_and_readable_references(prepared_task, monkeypatch):
    from fmst_analyzer.framework import guestweave_skill
    from fmst_basic.agent import create_analysis_agent
    from fmst_basic.agent import claude_agent

    task, root, _ = prepared_task
    observed = {}

    class Client:
        def __init__(self, *, options):
            observed['options'] = options

        async def connect(self):
            pass

        async def disconnect(self):
            pass

        async def query(self, prompt):
            observed['prompt'] = prompt

        async def receive_response(self):
            yield ResultMessage(subtype='success', duration_ms=1, duration_api_ms=1,
                                is_error=False, num_turns=1, session_id='fixture', result='readable')

    monkeypatch.setattr(claude_agent, 'ClaudeSDKClient', Client)
    monkeypatch.setenv('FMST_RUNNER_CONTAINER', '1')
    monkeypatch.setenv('FMST_CLAUDE_AUTH_TOKEN', 'fixture-token')
    original = Path.is_file
    monkeypatch.setattr(Path, 'is_file', lambda path: str(path) == '/.dockerenv' or original(path))
    skill = guestweave_skill(root / 'task/work/framework/GuestWeave')
    agent = create_analysis_agent(provider='claude', model='test',
        developer_instructions='', filesystem_access='container',
        workdir=root / 'task/work', skills=[skill])

    async def invoke():
        try:
            await agent.ainvoke(worker.initial_message(task))
        finally:
            await agent.aclose()

    asyncio.run(invoke())
    assert observed['options'].system_prompt == {'type': 'preset', 'preset': 'claude_code'}
    assert worker.TASK_INSTRUCTIONS in observed['prompt']
    assert skill.skill_file.read_text() not in observed['prompt']
    assert observed['options'].skills == ['fmst-task:guestweave-intervention-engineering']
    assert observed['options'].plugins
    assert task['goal'] in observed['prompt']
    for key in ('candidate_engineering',):
        path = task['paths'][key]
        assert path in observed['prompt']
        assert (root / path.lstrip('/')).is_file()
    assert str(APPLICATION_REFERENCES / 'generation.md') not in observed['prompt']
