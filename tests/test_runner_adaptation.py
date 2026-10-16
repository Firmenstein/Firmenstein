"""Source/ownership admission counterexamples; these are not guest evidence."""
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fmst_analyzer.runner.adaptation import validate_proposal
from fmst_analyzer.runner.adaptation_schema import RuntimeUnitDefinition, RuntimeUnitProposal, AdaptationEvidence


def unit(unit_id='runtime-status', path='/vendor/status'):
    return RuntimeUnitDefinition(unit_id=unit_id, strategy='pseudo_file',
        anchors=[dict(kind='resource', resource_kind='path', value=path, source_ref='evidence:0')],
        summary='Preserve caller-visible descriptor state', contract=dict(
            applicability=['Only this exact path'], owned_resources=[path], operations=['Read per-open state'],
            state=['Initialized from the cited firmware source'], native_fallback=['All other paths remain native'],
            verification=['Offset and EOF behavior; unchanged service scenario'], allowed_refinement_scope=['Owned descriptor implementation']))


def proposal_fixture(tmp_path):
    attempt = tmp_path / 'attempt/attempt.json'
    attempt.parent.mkdir()
    attempt.write_text('{"outcome":"blocked"}')
    evidence = AdaptationEvidence(path=str(attempt), sha256=hashlib.sha256(attempt.read_bytes()).hexdigest(), excerpt='blocked')
    proposal = RuntimeUnitProposal(operation='upsert', unit=unit(), evidence=[evidence], rationale='Failed observed read', limitations=['State remains a hypothesis'])
    args = dict(units={}, active_id=None, view=object(), readable_roots=[tmp_path],
        attempt_path=attempt, artifact_root=attempt.parent, check_budget=lambda: None)
    return proposal, args


def test_new_owner_outside_conventional_directories_and_conflicting_owner(tmp_path):
    proposal, args = proposal_fixture(tmp_path)
    assert validate_proposal(proposal, **args) is None
    args['units'] = {'other': unit('other')}
    with pytest.raises(RuntimeError, match='overlaps'):
        validate_proposal(proposal, **args)


@pytest.mark.parametrize('fault,match', [('hash', 'hash/excerpt'), ('excerpt', 'hash/excerpt'),
    ('parent', 'stale'), ('source_ref', 'evidence:N'), ('path', 'normalized'), ('outside', 'outside'), ('static', 'current runtime')])
def test_admission_rejects_unbound_or_stale_evidence(tmp_path, fault, match):
    proposal, args = proposal_fixture(tmp_path)
    if fault == 'hash': proposal.evidence[0].sha256 = '0' * 64
    elif fault == 'excerpt': proposal.evidence[0].excerpt = 'invented'
    elif fault == 'parent': proposal.parent_adaptation_id = 'stale'
    elif fault == 'source_ref': proposal.unit.anchors[0].source_ref = 'invented-finding'
    elif fault == 'path': proposal.unit.anchors[0].value = '/vendor/../status'
    elif fault == 'outside': args['readable_roots'] = [tmp_path / 'elsewhere']
    elif fault == 'static': args['artifact_root'] = tmp_path / 'different'; args['attempt_path'] = tmp_path / 'different/attempt.json'
    with pytest.raises(RuntimeError, match=match):
        validate_proposal(proposal, **args)


def test_contract_replacement_retains_original_owner_and_module_uniqueness(tmp_path):
    proposal, args = proposal_fixture(tmp_path)
    original = unit()
    args['units'] = {original.unit_id: original}
    proposal.unit.contract.operations = ['Read and seek per-open state']
    before = validate_proposal(proposal, **args)
    assert before == original and original.contract.operations == ['Read per-open state']
    proposal.unit.anchors[0].value = '/different'
    with pytest.raises(RuntimeError, match='retain'):
        validate_proposal(proposal, **args)
    args['units'] = {'runtime_status': unit('runtime_status', '/other')}
    with pytest.raises(RuntimeError, match='module name'):
        validate_proposal(proposal, **args)


def test_rollback_needs_active_parent_and_actual_failure_evidence(tmp_path):
    proposal, args = proposal_fixture(tmp_path)
    proposal.operation, proposal.unit = 'rollback', None
    with pytest.raises(RuntimeError, match='No active'):
        validate_proposal(proposal, **args)
    proposal.parent_adaptation_id = args['active_id'] = 'active'
    assert validate_proposal(proposal, **args) is None


def test_admission_preserves_source_bytes_independent_of_original_path(tmp_path):
    from fmst_analyzer.runner.adaptation import snapshot_evidence
    proposal, args = proposal_fixture(tmp_path)
    root = tmp_path / 'snapshots'
    references = snapshot_evidence(proposal, root, check_budget=lambda: None)
    source = Path(proposal.evidence[0].path)
    source.unlink()
    saved = root / references[str(source)]
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == proposal.evidence[0].sha256
    source.write_text('changed')
    with pytest.raises(RuntimeError, match='changed before snapshot'):
        snapshot_evidence(proposal, root, check_budget=lambda: None)
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == proposal.evidence[0].sha256


def test_environment_contract_revision_requires_both_runtime_and_source(tmp_path):
    proposal, args = proposal_fixture(tmp_path)
    proposal.unit.strategy = 'environment_setup'
    original = proposal.unit.model_copy(deep=True)
    args['units'] = {original.unit_id: original}
    proposal.unit.contract.state = ['Use the value from the retained firmware source']
    with pytest.raises(RuntimeError, match='source evidence'):
        validate_proposal(proposal, **args)
    source = tmp_path / 'firmware/init.sh'
    source.parent.mkdir()
    source.write_text('source supplied state')
    proposal.evidence.append(AdaptationEvidence(path=str(source),
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(), excerpt='source supplied state'))
    before = validate_proposal(proposal, **args)
    assert before == original and original.contract.state != proposal.unit.contract.state
    args['units'] = {}
    with pytest.raises(RuntimeError, match='existing owner'):
        validate_proposal(proposal, **args)


def test_execution_owner_admission_keeps_static_environment_owners_separate(tmp_path):
    proposal, args = proposal_fixture(tmp_path)
    environment = unit('seed')
    environment.strategy = 'environment_setup'
    args['units'] = {'seed': environment}
    assert validate_proposal(proposal, **args) is None
    assert environment.strategy == 'environment_setup'


def test_current_native_evidence_is_admitted_but_foreign_instance_is_not(tmp_path):
    proposal, args = proposal_fixture(tmp_path)
    native = tmp_path / 'native/current/runtime'
    native.mkdir(parents=True)
    log = native / 'diagnostics-42.log'
    log.write_text('observed child failure')
    proposal.evidence = [AdaptationEvidence(path=str(log),
        sha256=hashlib.sha256(log.read_bytes()).hexdigest(), excerpt='child failure')]
    args['runtime_artifact_roots'] = [native]
    assert validate_proposal(proposal, **args) is None
    args['runtime_artifact_roots'] = [tmp_path / 'native/other/runtime']
    with pytest.raises(RuntimeError, match='current runtime'):
        validate_proposal(proposal, **args)


def test_native_runtime_evidence_cannot_replace_environment_source(tmp_path):
    proposal, args = proposal_fixture(tmp_path)
    proposal.unit.strategy = 'environment_setup'
    args['units'] = {proposal.unit.unit_id:proposal.unit.model_copy(deep=True)}
    native = tmp_path / 'native'
    native.mkdir()
    log = native / 'error.log'
    log.write_text('observed runtime failure')
    args['runtime_artifact_roots'] = [native]
    proposal.evidence.append(AdaptationEvidence(path=str(log),
        sha256=hashlib.sha256(log.read_bytes()).hexdigest(), excerpt='runtime failure'))
    with pytest.raises(RuntimeError, match='source evidence'):
        validate_proposal(proposal, **args)
