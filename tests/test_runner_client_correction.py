"""Client errors may be repaired without changing business assertions."""
import hashlib
from pathlib import Path
import pytest
from fmst_analyzer.analysis.base.report_io import write_model_json
from fmst_analyzer.runner.request_wire import admit_client_request_correction
from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario, RuntimeAttempt, ScenarioRequestCorrection

@pytest.fixture
def correction_case(tmp_path):
    artifact = tmp_path / 'attempt'
    artifact.mkdir()
    native = tmp_path / 'native-client.js'
    native.write_text('fetch("/login?form=login", {method: "POST"})')
    floor = InteractionScenario(protocol='http',port=80,evidence_refs=['native fixture'],steps=[
        dict(request_text='POST /login HTTP/1.0\r\n\r\n', expected_status_code=401)])
    previous = RuntimeAttempt(tree_identity_version=2,attempt_number=1,
        probe=InteractionProbe(port=80,request_text=floor.steps[0].request_text),scenario=floor,
        guest_args=[],guest_working_directory='/',guest_environment={},rootfs_actions=[],disabled_unit_ids=[],
        outcome='blocked',probe_result=dict(connected=True,interacted=False,attempts=1),
        runtime_trace_path='unavailable',runtime_trace_context_path='unavailable',container_log_path='unavailable',
        runtime_trace_available=False,runtime_trace_context_available=False,agent_summary='wrong native route')
    path = artifact / 'attempt.json'
    write_model_json(path,previous)
    current=floor.model_copy(deep=True)
    current.steps[0].request_text='POST /login?form=login HTTP/1.0\r\n\r\n'
    proposal=ScenarioRequestCorrection(parent_sha256=hashlib.sha256(floor.model_dump_json().encode()).hexdigest(),
        step_indices=[1],reason='Native UI sends the form selector; retain wrong-password rejection',
        evidence=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),excerpt=p.read_text()) for p in [path,native]])
    return floor,current,dict(proposal=proposal,previous=previous,attempt_path=path,readable_roots=[tmp_path],check_budget=lambda:None)

def test_native_route_correction_retains_old_failure_and_business_assertion(correction_case):
    floor,current,args=correction_case
    original=args['attempt_path'].read_bytes()
    revision=admit_client_request_correction(floor,current,**args)
    assert revision.kind=='client_request' and revision.before==floor and revision.after==current
    assert revision.after.steps[0].expected_status_code==401
    assert args['attempt_path'].read_bytes()==original
    assert revision.source_attempt_sha256==hashlib.sha256(original).hexdigest()

def test_controller_binds_parent_digest_when_agent_has_no_hash_tool(correction_case):
    floor,current,args=correction_case
    args['proposal'].parent_sha256=None
    revision=admit_client_request_correction(floor,current,**args)
    assert revision.correction.parent_sha256==revision.parent_sha256
    assert args['proposal'].parent_sha256 is None

@pytest.mark.parametrize('change',['status','remove','stale','index','source','hash','capture'])
def test_invalid_correction_cannot_erase_checks_or_forge_lineage(correction_case,change):
    floor,current,args=correction_case
    if change=='status':current.steps[0].expected_status_code=200
    elif change=='remove':current.steps=[]
    elif change=='stale':args['proposal'].parent_sha256='0'*64
    elif change=='index':args['proposal'].step_indices=[2]
    elif change=='source':args['proposal'].evidence=args['proposal'].evidence[:1]
    elif change=='hash':args['proposal'].evidence[1].sha256='0'*64
    elif change=='capture':current.steps[0].save_cookies=True
    with pytest.raises(RuntimeError):admit_client_request_correction(floor,current,**args)

def test_host_rollback_replaces_read_only_inode_and_does_not_follow_link(tmp_path):
    from fmst_analyzer.runner.runner import _restore_workspace
    lock=tmp_path/'Cargo.lock';lock.write_bytes(b'wrong');lock.chmod(0o444)
    _restore_workspace(tmp_path,{'Cargo.lock':b'original'})
    assert lock.read_bytes()==b'original' and lock.stat().st_mode & 0o777==0o444
    outside=tmp_path.parent/(tmp_path.name+'-outside');outside.write_bytes(b'protected')
    lock.unlink();lock.symlink_to(outside)
    _restore_workspace(tmp_path,{'Cargo.lock':b'original'})
    assert outside.read_bytes()==b'protected' and not lock.is_symlink()
