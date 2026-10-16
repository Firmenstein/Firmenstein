"""State-consuming validation cannot be handed to an interactive user."""

import json
from pathlib import Path
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner import delivery, docker_sandbox
from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped
from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario, RuntimeNetwork
from fmst_analyzer.runner.service_readiness import tcp_listeners, wait_for_service
from fmst_analyzer.runner.supervision import TargetProgressWatchdog


TCP_HEADER = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode'
TCP6_HEADER = TCP_HEADER.replace('rem_address', 'remote_address')


def row(address='00000000', port='1F90', state='0A', inode='123'):
    return f'  0: {address}:{port} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 0 0 {inode}'


def test_kernel_listener_parser_filters_state_and_port_and_retains_raw_evidence():
    output = TCP_HEADER + '\n' + row() + '\n' + row('0100007F', state='01') + '\n' + row(port='0050')
    listeners = tcp_listeners(output, 8080)
    assert listeners == [{'address': '0.0.0.0', 'port': 8080, 'inode': 123, 'family': 'ipv4', 'row': row()}]
    assert tcp_listeners(TCP_HEADER+'\n'+row('0100007F'),8080)[0]['address']=='127.0.0.1'
    ipv6 = tcp_listeners(TCP6_HEADER+'\n'+row('00000000000000000000000001000000'),8080,ipv6=True)
    assert ipv6[0]['address']=='::1'
    for invalid in ('', 'wrong header', TCP_HEADER+'\ninvalid row', TCP_HEADER+'\n'+row('00')):
        with pytest.raises(ValueError):tcp_listeners(invalid,8080)


def observer(tmp_path, alive=True):
    return SimpleNamespace(interrupted=threading.Event(), termination_reason='unknown', observation_error=None,
        last_sample_monotonic=time.monotonic(), target_alive=alive, final_observation=None,
        final_process_path=tmp_path/'processes-final.json', stop=lambda *_:None, join=lambda:None)


@pytest.mark.parametrize('lost', [False,True])
def test_passive_readiness_requires_final_live_sample_and_listener(tmp_path,lost):
    watch=observer(tmp_path)
    def final():
        watch.final_observation={'status':'complete'}
        watch.target_alive=not lost
    watch.sample_for_service=final
    path=tmp_path/'service-readiness.json'
    args=dict(observer=watch,observe_listeners=lambda:[{'inode':1}],deadline=time.monotonic()+1,
        evidence_path=path,check_budget=lambda:None)
    if lost:
        with pytest.raises(RuntimeError,match='lost'):wait_for_service(**args)
    else:
        result=wait_for_service(**args)
        assert result['state']=='ready' and result['active_probe_performed'] is False
    saved=json.loads(path.read_text())
    assert saved['state']==('failed' if lost else 'ready')


def test_stale_process_sample_never_admits_listener_and_cancellation_is_retained(tmp_path):
    watch=observer(tmp_path);watch.last_sample_monotonic=time.monotonic()-10
    calls=[]
    budget=ExecutionBudget(60)
    def check():
        calls.append(True)
        if len(calls)>1:raise RunnerStopped('user_cancelled')
    with pytest.raises(RunnerStopped):
        wait_for_service(observer=watch,observe_listeners=lambda:pytest.fail('stale process sampled endpoint'),
            deadline=time.monotonic()+1,evidence_path=tmp_path/'ready.json',check_budget=check)
    assert json.loads((tmp_path/'ready.json').read_text())['state']=='failed'


def test_startup_final_process_sample_does_not_claim_a_protocol_response(tmp_path,monkeypatch):
    watch=TargetProgressWatchdog(container_name='fixture',attempt_dir=tmp_path,stall_seconds=5)
    monkeypatch.setattr(watch,'_read_processes',lambda:[{'pid':1,'ppid':0,'state':'S','started':'start',
        'command':'harness --trace-output /fmst-output/runtime_trace.json -- /guest'}])
    watch.sample_for_service()
    assert watch.target_alive and not watch.target_alive_after_probe
    assert watch.final_observation['purpose']=='service_startup'
    assert watch.final_observation['last_response_unix_ns'] is None


@pytest.mark.parametrize('ready', [True,False])
def test_user_startup_never_executes_active_probe_and_cleans_failed_startup(tmp_path,monkeypatch,ready):
    box=docker_sandbox.DockerRootfsSandbox(rootfs=tmp_path,workdir=tmp_path,target_binary='fixture',
        executable_path='/guest',guest_arch='arm',runtime_workspace=tmp_path,env_script=None,expose_service=True)
    box._prepared=True;box._active_rootfs=tmp_path;box.bundle_dir.mkdir(parents=True)
    commands=[]
    monkeypatch.setattr(box,'_process',lambda command,**kwargs:(commands.append(command) or subprocess.CompletedProcess(command,0,'')))
    monkeypatch.setattr(TargetProgressWatchdog,'start',lambda *_:None)
    monkeypatch.setattr(box,'_run_tcp_probe_in_container',lambda *a,**k:pytest.fail('user instance actively probed'))
    def wait(**kwargs):
        if not ready:raise RuntimeError('startup failed')
        return {'state':'ready','active_probe_performed':False}
    monkeypatch.setattr(docker_sandbox,'wait_for_service',wait)
    args=dict(intervention_so=None,executable_path='/guest',guest_args=[],guest_working_directory='/',
        guest_environment={},companion_processes=[],port=80,host_port=8080,timeout_seconds=5)
    if ready:
        result=box.start_service(**args)
        assert result.readiness['active_probe_performed'] is False
    else:
        with pytest.raises(RuntimeError,match='startup failed'):box.start_service(**args)
    assert len([c for c in commands if c[:3]==['docker','rm','--force']])==int(not ready)
    run=next(c for c in commands if c[:2]==['docker','run'])
    assert run[run.index('--publish')+1]=='127.0.0.1:8080:80'
    receipt=json.loads(next((box.session_root/'attempt_receipts').glob('*.json')).read_text())
    assert receipt['scenario'] is None and receipt['probe_results']==[]


@pytest.mark.parametrize('companions', [[], [
    {'executable_path': '/peer', 'working_directory': '/', 'evidence_ref': 'fixture peer'},
]])
def test_fresh_service_launches_preserve_runtime_identity_and_instance_scripts(tmp_path, monkeypatch, companions):
    from fmst_analyzer.runner.identity import tree_sha256
    from fmst_analyzer.runner.schema import CompanionProcess
    box = docker_sandbox.DockerRootfsSandbox(rootfs=tmp_path, workdir=tmp_path, target_binary='fixture',
        executable_path='/guest', guest_arch='arm', runtime_workspace=tmp_path, env_script=None, expose_service=True)
    box._prepared = True
    box._active_rootfs = tmp_path
    box.bundle_dir.mkdir(parents=True)
    (box.bundle_dir / 'fixture-harness').write_bytes(b'immutable runtime')
    initial_hash = tree_sha256(box.bundle_dir)
    commands = []
    monkeypatch.setattr(box, '_process', lambda command, **kwargs:
        (commands.append(command) or subprocess.CompletedProcess(command, 0, '')))
    monkeypatch.setattr(TargetProgressWatchdog, 'start', lambda *_: None)
    monkeypatch.setattr(docker_sandbox, 'wait_for_service', lambda **kwargs:
        {'state': 'ready', 'active_probe_performed': False})
    for number in (1, 100002):
        box.start_service(intervention_so=None, executable_path='/guest', guest_args=[],
            guest_working_directory='/', guest_environment={},
            companion_processes=[CompanionProcess.model_validate(c) for c in companions],
            port=80, host_port=8080, timeout_seconds=5, attempt_number=number)
        assert tree_sha256(box.bundle_dir) == initial_hash
        control = box.session_root / 'control' / f'attempt-{number:02d}'
        retained = box.output_root / f'attempt-{number:02d}' / 'launch.sh'
        assert retained.read_bytes() == (control / 'launch.sh').read_bytes()
        box.stop_service(f'{box.network_name}-a{number}', number)
    runs = [c for c in commands if c[:2] == ['docker', 'run']]
    assert len(runs) == 2
    for command in runs:
        assert '/fmst-control/launch.sh' in command
        assert any(value.endswith(',dst=/fmst-control,readonly') for value in command)


@pytest.mark.parametrize('failure', [None,'validation','cleanup','startup'])
def test_up_isolates_consumed_state_and_gates_user_startup_on_validation_cleanup(tmp_path,monkeypatch,failure):
    build=tmp_path/'state/builds/fixture';build.mkdir(parents=True)
    (build/'receipt.json').write_text(json.dumps({'runtime_sha256':'runtime'}))
    monkeypatch.setattr(delivery,'_ensure_image',lambda *_:None)
    monkeypatch.setattr(delivery,'current_build',lambda *_:build)
    monkeypatch.setattr(delivery,'DockerRuntimeBuilder',lambda **kwargs:None)
    instances=[];events=[]
    scenario=InteractionScenario(protocol='http',port=80,evidence_refs=['floor'],steps=[
        {'request_text':'POST /state HTTP/1.0\r\n\r\n','expected_status_code':200}])
    launch=SimpleNamespace(browser_origin=None,network=RuntimeNetwork(),scenario=scenario,probe=InteractionProbe(port=80,request_text=scenario.steps[0].request_text),
        intervention_binary_path=None,guest_args=[],guest_working_directory='/',guest_environment={'CPU':'chosen'},companion_processes=[])
    original=SimpleNamespace(executable_path='/guest',attempt=launch,watchdog_stall_seconds=10)
    class Sandbox:
        def __init__(self,**kwargs):
            self.session_id=f'{len(instances)+1:012x}';self.network=kwargs['network'];self.target_slug='guest'
            self.session_root=kwargs['workdir']/'runner_sessions/guest'/self.session_id
            self.image_tag='image-'+self.session_id;self.network_name='network-'+self.session_id
            self.cleanup_records=[];self.state='fresh';self.inputs=None;instances.append(self)
        def prepare_frozen(self,runtime,**kwargs):self.inputs=(runtime,kwargs)
        def run_attempt(self,**kwargs):
            assert kwargs['scenario']==scenario
            events.append('validate');self.state='consumed'
            return SimpleNamespace(scenario_result=SimpleNamespace(status='blocked' if failure=='validation' else 'success',model_dump=lambda:{}))
        def start_service(self,**kwargs):
            assert self.state=='fresh' and instances[0].state=='closed'
            assert self.inputs==instances[0].inputs
            assert 'probe' not in kwargs and 'scenario' not in kwargs
            events.append('start')
            if failure=='startup':raise RuntimeError('failed passive startup')
            return SimpleNamespace(container_name='container',readiness={'state':'ready','active_probe_performed':False},readiness_path=self.session_root/'ready.json')
        def close(self):
            events.append('close');self.state='closed'
            if failure=='cleanup':self.cleanup_records.append({'remove_returncode':1})
    monkeypatch.setattr(delivery,'DockerRootfsSandbox',Sandbox)
    package=SimpleNamespace(package_id='package',rootfs_sha256='rootfs',builder_image_id='image',host_platform='linux/amd64',target_binary='guest',guest_arch='arm',browser_access=None)
    if failure:
        with pytest.raises(RuntimeError):delivery.run_service(tmp_path,package,original,persistent=True,port=8080)
        assert not (tmp_path/'state/service.json').exists()
        assert len(instances)==(2 if failure=='startup' else 1)
    else:
        result=delivery.run_service(tmp_path,package,original,persistent=True,port=8080)
        assert events==['validate','close','start']
        assert result['validation']['sandbox_session_id']!=result['sandbox_session_id']
        assert result['validation']['input_identity']==result['input_identity']
        assert 'scenario_result' not in result and result['readiness']['active_probe_performed'] is False
        assert json.loads((tmp_path/'state/service.json').read_text())['state']=='running'


@pytest.mark.parametrize('persistent', [True, False])
def test_native_delivery_accepts_no_scenario_and_reports_only_startup(tmp_path, monkeypatch, persistent):
    build = tmp_path/'state/builds/fixture'; build.mkdir(parents=True)
    (build/'receipt.json').write_text(json.dumps({'runtime_sha256':'runtime'}))
    monkeypatch.setattr(delivery, '_ensure_image', lambda *args: None)
    monkeypatch.setattr(delivery, 'current_build', lambda *args: build)
    monkeypatch.setattr(delivery, 'DockerRuntimeBuilder', lambda **kwargs: None)
    monkeypatch.setattr(delivery, '_available_service_port', lambda: 19081)
    origin = 'http://192.0.2.10:8080/ui/'
    launch = SimpleNamespace(browser_origin=origin, network=RuntimeNetwork(), scenario=None, probe=None,
        intervention_binary_path=None, guest_args=[], guest_working_directory='/', guest_environment={}, companion_processes=[])
    original = SimpleNamespace(executable_path='/guest', attempt=launch, watchdog_stall_seconds=10)
    instances = []
    class Sandbox:
        def __init__(self, **kwargs):
            self.session_id='a'*12; self.network=kwargs['network']; self.target_slug='guest'
            self.session_root=kwargs['workdir']/'runner_sessions/guest'/self.session_id
            self.image_tag='image'; self.cleanup_records=[]; self.closed=False
            instances.append(self)
        def prepare_frozen(self, *args, **kwargs): pass
        def start_service(self, **kwargs):
            assert kwargs['port']==8080 and kwargs['host_port']==(19080 if persistent else 19081)
            assert 'scenario' not in kwargs and 'probe' not in kwargs
            return SimpleNamespace(container_name='owned', readiness={'state':'ready'}, readiness_path=self.session_root/'readiness.json')
        def run_attempt(self, **kwargs):
            pytest.fail('Native delivery must not add a protocol acceptance phase')
        def close(self): self.closed=True
    monkeypatch.setattr(delivery, 'DockerRootfsSandbox', Sandbox)
    package=SimpleNamespace(package_id='package', rootfs_sha256='rootfs', builder_image_id='image', host_platform='linux/amd64', target_binary='guest', guest_arch='arm', browser_access=None)
    result=delivery.run_service(tmp_path, package, original, persistent=persistent, port=19080)
    assert len(instances)==1 and instances[0].closed== (not persistent)
    assert result['state']==('running' if persistent else 'ready')
    assert result['url']==origin and result['browser_required'] is True
    assert result['verification_scope'].startswith('startup readiness only')
    assert 'scenario_result' not in result and 'validation' not in result
