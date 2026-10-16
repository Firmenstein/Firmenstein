"""Body-token continuity must retain wire provenance and the scenario floor."""
import pytest
from pydantic import ValidationError

from fmst_analyzer.runner.probe import build_probe_result, evaluate_interaction_scenario
from fmst_analyzer.runner.request_wire import capture_response_values, substitute_response_values
from fmst_analyzer.runner.runner import _scenario_weakening
from fmst_analyzer.runner.schema import InteractionProbe, InteractionScenario, ResponseValueCapture


def scenario():
    return InteractionScenario(protocol="http", port=80, evidence_refs=["controlled fixture"], steps=[
        dict(request_text="GET /login HTTP/1.0\r\n\r\n", expected_status_code=200,
            response_captures=[dict(name="session", prefix='next="', suffix='"', max_chars=32)]),
        dict(request_text="GET /?id={{response:session}} HTTP/1.0\r\n\r\n", expected_status_code=200)])


def response(body=b'next="a/b +?"', *, chunked=False):
    header = b"HTTP/1.1 200 OK\r\nX-Decoy: next=\"wrong\"\r\n"
    wire = (b"HTTP/1.1 103 Early Hints\r\nX-Decoy: next=\"hint\"\r\n\r\n" + header)
    if chunked:
        wire += b'Transfer-Encoding: chunked\r\n\r\n' + format(len(body), 'x').encode() + b'\r\n' + body + b'\r\n0\r\nX-Decoy: next="trailer"\r\n\r\n'
    else:
        wire += b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    return build_probe_result(InteractionProbe(port=80, request_text="GET / HTTP/1.0\r\n\r\n"),
        connected=True, response=wire, attempts=1)


@pytest.mark.parametrize('chunked', [False, True])
def test_only_final_body_supplies_encoded_url_value(chunked):
    plan = scenario()
    probe = response(chunked=chunked)
    values = capture_response_values(plan.steps[0], probe)
    assert values == {'session': 'a/b +?'}
    assert substitute_response_values(plan.steps[1].request_text, values) == 'GET /?id=a%2Fb%20%2B%3F HTTP/1.0\r\n\r\n'
    result = evaluate_interaction_scenario(plan, [probe, response(b'ok')])
    assert result.status == 'success'
    assert result.steps[0].captured_response_values == values
    assert result.steps[0].http_response.wire_sha256 == probe.http_response.wire_sha256
    assert InteractionScenario.model_validate_json(plan.model_dump_json()) == plan


@pytest.mark.parametrize('body', [b'nothing', b'next=""', b'next="x" next="y"',
    b'next="unterminated', b'next="' + b'x' * 33 + b'"', b'next="x\r\ny"', b'next="\xff"'])
def test_capture_failure_rejects_step_even_with_http_200(body):
    plan = scenario()
    probe = response(body)
    with pytest.raises(ValueError):
        capture_response_values(plan.steps[0], probe)
    result = evaluate_interaction_scenario(plan, [probe, response(b'ok')])
    assert result.status == 'blocked' and not result.steps[0].passed
    assert not result.steps[0].captured_response_values


@pytest.mark.parametrize('change', ['truncated', 'saved_text', 'framing', 'status', 'required', 'forbidden'])
def test_untrusted_or_failed_response_cannot_issue_values(change):
    plan = scenario()
    probe = response()
    if change == 'truncated': probe.response_truncated = True
    elif change == 'saved_text': probe.http_response.source = 'saved_text'
    elif change == 'framing': probe.http_response.error = 'incomplete'
    elif change == 'status': probe.http_response.status_code = 401
    elif change == 'required': plan.steps[0].response_contains = 'authenticated'
    else: plan.steps[0].response_not_contains = ['next=']
    with pytest.raises(ValueError):
        capture_response_values(plan.steps[0], probe)


@pytest.mark.parametrize('change', ['tcp', 'forward', 'header', 'body', 'malformed', 'duplicate'])
def test_capture_contract_rejects_unsupported_placement_or_sources(change):
    raw = scenario().model_dump()
    if change == 'tcp': raw['protocol'] = 'tcp'
    elif change == 'forward': raw['steps'].reverse()
    elif change == 'header': raw['steps'][1]['request_text'] = 'GET / HTTP/1.0\r\nX-Token: {{response:session}}\r\n\r\n'
    elif change == 'body': raw['steps'][1]['request_text'] = 'POST / HTTP/1.0\r\n\r\n{{response:session}}'
    elif change == 'malformed': raw['steps'][1]['request_text'] = 'GET /?id={{response:bad-name}} HTTP/1.0\r\n\r\n'
    else: raw['steps'][0]['response_captures'] *= 2
    with pytest.raises(ValidationError):
        InteractionScenario.model_validate(raw)


def test_no_missing_or_stale_value_fallback_and_no_silent_capture_revision():
    plan = scenario()
    with pytest.raises(ValueError, match='has not been captured'):
        substitute_response_values(plan.steps[1].request_text, {})
    values = capture_response_values(plan.steps[0], response(b'next="old"'))
    values.update(capture_response_values(plan.steps[0], response(b'next="new"')))
    assert '?id=new ' in substitute_response_values(plan.steps[1].request_text, values)
    changed = plan.model_copy(deep=True)
    changed.steps[0].response_captures[0].prefix = 'different="'
    assert 'response capture' in _scenario_weakening(plan, changed)
    changed = plan.model_copy(deep=True)
    changed.steps[1].response_captures = [ResponseValueCapture(name='session', prefix='evil="', suffix='"')]
    assert 'response capture' in _scenario_weakening(plan, changed)


@pytest.mark.parametrize('missing', [False, True])
def test_production_loop_stops_before_dependent_request_on_capture_failure(tmp_path, monkeypatch, missing):
    import subprocess
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    from fmst_analyzer.runner.supervision import TargetProgressWatchdog
    from fmst_analyzer.runner.attempt_facts import build_attempt_facts
    from fmst_analyzer.runner.schema import RuntimeAttempt
    rootfs = tmp_path / 'rootfs'
    rootfs.mkdir()
    box = DockerRootfsSandbox(rootfs=rootfs, workdir=tmp_path, target_binary='guest',
        executable_path='/guest', guest_arch='arm', runtime_workspace=tmp_path / 'runtime', env_script=None)
    box._prepared, box._active_rootfs = True, rootfs
    box.bundle_dir.mkdir(parents=True)
    monkeypatch.setattr(TargetProgressWatchdog, 'start', lambda watch: None)
    monkeypatch.setattr(TargetProgressWatchdog, '_read_processes', lambda watch: [])
    def command(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0, 'true 0' if argv[:2] == ['docker', 'inspect'] else '', '')
    monkeypatch.setattr(box, '_process', command)
    sent = []
    def probe(container, item, *, observer, **kwargs):
        sent.append(item.request_text)
        observer.response_received()
        return response(b'nothing' if missing else b'next="a/b +?"')
    monkeypatch.setattr(box, '_run_tcp_probe_in_container', probe)
    plan = scenario()
    result = box.run_attempt(attempt_number=1, intervention_so=None, executable_path='/guest',
        guest_args=[], guest_working_directory='/', guest_environment={}, companion_processes=[],
        probe=InteractionProbe(port=80, request_text=plan.steps[0].request_text), scenario=plan, timeout_seconds=20)
    assert len(sent) == (1 if missing else 2)
    assert result.scenario_result.status == ('unsupported' if missing else 'success')
    if missing:
        assert 'prefix missing' in result.scenario_result.steps[0].error
        assert not (box.session_root / 'attempt_receipts/attempt-01-requests/step-02.bin').exists()
    else:
        assert sent[1] == 'GET /?id=a%2Fb%20%2B%3F HTTP/1.0\r\n\r\n'
        attempt = RuntimeAttempt(tree_identity_version=2, attempt_number=1, probe=dict(port=80, request_text=sent[0]), scenario=plan,
            scenario_result=result.scenario_result, guest_args=[], guest_working_directory='/', guest_environment={},
            rootfs_actions=[], disabled_unit_ids=[], outcome='success', probe_result=result.probe_result,
            runtime_trace_path='unused', runtime_trace_context_path='unused', container_log_path='unused', agent_summary='fixture',
            runtime_trace_available=False, runtime_trace_context_available=False)
        facts = build_attempt_facts(attempt, previous=None, requests={i: s.encode() for i, s in enumerate(sent, 1)}, request_errors=[])
        assert facts.steps[0].response_values_captured == ['session']
        assert facts.steps[1].response_value_target_matches is True
