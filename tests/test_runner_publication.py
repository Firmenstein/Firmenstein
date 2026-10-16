"""Frozen-input publication contracts, not real firmware success claims."""

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json
from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped
from fmst_analyzer.runner.identity import tree_sha256
from fmst_analyzer.runner.publication import publish_success, load_success, load_frozen_inputs, SuccessfulConfiguration, SuccessfulConfigurationPointer
from fmst_analyzer.runner.schema import RuntimeAttempt


def test_network_must_match_execution_and_survive_clean_replay(publication, tmp_path, monkeypatch):
    from fmst_analyzer.runner.schema import RuntimeNetwork, ScenarioResult
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    from fmst_analyzer.runner.publication import replay_success
    config = RuntimeNetwork(subnet="192.168.9.0/24", gateway="192.168.9.254",
        target_address="192.168.9.1", probe_destination="interface")
    publication["attempt"].network = config
    with pytest.raises(ValueError, match="network differs"):
        publish_success(**publication)
    publication["sandbox"].network = config
    write_model_json(publication["attempt_dir"] / "attempt.json", publication["attempt"])
    path = publish_success(**publication)
    observed = []
    def run(self, **kwargs):
        observed.append(self.network)
        assert kwargs["scenario"] == publication["attempt"].scenario
        return SimpleNamespace(scenario_result=ScenarioResult(status="success"))
    monkeypatch.setattr(DockerRootfsSandbox, "_docker", lambda *a: None)
    monkeypatch.setattr(DockerRootfsSandbox, "_import_rootfs", lambda *a: None)
    monkeypatch.setattr(DockerRootfsSandbox, "run_attempt", run)
    monkeypatch.setattr(DockerRootfsSandbox, "close", lambda *a: None)
    receipt = replay_success(path, workdir=tmp_path / "replay", budget=ExecutionBudget(60))
    assert receipt.state == "success" and receipt.input_identity_verified and receipt.runtime_identity_verified
    assert observed == [config]


def test_response_capture_rules_survive_publication_and_replay(publication, tmp_path, monkeypatch):
    from fmst_analyzer.runner.schema import InteractionScenario, ScenarioResult
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    from fmst_analyzer.runner.publication import replay_success
    scenario = InteractionScenario(protocol='http', port=8080, evidence_refs=['fixture'], steps=[
        dict(request_text='GET /login HTTP/1.0\r\n\r\n', expected_status_code=200,
            response_captures=[dict(name='session', prefix='next="', suffix='"', max_chars=32)]),
        dict(request_text='GET /?id={{response:session}} HTTP/1.0\r\n\r\n', expected_status_code=200)])
    publication['attempt'].scenario = scenario
    write_model_json(publication['attempt_dir'] / 'attempt.json', publication['attempt'])
    path = publish_success(**publication)
    observed = []
    def run(self, **kwargs):
        observed.append(kwargs['scenario'])
        return SimpleNamespace(scenario_result=ScenarioResult(status='success'))
    monkeypatch.setattr(DockerRootfsSandbox, '_docker', lambda *a: None)
    monkeypatch.setattr(DockerRootfsSandbox, '_import_rootfs', lambda *a: None)
    monkeypatch.setattr(DockerRootfsSandbox, 'run_attempt', run)
    monkeypatch.setattr(DockerRootfsSandbox, 'close', lambda *a: None)
    replay = replay_success(path, workdir=tmp_path / 'replay', budget=ExecutionBudget(60))
    assert replay.state == 'success' and observed == [scenario]
    assert load_success(path, publication['budget']).attempt.scenario == scenario


@pytest.fixture
def publication(tmp_path):
    for name in ("rootfs", "runtime", "evidence", "authored/environment", "baseline",
                 "authored/interventions/guest/src", "authored/interventions/guest/target",
                 "authored/test_harnesses/guest/tests"):
        (tmp_path / name).mkdir(parents=True)
    (tmp_path / "rootfs/guest").write_bytes(b"controlled fixture, not executable")
    (tmp_path / "rootfs/guest").chmod(0o755)
    (tmp_path / "rootfs/alias").symlink_to("guest")
    (tmp_path / "runtime/harness").write_bytes(b"controlled harness identity")
    script = tmp_path / "authored/environment/setup_rootfs.py"
    script.write_text("# exact authored environment\n")
    (tmp_path / "authored/interventions/guest/src/lib.rs").write_text("// authored revision\n")
    (tmp_path / "authored/interventions/guest/target/cache").write_bytes(b"not authored")
    (tmp_path / "authored/test_harnesses/guest/tests/contract.rs").write_text("// authored contract test\n")
    (tmp_path / "baseline/baseline_manifest.json").write_text('{"original": true}')
    attempt = RuntimeAttempt(tree_identity_version=2, attempt_number=2,
        probe={"port": 8080, "request_text": "GET / HTTP/1.0\r\n\r\n"},
        scenario={"protocol": "http", "port": 8080, "evidence_refs": ["offline fixture"],
                  "steps": [{"request_text": "GET / HTTP/1.0\r\n\r\n", "expected_status_code": 200}]},
        scenario_result={"status": "success", "observations": [
            {"source": "lifecycle", "kind": "target_lifecycle", "fact": "target_exit_code=not_observed", "evidence_path": None},
            {"source": "container", "kind": "staged_rootfs", "fact": "staged_rootfs_ready=true", "evidence_path": str(tmp_path / "rootfs")},
        ]}, guest_args=["literal $ argument"],
        guest_working_directory="/", guest_environment={"EXACT": "value"},
        rootfs_actions=[], disabled_unit_ids=[], outcome="success",
        probe_result={"connected": True, "interacted": True, "attempts": 1},
        runtime_trace_path="old/trace.json", runtime_trace_context_path="old/context.json",
        container_log_path="old/container.log", runtime_trace_available=False,
        runtime_trace_context_available=False, agent_summary="not a real guest",
        rootfs_sha256=tree_sha256(tmp_path / "rootfs"), harness_sha256=tree_sha256(tmp_path / "runtime"),
        target_binary_sha256=hashlib.sha256((tmp_path / "rootfs/guest").read_bytes()).hexdigest())
    write_model_json(tmp_path / "evidence/attempt.json", attempt)
    sandbox = SimpleNamespace(_active_rootfs=tmp_path / "rootfs", bundle_dir=tmp_path / "runtime",
        executable_path="/guest", session_id="sandbox", target_binary="guest", guest_arch="arm", network=attempt.network,
        output_root=tmp_path / "raw-attempts", session_root=tmp_path,
        runtime_builder=SimpleNamespace(platform_name="linux/arm64"), _env_script_snapshot=script)
    return dict(root=tmp_path / "successes", sandbox=sandbox, attempt=attempt,
        attempt_dir=tmp_path / "evidence", controller_session_id="controller", baseline_id="original-baseline",
        baseline_root=tmp_path / "baseline", authored_root=tmp_path / "authored", source_records={},
        revisions=[], budget=ExecutionBudget(60))


def test_freeze_and_relocate_does_not_depend_on_original_paths(publication, tmp_path):
    path = publish_success(**publication)
    manifest = load_success(path, publication["budget"])
    assert manifest.attempt == publication["attempt"]
    assert manifest.input_trees["rootfs"] == publication["attempt"].rootfs_sha256
    assert manifest.evidence_locations[str(tmp_path / "rootfs")] == "rootfs"
    assert (path.parent / "rootfs/alias").is_symlink()
    assert (path.parent / "authored/environment/setup_rootfs.py").read_bytes() == (path.parent / "sources/setup_rootfs.executed.py").read_bytes()
    assert (path.parent / "authored/interventions/guest/src/lib.rs").is_file()
    assert (path.parent / "authored/test_harnesses/guest/tests/contract.rs").is_file()
    assert not (path.parent / "authored/interventions/guest/target").exists()
    pointer = load_model_json(publication["root"] / "current.json", SuccessfulConfigurationPointer)
    assert pointer.configuration_id == manifest.configuration_id
    (tmp_path / "rootfs/guest").write_bytes(b"original subsequently changed")
    destination = tmp_path / "relocated"
    path.parent.rename(destination)
    assert load_success(destination / "manifest.json", publication["budget"]) == manifest


def test_completion_is_frozen_and_checked_against_attempt_identity(publication):
    from fmst_analyzer.runner.schema import RunnerCompletion
    evidence = publication['attempt_dir']
    completion = RunnerCompletion(attempt_number=publication['attempt'].attempt_number,
        attempt_sha256=hashlib.sha256((evidence / 'attempt.json').read_bytes()).hexdigest(),
        coverage='Controlled fixture scope only', limitations=['Not real firmware acceptance'])
    write_model_json(evidence / 'completion.json', completion)
    publication['completion'] = completion
    path = publish_success(**publication)
    assert load_frozen_inputs(path, publication['budget']).attempt == publication['attempt']
    assert load_model_json(path.parent / 'evidence/completion.json', RunnerCompletion) == completion
    completion.attempt_sha256 = '0' * 64
    write_model_json(evidence / 'completion.json', completion)
    with pytest.raises(ValueError, match='completion evidence'):
        publish_success(**publication)


@pytest.mark.parametrize("mutation", [None, "rootfs", "validator_claim", "scenario"])
def test_explicit_legacy_input_reader_preserves_version_and_checks_identity(publication, mutation):
    """The migration fixture may read v2 inputs; production replay still rejects them."""
    import importlib.util
    import json
    path = publish_success(**publication)
    raw = json.loads(path.read_text())
    raw["schema_version"] = 2
    for name in ("request_wire.py", "peer_readiness.py", "adaptation_schema.py",
                 "runtime_builder.py", "container_output.py", "live_client.py", "browser_access.py"):
        raw["validation_code_sha256"].pop(name)
        (path.parent / "sources/validator" / name).unlink()
    raw["input_trees"]["sources"] = tree_sha256(path.parent / "sources")
    path.write_text(json.dumps(raw))
    if mutation == "rootfs":
        (path.parent / "rootfs/guest").write_bytes(b"changed guest")
    elif mutation == "validator_claim":
        raw["validation_code_sha256"]["probe.py"] = "0" * 64
        path.write_text(json.dumps(raw))
    elif mutation == "scenario":
        raw["attempt"]["scenario"]["steps"][0]["expected_status_code"] = 201
        path.write_text(json.dumps(raw))
    before = path.read_bytes()
    with pytest.raises(ValueError, match="schema_version"):
        load_success(path, publication["budget"])
    module_path = Path(__file__).parent / "runtime_fixtures/guestweave/legacy_publication.py"
    spec = importlib.util.spec_from_file_location("legacy_publication", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if mutation is not None:
        with pytest.raises(ValueError):
            module.load_legacy_inputs(path, publication["budget"])
    else:
        inputs = module.load_legacy_inputs(path, publication["budget"])
        assert inputs.schema_version == 2
        assert inputs.attempt == publication["attempt"]
    assert path.read_bytes() == before


@pytest.mark.parametrize("mutation", ["mode", "bytes", "runtime", "scenario", "tree_escape", "validator", "legacy"])
def test_replay_rejects_changed_identity(publication, mutation):
    path = publish_success(**publication)
    if mutation == "mode":
        (path.parent / "rootfs/guest").chmod(0o700)
    elif mutation == "bytes":
        (path.parent / "rootfs/guest").write_bytes(b"different")
    elif mutation == "runtime":
        (path.parent / "runtime/harness").write_bytes(b"different runtime")
    else:
        manifest = load_model_json(path, SuccessfulConfiguration)
        if mutation == "scenario":
            manifest.attempt.scenario.steps[0].expected_status_code = 201
        elif mutation == "validator":
            manifest.validation_code_sha256["probe.py"] = "different-validation-code"
        elif mutation == "legacy":
            manifest.schema_version = 1
        else:
            manifest.input_trees["../outside"] = manifest.input_trees.pop("rootfs")
        write_model_json(path, manifest)
    with pytest.raises(ValueError):
        load_success(path, publication["budget"])


def test_failed_publication_never_replaces_last_success(publication):
    publish_success(**publication)
    pointer = (publication["root"] / "current.json").read_bytes()
    publication["sandbox"]._active_rootfs.joinpath("guest").chmod(0o700)
    with pytest.raises(ValueError, match="identity differs"):
        publish_success(**publication)
    assert (publication["root"] / "current.json").read_bytes() == pointer
    assert len(list(publication["root"].glob(".pending-*"))) == 1


def test_manifest_cannot_relabel_frozen_validator_sources(publication):
    path = publish_success(**publication)
    manifest = load_model_json(path, SuccessfulConfiguration)
    # Re-labeling old copied sources as current code must fail even if the
    # copied source tree still has its original, valid tree hash.
    manifest.validation_code_sha256["probe.py"] = "f" * 64
    write_model_json(path, manifest)
    for loader in (load_frozen_inputs, load_success):
        with pytest.raises(ValueError, match="validator source hash mismatch: probe.py"):
            loader(path, publication["budget"])


def test_historical_input_integrity_does_not_authorize_current_replay(publication):
    path = publish_success(**publication)
    manifest = load_model_json(path, SuccessfulConfiguration)
    source = path.parent / "sources/validator/probe.py"
    source.write_bytes(source.read_bytes() + b"\n# historical implementation\n")
    manifest.validation_code_sha256["probe.py"] = hashlib.sha256(source.read_bytes()).hexdigest()
    manifest.input_trees["sources"] = tree_sha256(path.parent / "sources")
    write_model_json(path, manifest)
    assert load_frozen_inputs(path, publication["budget"]) == manifest
    with pytest.raises(ValueError, match="frozen validation implementation differs"):
        load_success(path, publication["budget"])


def test_cancelled_or_blocked_attempt_cannot_publish(publication):
    publication["budget"].cancelled.set()
    with pytest.raises(RunnerStopped):
        publish_success(**publication)
    assert not publication["root"].exists()
    publication["budget"] = ExecutionBudget(60)
    publication["attempt"].outcome = "blocked"
    with pytest.raises(ValueError, match="satisfied scenario"):
        publish_success(**publication)
    assert not publication["root"].exists()


@pytest.mark.parametrize('tamper', [False, True])
def test_cookie_revision_sources_survive_relocation_or_reject_changed_evidence(publication, tmp_path, tamper):
    from fmst_analyzer.runner.schema import RequestRepresentationRevision, CookieSourceEvidence
    source_attempt = tmp_path / 'prior-failed-attempt.json'
    source_attempt.write_text('{"fixture": "prior failure bytes; admission is tested separately"}')
    response = tmp_path / 'prior-response.bin'
    response.write_bytes(b'HTTP/1.0 401 Unauthorized\r\nSet-Cookie: sid=opaque\r\n\r\n')
    scenario = publication['attempt'].scenario
    revision = RequestRepresentationRevision(kind='cookie_continuity', reason='controlled publication provenance fixture',
        parent_sha256='a' * 64, result_sha256='b' * 64, before=scenario, after=scenario,
        source_attempt_path=str(source_attempt), source_attempt_sha256=hashlib.sha256(source_attempt.read_bytes()).hexdigest(),
        cookie_sources=[CookieSourceEvidence(step_index=1, response_path=str(response),
            response_sha256=hashlib.sha256(response.read_bytes()).hexdigest(), cookie_names=['sid'])])
    publication['attempt'].request_revisions = [revision]
    write_model_json(publication['attempt_dir'] / 'attempt.json', publication['attempt'])
    if tamper:
        response.write_bytes(b'changed after admission')
        with pytest.raises(ValueError, match='source changed'):
            publish_success(**publication)
        assert not (publication['root'] / 'current.json').exists()
        return
    path = publish_success(**publication)
    frozen = load_success(path, publication['budget'])
    for original in (source_attempt, response):
        copied = path.parent / frozen.evidence_locations[str(original)]
        assert copied.read_bytes() == original.read_bytes()
        original.unlink()
    destination = tmp_path / 'relocated-cookie-publication'
    path.parent.rename(destination)
    assert load_success(destination / 'manifest.json', publication['budget']).attempt.request_revisions == [revision]


def test_replay_collects_outputs_with_configured_builder_without_build(publication, tmp_path, monkeypatch):
    import fmst_analyzer.runner.publication as module
    from fmst_analyzer.runner.schema import ScenarioResult
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    builder = SimpleNamespace(platform_name=None, handoff_output=lambda root: None)
    calls = []
    monkeypatch.setenv("FMST_RUNTIME_BUILDER_IMAGE", "collector-image")
    def select(**kwargs):
        calls.append(kwargs)
        return builder
    monkeypatch.setattr(module, "create_runtime_builder", select)
    path = publish_success(**publication)
    monkeypatch.setattr(DockerRootfsSandbox, "_docker", lambda *args: None)
    monkeypatch.setattr(DockerRootfsSandbox, "_import_rootfs", lambda *args: None)
    monkeypatch.setattr(DockerRootfsSandbox, "close", lambda *args: None)
    def run(sandbox, **kwargs):
        assert sandbox.runtime_builder is builder
        return SimpleNamespace(scenario_result=ScenarioResult(status="success"))
    monkeypatch.setattr(DockerRootfsSandbox, "run_attempt", run)
    receipt = module.replay_success(path, workdir=tmp_path / "replay", budget=ExecutionBudget(60))
    assert receipt.state == "success"
    assert calls[0]["image"] == "collector-image"
    assert calls[0]["platform_name"] == publication["sandbox"].runtime_builder.platform_name
    assert "runtime_builder.py" in module._VALIDATOR_HASHES
    assert "container_output.py" in module._VALIDATOR_HASHES


def test_native_completion_preserves_failed_protocol_check_and_browser_evidence(publication):
    import json
    from fmst_analyzer.runner.schema import RunnerCompletion, ScenarioResult
    attempt = publication['attempt']
    attempt.outcome = 'blocked'
    attempt.browser_origin = 'http://native.router:8080/'
    attempt.probe = None
    attempt.scenario = None
    attempt.scenario_result = None
    evidence = publication['attempt_dir']
    write_model_json(evidence/'attempt.json', attempt)
    digest = hashlib.sha256((evidence/'attempt.json').read_bytes()).hexdigest()
    completion = RunnerCompletion(attempt_number=attempt.attempt_number, attempt_sha256=digest,
        client_receipt='/original/native/receipt.json', coverage='Actual native write/readback verified')
    write_model_json(evidence/'completion.json', completion)
    (evidence/'native-client').mkdir()
    (evidence/'native-client/receipt.json').write_text(json.dumps({'attempt_sha256':digest, 'commands':['command.json']}))
    path = publish_success(**publication, completion=completion)
    restored = load_frozen_inputs(path, publication['budget'])
    assert restored.attempt.outcome == 'blocked'
    assert (path.parent/'evidence/native-client/receipt.json').is_file()
