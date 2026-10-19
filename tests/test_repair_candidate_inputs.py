"""Actual repair packaging with only Docker and native build boundaries replaced."""
import json
import tomllib
from importlib import import_module
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner.repair_intake import UpstreamRepairInput
from fmst_analyzer.runner.identity import tree_sha256
from fmst_analyzer.synthesizer.intervention_generator.repair_candidate import publish_repair_candidate
from test_upstream_repair import inputs


@pytest.mark.parametrize("stage", ["file", "generation"])
def test_scaffold_is_honest_fresh_and_bound_with_separate_unvalidated_code(tmp_path, stage):
    root, target, reports, config = inputs(tmp_path)
    source = config.workdir / "interventions/service"
    (source / "src").mkdir(parents=True)
    (source / "src/lib.rs").write_text("// unfinished authored source")
    (source / "target").mkdir()
    (source / "target/binary").write_text("old build must not be reused")
    repair = UpstreamRepairInput.capture(error=RuntimeError("tool failure"), stage=stage, rootfs=root, target=target)
    repair.generator_materials_current = stage == "generation"
    published = publish_repair_candidate(tmp_path / "candidate", config=config, repair_input=repair, arch="mipsel")
    candidate = published["root"]
    assert published["baseline_id"] == "upstream-repair:" + tree_sha256(candidate)
    manifest = tomllib.loads((candidate / "intervention/Cargo.toml").read_text())
    assert manifest["dependencies"]["guestweave"]["features"] == ["mips"]
    assert published["record"]["generation_status"] == "not_completed"
    assert (candidate / "upstream-generator/intervention/src/lib.rs").exists() == (stage == "generation")
    assert not (candidate / "upstream-generator/intervention/target").exists()
    assert (source / "src/lib.rs").read_text() == "// unfinished authored source"
    assert "ExecLauncher::current_process" in (candidate / "intervention/src/main.rs").read_text()


def test_scaffold_does_not_copy_external_or_nested_symlink_sources(tmp_path):
    root, target, reports, config = inputs(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    (external / "secret.rs").write_text("external source")
    source = config.workdir / "interventions/service"
    source.parent.mkdir()
    source.symlink_to(external, target_is_directory=True)
    repair = UpstreamRepairInput.capture(error=RuntimeError("tool"), stage="generation", rootfs=root, target=target)
    repair.generator_materials_current = True
    record = publish_repair_candidate(tmp_path / "candidate", config=config, repair_input=repair, arch="arm")
    assert record["record"]["upstream_generator_materials"][0]["status"] == "unavailable"
    assert not (record["root"] / "upstream-generator").exists()


def test_failed_generation_preflight_does_not_inherit_older_authored_source(tmp_path):
    root, target, reports, config = inputs(tmp_path)
    source = config.workdir / "interventions/service"
    source.mkdir(parents=True)
    (source / "old.rs").write_text("older unbound attempt")
    repair = UpstreamRepairInput.capture(error=ValueError("Plan invalid before generation began"),
                                        stage="generation", rootfs=root, target=target)
    candidate = publish_repair_candidate(tmp_path / "candidate", config=config,repair_input=repair,arch="arm")
    assert not (candidate["root"] / "upstream-generator").exists()


@pytest.mark.parametrize("bound", [False, True])
def test_prepare_uses_real_scaffold_or_prefers_valid_publication_and_retains_failed_reports(tmp_path, monkeypatch, bound):
    module = import_module("fmst_analyzer.runner.task.inputs")
    materials = import_module("fmst_analyzer.runner.task.materials")
    root, target, reports, config = inputs(tmp_path)
    config.decompiler_db_dir = None
    fail = reports / ".attempts/file/current/artifacts/reports/failed.json"
    fail.parent.mkdir(parents=True)
    fail.write_text('{"execution":{"status":"failed"}}')
    trace = reports / ".attempts/file/current/artifacts/traces/native.json"
    trace.parent.mkdir()
    trace.write_text("private native transcript")
    repair = UpstreamRepairInput.capture(error=RuntimeError("missing upstream"), stage="file", rootfs=root, target=target)
    candidate = tmp_path / "published"
    candidate.mkdir()
    (candidate / "code").write_text("source-bound publication")
    def load(*args):
        if not bound: raise ValueError("Incomplete Analyzer source cannot make a Plan")
        return (SimpleNamespace(launch_candidates={}),
            SimpleNamespace(service_goal="Plan goal",launch_choice=SimpleNamespace(recipe_id="none")),
            SimpleNamespace(arch="x86_64"), SimpleNamespace(root=candidate,baseline_id="verified-baseline"))
    monkeypatch.setattr(module, "load_bound_candidate", load)
    monkeypatch.setattr(module, "image_analysis_environment", lambda task: {})
    monkeypatch.setattr(module, "transfer_rootfs", lambda task, root: {})
    monkeypatch.setattr(import_module("fmst_analyzer.runner.task.runtime_inputs"), "prepare_runtime",
                        lambda *a: {"harness":"/task/native/harness"})
    calls = []
    def copy(name, source, dest, **kwargs): calls.append((source, dest, kwargs))
    monkeypatch.setattr(module, "copy_tree", copy)
    monkeypatch.setattr(materials, "copy_tree", copy)
    monkeypatch.setattr(module, "docker", lambda *a: None)
    monkeypatch.setattr(materials, "docker", lambda *a: None)
    task = SimpleNamespace(name="fixture",output=tmp_path / "task",delivery_mode="rehosting_only",resource_limits=None,
                           put_json=lambda *a: None)
    task.output.mkdir()
    result = module.prepare(task, config=config,view=None,rootfs=root,framework=config.runtime_workspace,
                            service_goal="Caller goal",repair_input=repair)
    assert result["input_mode"] == "upstream_repair"
    assert result["goal"] == "Caller goal" and result["goal_source"] == "caller"
    assert result["candidate_origin"] == ("generation_publication" if bound else "diagnostic_scaffold")
    assert result["baseline_id"] == ("verified-baseline" if bound else "upstream-repair:" + tree_sha256(task.output / "repair-candidate"))
    included = next(item for item in calls if item[1] == "/task/input/reports")
    assert "traces" in included[2]["exclude"]
    index = json.loads((task.output / "materials.json").read_text())
    selected = next(item for item in index["materials"] if item["kind"] == "selected_target_reports")
    assert selected["files"] == 2  # failed JSON + source-bound repair packet; no native trace
    assert fail.exists() and trace.exists()
    assert not (reports / "intervention_plan_reports").exists()


def test_repair_prompt_preserves_native_completion_and_explains_scaffold():
    from fmst_analyzer.runner.task.worker import initial_message
    message = initial_message(dict(input_mode="upstream_repair",candidate_origin="diagnostic_scaffold",
                                   goal="native web management",delivery_mode="rehosting_only"))
    assert "not a completed Generator intervention" in message
    assert "Failed or missing analysis is not a firmware conclusion" in message
    assert "complete only from actual native interaction" in message
    assert "complete_service" in message


def test_generator_resource_error_closes_semaphore_gate_without_requesting_next_agent(monkeypatch):
    import asyncio
    from fmst_analyzer.synthesizer.intervention_generator import generator as module
    generator = module.InterventionGenerator(SimpleNamespace(agent_provider="claude",synthesizer_model="test",agent_concurrency_limit=1))
    calls = []
    async def invoke(*a, **k):
        calls.append(a)
        raise OSError(24, "Too many open files")
    monkeypatch.setattr(module, "invoke_agent", invoke)
    async def run():
        return await asyncio.gather(generator._invoke_limited("first", "task"),
                                    generator._invoke_limited("next", "task"),return_exceptions=True)
    failures = asyncio.run(run())
    assert len(calls) == 1 and all(isinstance(item,OSError) for item in failures)
