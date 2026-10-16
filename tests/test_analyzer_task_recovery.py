"""Exact-input recovery and correctable Network output boundaries."""
import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from fmst_basic.agent import AgentProviderError
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import CodeAnalyzerAgent
from fmst_analyzer.analysis.base.input_provenance import AnalysisInputs, analysis_input_scope
from fmst_analyzer.analysis.base.task_recovery import task_recovery_scope
from fmst_analyzer.analysis.network_analyzer.analyzer_schema import NetworkResourceAgentResult
from test_network_analyzer_controller import _listener, _fact, _View
from fmst_analyzer.analysis.network_analyzer.controller import validate_resource_result


@pytest.mark.parametrize("element", [{}, [], 1, None, True])
def test_wrong_id_elements_are_located_pydantic_errors(element):
    raw = NetworkResourceAgentResult(analyses=[_listener(["bind"])]).model_dump(mode="json")
    raw["analyses"][0]["callsite_ids"] = [element]
    with pytest.raises(ValidationError) as rejected:
        NetworkResourceAgentResult.model_validate(raw)
    assert rejected.value.errors()[0]["loc"] == ("analyses", 0, "callsite_ids", 0)


def _inputs(**updates):
    return AnalysisInputs(stage="network", phase="full", target_path="usr/sbin/httpd",
        target_sha256=updates.get("target_sha256", "a" * 64),
        rootfs_sha256=updates.get("rootfs_sha256", "b" * 64),
        implementation_sha256=updates.get("implementation_sha256", "c" * 64),
        settings=updates.get("settings", {"agent_provider": "claude", "agent_concurrency_limit": 4}))


def test_same_agent_corrects_malformed_id_and_missing_seed(monkeypatch, tmp_path):
    import fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent as module
    messages, responses = [], []
    good = NetworkResourceAgentResult(analyses=[_listener(["bind"])]).model_dump(mode="json")
    malformed = json.loads(json.dumps(good))
    malformed["analyses"][0]["callsite_ids"] = [{}]
    missing = NetworkResourceAgentResult(analyses=[_listener(["listen"])]).model_dump(mode="json")
    class Agent:
        async def ainvoke(self, message, trace=None):
            messages.append(message)
            raw = [malformed, missing, good][len(messages) - 1]
            responses.append(raw)
            return SimpleNamespace(structured_response=NetworkResourceAgentResult.model_validate(raw))
        async def aclose(self):
            self.closed = True
    agent = Agent()
    factories = []
    def factory(**kwargs):
        factories.append(kwargs)
        return agent
    monkeypatch.setattr(module, "create_analysis_agent", factory)
    facts = [_fact("bind", "bind", 3), _fact("listen", "listen", 4)]
    analysis = CodeAnalyzerAgent("NetworkInteractionAgent", "Analyze source", NetworkResourceAgentResult,
                                 "deepseek-flash[1m]", include_analyzer_tools=False)
    output = asyncio.run(analysis.analyze("source", _View(), output_validator=lambda output:
        validate_resource_result(output, "bind", facts, _View())))
    assert output.analyses[0].callsite_ids == ["bind"]
    assert len(factories) == 1 and len(messages) == 3 and agent.closed
    assert "analyses.0.callsite_ids.0" in messages[1]
    assert "seed_callsite_id='bind'" in messages[2]
    assert responses[0]["analyses"][0]["callsite_ids"] == [{}]


def test_successes_survive_interruption_and_only_exact_inputs_recover(monkeypatch, tmp_path):
    import fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent as module
    monkeypatch.setattr("fmst_analyzer.analysis.base.semantic_identity.view_semantic_identity", lambda _: [])
    calls = []
    validated = []
    fail = {"value": True}
    config = SimpleNamespace(workdir=tmp_path, resume_analyzer_tasks=False,
                             target_diagnostic_reports_dir=lambda: tmp_path / "reports")
    class Agent:
        async def ainvoke(self, message, trace=None):
            calls.append(message)
            if "task-two" in message and fail["value"]:
                raise AgentProviderError("connection interrupted", provider="claude")
            return SimpleNamespace(structured_response=NetworkResourceAgentResult(analyses=[_listener(["bind", "bind"])]))
        async def aclose(self): pass
    monkeypatch.setattr(module, "create_analysis_agent", lambda **kwargs: Agent())
    agent = CodeAnalyzerAgent("NetworkInteractionAgent", "Analyze source", NetworkResourceAgentResult,
                              "deepseek-flash[1m]", include_analyzer_tools=False)
    async def task(label):
        return await agent.analyze(label, _View(), output_validator=lambda output: validated.append(output.model_dump()))
    source_attempt = str(tmp_path / "original-failed-attempt")
    first = {"attempt_path": source_attempt}
    with analysis_input_scope(_inputs()), task_recovery_scope(config, first):
        asyncio.run(task("task-one"))
        with pytest.raises(AgentProviderError):
            asyncio.run(task("task-two"))
    assert len(list((tmp_path / "reports/.task_checkpoints/network").glob("*.json"))) == 1
    original = json.loads(next((tmp_path / "reports/.task_checkpoints/network").glob("*.json")).read_text())
    config.resume_analyzer_tasks = True
    fail["value"] = False
    resumed = {"attempt_path": str(tmp_path / "resumed-attempt")}
    changed_concurrency = _inputs(settings={"agent_provider": "claude", "agent_concurrency_limit": 1})
    with analysis_input_scope(changed_concurrency), task_recovery_scope(config, resumed):
        asyncio.run(task("task-one"))
        asyncio.run(task("task-two"))
    assert len(calls) == 3  # one recovery, one new request
    assert len(validated) == 3  # recovered output is revalidated
    assert any(event["disposition"] == "reused_after_validation" for event in resumed["task_recovery"])
    loaded = next(event for event in resumed["task_recovery"] if event["disposition"] == "loaded")
    assert loaded["source_attempt"] == source_attempt
    assert json.loads(Path(loaded["checkpoint"]).read_text()) == original
    assert (Path(source_attempt) / "task_checkpoints" / Path(loaded["checkpoint"]).name).is_file()
    assert "stored" in (Path(source_attempt) / "task_recovery.jsonl").read_text()
    for update in ({"target_sha256": "d" * 64}, {"rootfs_sha256": "d" * 64},
                   {"implementation_sha256": "d" * 64}, {"settings": {"agent_provider": "codex"}}):
        with analysis_input_scope(_inputs(**update)), task_recovery_scope(config, {}):
            asyncio.run(task("task-one"))
    assert len(calls) == 7
    # A static call never loads or creates checkpoints.
    static = _inputs().model_copy(update={"phase": "static"})
    with analysis_input_scope(static), task_recovery_scope(config, {}):
        from fmst_analyzer.analysis.base.task_recovery import checkpoint_path
        assert checkpoint_path(contract={}) is None


@pytest.mark.parametrize("mode", ["corrupt", "failed", "invalid_reference"])
def test_invalid_checkpoint_is_not_a_completed_task(mode, monkeypatch, tmp_path):
    from fmst_analyzer.analysis.base.task_recovery import checkpoint_path, load_checkpoint, store_checkpoint
    config = SimpleNamespace(workdir=tmp_path, resume_analyzer_tasks=True,
                             target_diagnostic_reports_dir=lambda: tmp_path / "reports")
    with analysis_input_scope(_inputs()), task_recovery_scope(config, {}) as _:
        path = checkpoint_path(contract={"test": 1})
        store_checkpoint(path, NetworkResourceAgentResult(analyses=[_listener(["bind"])]))
        envelope = json.loads(path.read_text())
        if mode == "corrupt":
            envelope["output"]["analyses"][0]["summary"] = "tampered"
        elif mode == "failed":
            envelope["status"] = "failed"
        else:
            envelope["key"] = "other-input"
        path.write_text(json.dumps(envelope))
        assert load_checkpoint(path, NetworkResourceAgentResult) is None


def test_init_recovery_preserves_tool_source_handles_and_revalidates_text(monkeypatch, tmp_path):
    from test_init_correction_history import _fixture
    from fmst_analyzer.analysis.init_launch.launch_recipe_agent import LaunchRecipeAgent
    from fmst_analyzer.analysis.init_launch.analyzer_schema import LaunchRecipeAgentOutput, SourceSnippet, TargetIdentity
    from fmst_analyzer.analysis.base.output_validation import OutputValidationError
    rootfs, draft, _ = _fixture(tmp_path)
    config = SimpleNamespace(workdir=tmp_path, resume_analyzer_tasks=False,
        diagnosis_model="test", agent_provider="test", target_diagnostic_reports_dir=lambda: tmp_path / "reports")
    calls = []
    def factory(**kwargs):
        read_source = next(tool for tool in kwargs["tools"] if tool.name == "read_source")
        class Agent:
            async def ainvoke(self, message, **extra):
                calls.append(message)
                reference = read_source.invoke({"path": "etc/rcS", "start_line": 1, "end_line": 1})
                source = SourceSnippet.model_validate(reference["source_snippet"])
                output = draft.model_copy(update={"launch_site": source, "context_anchor": source,
                                                  "initialization_chain": [source]})
                return SimpleNamespace(structured_response=LaunchRecipeAgentOutput(launch_recipes=[output]))
            async def aclose(self): pass
        return Agent()
    monkeypatch.setattr("fmst_analyzer.analysis.init_launch.launch_recipe_agent.create_analysis_agent", factory)
    monkeypatch.setattr(LaunchRecipeAgent, "_maybe_build_trace_handler", lambda *args: None)
    inputs = _inputs().model_copy(update={"stage": "init_launch"})
    target = TargetIdentity(target_basename="httpd", selected_rootfs_path="sbin/httpd")
    async def analyze():
        return await LaunchRecipeAgent(config).analyze(target, rootfs, ["etc/rcS"], phase="full")
    with analysis_input_scope(inputs), task_recovery_scope(config, {"attempt_path": str(tmp_path / "first")}):
        first = asyncio.run(analyze())
    config.resume_analyzer_tasks = True
    metadata = {"attempt_path": str(tmp_path / "recovery")}
    with analysis_input_scope(inputs), task_recovery_scope(config, metadata):
        recovered = asyncio.run(analyze())
    assert recovered == first and len(calls) == 1
    assert any(event["disposition"] == "reused_after_validation" for event in metadata["task_recovery"])
    assert next(iter(recovered.launch_recipes.values())).launch_site.text == "/sbin/httpd -D"
    # Even a matched envelope must pass fresh source validation.
    (rootfs / "etc/rcS").write_text("/sbin/httpd -E\n")
    metadata = {}
    with analysis_input_scope(inputs), task_recovery_scope(config, metadata):
        asyncio.run(analyze())
    assert len(calls) == 2
    assert any(event["disposition"] == "rejected_after_validation" for event in metadata["task_recovery"])
