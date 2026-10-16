"""Rejected locator repairs cannot silently erase behavioral conclusions."""
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_analyzer.analysis.init_launch.analyzer_schema import (
    InitLaunchAnalysisResult, LaunchRecipeAgentOutput, LaunchRecipeAnalysis, SourceSnippet, TargetIdentity,
)
from fmst_analyzer.analysis.init_launch.launch_recipe_agent import LaunchRecipeAgent


def _fixture(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin/httpd").write_bytes(b"synthetic target")
    (rootfs / "etc").mkdir()
    (rootfs / "etc/rcS").write_text("/sbin/httpd -D\n")
    source = SourceSnippet(path="etc/rcS", location="line 1", text="/sbin/httpd -D")
    draft = LaunchRecipeAnalysis(
        launch_site=source, context_anchor=source, applicability="Direct invocation at rcS entry.",
        executable_path="/sbin/httpd", command_template=["/sbin/httpd", "-D"], initialization_chain=[source],
        finding={"summary": "The script launches httpd with -D.",
            "claims": [{"kind": "guarantee", "statement": "The invocation supplies -D.", "unknown_kind": None, "evidence_refs": ["/launch_site"]}],
            "reachability_refs": ["/initialization_chain/0"], "coverage_refs": ["/launch_site"]},
    )
    wrong = SourceSnippet(path="etc/rcS", location="line 1", text="not in the script")
    invalid = draft.model_copy(update={"launch_site": wrong, "context_anchor": wrong, "initialization_chain": [wrong]})
    return rootfs, draft, invalid


def _run_agent(monkeypatch, rootfs, outputs):
    pending = iter(outputs)
    prompts = []
    class FakeAgent:
        async def ainvoke(self, prompt, **_):
            prompts.append(prompt)
            return SimpleNamespace(structured_response=next(pending))
        async def aclose(self):
            pass
    monkeypatch.setattr("fmst_analyzer.analysis.init_launch.launch_recipe_agent.create_analysis_agent", lambda **_: FakeAgent())
    agent = LaunchRecipeAgent(SimpleNamespace(diagnosis_model="test", agent_provider="test", workdir=None))
    invocation = agent.analyze(TargetIdentity(target_basename="httpd", selected_rootfs_path="sbin/httpd"), rootfs, ["etc/rcS"], phase="full")
    return agent, invocation, prompts


def test_locator_only_correction_preserves_claim_and_original_response(tmp_path, monkeypatch):
    rootfs, good, invalid = _fixture(tmp_path)
    agent, invocation, prompts = _run_agent(monkeypatch, rootfs, [
        LaunchRecipeAgentOutput(launch_recipes=[invalid]), LaunchRecipeAgentOutput(launch_recipes=[good]),
    ])
    result = asyncio.run(invocation)
    assert len(prompts) == 2
    assert len(result.correction_history) == 1
    assert result.correction_history[0].rejected_response["launch_recipes"][0]["launch_site"]["text"] == "not in the script"
    assert result.correction_history[0].revision_explanation is None
    assert next(iter(result.planning_findings.values())).claims[0].statement == "The invocation supplies -D."
    assert InitLaunchAnalysisResult.model_validate_json(result.model_dump_json()) == result


def test_repeated_omission_cannot_escape_revision_accounting(tmp_path, monkeypatch):
    rootfs, good, invalid = _fixture(tmp_path)
    reduced = good.model_copy(update={"finding": good.finding.model_copy(update={
        "claims": [good.finding.claims[0].model_copy(update={"kind": "unknown", "unknown_kind": "instance_data", "statement": "The device value is unknown."})],
        "reachability_refs": [], "coverage_refs": [],
    })})
    agent, invocation, prompts = _run_agent(monkeypatch, rootfs, [
        LaunchRecipeAgentOutput(launch_recipes=[invalid]), *[LaunchRecipeAgentOutput(launch_recipes=[reduced]) for _ in range(3)],
    ])
    asyncio.run(invocation)
    assert len(prompts) == 2 and len(agent.correction_history) == 1
    assert agent.correction_history[0].rejected_response["launch_recipes"][0]["finding"]["claims"][0]["kind"] == "guarantee"


def test_explained_withdrawal_retains_precise_semantic_and_applicability_gaps(tmp_path, monkeypatch):
    rootfs, good, invalid = _fixture(tmp_path)
    reduced = good.model_copy(update={"finding": good.finding.model_copy(update={
        "claims": [good.finding.claims[0].model_copy(update={"kind": "unknown", "unknown_kind": "instance_data", "statement": "Device configuration value is unknown."})],
        "reachability_refs": [], "coverage_refs": [],
    })})
    explanation = "Withdraw the unverified argv claim because its quoted source was absent; invocation effects and guards remain unestablished."
    _, invocation, _ = _run_agent(monkeypatch, rootfs, [
        LaunchRecipeAgentOutput(launch_recipes=[invalid]),
        LaunchRecipeAgentOutput(launch_recipes=[reduced], revision_explanation=explanation),
    ])
    result = asyncio.run(invocation)
    assert result.correction_history[0].revision_explanation == explanation
    assert result.analysis_gaps == []
    assert all(gap.source.position_key() == good.context_anchor.position_key() for gap in result.analysis_gaps)
    data = result.model_dump(mode="json")
    data["analysis_gaps"] = []
    InitLaunchAnalysisResult.model_validate(data)


def test_omitting_one_context_with_identical_claim_text_requires_explanation(tmp_path, monkeypatch):
    rootfs, good, _ = _fixture(tmp_path)
    (rootfs / "etc/rcS").write_text(
        "start_httpd() {\n/sbin/httpd -D\n}\n"
        "if lan_enabled; then start_httpd; fi\n"
        "if wan_enabled; then start_httpd; fi\n"
    )
    launch = good.launch_site.model_copy(update={"location": "line 2"})
    recipes = []
    for name, line in (("lan", 4), ("wan", 5)):
        anchor = SourceSnippet(path="etc/rcS", location=f"line {line}",
                               text=f"if {name}_enabled; then start_httpd; fi")
        recipes.append(good.model_copy(update={"launch_site": launch, "context_anchor": anchor,
            "applicability": f"Only when {name}_enabled is true.", "initialization_chain": [anchor, launch]}))
    invalid = recipes[1].model_copy(update={"context_anchor": recipes[1].context_anchor.model_copy(
        update={"text": "not in the script"})})
    reduced = LaunchRecipeAgentOutput(launch_recipes=[recipes[0]])
    agent, invocation, prompts = _run_agent(monkeypatch, rootfs, [
        LaunchRecipeAgentOutput(launch_recipes=[recipes[0], invalid]), reduced, reduced, reduced,
    ])
    asyncio.run(invocation)
    assert len(prompts) == 2 and len(agent.correction_history) == 1


def test_changing_claim_applicability_requires_explanation(tmp_path, monkeypatch):
    rootfs, good, invalid = _fixture(tmp_path)
    conditional = invalid.model_copy(update={"applicability": "Only when LAN is enabled."})
    corrected = LaunchRecipeAgentOutput(launch_recipes=[good])
    _, invocation, _ = _run_agent(monkeypatch, rootfs, [
        LaunchRecipeAgentOutput(launch_recipes=[conditional]), corrected, corrected, corrected,
    ])
    asyncio.run(invocation)
