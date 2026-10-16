"""Launch identity distinguishes invocation context without hashing all evidence."""
from pathlib import Path

import pytest

from fmst_analyzer.analysis.init_launch.analyzer_schema import (
    LaunchRecipeAnalysis, LaunchRecipeAgentOutput, SourceSnippet, TargetIdentity,
)
from fmst_analyzer.analysis.init_launch.controller import finalise_agent_output


def _inputs(tmp_path: Path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin/httpd").write_bytes(b"target fixture, never executed")
    (rootfs / "etc/init.d").mkdir(parents=True)
    (rootfs / "etc/init.d/rcS").write_text(
        "load_config\nstart_httpd() {\n/sbin/httpd -f /etc/httpd.conf\n}\n"
        "if lan_enabled; then start_httpd lan; fi\n"
        "if bridge_enabled; then start_httpd bridge; fi\n"
        "if wan_enabled; then start_httpd wan; fi\n"
    )
    identity = TargetIdentity(target_basename="httpd", selected_rootfs_path="sbin/httpd")
    launch = SourceSnippet(path="etc/init.d/rcS", location="line 3",
                           text="/sbin/httpd -f /etc/httpd.conf")
    return rootfs, identity, launch


def _recipe(launch, name, line):
    context = SourceSnippet(path="etc/init.d/rcS", location=f"line {line}",
                            text=f"if {name}_enabled; then start_httpd {name}; fi")
    return LaunchRecipeAnalysis(
        launch_site=launch, context_anchor=context,
        applicability=f"The {name} configuration is enabled.",
        executable_path="/sbin/httpd", command_template=["/sbin/httpd", "-f", "/etc/httpd.conf"],
        initialization_chain=[context, launch], preparation_actions=[],
        finding=dict(summary=f"The {name} configuration prepares the target invocation.",
                     claims=[dict(kind="guarantee", statement=f"The target is invoked when {name}_enabled is true.",
                                  unknown_kind=None, evidence_refs=["/context_anchor"])],
                     reachability_refs=["/context_anchor"], coverage_refs=[]),
    )


def test_three_contexts_survive_identical_launch_site_and_arguments(tmp_path):
    rootfs, identity, launch = _inputs(tmp_path)
    drafts = [_recipe(launch, name, line) for name, line in (("lan", 5), ("bridge", 6), ("wan", 7))]
    forward = finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=drafts))
    reverse = finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=list(reversed(drafts))))
    assert forward == reverse
    assert len(forward.launch_recipes) == 3
    assert {recipe.applicability for recipe in forward.launch_recipes.values()} == {
        f"The {name} configuration is enabled." for name in ("lan", "bridge", "wan")
    }
    assert len(forward.planning_findings) == 3


def test_adding_evidence_preserves_context_identity_and_claim_target(tmp_path):
    rootfs, identity, launch = _inputs(tmp_path)
    draft = _recipe(launch, "lan", 5)
    first = finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=[draft]))
    extra = SourceSnippet(path="etc/init.d/rcS", location="line 1", text="load_config")
    enriched = draft.model_copy(update={"initialization_chain": [extra, *draft.initialization_chain]})
    second = finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=[enriched]))
    assert first.launch_recipes.keys() == second.launch_recipes.keys()
    assert first.planning_findings == second.planning_findings
    assert next(iter(second.launch_recipes.values())).initialization_chain[0] == extra


def test_differing_records_for_one_context_cannot_silently_select_a_winner(tmp_path):
    rootfs, identity, launch = _inputs(tmp_path)
    draft = _recipe(launch, "lan", 5)
    changed = draft.model_copy(update={"applicability": "The LAN configuration is disabled."})
    result = finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=[draft, changed]))
    assert {r.applicability for r in result.launch_recipes.values()} == {draft.applicability, changed.applicability}
    assert type(result).model_validate_json(result.model_dump_json()) == result


def test_context_must_belong_to_the_verified_initialization_chain(tmp_path):
    rootfs, identity, launch = _inputs(tmp_path)
    draft = _recipe(launch, "lan", 5).model_copy(update={
        "context_anchor": SourceSnippet(path="etc/init.d/rcS", location="line 1", text="load_config"),
    })
    with pytest.raises(ValueError, match="context_anchor.*initialization_chain"):
        finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=[draft]))


def test_persisted_context_cannot_escape_chain_but_accepts_same_source_spelling(tmp_path):
    rootfs, identity, launch = _inputs(tmp_path)
    result = finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=[_recipe(launch, "lan", 5)]))
    data = result.model_dump(mode="json")
    recipe = next(iter(data["launch_recipes"].values()))
    recipe["context_anchor"]["location"] = "L5"
    assert type(result).model_validate(data).launch_recipes
    recipe["context_anchor"]["location"] = "line 99"
    with pytest.raises(ValueError, match="context_anchor.*initialization_chain"):
        type(result).model_validate(data)


def test_repeated_dispatcher_source_is_not_mistaken_for_a_runtime_cycle(tmp_path):
    rootfs, identity, launch = _inputs(tmp_path)
    dispatcher = SourceSnippet(path="etc/init.d/rcS", location="line 2", text="start_httpd() {")
    draft = _recipe(launch, "lan", 5)
    draft = draft.model_copy(update={"initialization_chain": [
        draft.context_anchor, dispatcher, draft.context_anchor, dispatcher, launch]})
    result = finalise_agent_output(rootfs, identity, LaunchRecipeAgentOutput(launch_recipes=[draft]))
    recipe = next(iter(result.launch_recipes.values()))
    assert recipe.initialization_chain == draft.initialization_chain
