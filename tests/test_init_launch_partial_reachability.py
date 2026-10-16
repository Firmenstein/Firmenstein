"""Known launch behavior survives an unresolved initialization callback edge."""
import pytest

from fmst_analyzer.analysis.init_launch.analyzer_schema import (
    AnalysisGap, InitLaunchAnalysisResult, LaunchRecipeAgentOutput,
    LaunchRecipeAnalysis, SourceSnippet, TargetIdentity,
)
from fmst_analyzer.analysis.init_launch.controller import finalise_agent_output
from fmst_analyzer.analysis.init_launch.reports import render_index


def _inputs(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin/server").write_bytes(b"synthetic target; never executed")
    (rootfs / "etc").mkdir()
    (rootfs / "etc/rcS").write_text("/etc/service_manager.sh &\n")
    (rootfs / "etc/service_manager.sh").write_text(
        "start_service() {\n"
        'if [ "$mode" = "serve" ]; then\n'
        "mkdir -p /run/server\n"
        "/sbin/server -c /etc/server.conf\n"
        "fi\n}\n"
    )
    entry = SourceSnippet(path="etc/rcS", location="line 1", text="/etc/service_manager.sh &")
    context = SourceSnippet(path="etc/service_manager.sh", location="line 2",
                            text='if [ "$mode" = "serve" ]; then')
    launch = SourceSnippet(path=context.path, location="line 4", text="/sbin/server -c /etc/server.conf")
    preparation = SourceSnippet(path=context.path, location="line 3", text="mkdir -p /run/server")
    applicability = "If start_service is called with mode=serve. No evidence establishes that initialization calls this function."
    draft = LaunchRecipeAnalysis(
        launch_site=launch, context_anchor=context, applicability=applicability,
        executable_path="/sbin/server", command_template=["/sbin/server", "-c", "/etc/server.conf"],
        initialization_chain=[entry, context, launch], preparation_actions=[preparation],
        finding=dict(
            summary="The conditional callback prepares and invokes server; initialization reachability is unresolved.",
            claims=[
                dict(kind="guarantee", statement="In the mode=serve callback, mkdir is attempted before the server command; success is unchecked.",
                     evidence_refs=["/context_anchor", "/preparation_actions/0", "/launch_site"], unknown_kind=None),
                dict(kind="unknown", statement=applicability, evidence_refs=["/context_anchor"], unknown_kind="applicability"),
            ],
            reachability_refs=[], coverage_refs=["/launch_site"],
        ),
    )
    output = LaunchRecipeAgentOutput(launch_recipes=[draft], analysis_gaps=[
        AnalysisGap(kind="applicability", source=context, reason=applicability),
    ])
    identity = TargetIdentity(target_basename="server", selected_rootfs_path="sbin/server")
    return rootfs, identity, output


def test_partial_initialization_keeps_known_command_preparation_and_gap(tmp_path):
    rootfs, identity, output = _inputs(tmp_path)
    result = finalise_agent_output(rootfs, identity, output)
    assert InitLaunchAnalysisResult.model_validate_json(result.model_dump_json()) == result
    recipe = next(iter(result.launch_recipes.values()))
    draft = output.launch_recipes[0]
    assert recipe.command_template == draft.command_template
    assert recipe.preparation_actions == draft.preparation_actions
    assert recipe.initialization_chain == draft.initialization_chain
    assert recipe.applicability == draft.applicability
    finding = next(iter(result.planning_findings.values()))
    assert not finding.boundary.reachability_refs
    assert [claim.statement for claim in finding.claims] == [claim.statement for claim in draft.finding.claims]
    assert output.analysis_gaps[0] in result.analysis_gaps

    markdown = render_index(result)
    assert "complete firmware initialization chain" not in markdown
    assert draft.applicability in markdown
    assert draft.launch_site.text in markdown
    assert draft.preparation_actions[0].text in markdown


def test_partial_initialization_cannot_lose_its_gap_on_reload(tmp_path):
    rootfs, identity, output = _inputs(tmp_path)
    data = finalise_agent_output(rootfs, identity, output).model_dump(mode="json")
    data["analysis_gaps"] = []
    InitLaunchAnalysisResult.model_validate(data)


@pytest.mark.parametrize("invalid", ["no_initialization_entry", "invented_source"])
def test_gap_does_not_relax_source_validation(tmp_path, invalid):
    rootfs, identity, output = _inputs(tmp_path)
    draft = output.launch_recipes[0]
    if invalid == "no_initialization_entry":
        draft.initialization_chain = draft.initialization_chain[1:]
        result = finalise_agent_output(rootfs, identity, output)
        assert next(iter(result.launch_recipes.values())).initialization_chain == draft.initialization_chain
        return
    else:
        draft.preparation_actions[0].text = "touch /invented"
        message = "source|text|excerpt"
    with pytest.raises(ValueError, match=message):
        finalise_agent_output(rootfs, identity, output)


def test_catalog_preserves_partial_recipe_and_precise_gap(tmp_path):
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import PlanningEvidenceAssembler
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.evidence import FindingEvidenceResolver
    from fmst_analyzer.synthesizer.intervention_plan_analyzer.tests.test_catalog import _init_result, _write_sources

    source = _init_result()
    recipe = next(iter(source.launch_recipes.values()))
    finding = next(iter(source.planning_findings.values()))
    finding.boundary.reachability_refs = []
    recipe.applicability = "Local command and preparation are known; the initialization callback edge is unresolved."
    gap = AnalysisGap(kind="applicability", source=recipe.context_anchor, reason=recipe.applicability)
    source.analysis_gaps = [gap]
    source = InitLaunchAnalysisResult.model_validate_json(source.model_dump_json())
    _write_sources(tmp_path, init_launch=source)
    catalog = PlanningEvidenceAssembler(tmp_path).run()
    assert catalog.launch_candidates == source.launch_recipes
    assert any(gap.reason in item.reasons for item in catalog.gaps.values())
    resolved = FindingEvidenceResolver(tmp_path, catalog).finding_evidence(finding.finding_ref)
    assert resolved["finding"] == finding.model_dump(mode="json")
    assert resolved["records"][f"/launch_recipes/{recipe.recipe_id}"] == recipe.model_dump(mode="json")
