"""Tool evidence handles reduce transcription while preserving source identity."""
import json
import pytest

from fmst_analyzer.analysis.init_launch.analyzer_schema import LaunchRecipeAgentOutput, LaunchRecipeAnalysis, TargetIdentity
from fmst_analyzer.analysis.init_launch.controller import finalise_agent_output
from fmst_analyzer.analysis.init_launch.source_evidence import SourceEvidence, make_source_tool


def _case(tmp_path):
    rootfs = tmp_path / "rootfs"
    (rootfs / "sbin").mkdir(parents=True)
    (rootfs / "sbin/httpd").write_bytes(b"portable target fixture")
    script = rootfs / "etc/rcS"
    script.parent.mkdir()
    script.write_text("\t/sbin/httpd\t-D\n")
    sources = SourceEvidence()
    tool = make_source_tool(rootfs, sources)
    returned = tool.invoke({"path": "etc/rcS", "start_line": 1, "end_line": 1})
    reference = returned["source_snippet"]
    draft = LaunchRecipeAnalysis(launch_site=reference, context_anchor=reference,
        applicability="Direct initialization invocation.", executable_path="/sbin/httpd",
        command_template=["/sbin/httpd", "-D"], initialization_chain=[reference],
        finding=dict(summary="Script invokes httpd with -D.", claims=[dict(kind="guarantee",
            statement="Invocation supplies -D.", evidence_refs=["/launch_site"], unknown_kind=None)],
            reachability_refs=["/launch_site"], coverage_refs=[]))
    return rootfs, script, sources, LaunchRecipeAgentOutput(launch_recipes=[draft]), returned


def test_source_reference_preserves_tabs_and_claim_binding(tmp_path):
    rootfs, script, sources, output, returned = _case(tmp_path)
    assert returned["content"] == "\t/sbin/httpd\t-D"
    expanded = sources.materialize(output)
    result = finalise_agent_output(rootfs, TargetIdentity(target_basename="httpd", selected_rootfs_path="sbin/httpd"), expanded)
    recipe = next(iter(result.launch_recipes.values()))
    assert recipe.launch_site.text == returned["content"]
    assert "@source:" not in result.model_dump_json()
    assert next(iter(result.planning_findings.values())).claims[0].statement == "Invocation supplies -D."


def test_source_reference_cannot_move_to_another_location(tmp_path):
    rootfs, script, sources, output, returned = _case(tmp_path)
    draft = output.launch_recipes[0]
    wrong = draft.launch_site.model_copy(update={"location": "line 2"})
    changed = output.model_copy(update={"launch_recipes": [draft.model_copy(update={
        "launch_site": wrong, "context_anchor": wrong, "initialization_chain": [wrong]})]})
    with pytest.raises(ValueError, match="different path or location"):
        sources.materialize(changed)
    with pytest.raises(ValueError, match="Unknown source"):
        SourceEvidence().materialize(output)


def test_source_is_rechecked_after_tool_read(tmp_path):
    rootfs, script, sources, output, returned = _case(tmp_path)
    script.write_text("/sbin/httpd -W\n")
    with pytest.raises(ValueError, match="excerpt"):
        finalise_agent_output(rootfs, TargetIdentity(target_basename="httpd", selected_rootfs_path="sbin/httpd"), sources.materialize(output))


def test_source_correction_reports_all_locations_and_exact_range_choices(tmp_path):
    _, _, sources, output, returned = _case(tmp_path)
    other_range = sources.reference(dict(path="etc/rcS", location="line 1",
        text="\t/sbin/httpd\t-D\nother preparation"))
    draft = output.launch_recipes[0]
    unknown = draft.launch_site.model_copy(update={"text": "@source:corrupted"})
    wrong_location = draft.launch_site.model_copy(update={"location": "line 7"})
    changed = output.model_copy(update={"launch_recipes": [draft.model_copy(update={
        "launch_site": unknown, "context_anchor": unknown,
        "initialization_chain": [wrong_location]})]})
    before = changed.model_dump_json()
    with pytest.raises(ValueError) as caught:
        sources.materialize(changed)
    problems = json.loads(str(caught.value).split("\n", 1)[1])
    assert len(problems) == 2
    unknown_error, wrong_error = problems
    assert unknown_error["output_paths"] == [
        "/launch_recipes/0/launch_site/text", "/launch_recipes/0/context_anchor/text"]
    choices = unknown_error["available_sources"]
    assert {item["source_snippet"]["text"] for item in choices} == {
        returned["source_snippet"]["text"], other_range["text"]}
    assert {item["content"] for item in choices} == {
        returned["content"], "\t/sbin/httpd\t-D\nother preparation"}
    assert wrong_error["output_paths"] == ["/launch_recipes/0/initialization_chain/0/text"]
    assert wrong_error["bound_source"]["content"] == returned["content"]
    assert wrong_error["available_sources"] == []
    assert changed.model_dump_json() == before


def test_source_handle_collision_cannot_replace_registered_evidence(tmp_path, monkeypatch):
    import fmst_analyzer.analysis.init_launch.source_evidence as module
    _, _, sources, output, returned = _case(tmp_path)
    token = returned["source_snippet"]["text"].removeprefix("@source:")

    class SameHandleDigest:
        def hexdigest(self):
            return token + "0" * (64 - len(token))

    monkeypatch.setattr(module.hashlib, "sha256", lambda _: SameHandleDigest())
    with pytest.raises(ValueError, match="collision"):
        sources.reference(dict(path="etc/rcS", location="line 1", text="different source"))
    assert sources.materialize(output).launch_recipes[0].launch_site.text == returned["content"]
