"""Framework documentation selected by the production Runner session."""
from pathlib import Path

import pytest

from fmst_analyzer.runner import agent as runner_agent
from fmst_analyzer.framework import guestweave_skill, runtime_workspace
from fmst_basic.agent.codex_agent import _permission_profile_config


def test_implicit_framework_uses_the_configured_checkout(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from fmst_analyzer.framework import runtime_workspace
    selected = tmp_path / "selected"
    selected.mkdir()
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    monkeypatch.setenv("FMST_GUESTWEAVE_WORKSPACE", str(selected))
    assert runtime_workspace() == selected
    assert runtime_workspace(SimpleNamespace(runtime_workspace=explicit)) == explicit


def test_framework_skill_uses_public_read_roots_without_application_or_build_outputs():
    framework = runtime_workspace()
    skill = guestweave_skill(framework)
    skill.validate_current()
    assert skill.skill_file == framework / "skills/intervention-engineering/SKILL.md"
    profile = _permission_profile_config("write", [skill])
    filesystem = profile["permissions"][profile["default_permissions"]]["filesystem"]
    for root in skill.reference_roots:
        assert filesystem[str(root)] == ("read" if root.is_file() else {".": "read"})
        assert root != framework and root.parent != framework.parent
        assert not (framework / "target").is_relative_to(root)
        assert not (framework / "tmp").is_relative_to(root)


def test_public_root_document_is_readable_without_granting_its_siblings(tmp_path):
    import pytest
    framework = tmp_path / "framework"
    skill_dir = framework / "skills/intervention-engineering"
    skill_dir.mkdir(parents=True)
    docs = framework / "docs"
    docs.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: guestweave-intervention-engineering\ndescription: Public library.\n---\n"
        "[Build](../../docs/build.md)\n")
    (docs / "build.md").write_text("[Provenance](../THIRD_PARTY.md)\n")
    provenance = framework / "THIRD_PARTY.md"
    provenance.write_text("Public source provenance.\n")
    (framework / "private.md").write_text("Unrelated private file.\n")
    skill = guestweave_skill(framework)
    assert provenance in skill.source_files
    profile = _permission_profile_config("write", [skill])
    permissions = profile["permissions"][profile["default_permissions"]]["filesystem"]
    assert permissions[str(provenance)] == "read"
    assert str(framework) not in permissions
    provenance.write_text("[Private](private.md)\n")
    with pytest.raises(ValueError, match="escapes declared read roots"):
        skill.validate_current()


@pytest.mark.parametrize("explicit_checkout", [True, False])
def test_runner_attaches_the_selected_framework_and_retains_writable_scope(tmp_path, monkeypatch, explicit_checkout):
    framework = tmp_path / "selected-framework"
    directory = framework / "skills/intervention-engineering"
    directory.mkdir(parents=True)
    (directory / "SKILL.md").write_text(
        "---\nname: guestweave-intervention-engineering\n"
        "description: Selected framework documentation.\n---\nAPI guide.\n"
    )
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    captured = {}
    monkeypatch.setattr(runner_agent, "make_analyzer_tools", lambda view: [])
    monkeypatch.setattr(runner_agent, "make_runner_tools", lambda **kwargs: [])
    monkeypatch.setattr(runner_agent, "create_analysis_agent", lambda **kwargs: captured.update(kwargs))
    monkeypatch.setenv("FMST_GUESTWEAVE_WORKSPACE", str(framework))
    runner_agent.RunnerAgentSession(view=object(), rootfs=tmp_path,
        diagnostic_reports_root=tmp_path, intervention_root=workspace,
        trace_path=tmp_path / "trace.md", evidence_state=runner_agent.RuntimeEvidenceState(),
        writable_roots=[workspace],
        **({"runtime_workspace": framework} if explicit_checkout else {}))
    assert [skill.name for skill in captured["skills"]] == ["guestweave-intervention-engineering"]
    assert captured["skills"][0].skill_file == directory / "SKILL.md"
    from fmst_analyzer.synthesizer.intervention_skill import APPLICATION_CONTRACT, APPLICATION_REFERENCES
    assert str(APPLICATION_CONTRACT) in captured["developer_instructions"]
    assert str(APPLICATION_REFERENCES / "runtime-refinement.md") in captured["developer_instructions"]
    assert captured["writable_roots"] == [workspace]


def test_new_context_reads_updated_skill_references_and_old_context_rejects_drift(tmp_path):
    framework = tmp_path / "framework"
    directory = framework / "skills/intervention-engineering"
    directory.mkdir(parents=True)
    docs = framework / "docs"
    docs.mkdir()
    (directory / "SKILL.md").write_text(
        "---\nname: guestweave-intervention-engineering\ndescription: Current API.\n---\n"
        "[API](../../docs/api.md)\n")
    reference = docs / "api.md"
    reference.write_text("Original API documentation.\n")
    previous = guestweave_skill(framework)
    previous.validate_current()
    reference.write_text("Updated API documentation.\n")
    current = guestweave_skill(framework)
    current.validate_current()
    assert previous.content_sha256 != current.content_sha256
    with pytest.raises(ValueError, match="Agent Skill content changed"):
        previous.validate_current()
