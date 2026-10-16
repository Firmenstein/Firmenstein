"""Agent Skill bundle and provider-adapter boundaries."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest

from fmst_analyzer.synthesizer.intervention_skill import (
    REHOSTING_PLANNING_SKILL,
)

from fmst_basic.agent.claude_agent import (
    ClaudeAnalysisAgent,
    _make_filesystem_guard,
)
from fmst_basic.agent.codex_agent import (
    CodexAnalysisAgent,
    _permission_profile_config,
    codex_turn_input,
)
from fmst_basic.agent.skill import AgentSkillSpec


def _copy_skill(tmp_path: Path) -> tuple[Path, Path]:
    plugin_root = tmp_path / "bundle"
    shutil.copytree(REHOSTING_PLANNING_SKILL.plugin_root, plugin_root)
    return plugin_root, plugin_root / "skills" / "rehosting-planning"


def test_intervention_skill_is_one_valid_provider_neutral_bundle():
    skill = REHOSTING_PLANNING_SKILL
    assert skill.name == "rehosting-planning"
    assert skill.claude_qualified_name == (
        "fmst-intervention:rehosting-planning"
    )
    assert skill.skill_file.is_file()
    assert skill.trace_identity()["name"] == "rehosting-planning"
    assert len(skill.trace_identity()["content_sha256"]) == 64
    assert skill.trace_identity()["path"] == str(skill.skill_file)


def test_skill_revalidation_rejects_changed_reference_content(tmp_path):
    plugin_root, skill_dir = _copy_skill(tmp_path)
    copied = AgentSkillSpec(
        name="rehosting-planning",
        plugin_root=plugin_root,
        skill_dir=skill_dir,
    )
    reference = skill_dir / "references" / "planning.md"
    reference.write_text(reference.read_text() + "\nnew rule\n")
    with pytest.raises(ValueError, match="content changed"):
        copied.validate_current()


def test_invalid_skill_fails_before_provider_construction(tmp_path):
    plugin_root, skill_dir = _copy_skill(tmp_path)
    manifest = plugin_root / ".claude-plugin" / "plugin.json"
    payload = json.loads(manifest.read_text())
    payload["name"] = "Invalid Name"
    manifest.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="plugin name"):
        AgentSkillSpec(
            name="rehosting-planning",
            plugin_root=plugin_root,
            skill_dir=skill_dir,
        )


def test_skill_revalidation_rejects_plugin_identity_drift(tmp_path):
    plugin_root, skill_dir = _copy_skill(tmp_path)
    copied = AgentSkillSpec(
        name="rehosting-planning",
        plugin_root=plugin_root,
        skill_dir=skill_dir,
    )
    manifest = plugin_root / ".claude-plugin" / "plugin.json"
    payload = json.loads(manifest.read_text())
    payload["name"] = "renamed-plugin"
    manifest.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="plugin identity changed"):
        copied.validate_current()


def test_missing_nested_reference_fails_before_provider_construction(tmp_path):
    plugin_root, skill_dir = _copy_skill(tmp_path)
    reference = skill_dir / "references" / "planning.md"
    reference.write_text(
        reference.read_text() + "\n[missing](not-present.md)\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reference is missing"):
        AgentSkillSpec(
            name="rehosting-planning",
            plugin_root=plugin_root,
            skill_dir=skill_dir,
        )


def test_codex_turn_explicitly_attaches_skill_without_global_roots():
    skill = REHOSTING_PLANNING_SKILL
    items = codex_turn_input("task", [skill])
    assert items == [
        {
            "type": "text",
            "text": "$rehosting-planning\n\ntask",
        },
        {
            "type": "skill",
            "name": skill.name,
            "path": str(skill.skill_file),
        },
    ]
    profile = _permission_profile_config("none", [skill])
    permissions = profile["permissions"][profile["default_permissions"]]
    assert permissions["filesystem"][str(skill.skill_dir)] == "read"
    assert "extraRoots" not in json.dumps(profile)
    assert codex_turn_input("task", []) == [{"type": "text", "text": "task"}]


def test_codex_additional_root_is_read_only(tmp_path):
    root = tmp_path / "decompiled"
    root.mkdir()

    for access in ("read_shell", "write"):
        profile = _permission_profile_config(access, [], [root])
        permissions = profile["permissions"][profile["default_permissions"]]

        assert permissions["filesystem"][str(root.resolve())] == {".": "read"}


def _standalone_skill(tmp_path):
    skill_dir = tmp_path / "skills" / "library-guide"
    docs = tmp_path / "docs"
    skill_dir.mkdir(parents=True)
    docs.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: library-guide\ndescription: Use the local library API.\n---\n"
        "[API](../../docs/api.md)\n"
    )
    (docs / "api.md").write_text("[details](details.md)\n")
    (docs / "details.md").write_text("Public semantics.\n")
    return skill_dir, docs


def test_standalone_skill_attaches_original_files_with_read_only_references(tmp_path):
    skill_dir, docs = _standalone_skill(tmp_path)
    skill = AgentSkillSpec(name="library-guide", skill_dir=skill_dir, reference_roots=(docs,))
    assert skill.plugin_root is None and skill.claude_qualified_name is None
    assert codex_turn_input("task", [skill])[1]["path"] == str(skill_dir / "SKILL.md")
    profile = _permission_profile_config("write", [skill])
    filesystem = profile["permissions"][profile["default_permissions"]]["filesystem"]
    assert filesystem[str(docs)] == {".": "read"}
    assert str(tmp_path) not in filesystem
    # A link in the referenced document is also checked, before dispatch.
    (docs / "details.md").unlink()
    with pytest.raises(ValueError, match="reference is missing"):
        skill.validate_current()


def test_standalone_skill_cannot_expand_declared_reference_roots(tmp_path):
    skill_dir, docs = _standalone_skill(tmp_path)
    with pytest.raises(ValueError, match="escapes declared read roots"):
        AgentSkillSpec(name="library-guide", skill_dir=skill_dir)
    (tmp_path / "private.md").write_text("Private application data.\n")
    (docs / "details.md").write_text("[outside](../private.md)\n")
    with pytest.raises(ValueError, match="escapes declared read roots"):
        AgentSkillSpec(name="library-guide", skill_dir=skill_dir, reference_roots=(docs,))


def test_standalone_skill_rejects_symlink_outside_read_roots(tmp_path):
    skill_dir, docs = _standalone_skill(tmp_path)
    outside = tmp_path / "private.md"
    outside.write_text("Private application data.\n")
    (docs / "details.md").unlink()
    (docs / "details.md").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes declared read roots"):
        AgentSkillSpec(name="library-guide", skill_dir=skill_dir, reference_roots=(docs,))


def test_claude_plain_skill_uses_native_plugin_and_live_read_only_references(tmp_path, monkeypatch):
    from claude_agent_sdk import ResultMessage
    from fmst_basic.agent import claude_agent

    skill_dir, docs = _standalone_skill(tmp_path)
    # Source directory and frontmatter names need not match for a plain Skill.
    renamed = skill_dir.with_name("library-source")
    skill_dir.rename(renamed)
    skill = AgentSkillSpec(name="library-guide", skill_dir=renamed,
                          reference_roots=(docs, docs / "api.md"))
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-key")
    work = tmp_path / "work"
    work.mkdir()
    prompts = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def connect(self):
            pass

        async def query(self, prompt):
            prompts.append(prompt)

        async def receive_response(self):
            yield ResultMessage(subtype="success", duration_ms=1, duration_api_ms=1,
                is_error=False, num_turns=1, session_id="session", result="done")

        async def disconnect(self):
            pass

    monkeypatch.setattr(claude_agent, "ClaudeSDKClient", Client)
    agent = ClaudeAnalysisAgent(model="test", developer_instructions="stable policy",
        workdir=work, filesystem_access="write", writable_roots=[work], skills=[skill])

    async def run():
        try:
            assert agent._options.skills == ["fmst-task:library-guide"]
            assert "Skill" in agent._options.tools
            assert agent._options.setting_sources == []
            wrapper = Path(agent._options.plugins[0]["path"])
            manifest = json.loads((wrapper / ".claude-plugin/plugin.json").read_text())
            entry = wrapper / manifest["skills"][0]
            assert (entry / "SKILL.md").resolve() == skill.skill_file
            # Resolve links both lexically (CLI) and through the filesystem.
            import os
            reference = entry / "../../docs/api.md"
            lexical = Path(os.path.normpath(reference))
            assert lexical.resolve() == reference.resolve() == docs / "api.md"
            assert lexical.read_text() == "[details](details.md)\n"
            assert not (wrapper / "sources/library-guide/work").exists()
            original = (docs / "api.md").read_text()
            (docs / "api.md").write_text("Live working-copy revision.\n")
            assert reference.read_text() == lexical.read_text() == "Live working-copy revision.\n"
            (docs / "api.md").write_text(original)
            assert agent._options.system_prompt["append"] == "stable policy"
            assert docs in agent._options.add_dirs
            first = await agent.ainvoke("first task")
            await agent.ainvoke("follow-up")
            assert first.skills == [skill.trace_identity()]
            assert prompts == ["first task", "follow-up"]
            read = await agent._filesystem_guard({"tool_name": "Read",
                "tool_input": {"file_path": str(lexical)}}, None, None)
            write = await agent._filesystem_guard({"tool_name": "Write",
                "tool_input": {"file_path": str(lexical)}}, None, None)
            assert read == {}
            assert write["hookSpecificOutput"]["permissionDecision"] == "deny"
        finally:
            await agent.aclose()
        assert wrapper.exists()  # Native Skill references remain usable on resume.
        assert skill.skill_file.is_file() and (docs / "api.md").is_file()

    asyncio.run(run())


def test_claude_mixes_native_and_standalone_skills_without_copying_sources(tmp_path, monkeypatch):
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-key")
    source = tmp_path / "entry"
    source.mkdir()
    (source / "SKILL.md").write_text("---\nname: self-contained\ndescription: A fixture.\n---\nUse the fixture.\n")
    standalone = AgentSkillSpec(name="self-contained", skill_dir=source)
    agent = ClaudeAnalysisAgent(model="test", developer_instructions="",
        workdir=tmp_path, filesystem_access="read_shell",
        skills=[REHOSTING_PLANNING_SKILL, standalone])
    try:
        assert agent._options.skills == [REHOSTING_PLANNING_SKILL.claude_qualified_name,
                                        "fmst-task:self-contained"]
        assert agent._options.plugins[0]["path"] == str(REHOSTING_PLANNING_SKILL.plugin_root)
        wrapper = Path(agent._options.plugins[1]["path"])
        manifest = json.loads((wrapper / ".claude-plugin/plugin.json").read_text())
        assert (wrapper / manifest["skills"][0] / "SKILL.md").resolve() == standalone.skill_file
        assert wrapper in agent._options.add_dirs
        assert str(wrapper) in agent._options.settings
    finally:
        asyncio.run(agent.aclose())


def test_codex_additional_root_treats_glob_characters_as_literal(tmp_path):
    root = tmp_path / "firmware[release]" / "decompiled"
    root.mkdir(parents=True)

    profile = _permission_profile_config("read_shell", [], [root])
    filesystem = profile["permissions"][profile["default_permissions"]][
        "filesystem"
    ]

    assert filesystem[str(root.resolve())] == {".": "read"}


def test_codex_writable_directory_does_not_expand_read_only_context(tmp_path):
    context = tmp_path / "decompiled"
    test_dir = tmp_path / "tests" / "unit_test"
    context.mkdir()
    test_dir.mkdir(parents=True)

    profile = _permission_profile_config(
        "write", [], [context], [test_dir]
    )
    permissions = profile["permissions"][profile["default_permissions"]]

    assert permissions["filesystem"][str(context.resolve())] == {".": "read"}
    assert permissions["filesystem"][str(test_dir.resolve())] == {".": "write"}
    assert str(test_dir.parent.resolve()) not in permissions["filesystem"]


def test_writable_roots_reject_files_before_provider_start(monkeypatch, tmp_path):
    test_file = tmp_path / "main.rs"
    test_file.touch()
    with pytest.raises(ValueError, match="existing directories"):
        CodexAnalysisAgent(
            model="gpt-5.6-terra",
            developer_instructions="task",
            workdir=tmp_path,
            filesystem_access="write",
            writable_roots=[test_file],
        )

    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-key")
    with pytest.raises(ValueError, match="existing directories"):
        ClaudeAnalysisAgent(
            model="deepseek-flash[1m]",
            developer_instructions="task",
            workdir=tmp_path,
            filesystem_access="write",
            writable_roots=[test_file],
        )


def test_claude_uses_exact_plugin_skill_and_no_settings_sources(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("FMST_CLAUDE_AUTH_TOKEN", "test-key")
    agent = ClaudeAnalysisAgent(
        model="deepseek-flash[1m]",
        developer_instructions="task",
        workdir=tmp_path,
        filesystem_access="write",
        skills=[REHOSTING_PLANNING_SKILL],
    )
    try:
        assert agent._options.setting_sources == []
        assert agent._options.plugins == [{
            "type": "local",
            "path": str(REHOSTING_PLANNING_SKILL.plugin_root),
        }]
        assert agent._options.skills == [
            REHOSTING_PLANNING_SKILL.claude_qualified_name
        ]
        assert agent._options.tools == [
            "Read", "Write", "Edit", "Glob", "Grep", "Skill",
        ]
        assert "Skill" not in agent._options.allowed_tools
    finally:
        asyncio.run(agent.aclose())

    plain = ClaudeAnalysisAgent(
        model="deepseek-flash[1m]",
        developer_instructions="task",
    )
    try:
        assert plain._options.plugins == []
        assert plain._options.skills == []
        assert plain._options.tools == []
    finally:
        asyncio.run(plain.aclose())


def test_claude_file_guard_makes_skill_read_only(tmp_path):
    workdir = tmp_path / "work"
    workdir.mkdir()
    skill_dir = REHOSTING_PLANNING_SKILL.skill_dir
    guard = _make_filesystem_guard(workdir, [skill_dir])

    allowed = asyncio.run(guard(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": str(skill_dir / "SKILL.md")},
        },
        None,
        None,
    ))
    denied = asyncio.run(guard(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(skill_dir / "SKILL.md")},
        },
        None,
        None,
    ))
    assert allowed == {}
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_file_guard_allows_additional_read_root(tmp_path):
    workdir = tmp_path / "rootfs"
    decompiled = tmp_path / "decompiled"
    workdir.mkdir()
    decompiled.mkdir()
    source = decompiled / "main.c"
    source.write_text("int main(void);", encoding="utf-8")
    guard = _make_filesystem_guard(workdir, [decompiled])

    allowed = asyncio.run(guard(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": str(source)},
        },
        None,
        None,
    ))
    denied = asyncio.run(guard(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": str(tmp_path / "outside")},
        },
        None,
        None,
    ))
    denied_write = asyncio.run(guard(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(source)},
        },
        None,
        None,
    ))

    assert allowed == {}
    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert denied_write["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_file_guard_allows_only_attached_writable_directory(tmp_path):
    workdir = tmp_path / "unit"
    read_only = tmp_path / "reports"
    test_dir = tmp_path / "tests" / "unit_test"
    test_file = test_dir / "main.rs"
    other_test = test_dir.parent / "other_test" / "main.rs"
    workdir.mkdir()
    read_only.mkdir()
    test_dir.mkdir(parents=True)
    other_test.parent.mkdir()
    test_file.touch()
    other_test.touch()
    guard = _make_filesystem_guard(workdir, [read_only], [test_dir])

    assert asyncio.run(guard(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(test_file)},
        },
        None,
        None,
    )) == {}
    assert asyncio.run(guard(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": str(test_file)},
        },
        None,
        None,
    )) == {}
    denied = asyncio.run(guard(
        {
            "tool_name": "Edit",
            "tool_input": {"file_path": str(other_test)},
        },
        None,
        None,
    ))
    denied_read_only = asyncio.run(guard(
        {
            "tool_name": "Write",
            "tool_input": {"file_path": str(read_only / "index.md")},
        },
        None,
        None,
    ))

    assert denied["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert denied_read_only["hookSpecificOutput"]["permissionDecision"] == "deny"
