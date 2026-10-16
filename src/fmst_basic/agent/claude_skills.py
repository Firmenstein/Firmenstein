"""Session-local native Claude plugins for provider-neutral Skill sources."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .skill import AgentSkillSpec


def native_skill_plugins(
    skills: list[AgentSkillSpec], wrapper: Path,
) -> tuple[list[dict[str, str]], list[str]]:
    """Register original bundles and a retained plugin for standalone Skills.

    Mirror only declared source roots with symlinks, preserving their relative
    layout. Both lexical and filesystem resolution of Skill references reach
    the live originals; neither documentation nor backend code is copied.
    The caller owns the wrapper's lifetime and adds it to read access roots.
    """
    plugins = []
    names = []
    paths = []
    namespace = "fmst-task"
    for skill in skills:
        if skill.plugin_root is not None:
            plugin = {"type": "local", "path": str(skill.plugin_root)}
            if plugin not in plugins:
                plugins.append(plugin)
            names.append(skill.claude_qualified_name)
            continue
        roots = sorted(set((skill.skill_dir, *skill.reference_roots)),
                       key=lambda path: (len(path.parts), str(path)))
        common = Path(os.path.commonpath(roots))
        mirror = wrapper / "sources" / skill.name
        linked = []
        for root in roots:
            if any(root.is_relative_to(parent) for parent in linked):
                continue
            destination = mirror / root.relative_to(common)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.is_symlink() and destination.resolve() == root.resolve():
                pass  # The same session's plugin survives disconnect/resume.
            else:
                destination.symlink_to(root, target_is_directory=root.is_dir())
            linked.append(root)
        entry = mirror / skill.skill_dir.relative_to(common)
        paths.append("./" + entry.relative_to(wrapper).as_posix())
        names.append(f"{namespace}:{skill.name}")
    if paths:
        if any(skill.claude_qualified_name and
               skill.claude_qualified_name.startswith(namespace + ":") for skill in skills):
            raise ValueError(f"Claude plugin namespace is reserved for attached Skills: {namespace}")
        manifest = wrapper / ".claude-plugin" / "plugin.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps({"name": namespace, "skills": paths}) + "\n")
        plugins.append({"type": "local", "path": str(wrapper)})
    return plugins, names
