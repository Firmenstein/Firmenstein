"""Validated task-scoped Agent Skill bundles."""

from __future__ import annotations

import json
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def _frontmatter(skill_file: Path) -> dict[str, Any]:
    text = skill_file.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError(f"Skill frontmatter is missing: {skill_file}")
    try:
        end = next(
            index for index, line in enumerate(lines[1:], start=1)
            if line.strip() == "---"
        )
    except StopIteration as exc:
        raise ValueError(f"Skill frontmatter is not terminated: {skill_file}") from exc
    parsed = yaml.safe_load("\n".join(lines[1:end]))
    if not isinstance(parsed, dict):
        raise ValueError(f"Skill frontmatter must be a mapping: {skill_file}")
    return parsed


def _validate_markdown_references(skill_dir: Path, reference_roots: tuple[Path, ...]) -> tuple[Path, ...]:
    roots = (skill_dir, *reference_roots)
    pending = list(sorted(skill_dir.rglob("*.md")))
    visited: set[Path] = set()
    referenced: set[Path] = set()
    while pending:
        source = pending.pop().resolve()
        if source in visited:
            continue
        visited.add(source)
        referenced.add(source)
        for target in _MARKDOWN_LINK_RE.findall(source.read_text(encoding="utf-8")):
            if "://" in target or target.startswith("#"):
                continue
            path = source.parent / target.split("#", 1)[0]
            linked = path.resolve(strict=False)
            if not any(linked == root or root in linked.parents for root in roots):
                raise ValueError(f"Skill reference escapes declared read roots: {target}")
            if not linked.is_file() or path.is_symlink():
                raise ValueError(f"Skill reference is missing or invalid: {target}")
            referenced.add(linked)
            if linked.suffix == ".md":
                pending.append(linked)
    return tuple(sorted(referenced))


@dataclass(frozen=True, slots=True)
class AgentSkillSpec:
    """One provider-neutral, explicitly attached Agent Skill.

    Codex consumes a standard ``SKILL.md`` directly. ``plugin_root`` optionally
    supplies an existing Claude plugin; standalone Skills use a session-local
    native plugin pointing to their original files. References
    can live alongside a library in explicitly declared read-only files or directories;
    they do not require a second copied documentation tree.
    """

    name: str
    skill_dir: Path
    plugin_root: Path | None = None
    reference_roots: tuple[Path, ...] = ()
    claude_qualified_name: str | None = field(init=False, repr=False)
    source_files: tuple[Path, ...] = field(init=False, repr=False)
    content_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not _SKILL_NAME_RE.fullmatch(self.name):
            raise ValueError(f"Invalid Agent Skill name: {self.name!r}")

        skill_dir = Path(self.skill_dir).resolve(strict=True)
        plugin_root = Path(self.plugin_root).resolve(strict=True) if self.plugin_root else None
        reference_roots = tuple(Path(root).resolve(strict=True) for root in self.reference_roots)
        if any(not (root.is_dir() or root.is_file()) for root in reference_roots):
            raise ValueError("Skill reference_roots must be existing files or directories")
        if plugin_root is not None:
            expected_skill_dir = (plugin_root / "skills" / self.name).resolve(strict=True)
            if skill_dir != expected_skill_dir:
                raise ValueError(
                    "Plugin Skill must live at plugin_root/skills/<name>: "
                    f"{skill_dir} != {expected_skill_dir}"
                )

        skill_file = skill_dir / "SKILL.md"
        if not skill_file.is_file() or skill_file.is_symlink():
            raise ValueError(f"Agent Skill entrypoint is invalid: {skill_file}")
        metadata = _frontmatter(skill_file)
        if metadata.get("name") != self.name:
            raise ValueError(
                f"Skill name mismatch: expected {self.name!r}, "
                f"got {metadata.get('name')!r}"
            )
        description = metadata.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"Skill description is missing: {skill_file}")
        for path in skill_dir.rglob("*"):
            if path.is_symlink():
                raise ValueError(f"Skill bundle must not contain symlinks: {path}")

        qualified_name = None
        if plugin_root is not None:
            manifest_path = plugin_root / ".claude-plugin" / "plugin.json"
            if not manifest_path.is_file() or manifest_path.is_symlink():
                raise ValueError(f"Claude plugin manifest is invalid: {manifest_path}")
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(
                    f"Claude plugin manifest is not valid JSON: {manifest_path}"
                ) from exc
            plugin_name = manifest.get("name") if isinstance(manifest, dict) else None
            if not isinstance(plugin_name, str) or not _SKILL_NAME_RE.fullmatch(plugin_name):
                raise ValueError(f"Claude plugin name is invalid: {plugin_name!r}")
            qualified_name = f"{plugin_name}:{self.name}"

        source_files = _validate_markdown_references(skill_dir, reference_roots)
        content = {}
        for source in source_files:
            for index, root in enumerate((skill_dir, *reference_roots)):
                if source.is_relative_to(root):
                    key = f"{index}/{source.relative_to(root).as_posix()}"
                    content[key] = hashlib.sha256(source.read_bytes()).hexdigest()
                    break

        object.__setattr__(self, "skill_dir", skill_dir)
        object.__setattr__(self, "plugin_root", plugin_root)
        object.__setattr__(self, "reference_roots", reference_roots)
        object.__setattr__(self, "source_files", source_files)
        object.__setattr__(self, "content_sha256", hashlib.sha256(
            json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest())
        object.__setattr__(
            self,
            "claude_qualified_name",
            qualified_name,
        )

    @property
    def skill_file(self) -> Path:
        return self.skill_dir / "SKILL.md"

    def trace_identity(self) -> dict[str, str]:
        """Bind the attached entrypoint and its referenced content to traces."""
        return {"name": self.name, "content_sha256": self.content_sha256,
                "path": str(self.skill_file)}

    def validate_current(self) -> None:
        """Revalidate the bundle structure immediately before provider use."""
        current = AgentSkillSpec(
            name=self.name,
            skill_dir=self.skill_dir,
            plugin_root=self.plugin_root,
            reference_roots=self.reference_roots,
        )
        if current.claude_qualified_name != self.claude_qualified_name:
            raise ValueError(
                f"Agent Skill plugin identity changed: {self.name!r}"
            )
        if current.content_sha256 != self.content_sha256:
            raise ValueError(f"Agent Skill content changed: {self.name!r}; create a new task context")


__all__ = ["AgentSkillSpec"]
