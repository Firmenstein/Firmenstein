"""Typed mutations applied only to a disposable Runner rootfs."""

from __future__ import annotations

import os
import posixpath
import shutil
from pathlib import Path, PurePosixPath
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator


RootfsActionKind = Literal[
    "mkdir",
    "write_file",
    "symlink",
    "copy_file",
    "chmod",
    "remove",
]


class RootfsAction(BaseModel):
    """One Controller-executed mutation of the current disposable rootfs.

    Runtime actions are deliberately not owned by an Intervention Unit. A
    Runner task can exist without a generated Unit, while disabling a Unit is
    represented independently by ``RunnerDecision.disabled_unit_ids``.
    """

    model_config = ConfigDict(extra="forbid")

    action: RootfsActionKind = Field(
        description="One supported, deterministic disposable-rootfs mutation.",
    )
    path: str = Field(
        min_length=1,
        description="Absolute guest path changed by the action.",
    )
    content: str | None = Field(
        default=None,
        description="Exact UTF-8 contents for write_file.",
    )
    target: str | None = Field(
        default=None,
        description="Guest-visible symlink target for symlink.",
    )
    source_path: str | None = Field(
        default=None,
        description="Absolute guest source path for copy_file.",
    )
    mode: int | None = Field(
        default=None,
        ge=0,
        le=0o7777,
        description="Optional Unix mode; required for chmod.",
    )

    @model_validator(mode="after")
    def validate_action_fields(self) -> Self:
        required = {
            "write_file": ("content",),
            "symlink": ("target",),
            "copy_file": ("source_path",),
            "chmod": ("mode",),
        }.get(self.action, ())
        for field in required:
            if getattr(self, field) is None:
                raise ValueError(f"{self.action} requires {field}")
        allowed = {
            "mkdir": {"mode"},
            "write_file": {"content", "mode"},
            "symlink": {"target"},
            "copy_file": {"source_path", "mode"},
            "chmod": {"mode"},
            "remove": set(),
        }[self.action]
        for field in {"content", "target", "source_path", "mode"} - allowed:
            if getattr(self, field) is not None:
                raise ValueError(f"{self.action} does not accept {field}")
        return self


def normalize_rootfs_actions(
    actions: list[RootfsAction],
    rootfs: Path,
    *,
    require_sources: bool = True,
) -> list[RootfsAction]:
    """Validate and deterministically normalize actions for a rootfs copy.

    The Runner validates an Agent decision before the static Environment
    script has run, so a ``copy_file`` source may be created by that script.
    In that early pass callers set ``require_sources=False`` for structural
    validation only. The executor validates each action against the current
    staged tree immediately before applying it, preserving order and repeats.
    """
    normalized: list[RootfsAction] = []
    for action in actions:
        payload = action.model_dump(mode="json")
        payload["path"] = _normalize_guest_path(action.path)
        if action.source_path is not None:
            payload["source_path"] = _normalize_guest_path(action.source_path)
            if require_sources:
                _require_existing_inside(rootfs, payload["source_path"])
        if action.target is not None:
            payload["target"] = _normalize_symlink_target(action.target)
        if require_sources:
            _require_parent_inside(rootfs, payload["path"])
            candidate = _guest_host_path(rootfs, payload["path"])
            if candidate.is_symlink() and action.action not in {"symlink", "remove"}:
                raise ValueError(
                    f"action would follow an existing symlink: {action.path}"
                )
        item = RootfsAction.model_validate(payload)
        normalized.append(item)
    return normalized


def _normalize_guest_path(value: str) -> str:
    value = value.strip()
    if not value.startswith("/"):
        raise ValueError(f"guest path must be absolute: {value!r}")
    if ".." in PurePosixPath(value).parts:
        raise ValueError(f"guest path must not contain '..': {value!r}")
    normalized = posixpath.normpath(value)
    if normalized == "/":
        raise ValueError("rootfs root is not a valid action target")
    return normalized


def _normalize_symlink_target(value: str) -> str:
    value = value.strip()
    if not value or ".." in PurePosixPath(value).parts:
        raise ValueError(f"unsafe symlink target: {value!r}")
    return posixpath.normpath(value)


def _guest_host_path(
    rootfs: Path, guest_path: str, *, follow_final_symlink: bool = False,
) -> Path:
    """Map a guest absolute path without escaping on guest absolute links.

    Firmware trees commonly contain links such as ``/var -> /tmp``.  On the
    host, ``Path.resolve`` would follow that link to the host's ``/tmp`` and
    reject an otherwise contained action.  Resolve links in guest namespace,
    then anchor the resulting components under the staged rootfs. Mutation
    destinations keep their final link so remove/replace affect the link,
    and writes/chmod retain the existing final-link rejection.
    """
    root = rootfs.resolve()
    pending = list(PurePosixPath(guest_path.lstrip("/")).parts)
    resolved: list[str] = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part in {"", ".", "/"}:
            continue
        if part == "..":
            if resolved:
                resolved.pop()
            else:
                raise ValueError(f"guest path escapes rootfs through '..': {guest_path}")
            continue
        candidate = root.joinpath(*resolved, part)
        if candidate.is_symlink() and (pending or follow_final_symlink):
            links += 1
            if links > 40:
                raise ValueError(f"guest path contains too many symlinks or a loop: {guest_path}")
            target = os.readlink(candidate)
            target_parts = [piece for piece in PurePosixPath(target).parts if piece != "/"]
            if target.startswith("/"):
                resolved = []
            pending = target_parts + pending
            continue
        if pending and candidate.exists() and not candidate.is_dir():
            raise ValueError(f"guest path parent is not a directory: {guest_path}")
        resolved.append(part)
    return root.joinpath(*resolved)


def _require_parent_inside(rootfs: Path, guest_path: str) -> None:
    parent = PurePosixPath(guest_path).parent.as_posix()
    try:
        _guest_host_path(rootfs, parent, follow_final_symlink=True)
    except ValueError as error:
        raise ValueError(f"action path escapes rootfs through symlink: {guest_path}") from error


def _require_existing_inside(rootfs: Path, guest_path: str) -> None:
    candidate = _guest_host_path(rootfs, guest_path, follow_final_symlink=True)
    if not candidate.exists():
        raise ValueError(f"copy_file source does not exist: {guest_path}")


def apply_rootfs_actions(
    actions: list[RootfsAction],
    rootfs: Path,
) -> list[RootfsAction]:
    """Validate and apply Runner actions directly to one staged rootfs.

    Runner actions are already structured data.  Executing them in-process
    avoids creating a second, transient Python script whose only purpose was
    to replay the same operations.  The normalized list is returned for the
    attempt report.
    """
    normalized = normalize_rootfs_actions(actions, rootfs, require_sources=False)
    for action in normalized:
        # Re-check the live staged tree.  Earlier actions in the same batch
        # may have created or replaced a parent symlink, so validating only
        # the initial tree would allow a later action to follow it.
        _require_parent_inside(rootfs, action.path)
        path = _guest_host_path(rootfs, action.path)
        if path.is_symlink() and action.action not in {"symlink", "remove"}:
            raise ValueError(
                f"action would follow an existing symlink: {action.path}"
            )
        if action.action == "mkdir":
            path.mkdir(parents=True, exist_ok=True)
        elif action.action == "write_file":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(action.content or "", encoding="utf-8")
        elif action.action == "symlink":
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_symlink() and path.readlink().as_posix() == action.target:
                continue
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
            path.symlink_to(action.target or "")
        elif action.action == "copy_file":
            _require_existing_inside(rootfs, action.source_path or "")
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(
                _guest_host_path(rootfs, action.source_path or "", follow_final_symlink=True),
                path,
            )
        elif action.action == "chmod":
            path.chmod(action.mode or 0)
        elif action.action == "remove":
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            elif path.exists() or path.is_symlink():
                path.unlink()
        if action.mode is not None and action.action in {
            "mkdir", "write_file", "copy_file",
        }:
            path.chmod(action.mode)
    return normalized


__all__ = [
    "RootfsAction",
    "RootfsActionKind",
    "apply_rootfs_actions",
    "normalize_rootfs_actions",
]
