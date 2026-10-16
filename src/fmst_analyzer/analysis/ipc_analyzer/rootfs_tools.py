"""Read-only exact-text retrieval over the frozen firmware rootfs."""

from __future__ import annotations

import json
import hashlib
import stat
import subprocess
from pathlib import Path

from fmst_basic.agent.tool import AgentTool, tool
from fmst_basic.utils.guest_paths import resolve_guest_file


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def make_rootfs_text_search_tool(rootfs: Path) -> AgentTool:
    """Return one exact retrieval tool; semantic judgment remains Agent-owned."""
    frozen_rootfs = Path(rootfs).absolute().resolve()

    @tool
    def search_rootfs_text(needle: str) -> dict:
        """Find an exact text fragment in non-binary files of the frozen rootfs.

        Use this to locate shipped init/config/script evidence for a resource,
        executable path or configuration value already relevant to the
        channel. The result is retrieval evidence only: a
        text occurrence does not prove reachability, endpoint behavior, peer
        identity, or dependency necessity. Inspect a returned path with the
        available read-only filesystem tools before citing its surrounding
        configuration.

        Args:
            needle: Exact fixed string of at least three characters.

        Returns every matching line as {path, line_number, text}; no result is
        silently truncated.
        """
        if len(needle) < 3:
            return {
                "needle": needle,
                "matches": [],
                "error": "needle must contain at least three characters",
            }
        completed = subprocess.run(
            [
                "rg", "--json", "--fixed-strings", "--no-messages",
                "--", needle, ".",
            ],
            cwd=frozen_rootfs,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if completed.returncode not in {0, 1}:
            return {
                "needle": needle,
                "matches": [],
                "error": completed.stderr.strip() or f"rg exited {completed.returncode}",
            }

        matches: list[dict[str, object]] = []
        for raw in completed.stdout.splitlines():
            event = json.loads(raw)
            if event.get("type") != "match":
                continue
            data = event["data"]
            path = str(data["path"]["text"])
            if path.startswith("./"):
                path = path[2:]
            matches.append({
                "path": path,
                "line_number": int(data["line_number"]),
                "text": str(data["lines"]["text"]).rstrip("\r\n"),
            })
        matches.sort(key=lambda item: (str(item["path"]), int(item["line_number"])))
        return {"needle": needle, "matches": matches, "error": None}

    return search_rootfs_text


def make_rootfs_path_info_tool(rootfs: Path) -> AgentTool:
    """Return guest-root path inspection for executable/config identity."""
    frozen_rootfs = Path(rootfs).absolute().resolve()

    @tool
    def inspect_rootfs_path(path: str) -> dict:
        """Inspect one exact firmware path using guest-root symlink semantics.

        Use this only after code/config/resource evidence identifies a concrete
        path. It proves existence, symlink aliases, executable mode, ELF/script
        kind, and content identity; it does not prove reachability, peer role,
        process lifetime, or dependency necessity. Absolute firmware symlinks
        are resolved inside the frozen rootfs, never against the host filesystem.

        Args:
            path: Exact absolute guest path or rootfs-relative path.
        """
        resolved = resolve_guest_file(frozen_rootfs, path)
        if resolved is None:
            return {"path": path, "exists": False, "error": "not a regular guest file"}
        chain, endpoint = resolved
        metadata = endpoint.stat()
        with endpoint.open("rb") as stream:
            prefix = stream.read(256)
        shebang = None
        if prefix.startswith(b"#!"):
            shebang = prefix.splitlines()[0].decode("utf-8", errors="replace")
        return {
            "path": chain[0],
            "exists": True,
            "symlink_chain": chain,
            "resolved_path": chain[-1],
            "mode": oct(stat.S_IMODE(metadata.st_mode)),
            "executable": bool(metadata.st_mode & 0o111),
            "kind": "elf" if prefix.startswith(b"\x7fELF") else "text_or_data",
            "shebang": shebang,
            "sha256": _sha256(endpoint),
            "error": None,
        }

    return inspect_rootfs_path


def make_rootfs_tools(rootfs: Path) -> list[AgentTool]:
    return [
        make_rootfs_text_search_tool(rootfs),
        make_rootfs_path_info_tool(rootfs),
    ]


__all__ = [
    "make_rootfs_path_info_tool",
    "make_rootfs_text_search_tool",
    "make_rootfs_tools",
    "resolve_guest_file",
]
