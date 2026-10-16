"""Tests for bounded read-only rootfs tools."""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
import pytest

load_dotenv()

from fmst_analyzer.analysis.ipc_analyzer.rootfs_tools import (  # noqa: E402
    make_rootfs_path_info_tool,
    make_rootfs_text_search_tool,
    resolve_guest_file,
)


@pytest.mark.external
def test_rootfs_text_search_returns_every_exact_text_line(tmp_path: Path) -> None:
    config = tmp_path / "etc/service.conf"
    script = tmp_path / "www/cgi-bin/demo"
    config.parent.mkdir(parents=True)
    script.parent.mkdir(parents=True)
    config.write_text("handler=/www/cgi-bin/demo\nother=value\n", encoding="utf-8")
    script.write_text("#!/bin/sh\nexec /www/cgi-bin/demo --serve\n", encoding="utf-8")

    result = make_rootfs_text_search_tool(tmp_path).invoke({
        "needle": "/www/cgi-bin/demo",
    })

    assert result == {
        "needle": "/www/cgi-bin/demo",
        "matches": [
            {
                "path": "etc/service.conf",
                "line_number": 1,
                "text": "handler=/www/cgi-bin/demo",
            },
            {
                "path": "www/cgi-bin/demo",
                "line_number": 2,
                "text": "exec /www/cgi-bin/demo --serve",
            },
        ],
        "error": None,
    }


def test_rootfs_text_search_rejects_non_selective_needles(tmp_path: Path) -> None:
    result = make_rootfs_text_search_tool(tmp_path).invoke({"needle": "x"})

    assert result["matches"] == []
    assert "at least three" in result["error"]


def test_rootfs_path_info_resolves_absolute_symlink_inside_guest(tmp_path: Path) -> None:
    target = tmp_path / "sbin/rc"
    alias = tmp_path / "sbin/init"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELFfixture")
    target.chmod(0o755)
    alias.symlink_to("/sbin/rc")

    result = make_rootfs_path_info_tool(tmp_path).invoke({"path": "/sbin/init"})

    assert result["exists"] is True
    assert result["symlink_chain"] == ["sbin/init", "sbin/rc"]
    assert result["resolved_path"] == "sbin/rc"
    assert result["kind"] == "elf"
    assert result["executable"] is True


def test_directory_symlink_and_parent_traversal_use_guest_root(tmp_path: Path) -> None:
    target = tmp_path / "srv/bin/peer"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\x7fELFfixture")
    (tmp_path / "usr").symlink_to("/srv", target_is_directory=True)
    (tmp_path / "srv/bin/link").symlink_to("../bin/peer")
    result = make_rootfs_path_info_tool(tmp_path).invoke({"path": "/usr/bin/link"})
    assert result["exists"] is True
    assert result["resolved_path"] == "srv/bin/peer"
    assert resolve_guest_file(tmp_path, "/usr/bin/link")[1] == target
    assert resolve_guest_file(tmp_path, "//usr/bin/link")[1] == target


def test_directory_symlink_is_followed_before_dotdot(tmp_path: Path) -> None:
    (tmp_path / "srv/bin").mkdir(parents=True)
    (tmp_path / "srv/peer").write_text("actual source")
    (tmp_path / "peer").write_text("different source")
    (tmp_path / "usr").symlink_to("/srv/bin", target_is_directory=True)
    assert resolve_guest_file(tmp_path, "/usr/../peer")[1] == tmp_path / "srv/peer"


def test_source_link_chain_above_old_bound_is_readable(tmp_path: Path) -> None:
    (tmp_path / "source").write_text("source")
    previous = "source"
    for index in range(20):
        current = f"alias-{index}"
        (tmp_path / current).symlink_to(previous)
        previous = current
    assert resolve_guest_file(tmp_path, previous)[1] == tmp_path / "source"
    (tmp_path / "loop").symlink_to("loop/child")
    assert resolve_guest_file(tmp_path, "loop") is None
    assert resolve_guest_file(tmp_path, "../source") is None


def test_permission_error_remains_a_source_tool_failure(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "source"
    target.write_text("source")
    original = Path.lstat
    def unreadable(path, *args, **kwargs):
        if path == target:
            raise PermissionError("source lookup denied")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", unreadable)
    with pytest.raises(PermissionError, match="source lookup denied"):
        resolve_guest_file(tmp_path, "source")
