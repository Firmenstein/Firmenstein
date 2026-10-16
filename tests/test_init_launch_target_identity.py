"""Exact target and rootfs-confined symlink identity tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.init_launch.target_identity import (
    enumerate_initialization_roots,
    enumerate_target_identity,
    resolve_symlink_chain_in_rootfs,
)


def _file(root: Path, relative: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF")
    return path


def _link(root: Path, relative: str, target: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, path)
    return path


def test_exact_same_basename_target_is_not_merged(tmp_path: Path) -> None:
    first = _file(tmp_path, "sbin/httpd")
    _file(tmp_path, "opt/httpd")
    _link(tmp_path, "usr/sbin/httpd", "../../sbin/httpd")
    identity = enumerate_target_identity(tmp_path, first)
    assert identity.selected_rootfs_path == "sbin/httpd"
    assert identity.target_aliases == ["usr/sbin/httpd"]
    assert "opt/httpd" not in identity.target_aliases


def test_busybox_applet_keeps_selected_applet_identity(tmp_path: Path) -> None:
    _file(tmp_path, "bin/busybox")
    selected = _link(tmp_path, "sbin/ftpd", "/bin/busybox")
    _link(tmp_path, "bin/nc", "/bin/busybox")
    identity = enumerate_target_identity(tmp_path, selected)
    assert identity.target_basename == "ftpd"
    assert identity.selected_rootfs_path == "sbin/ftpd"
    assert "bin/nc" not in identity.target_aliases


def test_alias_chain_is_recorded(tmp_path: Path) -> None:
    selected = _file(tmp_path, "sbin/httpd")
    _link(tmp_path, "usr/bin/httpd", "../../sbin/httpd")
    _link(tmp_path, "opt/httpd", "../usr/bin/httpd")
    identity = enumerate_target_identity(tmp_path, selected)
    assert identity.target_aliases == ["opt/httpd", "usr/bin/httpd"]


def test_symlinked_directory_alias_is_recorded(tmp_path: Path) -> None:
    selected = _file(tmp_path, "bin/httpd")
    _link(tmp_path, "sbin", "/bin")
    identity = enumerate_target_identity(tmp_path, selected)
    assert identity.target_aliases == ["sbin/httpd"]


def test_escape_broken_and_loop_are_rejected(tmp_path: Path) -> None:
    _file(tmp_path, "sbin/httpd")
    _link(tmp_path, "lib/escape", "../../outside")
    _link(tmp_path, "etc/missing", "nowhere")
    _link(tmp_path, "etc/a", "b")
    _link(tmp_path, "etc/b", "a")
    assert resolve_symlink_chain_in_rootfs(tmp_path, "lib/escape") is None
    assert resolve_symlink_chain_in_rootfs(tmp_path, "etc/missing") is None
    assert resolve_symlink_chain_in_rootfs(tmp_path, "etc/a") is None


def test_selected_escape_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-init-launch"
    outside.write_bytes(b"\x7fELF")
    selected = _link(tmp_path, "sbin/httpd", str(outside))
    try:
        with pytest.raises(ValueError, match="escapes rootfs"):
            enumerate_target_identity(tmp_path, selected)
    finally:
        outside.unlink()


def test_initialization_roots_include_entry_alias_and_final_file(
    tmp_path: Path,
) -> None:
    _file(tmp_path, "sbin/rc")
    _link(tmp_path, "sbin/init", "rc")
    (tmp_path / "etc").mkdir(exist_ok=True)
    (tmp_path / "etc/inittab").write_text("::sysinit:/etc/rcS\n")

    assert enumerate_initialization_roots(tmp_path) == [
        "etc/inittab",
        "sbin/init",
        "sbin/rc",
    ]


def test_initialization_roots_include_only_rc_start_symlink(
    tmp_path: Path,
) -> None:
    script = tmp_path / "etc/init.d/httpd"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\nstart_service\n")
    _link(tmp_path, "etc/rc.d/S50httpd", "../init.d/httpd")

    assert enumerate_initialization_roots(tmp_path) == ["etc/rc.d/S50httpd"]
