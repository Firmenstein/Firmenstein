"""Init reads and validates the same guest objects as the shared path resolver."""
from pathlib import Path
import stat

import pytest

from fmst_basic.utils.guest_paths import resolve_guest_path
from fmst_analyzer.analysis.init_launch.source_evidence import SourceEvidence, make_source_tool
from fmst_analyzer.analysis.init_launch.controller import _validate_snippet
from fmst_analyzer.analysis.init_launch.analyzer_schema import SourceSnippet
from fmst_analyzer.analysis.init_launch.target_identity import (
    enumerate_target_identity, resolve_symlink_chain_in_rootfs,
)


def test_init_source_read_follows_a_directory_link_before_dotdot(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "srv/bin").mkdir(parents=True)
    (tmp_path / "etc/launch").write_text("WRONG source\n")
    (tmp_path / "srv/launch").write_text("RIGHT source\n")
    (tmp_path / "etc/directory").symlink_to("/srv/bin", target_is_directory=True)
    (tmp_path / "etc/start").symlink_to("directory/../launch")
    sources = SourceEvidence()
    result = make_source_tool(tmp_path, sources).invoke({
        "path": "etc/start", "start_line": 1, "end_line": 1,
    })
    assert result["source_snippet"]["path"] == "srv/launch"
    assert result["content"] == "RIGHT source"
    source = sources.sources[result["source_snippet"]["text"]]
    assert _validate_snippet(tmp_path, source, {}) == source
    direct = SourceSnippet(path="etc/directory/../launch", location="line 1", text="RIGHT source")
    assert _validate_snippet(tmp_path, direct, {}) == direct


@pytest.mark.parametrize("count, readable", [(20, True), (40, True), (41, False)])
def test_init_source_links_follow_linux_lookup_bound(tmp_path, count, readable):
    (tmp_path / "source").write_text("source\n")
    previous = "source"
    for index in range(count):
        current = f"alias-{index}"
        (tmp_path / current).symlink_to(previous)
        previous = current
    result = resolve_symlink_chain_in_rootfs(tmp_path, previous)
    if readable:
        assert result[-1] == "source"
    else:
        assert result is None


@pytest.mark.parametrize("operation", ["lstat", "readlink"])
def test_init_source_io_failure_is_not_a_model_correction(tmp_path, monkeypatch, operation):
    source = tmp_path / "source"
    source.write_text("valid source\n")
    if operation == "lstat":
        original = Path.lstat
        def unreadable(path, *args, **kwargs):
            if path == source:
                raise PermissionError("source lookup denied")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(Path, "lstat", unreadable)
        snippet = SourceSnippet(path="source", location="line 1", text="valid source")
    else:
        from fmst_basic.utils import guest_paths
        alias = tmp_path / "alias"
        alias.symlink_to(".", target_is_directory=True)
        original = guest_paths.os.readlink
        def unreadable(path, *args, **kwargs):
            if path == alias:
                raise PermissionError("source link read denied")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(guest_paths.os, "readlink", unreadable)
        snippet = SourceSnippet(path="alias/source", location="line 1", text="valid source")
    with pytest.raises(PermissionError):
        _validate_snippet(tmp_path, snippet, {})


def test_shared_resolver_can_read_a_dangling_link_itself(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/link").symlink_to("missing")
    chain, mode = resolve_guest_path(tmp_path, "etc/link", follow_final_symlink=False)
    assert chain[-1] == "etc/link" and stat.S_ISLNK(mode)
    assert resolve_guest_path(tmp_path, "etc/link") is None


def test_applet_alias_through_a_parent_component_keeps_selected_identity(tmp_path):
    (tmp_path / "bin").mkdir()
    (tmp_path / "sbin").mkdir()
    (tmp_path / "opt").mkdir()
    (tmp_path / "bin/busybox").write_bytes(b"\x7fELFfixture")
    selected = tmp_path / "sbin/ftpd"
    selected.symlink_to("/bin/busybox")
    (tmp_path / "opt/service").symlink_to("../sbin/ftpd")
    (tmp_path / "bin/nc").symlink_to("/bin/busybox")
    identity = enumerate_target_identity(tmp_path, selected)
    assert identity.target_aliases == ["opt/service"]
