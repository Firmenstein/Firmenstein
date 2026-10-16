"""Guest search order and path containment, independent of host ELF tools."""
from types import SimpleNamespace
import struct

import lief
import pytest

from fmst_basic.utils.file_utils import AmbiguousBinaryError, _resolve_guest_symlink
from fmst_basic.utils.guest_libraries import GuestLibraryResolver


def _library(root, path, contents=b"shared"):
    dest = root / path
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"\x7fELF" + contents)
    return dest


def _resolver(root, monkeypatch, entries=()):
    executable = root / "bin/service"
    tag = lief.ELF.DynamicEntry.TAG
    metadata = SimpleNamespace(interpreter="/lib/ld-uClibc.so.0", header=SimpleNamespace(
        identity_data=lief.ELF.Header.ELF_DATA.LSB), dynamic_entries=[
            SimpleNamespace(tag=getattr(tag, name), paths=paths) for name, paths in entries
        ])
    monkeypatch.setattr(GuestLibraryResolver, "_elf", lambda self, path: metadata if path == executable else SimpleNamespace(dynamic_entries=[]))
    return GuestLibraryResolver(root, executable), executable


def test_default_order_resolves_distinct_copies_without_recursive_arbitrary_choice(tmp_path, monkeypatch):
    first = _library(tmp_path, "lib/libshared.so", b"default")
    _library(tmp_path, "usr/lib/libshared.so", b"other")
    resolver, executable = _resolver(tmp_path, monkeypatch)
    assert resolver.resolve("libshared.so", executable) == first
    _library(tmp_path, "unsearched/libhidden.so")
    assert resolver.resolve("libhidden.so", executable) is None


def test_runpath_overrides_defaults_and_does_not_propagate_to_children(tmp_path, monkeypatch):
    default = _library(tmp_path, "lib/libshared.so", b"default")
    custom = _library(tmp_path, "custom/libshared.so", b"custom")
    resolver, executable = _resolver(tmp_path, monkeypatch, [("RUNPATH", ["$ORIGIN/../custom"])])
    assert resolver.resolve("libshared.so", executable) == custom
    assert resolver.resolve("libshared.so", tmp_path / "custom/parent.so", (executable,)) == default


def test_rpath_is_inherited_by_transitive_dependencies(tmp_path, monkeypatch):
    custom = _library(tmp_path, "custom/libshared.so")
    resolver, executable = _resolver(tmp_path, monkeypatch, [("RPATH", ["${ORIGIN}/../custom"])])
    assert resolver.resolve("libshared.so", tmp_path / "custom/parent.so", (executable,)) == custom


def test_unknown_cwd_can_only_keep_a_known_candidate_with_unique_code(tmp_path, monkeypatch):
    default = _library(tmp_path, "lib/libshared.so")
    resolver, executable = _resolver(tmp_path, monkeypatch, [("RPATH", ["../lib"])])
    assert resolver.resolve("libshared.so", executable) == default
    _library(tmp_path, "usr/lib/libshared.so", b"different")
    resolver, executable = _resolver(tmp_path, monkeypatch, [("RPATH", ["../lib"])])
    with pytest.raises(AmbiguousBinaryError, match="Unknown guest search paths"):
        resolver.resolve("libshared.so", executable)


def test_guest_cache_precedes_default_dirs(tmp_path, monkeypatch):
    _library(tmp_path, "lib/libshared.so", b"default")
    cached = _library(tmp_path, "opt/lib/libshared.so", b"cached")
    strings = b"libshared.so\0/opt/lib/libshared.so\0"
    cache = tmp_path / "etc/ld.so.cache"
    cache.parent.mkdir()
    cache.write_bytes(b"ld.so-1.7.0\0" + struct.pack("<IIII", 1, 1, 0, 13) + strings)
    resolver, executable = _resolver(tmp_path, monkeypatch)
    assert resolver.resolve("libshared.so", executable) == cached


def test_guest_directory_and_file_symlinks_stay_inside_root(tmp_path):
    target = _library(tmp_path, "usr/lib/libshared.so")
    (tmp_path / "lib").symlink_to("/usr/lib", target_is_directory=True)
    assert _resolve_guest_symlink(tmp_path / "lib/libshared.so", tmp_path) == target
    (tmp_path / "usr/lib/alias.so").symlink_to("/lib/libshared.so")
    assert _resolve_guest_symlink(tmp_path / "lib/alias.so", tmp_path) == target
    (tmp_path / "escape").symlink_to("../outside", target_is_directory=True)
    assert _resolve_guest_symlink(tmp_path / "escape/libshared.so", tmp_path) is None


def test_shared_object_without_pt_interp_uses_guest_default_dirs(tmp_path, monkeypatch):
    library = _library(tmp_path, "lib/libshared.so")
    executable = tmp_path / "lib/plugin.so"
    executable.write_bytes(b"\x7fELFplugin")
    tag = lief.ELF.DynamicEntry.TAG
    metadata = SimpleNamespace(
        interpreter="",
        header=SimpleNamespace(identity_data=lief.ELF.Header.ELF_DATA.LSB),
        dynamic_entries=[
            SimpleNamespace(tag=tag.NEEDED, name="libshared.so"),
        ],
    )
    monkeypatch.setattr(
        GuestLibraryResolver,
        "_elf",
        lambda self, path: metadata if path == executable else SimpleNamespace(dynamic_entries=[]),
    )
    resolver = GuestLibraryResolver(tmp_path, executable)
    assert resolver.resolve("libshared.so", executable) == library
