"""Content and guest loader admission without a host compiler/IDA."""
import struct

import pytest

from fmst_basic.FirmProbe.admission import inspect_root_content, inspect_target_input
from fmst_basic.FirmProbe.extraction import inspect_root_candidate


def dynamic_elf(*, needed="libexample.so", interpreter="/lib/ld-uClibc.so.0"):
    """Minimal ELF64 loader data, with deliberately portable source bytes."""
    size = 1024
    header = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                         2, 62, 1, 0, 64, 0, 0, 64, 56, 3, 64, 0, 0)
    program = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, size, size, 4096)
    interp = interpreter.encode() + b"\0"
    strings = b"\0" + needed.encode() + b"\0"
    program += struct.pack("<IIQQQQQQ", 3, 4, 256, 0x400100, 0x400100, len(interp), len(interp), 1)
    tags = [(5, 0x400180), (10, len(strings)), (1, 1), (0, 0)] if needed else [(0, 0)]
    dynamic = b"".join(struct.pack("<QQ", *tag) for tag in tags)
    program += struct.pack("<IIQQQQQQ", 2, 4, 512, 0x400200, 0x400200, len(dynamic), len(dynamic), 8)
    payload = bytearray(size)
    payload[:64] = header
    payload[64:64 + len(program)] = program
    payload[256:256 + len(interp)] = interp
    payload[384:384 + len(strings)] = strings
    payload[512:512 + len(dynamic)] = dynamic
    return bytes(payload)


def static_elf():
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 62, 1)
    struct.pack_into("<H", header, 52, 64)
    return bytes(header)


def root_tree(tmp_path):
    root = tmp_path / "rootfs"
    for name in ("bin", "etc", "lib"):
        (root / name).mkdir(parents=True)
    (root / "etc/inittab").write_text("::sysinit:/bin/sh")
    return root


def test_directory_shape_empty_magic_and_unreadable_elf_are_not_admitted(tmp_path):
    root = root_tree(tmp_path)
    assert inspect_root_candidate(root, tmp_path) is None
    (root / "bin/app").write_bytes(b"\x7fELF")
    assert inspect_root_candidate(root, tmp_path) is None
    (root / "bin/app").write_bytes(static_elf())
    (root / "bin/app").chmod(0)
    assert inspect_root_candidate(root, tmp_path) is None
    assert inspect_root_content(root)["limitations"][0]["kind"] == "unreadable_file"


def test_guest_link_and_missing_loader_inputs_remain_explicit_partial(tmp_path):
    root = root_tree(tmp_path)
    (root / "bin/app").write_bytes(dynamic_elf())
    (root / "bin/alias").symlink_to("/bin/app")
    (root / "lib/broken").symlink_to("/missing")
    candidate = inspect_root_candidate(root, tmp_path)
    assert candidate is not None and candidate.elf_paths == ("bin/app",)
    assert candidate.limitations[0]["kind"] == "unresolved_guest_link"
    before = (root / "bin/app").read_bytes()
    admission = inspect_target_input(root, "/bin/alias")
    assert admission.status == "partial" and admission.resolved_path == "bin/app"
    assert {item["kind"] for item in admission.limitations} == {"missing_or_invalid_interpreter", "missing_or_invalid_dependency"}
    (root / "lib/ld-uClibc.so.0").write_bytes(static_elf())
    (root / "lib/libexample.so.1").write_bytes(static_elf())
    (root / "lib/libexample.so").symlink_to("libexample.so.1")
    complete = inspect_target_input(root, "bin/alias")
    assert complete.status == "complete"
    assert (root / "bin/app").read_bytes() == before
    assert (root / "bin/alias").readlink().as_posix() == "/bin/app"


def test_guest_loader_precedence_and_invalid_target_are_not_guessed(tmp_path):
    root = root_tree(tmp_path)
    (root / "bin/app").write_bytes(dynamic_elf())
    (root / "lib/ld-uClibc.so.0").write_bytes(static_elf())
    (root / "lib/libexample.so").write_bytes(static_elf())
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/libexample.so").write_bytes(static_elf())
    result = inspect_target_input(root, "bin/app")
    assert result.status == "complete"
    dependency = next(item for item in result.dependencies if item["kind"] == "DT_NEEDED")
    assert dependency["resolved_path"] == "lib/libexample.so"
    (root / "bin/app").write_bytes(b"not an ELF")
    with pytest.raises(ValueError, match="Selected target"):
        inspect_target_input(root, "bin/app")
    (root / "bin/escape").symlink_to("../../outside")
    with pytest.raises(ValueError, match="inside guest rootfs"):
        inspect_target_input(root, "bin/escape")
