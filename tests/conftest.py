"""Portable binary fixture: no host executable or compiler is required."""

import struct

import pytest


@pytest.fixture
def elf_wrapper(tmp_path):
    """Minimal ELF64 with a one-byte .text section for location validation."""
    names = b"\0.text\0.shstrtab\0"
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + bytes(9),
        1, 62, 1, 0, 0, 96, 0, 64, 0, 0, 64, 3, 2,
    )
    sections = bytes(64)
    sections += struct.pack("<IIQQQQIIQQ", 1, 1, 6, 0, 64, 1, 0, 0, 1, 0)
    sections += struct.pack("<IIQQQQIIQQ", 7, 3, 0, 0, 65, len(names), 0, 0, 1, 0)
    path = tmp_path / "wrapper.elf"
    path.write_bytes((header + b"\xc3" + names).ljust(96, b"\0") + sections)
    return path
