"""ELF citation validation never executes guest code or host disassemblers."""
from types import SimpleNamespace
from pathlib import Path
import hashlib
import json

import lief
import pytest

from fmst_analyzer.analysis.init_launch.elf_evidence import (
    _decoder, make_elf_evidence_tools, read_excerpt, validate_excerpt,
)


@pytest.mark.parametrize("machine,code,mnemonic", [
    (lief.ELF.ARCH.X86_64, "c3", "ret"),
    (lief.ELF.ARCH.I386, "c3", "ret"),
    (lief.ELF.ARCH.ARM, "1eff2fe1", "bx"),
    (lief.ELF.ARCH.AARCH64, "c0035fd6", "ret"),
    (lief.ELF.ARCH.MIPS, "0800e00300000000", "jr"),
])
def test_standard_decoder_handles_guest_isa_independent_of_host(machine, code, mnemonic):
    binary = SimpleNamespace(header=SimpleNamespace(
        machine_type=machine, identity_data=lief.ELF.Header.ELF_DATA.LSB,
        identity_class=lief.ELF.Header.CLASS.ELF32,
    ), symbols=[])
    decoded = list(_decoder(binary, 0x1000).disasm(bytes.fromhex(code), 0x1000))
    assert decoded[0].mnemonic == mnemonic


def test_tool_returns_auditable_range_and_rejects_fabricated_evidence(elf_wrapper):
    tools = {tool.name: tool for tool in make_elf_evidence_tools(elf_wrapper.parent)}
    overview = tools["inspect_elf"].invoke({"path": elf_wrapper.name})
    assert overview["machine"] == "ARCH.X86_64"
    excerpt = tools["read_elf"].invoke({"path": elf_wrapper.name, "location": ".text+0x0", "byte_count": 16})
    assert excerpt["assembly"] == "0x0: ret"
    assert (excerpt["requested_bytes"], excerpt["returned_bytes"], excerpt["decoded_bytes"]) == (16, 1, 1)
    assert excerpt["remaining_section_bytes"] == 0
    binary = lief.parse(str(elf_wrapper))
    validate_excerpt(binary, ".text+0x0", excerpt["assembly"])
    with pytest.raises(ValueError, match="does not match"):
        validate_excerpt(binary, ".text+0x0", "wrapper launches httpd")
    with pytest.raises(ValueError, match="section offset"):
        read_excerpt(binary, ".text+0xffff", 16)
    with pytest.raises(ValueError, match="byte_count"):
        read_excerpt(binary, ".text+0x0", 4097)
    with pytest.raises(ValueError, match="escapes rootfs"):
        tools["inspect_elf"].invoke({"path": "../outside"})


def test_exact_elf_string_requires_exact_start_address(elf_wrapper):
    binary = lief.parse(str(elf_wrapper))
    validate_excerpt(binary, ".shstrtab+0x1", ".text")
    with pytest.raises(ValueError, match="does not match"):
        validate_excerpt(binary, ".shstrtab+0x2", ".text")


def test_data_citation_is_explicit_and_matches_raw_bytes(elf_wrapper):
    binary = lief.parse(str(elf_wrapper))
    tools = {tool.name: tool for tool in make_elf_evidence_tools(elf_wrapper.parent)}
    result = tools["read_elf"].invoke({"path": elf_wrapper.name, "location": ".shstrtab+0x1", "byte_count": 5})
    snippet = result["source_snippet"]
    assert snippet["text"] == "hex:2e74657874"
    validate_excerpt(binary, snippet["location"], snippet["text"])
    for text in ("2e74657874", "hex:2e74657875"):
        with pytest.raises(ValueError, match="does not match"):
            validate_excerpt(binary, snippet["location"], text)


def test_selected_assembly_lines_validate_bytes_without_requiring_continuity():
    section = SimpleNamespace(
        name=".text", virtual_address=0x1000, size=3, flags=4,
        content=[0x90, 0x90, 0xc3],  # nop; nop; ret
    )
    binary = SimpleNamespace(
        sections=[section], symbols=[],
        header=SimpleNamespace(machine_type=lief.ELF.ARCH.X86_64),
    )
    binary.header.identity_data = lief.ELF.Header.ELF_DATA.LSB
    validate_excerpt(binary, "0x1000", "0x1000: nop\n0x1002: ret")
    for invalid in (
        "0x1000: nop\n0x1001: ret",  # wrong bytes at a valid address
        "0x1002: ret",  # first quote does not match source location
        "0x1000: nop\n0x1002: ret\n0x1001: nop",  # reordered
        "0x1000: nop\n0x1000: nop",  # overlapping
    ):
        with pytest.raises(ValueError, match="does not match"):
            validate_excerpt(binary, "0x1000", invalid)


def test_real_sparse_init_citations_match_frozen_guest_bytes():
    fixtures = Path(__file__).parent / "fixtures/g2"
    manifest = json.loads((fixtures / "manifest.json").read_text())
    result = json.loads((fixtures / "init_real_gap.json").read_text())
    count = 0
    for entry in manifest["elf_excerpts"]:
        data = (fixtures / entry["path"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        binary = SimpleNamespace(sections=[SimpleNamespace(
            name=".text", virtual_address=entry["address"], size=len(data), flags=4, content=list(data),
        )], symbols=[], header=SimpleNamespace(
            machine_type=getattr(lief.ELF.ARCH, entry["machine"]),
            identity_data=lief.ELF.Header.ELF_DATA.LSB, identity_class=lief.ELF.Header.CLASS.ELF32,
        ))
        source = result["analysis_gaps"][entry["gap_index"]]["source"]
        validate_excerpt(binary, entry["location"], source["text"])
        count += len(source["text"].splitlines())
    assert count == 34
