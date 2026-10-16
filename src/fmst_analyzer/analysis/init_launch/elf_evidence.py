"""Portable ELF evidence retrieval and exact citation validation.

LIEF reads object metadata; Capstone decodes instructions. Neither executes
guest code or invokes host programs. Imports stay at the native-tool boundary.
"""
from __future__ import annotations

from pathlib import Path
import re


def locate(binary, location: str):
    address_match = re.fullmatch(r"0x([0-9a-fA-F]+)", location)
    offset_match = re.fullmatch(r"(\.[A-Za-z0-9_.-]+)\+0x([0-9a-fA-F]+)", location)
    if address_match:
        address = int(address_match.group(1), 16)
        for section in binary.sections:
            offset = address - int(section.virtual_address)
            if 0 <= offset < int(section.size):
                return section, offset, address
        raise ValueError(f"ELF address {location} is outside all sections")
    if offset_match:
        section = binary.get_section(offset_match.group(1))
        offset = int(offset_match.group(2), 16)
        if section is not None and offset < int(section.size):
            return section, offset, int(section.virtual_address) + offset
        raise ValueError(f"ELF section offset {location} is invalid")
    raise ValueError("ELF location must be 0xADDR or .section+0xOFFSET")


def _decoder(binary, address: int):
    import capstone as cs
    import lief

    header = binary.header
    endian = cs.CS_MODE_BIG_ENDIAN if header.identity_data == lief.ELF.Header.ELF_DATA.MSB else cs.CS_MODE_LITTLE_ENDIAN
    machine = header.machine_type
    if machine == lief.ELF.ARCH.X86_64:
        return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    if machine == lief.ELF.ARCH.I386:
        return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
    if machine == lief.ELF.ARCH.AARCH64:
        return cs.Cs(cs.CS_ARCH_ARM64, endian)
    if machine == lief.ELF.ARCH.ARM:
        # ELF ARM mapping symbols define code mode without host heuristics.
        mappings = [symbol for symbol in binary.symbols
                    if symbol.name.split(".")[0] in {"$a", "$t"} and symbol.value <= address]
        thumb = bool(address & 1)
        if mappings:
            thumb = max(mappings, key=lambda symbol: symbol.value).name.split(".")[0] == "$t"
        return cs.Cs(cs.CS_ARCH_ARM, (cs.CS_MODE_THUMB if thumb else cs.CS_MODE_ARM) | endian)
    if machine == lief.ELF.ARCH.MIPS:
        width = cs.CS_MODE_MIPS64 if header.identity_class == lief.ELF.Header.CLASS.ELF64 else cs.CS_MODE_MIPS32
        return cs.Cs(cs.CS_ARCH_MIPS, width | endian)
    raise ValueError(f"No instruction decoder for {machine}; retain an explicit evidence gap")


def read_excerpt(binary, location: str, byte_count: int = 128) -> dict:
    if not 1 <= byte_count <= 4096:
        raise ValueError("byte_count must be between 1 and 4096")
    section, offset, address = locate(binary, location)
    data = bytes(section.content)[offset:offset + byte_count]
    instructions = list(_decoder(binary, address).disasm(data, address)) if int(section.flags) & 4 else []
    assembly = "\n".join(
        f"0x{item.address:x}: {item.mnemonic}" + (f" {item.op_str}" if item.op_str else "")
        for item in instructions
    )
    decoded = sum(item.size for item in instructions)
    return {
        "section": section.name, "address": f"0x{address:x}",
        "requested_bytes": byte_count, "returned_bytes": len(data),
        "remaining_section_bytes": max(0, int(section.size) - offset - len(data)),
        "bytes_hex": data.hex(), "assembly": assembly,
        "decoded_bytes": decoded, "undecoded_bytes": len(data) - decoded,
    }


def validate_excerpt(binary, location: str, text: str) -> None:
    """A valid address never suffices: the cited content must match there."""
    section, offset, start_address = locate(binary, location)
    data = bytes(section.content)
    if data[offset:].startswith(text.encode("utf-8")):
        return
    if re.fullmatch(r"hex:(?:[0-9a-f]{2})+", text):
        if data[offset:].startswith(bytes.fromhex(text.removeprefix("hex:"))):
            return
        raise ValueError("ELF hex excerpt does not match bytes at the cited location")
    if not int(section.flags) & 4:
        raise ValueError("ELF source excerpt does not match bytes at the cited location")
    # Addressed lines may select evidence from a larger listing. Their gaps
    # remain visible and do not assert contiguous execution or control flow.
    next_address = start_address
    for index, line in enumerate(text.rstrip("\n").splitlines()):
        match = re.fullmatch(r"0x([0-9a-f]+): (.+)", line)
        if match is None:
            raise ValueError(f"ELF source excerpt at {location} does not match canonical addressed assembly")
        address = int(match.group(1), 16)
        if (index == 0 and address != start_address) or address < next_address:
            raise ValueError(f"ELF source excerpt at {location} does not match its start or ordered instruction addresses")
        line_offset = address - int(section.virtual_address)
        if not 0 <= line_offset < len(data):
            raise ValueError(f"ELF source instruction 0x{address:x} is outside the cited section")
        # All supported ISAs have instructions at most 15 bytes long (x86).
        instruction = next(_decoder(binary, address).disasm(
            data[line_offset:line_offset + 16], address, count=1,
        ), None)
        actual = (
            f"{instruction.mnemonic}" + (f" {instruction.op_str}" if instruction.op_str else "")
            if instruction is not None else None
        )
        if actual != match.group(2):
            raise ValueError(f"ELF source instruction at 0x{address:x} does not match canonical disassembly")
        next_address = address + instruction.size


def make_elf_evidence_tools(rootfs: Path, sources=None):
    from fmst_basic.agent.tool import tool
    from .target_identity import resolve_symlink_chain_in_rootfs

    rootfs = rootfs.resolve()
    cache = {}

    def load(path: str):
        import lief

        chain = resolve_symlink_chain_in_rootfs(rootfs, path.lstrip("/"))
        if chain is None:
            raise ValueError("ELF path is missing or escapes rootfs")
        relative = chain[-1]
        if relative not in cache:
            binary = lief.parse(str(rootfs / relative))
            if not isinstance(binary, lief.ELF.Binary):
                raise ValueError("source is not an ELF")
            cache[relative] = binary
        return cache[relative]

    @tool
    def inspect_elf(path: str, symbol_query: str = "", string_query: str = "") -> dict:
        """Read ELF layout and exact symbol/string matches without host commands.

        Use for initialization ELF launchers. Symbol matches locate functions;
        string matches locate data, never prove execution or a launch edge.
        All matches are returned. Empty queries request layout only. The
        corresponding read_elf tool returns address-bounded instructions/data.

        Args:
            path: Guest rootfs-relative ELF path, including guest symlink aliases.
            symbol_query: Case-sensitive symbol-name substring; empty omits symbols.
            string_query: Exact UTF-8 string bytes to find; empty omits string search.
        """
        binary = load(path)
        symbols = {(symbol.name, int(symbol.value), int(symbol.size)) for symbol in binary.symbols
                   if symbol_query and symbol_query in symbol.name}
        matches = []
        if string_query:
            needle = string_query.encode("utf-8")
            for section in binary.sections:
                data = bytes(section.content)
                offset = data.find(needle)
                while offset >= 0:
                    matches.append({"location": f"{section.name}+0x{offset:x}",
                                    "address": f"0x{int(section.virtual_address) + offset:x}",
                                    "text": string_query})
                    offset = data.find(needle, offset + 1)
        return {
            "machine": str(binary.header.machine_type), "entrypoint": f"0x{binary.entrypoint:x}",
            "sections": [{"name": section.name, "address": f"0x{section.virtual_address:x}", "size": section.size}
                         for section in binary.sections],
            "symbols": [{"name": name, "address": f"0x{address:x}", "size": size}
                        for name, address, size in sorted(symbols)],
            "string_matches": matches,
        }

    @tool
    def read_elf(path: str, location: str, byte_count: int = 128) -> dict:
        """Read a bounded ELF byte range and canonical Capstone assembly.

        source_snippet is ready for exact citation, including hex-prefixed data
        for tables/non-text bytes. Metadata reports undecoded bytes and remaining
        section bytes. Unsupported decoding is an evidence gap; do not invent a
        decoder. This reads files, never runs guest code or host subprocesses.

        Args:
            path: Guest rootfs-relative ELF path.
            location: Virtual address 0xADDR or section-relative .section+0xOFFSET.
            byte_count: Explicit requested range, 1..4096 bytes; use symbol sizes when known.
        """
        excerpt = read_excerpt(load(path), location, byte_count)
        excerpt["source_snippet"] = {
            "path": path.lstrip("/"), "location": location,
            "text": excerpt["assembly"] or "hex:" + excerpt["bytes_hex"],
        }
        if sources is not None:
            excerpt["source_snippet"] = sources.reference(excerpt["source_snippet"])
        return excerpt

    return [inspect_elf, read_elf]
