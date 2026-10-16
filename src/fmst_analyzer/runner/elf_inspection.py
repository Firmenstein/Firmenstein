"""Bounded static ELF evidence, independent of semantic onboarding and cores."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
from typing import Literal
import uuid

from .budget import ExecutionBudget, RunnerStopped
from .rootfs_actions import _guest_host_path


def snapshot_file(source: Path, destination: Path, budget: ExecutionBudget | None) -> str:
    if not source.is_file():
        raise ValueError('Evidence source must be a regular file')
    digest = hashlib.sha256()
    with source.open('rb') as reader, destination.open('wb') as writer:
        if not stat.S_ISREG(os.fstat(reader.fileno()).st_mode):
            raise ValueError('Evidence source must be a regular file')
        while chunk := reader.read(1024 * 1024):
            if budget is not None:
                budget.check()
            digest.update(chunk)
            writer.write(chunk)
    destination.chmod(0o444)
    return digest.hexdigest()


def read_elf(path: Path, budget: ExecutionBudget | None = None) -> dict:
    """Read file-backed headers only, validating every declared file interval."""
    size = path.stat().st_size
    with path.open('rb') as stream:
        def read_at(offset, length):
            if offset < 0 or length < 0 or offset + length > size:
                raise ValueError('ELF interval extends beyond the file')
            if budget is not None:
                budget.check()
            stream.seek(offset)
            data = stream.read(length)
            if len(data) != length:
                raise ValueError('ELF source changed while reading')
            return data

        ident = read_at(0, 16)
        if ident[:4] != b'\x7fELF' or ident[4] not in {1, 2} or ident[5] not in {1, 2} or ident[6] != 1:
            raise ValueError('Unsupported or invalid ELF identification')
        wide = ident[4] == 2
        endian = '<' if ident[5] == 1 else '>'
        h = struct.unpack(endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'), read_at(16, 48 if wide else 36))
        kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = h
        if version != 1 or ehsize < (64 if wide else 52):
            raise ValueError('Invalid ELF header version/size')
        # Extended phnum is carried by section header zero, not a real 65535-entry table.
        if phnum == 0xffff:
            section_format = endian + ('IIQQQQIIQQ' if wide else 'IIIIIIIIII')
            needed = struct.calcsize(section_format)
            if not shoff or shsize < needed:
                raise ValueError('Missing extended ELF program-header count')
            phnum = struct.unpack(section_format, read_at(shoff, needed))[7]
        needed = 56 if wide else 32
        if phnum and phsize < needed:
            raise ValueError('ELF program-header entry is too small')
        if phoff + phsize * phnum > size:
            raise ValueError('ELF program-header table extends beyond the file')
        segments = []
        metadata = {'class_bits': 64 if wide else 32, 'byte_order': 'little' if ident[5] == 1 else 'big',
            'machine': machine, 'type': kind, 'entry': hex(entry), 'flags': hex(flags),
            'osabi': ident[7], 'abi_version': ident[8], 'program_header_count': phnum,
            'segments': segments, 'interpreter': None, 'mips_abi_flags': []}
        for i in range(phnum):
            v = struct.unpack(endian + ('IIQQQQQQ' if wide else 'IIIIIIII'), read_at(phoff + i * phsize, needed))
            ptype, pflags, offset, va, pa, filesz, memsz, align = v if wide else (v[0], v[6], v[1], v[2], v[3], v[4], v[5], v[7])
            if offset + filesz > size:
                raise ValueError('ELF segment extends beyond the file')
            if ptype == 1 and (filesz > memsz or va + memsz > 1 << metadata['class_bits']):
                raise ValueError('Invalid ELF PT_LOAD memory interval')
            segments.append({'index': i, 'type': ptype, 'offset': offset, 'virtual_address': hex(va),
                'file_size': filesz, 'memory_size': memsz, 'flags': pflags,
                'permissions': ''.join(c if pflags & b else '-' for c, b in [('r', 4), ('w', 2), ('x', 1)]), 'alignment': align})
            if ptype == 3:
                if not 1 <= filesz <= 4096:
                    raise ValueError('Invalid PT_INTERP size')
                raw = read_at(offset, filesz)
                if raw[-1:] != b'\0':
                    raise ValueError('PT_INTERP is not terminated')
                metadata['interpreter'] = raw[:-1].decode('utf-8', errors='replace')
            if machine == 8 and ptype == 0x70000003:
                if filesz < 24:
                    raise ValueError('Incomplete MIPS ABI flags')
                values = struct.unpack(endian + 'H6B4I', read_at(offset, 24))
                names = ['version', 'isa_level', 'isa_revision', 'gpr_size', 'cpr1_size', 'cpr2_size',
                    'fp_abi', 'isa_extensions', 'ases', 'flags1', 'flags2']
                metadata['mips_abi_flags'].append(dict(zip(names, values)))
        return metadata


def decoder_for(metadata: dict, requested_mode: str):
    import capstone as cs
    endian = cs.CS_MODE_LITTLE_ENDIAN if metadata['byte_order'] == 'little' else cs.CS_MODE_BIG_ENDIAN
    machine, bits, flags = metadata['machine'], metadata['class_bits'], int(metadata['flags'], 0)
    if machine == 8:
        modes = {'mips32': cs.CS_MODE_MIPS32, 'mips64': cs.CS_MODE_MIPS64,
            'mips32r6': cs.CS_MODE_MIPS32R6, 'micromips': cs.CS_MODE_MIPS32 | cs.CS_MODE_MICRO}
        # ELF e_flags encodes architecture and compressed modes; conflicting
        # MIPS16 requires an explicit unsupported result, never a MIPS32 guess.
        if requested_mode == 'auto':
            if flags & 0x04000000:
                raise ValueError('MIPS16 automatic decoding is unavailable in Capstone; choose a supported mode only with independent evidence')
            arch_flags = flags & 0xf0000000
            if arch_flags == 0xa0000000:
                raise ValueError('MIPS64R6 automatic decoding is unavailable; headers and raw bytes remain evidence')
            requested_mode = 'micromips' if flags & 0x02000000 else 'mips32r6' if arch_flags == 0x90000000 else 'mips64' if bits == 64 or arch_flags in {0x20000000, 0x30000000, 0x40000000, 0x60000000, 0x80000000} else 'mips32'
        if requested_mode not in modes:
            raise ValueError('Unsupported MIPS decoder mode')
        arch, mode = cs.CS_ARCH_MIPS, modes[requested_mode] | endian
    elif machine == 40:
        requested_mode = 'arm' if requested_mode == 'auto' else requested_mode
        if requested_mode not in {'arm', 'thumb'}:
            raise ValueError('ARM decoding requires arm or thumb mode')
        arch, mode = cs.CS_ARCH_ARM, (cs.CS_MODE_ARM if requested_mode == 'arm' else cs.CS_MODE_THUMB) | endian
    elif machine == 183 and requested_mode in {'auto', 'aarch64'}:
        arch, mode, requested_mode = cs.CS_ARCH_ARM64, endian, 'aarch64'
    elif machine in {3, 62} and requested_mode in {'auto', 'x86', 'x86_64'}:
        requested_mode = ('x86_64' if machine == 62 else 'x86') if requested_mode == 'auto' else requested_mode
        arch, mode = cs.CS_ARCH_X86, cs.CS_MODE_64 if requested_mode == 'x86_64' else cs.CS_MODE_32
    else:
        raise ValueError('This ELF machine/decoder mode is unsupported; raw bytes and headers remain available')
    decoder = cs.Cs(arch, mode)
    decoder.detail = True
    return decoder, {'name': 'capstone', 'version': cs.__version__, 'architecture': arch,
        'mode': requested_mode, 'mode_bits': mode, 'byte_order': metadata['byte_order'],
        'selection': 'ELF header default or explicit request; ARM/Thumb execution state and mixed code/data are not inferred'}


def inspect_elf(rootfs: Path, output_root: Path, *, path: str,
    operation: Literal['metadata', 'bytes', 'disassemble'] = 'metadata',
    address: str = '', address_space: Literal['virtual', 'file'] = 'virtual',
    byte_count: int = 64, decoder_mode: str = 'auto', source_sha256: str | None = None,
    budget: ExecutionBudget | None = None,
) -> dict:
    if not path.startswith('/') or '\x00' in path:
        raise ValueError('path must be a guest absolute ELF path')
    if operation not in {'metadata', 'bytes', 'disassemble'} or address_space not in {'virtual', 'file'}:
        raise ValueError('Unsupported static ELF query')
    if isinstance(byte_count, bool) or not isinstance(byte_count, int) or not 1 <= byte_count <= 256:
        raise ValueError('byte_count must be between 1 and 256')
    if operation != 'metadata' and not re.fullmatch(r'0[xX][0-9a-fA-F]+|[0-9]+', address):
        raise ValueError('address must be an unsigned static ELF virtual address or file offset')
    output = output_root / 'elf-inspections' / uuid.uuid4().hex
    output.mkdir(parents=True)
    receipt = {'schema_version': 1, 'status': 'unavailable', 'receipt_path': str(output / 'receipt.json'),
        'request': {'path': path, 'operation': operation, 'address': address, 'address_space': address_space,
            'byte_count': byte_count, 'decoder_mode': decoder_mode}, 'source': {}, 'error': None,
        'limitations': ['All bytes are static file evidence, not captured runtime memory or proof that an instruction executed.',
            'A runtime address requires an independently supported image/load-bias association before conversion to static VA.',
            'Decoded instruction groups describe this decoder interpretation, not minimum CPU requirements or runtime feature support.']}
    try:
        if budget is not None:
            budget.check()
        source = _guest_host_path(rootfs, path, follow_final_symlink=True)
        if not source.is_file():
            raise ValueError('ELF path does not resolve to a regular file')
        snapshot = output / 'image.elf'
        sha = snapshot_file(source, snapshot, budget)
        receipt['source'] = {'guest_path': path, 'resolved_guest_path': '/' + source.relative_to(rootfs.resolve()).as_posix(),
            'host_path': str(source), 'snapshot': str(snapshot), 'sha256': sha, 'size': snapshot.stat().st_size}
        if source_sha256 is not None and source_sha256 != sha:
            receipt['status'] = 'source_changed'
            raise ValueError('ELF bytes differ from the requested source SHA-256')
        metadata = read_elf(snapshot, budget)
        receipt['elf'] = metadata
        if operation != 'metadata':
            location = int(address, 16 if address.lower().startswith('0x') else 10)
            if address_space == 'virtual':
                candidates = [s for s in metadata['segments'] if s['type'] == 1 and
                    int(s['virtual_address'], 0) <= location and location + byte_count <= int(s['virtual_address'], 0) + s['file_size']]
                if len(candidates) != 1:
                    raise ValueError('Static VA interval has no unique file-backed PT_LOAD mapping; BSS bytes are not supplied')
                segment = candidates[0]
                offset = segment['offset'] + location - int(segment['virtual_address'], 0)
                va = location
            else:
                offset = location
                if offset + byte_count > snapshot.stat().st_size:
                    raise ValueError('Requested bytes extend beyond the ELF file')
                candidates = [s for s in metadata['segments'] if s['type'] == 1 and
                    s['offset'] <= offset and offset + byte_count <= s['offset'] + s['file_size']]
                va = int(candidates[0]['virtual_address'], 0) + offset - candidates[0]['offset'] if len(candidates) == 1 else None
            with snapshot.open('rb') as stream:
                stream.seek(offset)
                data = stream.read(byte_count)
            receipt['bytes'] = {'file_offset': hex(offset), 'static_virtual_address': hex(va) if va is not None else None,
                'hex': data.hex(), 'length': len(data)}
            if operation == 'disassemble':
                if va is None:
                    raise ValueError('Disassembly at a file offset requires a unique PT_LOAD virtual-address mapping')
                import capstone as cs
                try:
                    decoder, receipt['decoder'] = decoder_for(metadata, decoder_mode)
                except cs.CsError as error:
                    raise ValueError(f'Capstone cannot initialize the requested decoder: {error}') from error
                instructions = []
                for insn in decoder.disasm(data, va):
                    if budget is not None:
                        budget.check()
                    instructions.append({'address': hex(insn.address), 'bytes': insn.bytes.hex(), 'size': insn.size,
                        'mnemonic': insn.mnemonic, 'operands': insn.op_str,
                        'groups': [{'id': group, 'name': insn.group_name(group)} for group in insn.groups]})
                receipt['instructions'] = instructions
                receipt['decoded_bytes'] = sum(i['size'] for i in instructions)
                receipt['undecoded_bytes'] = len(data) - receipt['decoded_bytes']
        receipt['status'] = 'ok'
    except RunnerStopped as error:
        receipt.update(status='stopped', error=str(error))
        raise
    except (OSError, ValueError, struct.error) as error:
        receipt['error'] = str(error)
    finally:
        (output / 'receipt.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    return receipt


def render_static_inspection(receipt: dict) -> str:
    text = json.dumps(receipt, ensure_ascii=False)
    if len(text) <= 24000:
        return text
    return json.dumps({'schema_version': receipt['schema_version'], 'status': receipt['status'],
        'receipt_path': receipt['receipt_path'], 'request': receipt['request'],
        'output_notice': 'Complete result exceeds the 24000-character transport budget; read receipt_path. No values were truncated.',
        'complete_output_chars': len(text)})
