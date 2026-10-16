"""Static image provenance and address/decoder boundaries use synthetic ELFs."""

import asyncio
import hashlib
import json
from pathlib import Path
import struct
import subprocess

import pytest

from fmst_analyzer.runner.agent import RuntimeEvidenceState, make_runner_tools
from fmst_analyzer.runner.budget import ExecutionBudget, RunnerStopped
from fmst_analyzer.runner.elf_inspection import inspect_elf, read_elf, render_static_inspection
from fmst_analyzer.runner.emulator_inspection import inspect_emulator
from fmst_analyzer.runner.runtime_builder import DockerRuntimeBuilder, HostRuntimeBuilder


def fixture(tmp_path, wide=False, endian='<', machine=8, flags=0x70001007):
    root = tmp_path / 'rootfs'
    root.mkdir(exist_ok=True)
    ident = b'\x7fELF' + bytes([2 if wide else 1, 1 if endian == '<' else 2, 1]) + bytes(9)
    hsize, psize = (64, 56) if wide else (52, 32)
    header = struct.pack(endian + ('HHIQQQIHHHHHH' if wide else 'HHIIIIIHHHHHH'),
        3, machine, 1, 0x4000, hsize, 0, flags, hsize, psize, 1, 0, 0, 0)
    ph = struct.pack(endian + ('IIQQQQQQ' if wide else 'IIIIIIII'),
        *( (1, 5, hsize + psize, 0x4000, 0, 16, 32, 4) if wide else (1, hsize + psize, 0x4000, 0, 16, 32, 5, 4)))
    code = bytes.fromhex('0a28257e802004002120040201004224')
    if endian == '>':
        code = b''.join(code[i:i+4][::-1] for i in range(0, len(code), 4))
    path = root / 'image'
    path.write_bytes(ident + header + ph + code)
    return root, path


@pytest.mark.parametrize('wide,endian', [(False, '<'), (False, '>'), (True, '<'), (True, '>')])
def test_file_identity_mapping_endian_and_isa_groups(tmp_path, wide, endian):
    root, path = fixture(tmp_path, wide, endian)
    result = inspect_elf(root, tmp_path, path='/image', operation='bytes', address='0x4000', byte_count=16)
    assert result['status'] == 'ok'
    assert result['source']['sha256'] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert Path(result['source']['snapshot']).read_bytes() == path.read_bytes()
    assert result['elf']['class_bits'] == (64 if wide else 32)
    assert result['elf']['byte_order'] == ('little' if endian == '<' else 'big')
    assert result['bytes']['file_offset'] == hex((64 + 56) if wide else (52 + 32))
    assert result['elf']['segments'][0]['permissions'] == 'r-x'
    if not wide:
        decoded = inspect_elf(root, tmp_path, path='/image', operation='disassemble', address='0x4000', byte_count=16)
        assert decoded['status'] == 'ok' and decoded['decoded_bytes'] == 16
        assert decoded['decoder']['mode'] == 'mips32'
        first = decoded['instructions'][0]
        assert first['mnemonic'] == 'lwx' and any(g['name'] == 'dsp' for g in first['groups'])
        assert json.loads(Path(decoded['receipt_path']).read_text()) == decoded


def test_guest_absolute_symlinks_and_traversal(tmp_path):
    root, path = fixture(tmp_path)
    (root / 'link').symlink_to('/image')
    result = inspect_elf(root, tmp_path, path='/link')
    assert result['status'] == 'ok' and result['source']['resolved_guest_path'] == '/image'
    (root / 'escape').symlink_to('../../outside')
    assert inspect_elf(root, tmp_path, path='/escape')['status'] == 'unavailable'
    (root / 'loop').symlink_to('/loop')
    assert 'loop' in inspect_elf(root, tmp_path, path='/loop')['error']


def test_source_continuation_never_decodes_changed_file(tmp_path, monkeypatch):
    root, path = fixture(tmp_path)
    prior = inspect_elf(root, tmp_path, path='/image')
    path.write_bytes(b'changed')
    monkeypatch.setattr('fmst_analyzer.runner.elf_inspection.read_elf', lambda *a: pytest.fail('changed source parsed'))
    result = inspect_elf(root, tmp_path, path='/image', source_sha256=prior['source']['sha256'])
    assert result['status'] == 'source_changed'
    assert Path(result['source']['snapshot']).read_bytes() == b'changed'


def test_bss_unknown_offsets_and_ambiguous_loads(tmp_path):
    root, path = fixture(tmp_path)
    bss = inspect_elf(root, tmp_path, path='/image', operation='bytes', address='0x4010', byte_count=4)
    assert bss['status'] == 'unavailable' and 'BSS' in bss['error'] and 'bytes' not in bss
    offset = inspect_elf(root, tmp_path, path='/image', operation='disassemble', address='0', address_space='file', byte_count=4)
    assert offset['status'] == 'unavailable' and offset['bytes']['static_virtual_address'] is None
    beyond = inspect_elf(root, tmp_path, path='/image', operation='bytes', address='9999', address_space='file')
    assert 'beyond' in beyond['error']
    data = bytearray(path.read_bytes())
    data[44:46] = struct.pack('<H', 2)
    first = struct.pack('<IIIIIIII', 1, 116, 0x4000, 0, 16, 32, 5, 4)
    path.write_bytes(data[:52] + first + first + data[84:])
    assert 'unique' in inspect_elf(root, tmp_path, path='/image', operation='bytes', address='0x4000', byte_count=4)['error']


@pytest.mark.parametrize('mutation', ['truncated', 'small_ph', 'big_table', 'bad_segment', 'bad_mem'])
def test_malformed_file_intervals(tmp_path, mutation):
    root, path = fixture(tmp_path)
    data = bytearray(path.read_bytes())
    if mutation == 'truncated':
        data = data[:20]
    elif mutation == 'small_ph':
        data[42:44] = struct.pack('<H', 1)
    elif mutation == 'big_table':
        data[44:46] = struct.pack('<H', 40000)
    elif mutation == 'bad_segment':
        data[68:72] = struct.pack('<I', 999999)
    else:
        data[72:76] = struct.pack('<I', 1)
    path.write_bytes(data)
    assert inspect_elf(root, tmp_path, path='/image')['status'] == 'unavailable'


def test_interp_mips_abi_and_extended_phnum(tmp_path):
    root, path = fixture(tmp_path)
    ident = path.read_bytes()[:16]
    # Extended count in section zero; three PHs include PT_INTERP and ABI flags.
    header = struct.pack('<HHIIIIIHHHHHH', 3, 8, 1, 0, 52, 52+96, 0x70001007, 52, 32, 0xffff, 40, 1, 0)
    start = 52+96+40
    interp = b'/lib/ld.so\0'
    abi = struct.pack('<H6B4I', 0, 32, 2, 1, 1, 0, 1, 0, 3, 0, 0)
    phs = struct.pack('<IIIIIIII', 1, start, 0x4000, 0, len(interp)+24, 64, 4, 4)
    phs += struct.pack('<IIIIIIII', 3, start, 0, 0, len(interp), len(interp), 4, 1)
    phs += struct.pack('<IIIIIIII', 0x70000003, start+len(interp), 0, 0, 24, 24, 4, 8)
    sh0 = struct.pack('<IIIIIIIIII', 0, 0, 0, 0, 0, 0, 0, 3, 0, 0)
    path.write_bytes(ident + header + phs + sh0 + interp + abi)
    result = inspect_elf(root, tmp_path, path='/image')
    assert result['status'] == 'ok' and result['elf']['program_header_count'] == 3
    assert result['elf']['interpreter'] == '/lib/ld.so'
    assert result['elf']['mips_abi_flags'][0]['ases'] == 3


def test_decoder_unknown_and_explicit_state_are_not_guessed(tmp_path):
    root, path = fixture(tmp_path, machine=40, flags=0)
    result = inspect_elf(root, tmp_path, path='/image', operation='disassemble', address='0x4000', byte_count=4, decoder_mode='thumb')
    assert result['decoder']['mode'] == 'thumb'
    data = bytearray(path.read_bytes()); data[18:20] = struct.pack('<H', 999); path.write_bytes(data)
    result = inspect_elf(root, tmp_path, path='/image', operation='disassemble', address='0x4000', byte_count=4)
    assert result['status'] == 'unavailable' and result['bytes']['length'] == 4
    data[18:20] = struct.pack('<H', 8); data[36:40] = struct.pack('<I', 0x74001007); path.write_bytes(data)
    assert 'MIPS16' in inspect_elf(root, tmp_path, path='/image', operation='disassemble', address='0x4000', byte_count=4)['error']


@pytest.mark.parametrize('flags,mode', [(0x70000000, 'mips32'), (0x30000000, 'mips64'),
    (0x80000000, 'mips64'), (0x90000000, 'mips32r6'), (0x72000000, 'micromips')])
def test_mips_decoder_uses_elf_isa_flags_even_with_32_bit_container(tmp_path, flags, mode):
    from fmst_analyzer.runner.elf_inspection import decoder_for
    root, path = fixture(tmp_path, flags=flags)
    _, description = decoder_for(read_elf(path), 'auto')
    assert description['mode'] == mode


def test_mips64r6_is_explicitly_unavailable_not_decoded_as_older_isa(tmp_path):
    root, _ = fixture(tmp_path, wide=True, flags=0xa0000000)
    result = inspect_elf(root, tmp_path, path='/image', operation='disassemble', address='0x4000', byte_count=4)
    assert result['status'] == 'unavailable' and 'MIPS64R6' in result['error'] and 'decoder' not in result


def test_cancellation_receipt_and_lossless_render(tmp_path):
    root, _ = fixture(tmp_path)
    budget = ExecutionBudget(60); budget.cancelled.set()
    with pytest.raises(RunnerStopped):
        inspect_elf(root, tmp_path, path='/image', budget=budget)
    result = json.loads(next((tmp_path/'elf-inspections').glob('*/receipt.json')).read_text())
    assert result['status'] == 'stopped'
    result['large'] = 'x' * 30000
    rendered = json.loads(render_static_inspection(result))
    assert 'receipt_path' in rendered and 'output_notice' in rendered and 'large' not in rendered


class FakeBuilder:
    def list_cpu_models(self, harness):
        return subprocess.CompletedProcess(['fixed', str(harness)], 1, 'Available CPUs:\n TestCPU\n', '')


def test_actual_harness_source_hash_and_containment(tmp_path):
    harness = tmp_path/'release'/'harness'; harness.parent.mkdir(); harness.write_bytes(b'harness')
    root = harness.parent/'qemu-libafl-bridge'; root.mkdir()
    source = root/'cpu-defs.c.inc'; source.write_text('one\ntwo\nthree\n')
    result = inspect_emulator(harness, tmp_path, builder=FakeBuilder())
    assert result['status'] == 'query_completed' and result['returncode'] == 1
    sha = result['harness']['sha256']
    rejected = inspect_emulator(harness, tmp_path, builder=FakeBuilder(), execution_harness_sha256='0'*64)
    assert rejected['status'] == 'source_changed' and 'executed runtime bundle' in rejected['error']
    found = inspect_emulator(harness, tmp_path, builder=FakeBuilder(), operation='find_source', name='cpu-defs.c.inc', harness_sha256=sha)
    assert found['paths'] == ['cpu-defs.c.inc']
    result = inspect_emulator(harness, tmp_path, builder=FakeBuilder(), operation='read_source', source_path='cpu-defs.c.inc', start=1, limit=1)
    assert result['lines'] == [{'line': 2, 'text': 'two'}] and result['next_start'] == 2
    source.write_text('changed')
    assert inspect_emulator(harness, tmp_path, builder=FakeBuilder(), operation='read_source', source_path='cpu-defs.c.inc', source_sha256=result['source']['sha256'])['status'] == 'source_changed'
    assert inspect_emulator(harness, tmp_path, builder=FakeBuilder(), operation='read_source', source_path='../harness')['status'] == 'unavailable'
    harness.write_bytes(b'changed')
    assert inspect_emulator(harness, tmp_path, builder=FakeBuilder(), harness_sha256=sha)['status'] == 'source_changed'


def test_native_tools_and_reset_use_exact_rootfs_and_latest_harness(tmp_path, monkeypatch):
    root, _ = fixture(tmp_path)
    state = RuntimeEvidenceState()
    tools = make_runner_tools(view=object(), rootfs=root, diagnostic_reports_root=tmp_path,
        intervention_manifest=tmp_path/'Cargo.toml', evidence_state=state, runtime_builder=FakeBuilder())
    elf = next(t for t in tools if t.name == 'inspect_static_elf')
    assert json.loads(asyncio.run(elf.ainvoke({'path': '/image'})))['status'] == 'ok'
    state.emulator_harness = tmp_path/'old'
    state.emulator_harness_sha256 = '0'*64
    state.reset()
    assert state.emulator_harness_sha256 is None
    cpu = next(t for t in tools if t.name == 'inspect_emulator_cpu')
    assert json.loads(asyncio.run(cpu.ainvoke({})))['status'] == 'unavailable'


def test_cpu_query_is_fixed_and_does_not_inherit_credentials(tmp_path, monkeypatch):
    received = []
    host = HostRuntimeBuilder()
    monkeypatch.setattr(host, '_process', lambda cmd, **kwargs: received.append((cmd, kwargs)))
    host.list_cpu_models(tmp_path/'harness')
    assert received[0][1]['env'] == {'QEMU_CPU': 'help'}
    docker = DockerRuntimeBuilder(image='test', project_root=tmp_path, workdir=tmp_path, platform_name='linux/amd64')
    monkeypatch.setattr(docker, '_run', lambda cmd, **kwargs: received.append((cmd, kwargs)))
    docker.list_cpu_models(tmp_path/'harness')
    assert received[1][0][:3] == ['env', '-i', 'QEMU_CPU=help']
    assert received[1][0][-4:] == ['--binary', '/workspace/workdir/harness', '--rootfs', '/nonexistent']


@pytest.mark.parametrize('stopped', [True, False])
def test_emulator_query_cancellation_or_timeout_preserves_receipt(tmp_path, stopped):
    harness=tmp_path/'harness'; harness.write_bytes(b'fixture')
    class Builder:
        def list_cpu_models(self, _):
            if stopped:
                raise RunnerStopped('user_cancelled')
            raise subprocess.TimeoutExpired(['fixed'], 20, output=b'partial CPU list', stderr=b'error')
    if stopped:
        with pytest.raises(RunnerStopped):
            inspect_emulator(harness,tmp_path,builder=Builder())
    else:
        inspect_emulator(harness,tmp_path,builder=Builder())
    result=json.loads(next((tmp_path/'emulator-inspections').glob('*/receipt.json')).read_text())
    assert result['status']==('stopped' if stopped else 'timeout')
    if not stopped:
        assert result['stdout']=='partial CPU list' and result['stderr']=='error'
