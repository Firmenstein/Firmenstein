"""Deterministic core process attribution; fixtures are not real guest evidence."""
import json
import struct
from pathlib import Path

from fmst_analyzer.runner.runtime_dump import collect_runtime_dump


def core_bytes(pid=7, executable='/bin/service', tids=(7, 88), endian='<', machine=40):
    def note(kind, desc):
        return struct.pack(endian + 'III', 5, len(desc), kind) + b'CORE\0\0\0\0' + desc + b'\0' * (-len(desc) % 4)
    mips = machine == 8
    desc = bytearray(128 if mips else 124)
    struct.pack_into(endian + 'i', desc, 16 if mips else 12, pid)
    offset = 48 if mips else 44
    desc[offset:offset + len(executable)] = executable.encode()
    notes = note(3, desc)
    for tid in tids:
        status = bytearray(148)
        struct.pack_into(endian + 'i', status, 24, tid)
        notes += note(1, status)
    ident = b'\x7fELF' + bytes((1, 1 if endian == '<' else 2, 1)) + b'\0' * 9
    header = ident + struct.pack(endian + 'HHIIIIIHHHHHH', 4, machine, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    ph = struct.pack(endian + 'IIIIIIII', 4, 84, 0, 0, len(notes), len(notes), 0, 4)
    return header + ph + notes


def _fixture(tmp_path: Path):
    attempt, rootfs = tmp_path / 'attempt', tmp_path / 'rootfs'
    attempt.mkdir()
    (rootfs / 'bin').mkdir(parents=True)
    (rootfs / 'bin/service').write_bytes(b'guest static ELF fixture')
    (attempt / 'runtime_trace.json').write_text(json.dumps({
        'guest_arch': 'arm', 'byte_order': 'little', 'word_bits': 32,
        'host_pid': 7, 'origin_pid': 7, 'main_load_address': 0x10000, 'image_loads': [],
    }))
    (attempt / 'target-exit.json').write_text('{"pid":7,"tid":7,"exit_code":139}')
    (attempt / 'target.core').write_bytes(core_bytes())
    return attempt, rootfs


def collect(attempt, rootfs):
    path = collect_runtime_dump(attempt_dir=attempt, staged_rootfs=rootfs, executable_path='/bin/service',
        session_id='session', attempt_number=2, termination_reason='target_exit')
    return json.loads(path.read_text())


def test_complete_manifest_binds_notes_to_primary_target(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    manifest = collect(attempt, rootfs)
    assert manifest['schema_version'] == 2 and manifest['status'] == 'complete'
    assert manifest['pid'] == 7 and manifest['tid'] is None
    assert manifest['core_candidates'][0]['identity']['tids'] == [7, 88]
    assert manifest['core_candidates'][0]['association'] == 'target'
    assert (attempt / 'runtime-dump/guest.core').read_bytes() == core_bytes()
    assert (attempt / 'runtime-dump/guest.elf').read_bytes() == b'guest static ELF fixture'
    assert manifest['files']['runtime-dump/load-map.json']
    assert 'Uncaptured guest memory' in ' '.join(manifest['limitations'])


def test_peer_sorting_and_thread_ids_never_assign_target_identity(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    (attempt / 'a-peer.core').write_bytes(core_bytes(pid=88, executable='/bin/peer', tids=(88,)))
    manifest = collect(attempt, rootfs)
    assert manifest['status'] == 'complete'
    assert manifest['core_candidates'][0]['association'] == 'unverified'
    assert len(manifest['core_candidates']) == 2
    assert (attempt / 'runtime-dump/guest.core').read_bytes() == core_bytes()


def test_ambiguous_missing_or_mismatched_identity_is_partial(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    (attempt / 'other.core').write_bytes(core_bytes())
    assert collect(attempt, rootfs)['status'] == 'partial'
    (attempt / 'other.core').unlink()
    (attempt / 'target.core').write_bytes(core_bytes(executable='/bin/other'))
    manifest = collect(attempt, rootfs)
    assert manifest['status'] == 'partial' and manifest['pid'] is None
    assert manifest['core_path'] is None and not (attempt / 'runtime-dump/guest.elf').exists()


def test_basename_load_event_never_claims_a_resolved_library(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    (rootfs / 'libguest.so').write_bytes(b'unbound same basename')
    trace = json.loads((attempt / 'runtime_trace.json').read_text())
    trace['image_loads'] = [{'detail': 'libguest.so@0x40800000'}]
    (attempt / 'runtime_trace.json').write_text(json.dumps(trace))
    manifest = collect(attempt, rootfs)
    assert any('basename has no bound guest path' in s for s in manifest['missing'])
    assert not any('/images/' in p for p in manifest['files'])


def test_collected_guest_cwd_core_and_collection_failure_are_retained(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    (attempt / 'collected-cores').mkdir()
    (attempt / 'target.core').rename(attempt / 'collected-cores/0000.core')
    (attempt / 'core-collection.json').write_text(json.dumps({'candidates': [{'guest_path': '/changed/cwd/target.core'}], 'errors': ['another copy failed']}))
    manifest = collect(attempt, rootfs)
    assert manifest['status'] == 'partial'
    assert manifest['core_path'] and 'another copy failed' in manifest['errors']
    assert manifest['files']['runtime-dump/core-collection.json']


def test_missing_core_is_explicit_stall_capture(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    (attempt / 'target.core').unlink()
    path = collect_runtime_dump(attempt_dir=attempt, staged_rootfs=rootfs, executable_path='/bin/service',
        session_id='session', attempt_number=3, termination_reason='no_progress_watchdog')
    manifest = json.loads(path.read_text())
    assert manifest['status'] == 'unavailable' and manifest['capture_kind'] == 'stall_capture'


def test_invalid_core_is_preserved_without_claiming_captured_memory(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    (attempt / 'target.core').write_bytes(b'not an ELF core')
    manifest = collect(attempt, rootfs)
    assert manifest['status'] == 'partial' and manifest['core_path'] is None
    assert (attempt / manifest['core_candidates'][0]['path']).read_bytes() == b'not an ELF core'
    assert any('rejected' in error for error in manifest['errors'])


def test_mips_big_endian_note_identity_uses_its_uid_layout(tmp_path):
    attempt, rootfs = _fixture(tmp_path)
    trace = json.loads((attempt / 'runtime_trace.json').read_text())
    trace.update(guest_arch='mipsbe', byte_order='big')
    (attempt / 'runtime_trace.json').write_text(json.dumps(trace))
    (attempt / 'target.core').write_bytes(core_bytes(endian='>', machine=8))
    manifest = collect(attempt, rootfs)
    assert manifest['status'] == 'complete' and manifest['pid'] == 7


def test_core_collection_uses_changed_container_paths_and_retains_copy_failure(tmp_path):
    import subprocess
    from fmst_analyzer.runner.docker_sandbox import DockerRootfsSandbox
    box = object.__new__(DockerRootfsSandbox)
    commands = []
    def process(command, **kwargs):
        commands.append(command)
        if command[1] == 'diff':
            return subprocess.CompletedProcess(command, 0, 'A /changed cwd/guest.core\nA /other/peer.core\nD /deleted.core\nC /normal.txt\n', '')
        if 'changed cwd' in command[2]:
            Path(command[3]).write_bytes(core_bytes())
            return subprocess.CompletedProcess(command, 0, '', '')
        return subprocess.CompletedProcess(command, 1, '', 'controlled copy failure')
    box._process = process
    box._collect_container_cores('owned-container', tmp_path)
    receipt = json.loads((tmp_path / 'core-collection.json').read_text())
    assert len(receipt['candidates']) == 2 and receipt['errors']
    assert commands[1][2] == 'owned-container:/changed cwd/guest.core'
    assert (tmp_path / 'collected-cores/0000.core').read_bytes() == core_bytes()
