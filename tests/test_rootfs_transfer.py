"""Rootfs metadata and opt-in real GNU tar/Rootless transport regression."""
import copy
import json
import os
import socket
import subprocess
import uuid
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner.task import rootfs_metadata as metadata
from fmst_analyzer.runner.task import rootfs_transfer as transfer
from fmst_analyzer.runner.task.host import docker


def test_manifest_preserves_link_identity_without_following_guest_links(tmp_path):
    root = tmp_path / 'root'; root.mkdir()
    outside = tmp_path / 'outside'; outside.mkdir()
    (outside / 'not-firmware').write_text('outside')
    (root / 'one').write_bytes(b'firmware')
    os.chmod(root / 'one', 0o4751)
    os.link(root / 'one', root / 'two')
    (root / 'absolute').symlink_to(outside, target_is_directory=True)
    (root / 'relative').symlink_to('one')
    result = metadata.manifest(root)['entries']
    assert set(result) == {'.', 'one', 'two', 'absolute', 'relative'}
    assert result['one']['mode'] == 0o4751
    assert result['one']['hardlink_group'] == result['two']['hardlink_group']
    assert result['absolute']['target'] == str(outside)
    assert result['relative']['target'] == 'one'


@pytest.mark.parametrize('field,value', [
    ('type', 'directory'), ('mode', 0o600), ('uid', 0), ('gid', 0),
    ('sha256', 'different'), ('hardlink_group', 'independent-copy'),
    ('xattrs', {}), ('mtime_ns', 0), ('size', 9),
])
def test_static_metadata_loss_is_reported(field, value):
    expected = {'entries': {'binary': {'type': 'file', 'mode': 0o755, 'uid': 1000,
        'gid': 1000, 'sha256': 'original', 'hardlink_group': 'binary',
        'xattrs': {'system.posix_acl_access': '010203'}, 'mtime_ns': 1234, 'size': 3}}}
    actual = copy.deepcopy(expected)
    actual['entries']['binary'][field] = value
    delta = metadata.differences(expected, actual)
    assert len(delta) == 1 and delta[0]['path'] == 'binary'
    assert delta[0]['expected'][field] != delta[0]['actual'][field]


def test_runtime_entries_must_not_be_replaced_with_placeholder_files():
    source = {'entries': {'dev/test': {'type': 'character', 'device': [1, 3]},
                          'run/socket': {'type': 'socket'}}}
    assert metadata.differences(source, {'entries': {}}) == []
    wrong = {'entries': {'dev/test': {'type': 'file'}}}
    assert metadata.differences(source, wrong) == [
        {'path': 'dev/test', 'expected': None, 'actual': {'type': 'file'}}]
    assert source['entries']['dev/test']['device'] == [1, 3]


def test_root_symlink_is_not_accepted_as_a_tree(tmp_path):
    (tmp_path / 'alias').symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match='not a symlink'):
        metadata.manifest(tmp_path / 'alias')


@pytest.fixture
def real_task(tmp_path):
    if os.getenv('FMST_RUN_ROOTFS_TRANSFER_INTEGRATION') != '1':
        pytest.skip('Set FMST_RUN_ROOTFS_TRANSFER_INTEGRATION=1 for the real task engine')
    security = json.loads(docker('info', '--format', '{{json .SecurityOptions}}', text=True).stdout)
    assert 'name=userns' in security and 'name=rootless' in security
    name = 'fmst-transfer-test-' + uuid.uuid4().hex
    image = os.getenv('FMST_RUNNER_AGENT_IMAGE', 'firmenstein/runner-agent:20261014-ida-private')
    identity = docker('run', '-d', '--name', name, '--network', 'none', '--memory', '256m',
        '--memory-swap', '256m', '--cpus', '1', '--pids-limit', '32',
        '--entrypoint', '/bin/sleep', image, '180', text=True).stdout.strip()
    try:
        yield SimpleNamespace(name=identity, output=tmp_path / 'receipt')
    finally:
        docker('rm', '-f', identity)


@pytest.mark.external
def test_real_roundtrip_retains_acl_xattr_links_modes_and_sparsity(tmp_path, real_task):
    root = tmp_path / 'source'; root.mkdir()
    (root / 'program').write_bytes(b'fixture')
    os.chmod(root / 'program', 0o4751)
    os.link(root / 'program', root / 'hardlink')
    (root / 'absolute').symlink_to('/bin/nonexistent-firmware-target')
    (root / 'relative').symlink_to('program')
    (root / '-C\nfile').write_bytes(b'literal filename')
    (root / 'sticky').mkdir()
    os.chmod(root / 'sticky', 0o1777)
    os.mkfifo(root / 'fifo', 0o640)
    (root / 'metadata').write_bytes(b'acl-and-xattr')
    os.setxattr(root / 'metadata', 'user.fmst', b'keep-this')
    subprocess.run(['setfacl', '-m', 'u:1234:r--', str(root / 'metadata')], check=True)
    with (root / 'sparse').open('wb') as stream:
        stream.seek(8 * 1024**2)
        stream.write(b'end')
    # A proc-fd path avoids AF_UNIX's short pathname limit in long pytest dirs.
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with socket.socket(socket.AF_UNIX) as endpoint:
            endpoint.bind(f'/proc/self/fd/{descriptor}/socket')
    finally:
        os.close(descriptor)
    before = metadata.manifest(root)
    result = transfer.transfer_rootfs(real_task, root)
    assert result['status'] == 'verified_with_runtime_entries'
    receipts = real_task.output / 'input-transfer/rootfs'
    runtime = json.loads((receipts / 'runtime-entries.json').read_text())
    assert runtime['entries'] == {'socket': before['entries']['socket']}
    for filename in ('received.json', 'work.json'):
        assert metadata.differences(before, json.loads((receipts / filename).read_text())) == []
    assert metadata.manifest(root) == before
    assert json.loads((receipts / 'receipt.json').read_text())['warnings'] == []
    paths = [transfer.DESTINATION + '/sparse', transfer.WORK + '/sparse']
    blocks = docker('exec', real_task.name, 'python', '-c',
        'import os,sys,json;print(json.dumps([os.stat(p).st_blocks*512 for p in sys.argv[1:]]))',
        *paths, text=True)
    assert all(size < 1024**2 for size in json.loads(blocks.stdout))
    docker('exec', '--user', 'runner', real_task.name, 'test', '-r', result['receipt'])


@pytest.mark.external
def test_real_receiver_failure_retains_both_exits_and_does_not_publish(tmp_path, real_task, monkeypatch):
    root = tmp_path / 'source'; root.mkdir()
    (root / 'payload').write_bytes(b'x' * 1024**2)
    original = transfer.tar_commands
    def broken(*args):
        pack, unpack = original(*args)
        return pack, unpack + ['--fmst-invalid-option']
    monkeypatch.setattr(transfer, 'tar_commands', broken)
    with pytest.raises(RuntimeError, match='receipt.json'):
        transfer.transfer_rootfs(real_task, root)
    output = real_task.output / 'input-transfer/rootfs'
    receipt = json.loads((output / 'receipt.json').read_text())
    assert receipt['status'] == 'error' and receipt['unpack_exit'] != 0
    assert receipt['pack_exit'] is not None
    assert (output / 'unpack.stderr').stat().st_size
    docker('exec', real_task.name, 'test', '!', '-e', transfer.DESTINATION)
    docker('exec', real_task.name, 'test', '!', '-e', transfer.WORK)


@pytest.mark.external
def test_real_destination_is_not_merged_or_followed(tmp_path, real_task):
    root = tmp_path / 'source'; root.mkdir()
    (root / 'new-file').write_bytes(b'new')
    docker('exec', real_task.name, 'mkdir', '-p', '/task/input', '/sentinel')
    docker('exec', real_task.name, 'ln', '-s', '/sentinel', transfer.DESTINATION)
    with pytest.raises(RuntimeError, match='receipt.json'):
        transfer.transfer_rootfs(real_task, root)
    docker('exec', real_task.name, 'test', '!', '-e', '/sentinel/new-file')


@pytest.mark.external
def test_real_lost_xattr_is_detected_even_when_both_tar_processes_succeed(tmp_path, real_task, monkeypatch):
    root = tmp_path / 'source'; root.mkdir()
    (root / 'metadata').write_bytes(b'unchanged-content')
    os.setxattr(root / 'metadata', 'user.fmst', b'keep-this')
    original = transfer._snapshot
    def lose_attribute(container, path, output):
        if output.name == 'received.json':
            docker('exec', container, 'python', '-c',
                   'import os,sys;os.removexattr(sys.argv[1],"user.fmst")', path + '/metadata')
        return original(container, path, output)
    monkeypatch.setattr(transfer, '_snapshot', lose_attribute)
    with pytest.raises(RuntimeError, match='receipt.json'):
        transfer.transfer_rootfs(real_task, root)
    output = real_task.output / 'input-transfer/rootfs'
    receipt = json.loads((output / 'receipt.json').read_text())
    assert receipt['status'] == 'error'
    assert receipt['pack_exit'] == receipt['unpack_exit'] == 0
    delta = json.loads((output / 'received-differences.json').read_text())
    assert [item['path'] for item in delta] == ['metadata']
    assert delta[0]['actual']['xattrs'] == {}
    docker('exec', real_task.name, 'test', '!', '-e', transfer.DESTINATION)
