"""Regressions for offline source transport and runtime dependency identity."""
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
import hashlib

import pytest

from fmst_analyzer.runner.task import runtime_inputs, host, inputs


def test_vendor_directory_named_target_is_source_not_build_cache(tmp_path, monkeypatch):
    script = Path(__file__).resolve().parents[1] / 'docker/runner-agent/build-runtime-image.py'
    spec = importlib.util.spec_from_file_location('image_builder_test', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / 'vendor'
    file = source / 'cc/src/target/generated.rs'
    file.parent.mkdir(parents=True)
    file.write_text('required crate source')

    class Buffer(io.BytesIO):
        def close(self):
            pass

    stream = Buffer()

    class Copy:
        stdin = stream
        stderr = io.BytesIO()
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def wait(self): return 0

    monkeypatch.setattr(module.subprocess, 'Popen', lambda *args, **kwargs: Copy())
    module.copy(['fixture'], 'container', source, '/opt/guestweave/vendor')
    stream.seek(0)
    with tarfile.open(fileobj=stream) as archive:
        assert archive.extractfile('opt/guestweave/vendor/cc/src/target/generated.rs').read() == file.read_bytes()


def test_runtime_rejects_libafl_drift_before_preparing_task(tmp_path, monkeypatch):
    framework = tmp_path / 'workspace/GuestWeave'
    framework.mkdir(parents=True)
    libafl = framework.parent / 'lib/LibAFL'
    libafl.mkdir(parents=True)
    source = libafl / 'lib.rs'
    source.write_text('original')
    metadata = {'framework_source_id': runtime_inputs.source_identity(framework),
                'libafl_source_id': runtime_inputs.source_identity(libafl)}
    source.write_text('different ABI')
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout=json.dumps(metadata))
    monkeypatch.setattr(host, 'docker', docker)
    with pytest.raises(ValueError, match='LibAFL'):
        runtime_inputs.prepare_runtime(SimpleNamespace(name='fixture'), framework, 'arm')
    assert len(calls) == 1


def test_missing_runtime_source_has_no_valid_identity(tmp_path):
    with pytest.raises(ValueError, match='missing'):
        runtime_inputs.source_identity(tmp_path / 'missing')


def test_missing_ida_dependency_is_recorded_without_blocking_evidence(tmp_path, monkeypatch):
    error = RuntimeError('Image IDA preflight failed')
    error.process_result = SimpleNamespace(returncode=1)
    def docker(*args, **kwargs):
        raise error
    monkeypatch.setattr(inputs, 'docker', docker)
    published = {}
    task = SimpleNamespace(name='fixture', output=tmp_path,
                           put_json=lambda path, value: published.update({path: value}))
    environment = inputs.image_analysis_environment(task)
    record = json.loads((tmp_path / 'image-analysis.json').read_text())
    assert record['status'] == 'unavailable' and record['returncode'] == 1
    assert published['/task/evidence/image-analysis.json'] == record
    assert environment['IDADIR'] == '/opt/ida'


def extension_module():
    path = Path(__file__).resolve().parents[1] / 'docker/runner-agent/extend-runtime-delivery.py'
    spec = importlib.util.spec_from_file_location('delivery_extension_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_vendor_extension_uses_all_exact_consumer_lock_versions(tmp_path):
    module = extension_module()
    locks = []
    for n, version in enumerate(('3.0.3', '3.0.4')):
        path = tmp_path / f'{n}.lock'
        path.write_text(f'[[package]]\nname="syn"\nversion="{version}"\n'
                        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                        f'checksum="{str(n)*64}"\n')
        locks.append(path)
    assert module.registry_packages(locks) == {('syn', '3.0.3'): '0'*64, ('syn', '3.0.4'): '1'*64}


def test_vendor_extension_rejects_conflicting_lock_checksums(tmp_path):
    module = extension_module()
    paths = []
    for n in range(2):
        path = tmp_path / f'{n}.lock'
        path.write_text('[[package]]\nname="syn"\nversion="3.0.4"\n'
                        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                        f'checksum="{str(n)*64}"\n')
        paths.append(path)
    with pytest.raises(ValueError, match='Conflicting'):
        module.registry_packages(paths)


def test_wrong_registry_archive_never_enters_vendor(tmp_path):
    module = extension_module()
    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def raise_for_status(self): pass
        def iter_bytes(self): yield b'wrong package contents'
    client = SimpleNamespace(stream=lambda *args: Response())
    checksum = hashlib.sha256(b'expected contents').hexdigest()
    with pytest.raises(ValueError, match='does not match lockfile'):
        module.add_crate(client, tmp_path, 'syn', '3.0.4', checksum)
    assert list(tmp_path.iterdir()) == []
