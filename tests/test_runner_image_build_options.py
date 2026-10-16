"""Public image setup validates inputs before Docker and leaves limits optional."""
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def builder(name):
    path = Path(__file__).resolve().parents[1] / 'docker/runner-agent' / name
    spec = importlib.util.spec_from_file_location('image_options_test', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    monkeypatch.delenv('FMST_RUNNER_DOCKER_HOST', raising=False)
    monkeypatch.delenv('FMST_RUNNER_RUNTIME_INPUTS', raising=False)
    delivery = tmp_path / 'delivery'
    delivery.mkdir()
    (delivery / 'DELIVERY.json').write_text('{}')
    module = builder('build-runtime-image.py')
    arguments = ['--engine', 'fixture', '--build-engine', 'fixture',
                 '--delivery', str(delivery), '--output', str(tmp_path / 'output')]
    return module, arguments


def test_missing_runtime_inputs_fail_before_output_or_docker(tmp_path, capsys, monkeypatch):
    module = builder('build-runtime-image.py')
    for key in ('FMST_RUNNER_DOCKER_HOST', 'FMST_RUNNER_RUNTIME_INPUTS'):
        monkeypatch.delenv(key, raising=False)
    output = tmp_path / 'output'
    with pytest.raises(SystemExit) as failure:
        module.parse_args(['--output', str(output)])
    assert failure.value.code == 2
    assert 'FMST_RUNNER_DOCKER_HOST' in capsys.readouterr().err
    with pytest.raises(SystemExit):
        module.parse_args(['--engine', 'fixture', '--output', str(output)])
    assert 'FMST_RUNNER_RUNTIME_INPUTS' in capsys.readouterr().err
    assert not output.exists()


def test_unprepared_delivery_has_a_setup_error(runtime, tmp_path, capsys):
    module, arguments = runtime
    (tmp_path / 'delivery/DELIVERY.json').unlink()
    with pytest.raises(SystemExit):
        module.parse_args(arguments)
    assert 'DELIVERY.json' in capsys.readouterr().err
    assert not (tmp_path / 'output').exists()


@pytest.mark.parametrize('flag,value', [('--cpus', '0'), ('--pids-limit', '-1'),
                                      ('--jobs', '0'), ('--min-free-gib', '-1')])
def test_invalid_optional_limits_fail_during_parsing(runtime, flag, value):
    module, arguments = runtime
    with pytest.raises(SystemExit):
        module.parse_args(arguments + [flag, value])


def test_docker_limits_are_only_added_when_requested(runtime):
    module, arguments = runtime
    defaults = module.parse_args(arguments)
    command = module.build_container_command(['docker'], 'build', 'tooling', defaults)
    assert not {'--memory', '--memory-swap', '--cpus', '--pids-limit'} & set(command)
    assert defaults.jobs is defaults.min_free_gib is None
    assert command[-6:] == ['--network', 'none', '--entrypoint', '/bin/sleep', 'tooling', 'infinity']
    selected = module.parse_args(arguments + ['--memory', '8g', '--cpus', '2',
                                              '--pids-limit', '1024', '--jobs', '3'])
    command = module.build_container_command(['docker'], 'build', 'tooling', selected)
    assert command[command.index('--memory') + 1] == '8g'
    assert command[command.index('--memory-swap') + 1] == '8g'
    assert command[command.index('--cpus') + 1] == '2.0'
    assert command[command.index('--pids-limit') + 1] == '1024'


class Buffer(io.BytesIO):
    def close(self): pass


class Process:
    def __init__(self): self.stdin = Buffer()
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def wait(self): return 0


@pytest.mark.parametrize('jobs', [None, 3])
def test_runtime_build_preserves_requested_parallelism_and_has_no_default_disk_reserve(
        runtime, tmp_path, monkeypatch, jobs):
    module, arguments = runtime
    import dotenv
    from fmst_analyzer import framework
    root = tmp_path / 'framework'
    (root / 'tools').mkdir(parents=True)
    (root / 'dependencies').mkdir()
    pins = {name: {'repository': 'fixture', 'commit': name} for name in ('qemu', 'libvharness')}
    (root / 'dependencies/linux-runtime.json').write_text(json.dumps({'sources': pins}))
    (root / 'tools/offline.py').write_text('def verify(path):\n    return ' + repr({'sources': pins, 'delivery_id': 'fixture'}) + '\n')
    (root.parent / 'lib/LibAFL').mkdir(parents=True)
    monkeypatch.setattr(framework, 'runtime_workspace', lambda config: root)
    monkeypatch.setattr(dotenv, 'load_dotenv', lambda *_: None)
    monkeypatch.setattr(module.shutil, 'disk_usage', lambda *_: pytest.fail('No caller disk reserve was requested'))
    monkeypatch.setattr(module, 'copy', lambda *_ , **kwargs: None)
    monkeypatch.setattr(module.subprocess, 'Popen', lambda *args, **kwargs: Process())
    monkeypatch.setattr(module.subprocess, 'check_output', lambda *args, **kwargs: 'fixture-image')
    commands = []
    def run(command, **kwargs):
        commands.append(command)
        if 'cp' in command:
            (tmp_path / 'output/payload/runtime.json').write_text('{}')
        return SimpleNamespace(returncode=0, stdout='fixture-image')
    monkeypatch.setattr(module.subprocess, 'run', run)
    monkeypatch.setattr(module.sys, 'argv', ['build-runtime-image'] + arguments + ([] if jobs is None else ['--jobs', str(jobs)]))
    module.main()
    execution = next(command for command in commands if module.BUILD in command)
    assert execution[-1] == (module.BUILD if jobs is None else str(jobs))
    receipt = json.loads((tmp_path / 'output/receipt.json').read_text())
    assert receipt['build_options']['jobs'] == jobs
    assert receipt['pushed'] is False


def test_private_image_has_no_implicit_retained_service_disk_threshold(tmp_path, monkeypatch):
    module = builder('build-private-image.py')
    import dotenv
    monkeypatch.setattr(dotenv, 'load_dotenv', lambda *_: None)
    monkeypatch.setattr(module, 'select_user_files', lambda *_: {})
    monkeypatch.setattr(module, 'stream_context', lambda *_: None)
    monkeypatch.setattr(module.shutil, 'disk_usage', lambda *_: pytest.fail('No caller disk reserve was requested'))
    monkeypatch.setattr(module.subprocess, 'Popen', lambda *args, **kwargs: Process())
    monkeypatch.setattr(module.subprocess, 'run', lambda command, **kwargs:
        SimpleNamespace(stdout='[]' if 'info' in command else 'fixture-image', returncode=0))
    receipt = tmp_path / 'build.json'
    monkeypatch.setattr(sys, 'argv', ['build-private-image', '--ida-dir', str(tmp_path),
        '--engine', 'fixture', '--build-engine', 'fixture', '--receipt', str(receipt)])
    module.main()
    record = json.loads(receipt.read_text())
    assert record['required_disk_free_bytes'] is None
    assert record['pushed'] is False
