"""CLI help does not initialize IDA; an already loaded backend still closes."""
import builtins
import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def cli():
    spec = importlib.util.spec_from_file_location('cli_cleanup_test', Path(__file__).resolve().parents[1] / 'main.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_help_does_not_import_optional_ida_backend(monkeypatch):
    module = cli()
    monkeypatch.delitem(sys.modules, 'fmst_analyzer.nodes.decompiler.ida.idb_manager', raising=False)
    original = builtins.__import__
    def guarded(name, *args, **kwargs):
        if name == 'fmst_analyzer.nodes.decompiler.ida.idb_manager':
            pytest.fail('Help must not initialize the optional backend')
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', guarded)
    monkeypatch.setattr(sys, 'argv', ['main.py', '--help'])
    with pytest.raises(SystemExit) as outcome:
        module.main()
    assert outcome.value.code == 0


def test_help_closes_backend_already_initialized_by_caller(monkeypatch):
    module = cli()
    close = Mock()
    monkeypatch.setitem(sys.modules, 'fmst_analyzer.nodes.decompiler.ida.idb_manager',
                        SimpleNamespace(IDBManager=SimpleNamespace(close_current_idb=close)))
    monkeypatch.setattr(sys, 'argv', ['main.py', '--help'])
    with pytest.raises(SystemExit): module.main()
    close.assert_called_once_with()
