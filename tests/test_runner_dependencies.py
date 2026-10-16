from pathlib import Path
import tomllib
import pytest
from fmst_analyzer.runner.dependencies import bind_guestweave_api


def test_disposable_dependency_binding_preserves_features_and_unrelated_paths(tmp_path):
    crate = tmp_path / 'crate'
    crate.mkdir()
    manifest = crate / 'Cargo.toml'
    manifest.write_text('[dependencies]\nfmst-iib-api = { path = "../../old/api", features = ["mock"] }\nother = { path = "../../old/api" }\n')
    original = manifest.read_bytes()
    record = bind_guestweave_api([crate], tmp_path / 'public')
    parsed = tomllib.loads(manifest.read_text())['dependencies']
    assert parsed['fmst-iib-api'] == {'path': str((tmp_path / 'public/fmst-iib-api').resolve()), 'features': ['mock']}
    assert parsed['other']['path'] == '../../old/api'
    assert record[0]['before_sha256'] != record[0]['after_sha256']
    assert bind_guestweave_api([crate], tmp_path / 'public', check_only=True) == []
    manifest.write_bytes(original)
    with pytest.raises(RuntimeError, match='Controller-selected'):
        bind_guestweave_api([crate], tmp_path / 'public', check_only=True)
    assert manifest.read_bytes() == original
