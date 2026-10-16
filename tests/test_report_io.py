from pathlib import Path

from pydantic import BaseModel

from fmst_analyzer.analysis.base.report_io import write_model_json


class _Report(BaseModel):
    schema_version: int = 1
    value: str


def test_equivalent_model_is_republished_atomically(tmp_path: Path):
    path = tmp_path / "result.json"
    original = b'{"value":"same","schema_version":1}\n'
    path.write_bytes(original)

    write_model_json(path, _Report(value="same"))
    assert _Report.model_validate_json(path.read_text()) == _Report(value="same")
    assert path.read_bytes() != original


def test_changed_model_atomically_replaces_json(tmp_path: Path):
    path = tmp_path / "result.json"
    path.write_text('{"value":"old","schema_version":1}')

    write_model_json(path, _Report(value="new"))
    assert _Report.model_validate_json(path.read_text()) == _Report(value="new")
    assert list(tmp_path.glob("*.tmp")) == []
