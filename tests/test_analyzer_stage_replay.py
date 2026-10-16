"""Run real CLI validation stages against current-schema persisted reports."""
import asyncio
import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest


@pytest.mark.parametrize("kind,package,stage_module,stage_name", [
    ("file", "file_resolver", "file_resolver", "file_resolver"),
    ("network", "network_analyzer", "network_analyzer", "network_analyzer"),
    ("process", "process_lifecycle", "process_lifecycle", "process_lifecycle"),
    ("init", "init_launch", "init_launch", "init_launch"),
    ("ipc", "ipc_analyzer", "ipc_analysis", "ipc_analysis"),
])
def test_current_result_runs_through_cli_validation(tmp_path, kind, package, stage_module, stage_name):
    fixture_root = Path(__file__).parent / "fixtures/g2_integrity"
    manifest = json.loads((fixture_root / "manifest.json").read_text())
    entry = next(item for item in manifest["entries"] if item["path"] == f"{kind}_full.json")
    module, symbol = entry["model"].split(":")
    source_root = fixture_root.parent / entry.get("fixture_version", "g2_integrity")
    result = getattr(importlib.import_module(module), symbol).model_validate_json((source_root / entry["path"]).read_bytes())
    config = SimpleNamespace(workdir=tmp_path, agent_concurrency_limit=1,
                             target_diagnostic_reports_dir=lambda: tmp_path)
    if kind == "ipc":
        from fmst_analyzer.analysis.ipc_analyzer.reports import persist_result
        persist_result(result, tmp_path / "ipc_reports")
    else:
        classes = {"file": "FileResolver", "network": "NetworkAnalyzer", "process": "ProcessLifecycleAnalyzer", "init": "InitLaunchAnalyzer"}
        analyzer = getattr(importlib.import_module(f"fmst_analyzer.analysis.{package}.analyzer"), classes[kind])(config)
        analyzer.publish_reports(result)
    helpers = {"file": "file_resolver", "network": "network_analyzer", "process": "process_lifecycle", "init": "init_launch", "ipc": "ipc"}
    tester = SimpleNamespace(global_config=config, **{f"ensure_{helpers[kind]}_result": AsyncMock(return_value=result)})
    stage = getattr(importlib.import_module(f"fmst_analyzer.testing.stages.test_{stage_module}"), f"test_{stage_name}")
    success, detail = asyncio.run(stage(tester))
    assert success, detail
    from fmst_analyzer.analysis.base.input_provenance import ANALYZER_FILES, AnalysisInputs, publish_receipt, require_receipt
    source_kind = "init_launch" if kind == "init" else kind
    result_path = tmp_path / ANALYZER_FILES[source_kind]
    inputs = AnalysisInputs(stage=source_kind, phase="full", target_path="usr/sbin/httpd",
        target_sha256="1" * 64, rootfs_sha256="2" * 64, implementation_sha256="3" * 64, settings={})
    publish_receipt(result_path, result, inputs)
    preserved = {path: path.read_bytes() for path in (result_path, result_path.parent / "input_provenance.json",
                                                    result_path.parent / "input_provenance.md")}
    if kind == "ipc":
        persist_result(result, result_path.parent, persist_json=False)
    else:
        analyzer.publish_reports(result, persist_json=False)
    assert all(path.read_bytes() == content for path, content in preserved.items())
    require_receipt(result_path, result=result)
    success, detail = asyncio.run(stage(tester))
    assert success, detail
