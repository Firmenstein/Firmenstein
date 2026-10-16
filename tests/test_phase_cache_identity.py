"""Persisted analyzer caches are keyed by their explicit phase."""
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock
import asyncio
import tempfile

import pytest
from pydantic import ValidationError
from dotenv import load_dotenv
from fmst_analyzer.analysis.base.finding_binding import FindingTarget

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fmst_analyzer.analysis.process_lifecycle.analyzer_schema import (
    ProcessLifecycleAnalysisResult,
)
from fmst_analyzer.analysis.network_analyzer.analyzer_schema import (
    NetworkAnalysisResult,
)
from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
    FileResolverResult,
)
from fmst_analyzer.testing.pipeline_tester import (
    PipelineTester,
    _cache_matches_phase,
)
from fmst_analyzer.analysis.base.input_provenance import ANALYZER_FILES, capture_inputs, publish_receipt


def _stamp_cache(tester, stage, result):
    phase = result.phase.value if hasattr(result.phase, "value") else result.phase
    inputs = capture_inputs(tester.global_config, stage, phase, tester.target_binary_path,
                            rootfs=getattr(tester, "fw_rootfs_path", None))
    publish_receipt(tester.global_config.target_diagnostic_reports_dir() / ANALYZER_FILES[stage], result, inputs)


def _results(phase: str):
    return [
        FileResolverResult(execution={"tasks": {}},
            schema_version=12, finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={},
            phase=phase,
            root_binary="httpd",
        ),
        NetworkAnalysisResult(execution={"tasks": {}}, schema_version=11, finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={}, phase=phase, root_binary="httpd"),
        ProcessLifecycleAnalysisResult(execution={"tasks": {}}, schema_version=5, finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={}, phase=phase, root_binary="httpd"),
    ]


def test_explicit_phase_matches_only_itself_even_when_output_is_empty():
    for result in _results("full"):
        assert _cache_matches_phase(result, "full")
        assert not _cache_matches_phase(result, "static")

    for result in _results("static"):
        assert _cache_matches_phase(result, "static")
        assert not _cache_matches_phase(result, "full")


def test_legacy_cache_without_phase_is_rejected():
    with pytest.raises(ValidationError):
        ProcessLifecycleAnalysisResult.model_validate({"root_binary": "httpd"})
    with pytest.raises(ValidationError):
        FileResolverResult.model_validate({"schema_version": 10, "root_binary": "httpd"})
    with pytest.raises(ValidationError):
        NetworkAnalysisResult.model_validate({"root_binary": "httpd"})


def test_index_renderers_expose_the_persisted_phase():
    from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
        FileResolverResult,
    )
    from fmst_analyzer.analysis.file_resolver.reports import (
        render_index as render_file,
    )
    from fmst_analyzer.analysis.process_lifecycle.reports import (
        render_index as render_host,
    )
    from fmst_analyzer.analysis.network_analyzer.reports import (
        render_index as render_network,
    )

    rendered = [
        render_file(FileResolverResult(execution={"tasks": {}},
            schema_version=12, finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={}, phase="static", root_binary="httpd",
        )),
        render_network(NetworkAnalysisResult(execution={"tasks": {}}, schema_version=11, finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={}, phase="static", root_binary="httpd")),
        render_host(ProcessLifecycleAnalysisResult(execution={"tasks": {}}, schema_version=5, finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64}, planning_findings={}, phase="static", root_binary="httpd")),
    ]

    for markdown in rendered:
        assert "- phase: `static`" in markdown


def test_file_resolver_helper_reuses_matching_disk_phase():
    from fmst_analyzer.analysis.file_resolver.reports import render_index

    with tempfile.TemporaryDirectory() as tmp:
        reports_root = Path(tmp)
        file_dir = reports_root / "file_reports"
        file_dir.mkdir()
        rootfs = reports_root / "rootfs"
        target = rootfs / "usr/sbin/httpd"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"synthetic target")
        expected = FileResolverResult(execution={"tasks": {}},
            schema_version=12, finding_target=FindingTarget.from_file(rootfs, target), planning_findings={},
            phase="static",
            root_binary="httpd",
        )
        (file_dir / "file_resolver_result.json").write_text(
            expected.model_dump_json(),
            encoding="utf-8",
        )
        original_json = (file_dir / "file_resolver_result.json").read_bytes()

        tester = object.__new__(PipelineTester)
        tester._file_resolver_result = {}
        tester.fw_rootfs_path = rootfs
        tester.target_binary_path = target
        tester.global_config = SimpleNamespace(
            workdir=reports_root,
            agent_concurrency_limit=1,
            target_diagnostic_reports_dir=lambda: reports_root,
        )
        tester.ensure_analysis_view = AsyncMock()

        _stamp_cache(tester, "file", expected)
        actual = asyncio.run(
            tester.ensure_file_resolver_result(phase="static")
        )
        assert actual == expected
        tester.ensure_analysis_view.assert_not_awaited()
        assert (file_dir / "index.md").read_text(
            encoding="utf-8"
        ) == render_index(expected)
        assert (file_dir / "file_resolver_result.json").read_bytes() == original_json


def test_ipc_helper_republishes_markdown_without_rewriting_json():
    from fmst_analyzer.analysis.ipc_analyzer import (
        IPCAnalysisResult,
        IPC_ANALYSIS_SCHEMA_VERSION,
    )
    from fmst_analyzer.analysis.ipc_analyzer.reports import render_index
    from fmst_analyzer.analysis.ipc_analyzer.schema import TargetProcess

    with tempfile.TemporaryDirectory() as tmp:
        reports_root = Path(tmp)
        reports_dir = reports_root / "ipc_reports"
        reports_dir.mkdir()
        rootfs = reports_root / "rootfs"
        target = rootfs / "usr/sbin/httpd"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"synthetic target")
        identity = FindingTarget.from_file(rootfs, target)
        expected = IPCAnalysisResult(execution={"tasks": {}},
            schema_version=IPC_ANALYSIS_SCHEMA_VERSION,
            phase="static",
            planning_findings={},
            firmware_sha256="a" * 64,
            target_process=TargetProcess(
                executable_path="usr/sbin/httpd",
                executable_sha256=identity.sha256,
                argv0="httpd",
            ),
            callsites=[],
            channels=[],
            dependency_assessments=[],
            unresolved_items=[],
            callsite_accounting=[],
        )
        result_path = reports_dir / "ipc_analysis_result.json"
        result_path.write_text(expected.model_dump_json(), encoding="utf-8")
        original_json = result_path.read_bytes()
        (reports_dir / "index.md").write_text("stale", encoding="utf-8")

        tester = object.__new__(PipelineTester)
        tester._ipc_result = {}
        tester.fw_rootfs_path = rootfs
        tester.target_binary_path = target
        tester.target_binary_name = "httpd"
        tester.firmware_sha256 = "a" * 64
        tester.global_config = SimpleNamespace(
            workdir=reports_root,
            target_diagnostic_reports_dir=lambda: reports_root,
        )
        tester.ensure_analysis_view = AsyncMock()

        _stamp_cache(tester, "ipc", expected)
        actual = asyncio.run(tester.ensure_ipc_result(phase="static"))
        assert actual == expected
        tester.ensure_analysis_view.assert_not_awaited()
        assert (reports_dir / "index.md").read_text(
            encoding="utf-8"
        ) == render_index(expected)
        assert result_path.read_bytes() == original_json


def test_network_helper_republishes_markdown_on_disk_cache_hit():
    from fmst_analyzer.analysis.network_analyzer.reports import render_index

    with tempfile.TemporaryDirectory() as tmp:
        reports_root = Path(tmp)
        reports_dir = reports_root / "network_reports"
        reports_dir.mkdir()
        rootfs = reports_root / "rootfs"
        target = rootfs / "usr/sbin/httpd"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"synthetic target")
        expected = NetworkAnalysisResult(execution={"tasks": {}}, schema_version=11, finding_target=FindingTarget.from_file(rootfs, target), planning_findings={}, phase="static", root_binary="httpd")
        (reports_dir / "network_analysis_result.json").write_text(
            expected.model_dump_json(), encoding="utf-8"
        )
        original_json = (reports_dir / "network_analysis_result.json").read_bytes()
        (reports_dir / "index.md").write_text("stale", encoding="utf-8")

        tester = object.__new__(PipelineTester)
        tester._network_analyzer_result = {}
        tester.fw_rootfs_path = rootfs
        tester.target_binary_path = target
        tester.global_config = SimpleNamespace(
            workdir=reports_root,
            agent_concurrency_limit=1,
            target_diagnostic_reports_dir=lambda: reports_root,
        )
        tester.ensure_analysis_view = AsyncMock()

        _stamp_cache(tester, "network", expected)
        actual = asyncio.run(
            tester.ensure_network_analyzer_result(phase="static")
        )
        assert actual == expected
        tester.ensure_analysis_view.assert_not_awaited()
        assert (reports_dir / "index.md").read_text(
            encoding="utf-8"
        ) == render_index(expected)
        assert (reports_dir / "network_analysis_result.json").read_bytes() == original_json


def test_process_helper_republishes_markdown_on_disk_cache_hit():
    from fmst_analyzer.analysis.process_lifecycle.reports import render_index

    with tempfile.TemporaryDirectory() as tmp:
        reports_root = Path(tmp)
        target = reports_root / "rootfs/usr/sbin/httpd"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"target fixture")
        reports_dir = reports_root / "process_lifecycle_reports"
        reports_dir.mkdir()
        expected = ProcessLifecycleAnalysisResult(execution={"tasks": {}},
            schema_version=5, finding_target=FindingTarget.from_file(reports_root / "rootfs", target), planning_findings={},
            phase="static", root_binary="httpd"
        )
        (reports_dir / "process_lifecycle_analysis_result.json").write_text(
            expected.model_dump_json(), encoding="utf-8"
        )
        original_json = (
            reports_dir / "process_lifecycle_analysis_result.json"
        ).read_bytes()
        (reports_dir / "index.md").write_text("stale", encoding="utf-8")

        tester = object.__new__(PipelineTester)
        tester._process_lifecycle_result = {}
        tester.fw_rootfs_path = reports_root / "rootfs"
        tester.target_binary_path = target
        tester.global_config = SimpleNamespace(
            workdir=reports_root,
            agent_concurrency_limit=1,
            target_diagnostic_reports_dir=lambda: reports_root,
        )
        tester.ensure_analysis_view = AsyncMock()

        _stamp_cache(tester, "process", expected)
        actual = asyncio.run(
            tester.ensure_process_lifecycle_result(phase="static")
        )
        assert actual == expected
        tester.ensure_analysis_view.assert_not_awaited()
        assert (reports_dir / "index.md").read_text(
            encoding="utf-8"
        ) == render_index(expected)
        assert (
            reports_dir / "process_lifecycle_analysis_result.json"
        ).read_bytes() == original_json


def test_init_launch_helper_republishes_markdown_on_disk_cache_hit():
    from fmst_analyzer.analysis.init_launch.analyzer_schema import (
        AnalysisGap,
        InitLaunchAnalysisResult,
    )
    from fmst_analyzer.analysis.init_launch.reports import render_index
    from fmst_analyzer.analysis.init_launch.target_identity import (
        enumerate_target_identity,
    )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        rootfs = root / "rootfs"
        target = rootfs / "usr/sbin/httpd"
        target.parent.mkdir(parents=True)
        target.write_bytes(b"ELF fixture")
        reports_root = root / "reports"
        reports_dir = reports_root / "init_launch_reports"
        reports_dir.mkdir(parents=True)
        expected = InitLaunchAnalysisResult(execution={"tasks": {}},
            schema_version=7, phase="full", initialization_roots=[], planning_findings={},
            finding_target=FindingTarget.from_file(rootfs, target),
            target_identity=enumerate_target_identity(rootfs, target),
            analysis_gaps=[AnalysisGap(reason="no concrete launch command")],
        )
        (reports_dir / "init_launch_analysis_result.json").write_text(
            expected.model_dump_json(), encoding="utf-8"
        )
        original_json = (
            reports_dir / "init_launch_analysis_result.json"
        ).read_bytes()
        (reports_dir / "index.md").write_text("stale", encoding="utf-8")

        tester = object.__new__(PipelineTester)
        tester._init_launch_result = {}
        tester.target_binary_path = target
        tester.global_config = SimpleNamespace(
            workdir=reports_root,
            fw_rootfs_path=rootfs,
            target_diagnostic_reports_dir=lambda: reports_root,
        )

        _stamp_cache(tester, "init_launch", expected)
        actual = asyncio.run(tester.ensure_init_launch_result())
        assert actual == expected
        assert (reports_dir / "index.md").read_text(
            encoding="utf-8"
        ) == render_index(expected)
        assert (
            reports_dir / "init_launch_analysis_result.json"
        ).read_bytes() == original_json
