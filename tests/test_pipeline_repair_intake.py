"""The production pipeline must reach the same repair intake as Runner stage."""
import asyncio
from importlib import import_module
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("counts", [(1, 0), (0, 1), (2, 1)])
@pytest.mark.parametrize("run_after_generation", [True, False])
def test_generation_candidate_reaches_runner_only_when_requested(tmp_path, monkeypatch, counts, run_after_generation):
    module = import_module("fmst_analyzer.FirmAnalyzer")
    planner = import_module("fmst_analyzer.synthesizer.intervention_plan_analyzer")
    generator = import_module("fmst_analyzer.synthesizer.intervention_generator")
    runner = import_module("fmst_analyzer.runner")
    calls = []

    class Stage:
        def __init__(self, *args, **kwargs): pass
        async def run(self, *args, **kwargs):
            return SimpleNamespace(not_ready_count=counts[0], skipped_count=counts[1])

    class Repair:
        def __init__(self, *args, **kwargs): pass
        async def run(self, **kwargs):
            calls.append(kwargs)
            return SimpleNamespace(status="stopped")

    monkeypatch.setattr(planner, "InterventionPlanAnalyzer", Stage)
    monkeypatch.setattr(generator, "InterventionGenerator", Stage)
    monkeypatch.setattr(runner, "create_runner", Repair)
    monkeypatch.setattr(module, "detect_generator_arch", lambda _: "arm")
    framework = tmp_path / "framework"
    framework.mkdir()
    obj = object.__new__(module.FirmAnalyzer)
    obj.global_config = SimpleNamespace(runtime_workspace=framework,
        target_diagnostic_reports_dir=lambda: tmp_path / "reports",
        target_agent_debug_dir=lambda: tmp_path / "debug")
    obj.workdir = tmp_path
    obj.image_name = "fixture"
    obj.fw_rootfs_path = tmp_path / "rootfs"
    obj.run_after_generation = run_after_generation
    obj.runner_max_attempts = None
    obj.runner_timeout_seconds = 60
    view = SimpleNamespace(root=SimpleNamespace(binary_path=tmp_path / "guest"))
    with pytest.raises(RuntimeError, match="Runner ended with status=stopped" if run_after_generation else "not-ready"):
        asyncio.run(obj._run_synthesizer(view))
    assert len(calls) == int(run_after_generation)
    if calls:
        assert calls[0]["runtime_workspace"] == framework
