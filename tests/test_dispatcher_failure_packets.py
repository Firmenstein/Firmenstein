"""Isolated dispatcher copies consume structured failures before artifact deletion."""
import importlib.util
import json
from pathlib import Path


SOURCE = Path(__file__).parent / "fixtures/framework-repair-dispatcher/compact_errors.py"


def module():
    spec = importlib.util.spec_from_file_location("repair_compact_errors", SOURCE)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_nested_colored_provider_exception_is_observed_without_guessing_root_cause(tmp_path):
    log = tmp_path / "pipeline.log"
    log.write_text('\x1b[31mAgentProviderError: interrupted response\x1b[0m\nValueError: Analyzer execution is failed\n')
    record = module().log_record(log)
    assert record["provider_failure_observed"]
    assert record["error_type"] == "ValueError"
    assert record["cause_type"] == "AgentProviderError"


def test_structured_errno_survives_outer_error_and_missing_exit_code(tmp_path):
    case = tmp_path / "case-01"
    packet = case / "pipeline/firmware/reports/pipeline_failure.json"
    packet.parent.mkdir(parents=True)
    packet.write_text(json.dumps(dict(schema_version=1,failed_stage="file",dispatch_blocked=True,
        causes=[dict(error_type="AnalysisIncompleteError",reason="incomplete")],
        execution=dict(tasks={"probe:bad":dict(status="failed",failure=dict(kind="tool",errno=24,reason="fd"))}))))
    diagnostic = module().pipeline_diagnostic(case,case / "missing.log")
    assert diagnostic["dispatch_blocked"] and diagnostic["failure_stage"] == "file"
    assert diagnostic["pipeline_failures"][0]["execution"]["tasks"]["probe:bad"]["failure"]["errno"] == 24
    assert module().dispatch_stop_observed({"error_diagnostics":diagnostic})


def test_unknown_error_is_explicit_and_ordinary_error_does_not_hold_dispatch(tmp_path):
    diagnostic = module().pipeline_diagnostic(tmp_path, tmp_path / "missing.log")
    assert "cause unknown" in diagnostic["error_message"] and not diagnostic["dispatch_blocked"]
    log = tmp_path / "ordinary.log"
    log.write_text("ValueError: unsupported musl loader\n")
    assert not module().log_record(log)["provider_failure_observed"]
