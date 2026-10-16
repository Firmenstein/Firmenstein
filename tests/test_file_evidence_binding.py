"""Controller evidence must be visible before semantic references are checked."""
import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from fmst_analyzer.analysis.base.analysis_finding import resolve_evidence_ref
from fmst_analyzer.analysis.base.report_schema import EffectiveCallsite
from fmst_analyzer.analysis.file_resolver import resource_analysis_agent as module
from fmst_analyzer.analysis.file_resolver.analyzer_schema import FileCallsite, FileResource


def _resource():
    return FileResource(
        resource_group_id="file-test", path_value="/dev/example", path_kind="concrete",
        resource_class="pseudo_fs_dev",
        callsites=[FileCallsite(
            callsite_id=f"daemon::{name}::L12::open", candidate_idx=0,
            profile_key=f"daemon::{name}::L12::open#0", binary_name="daemon",
            function_name=name, line_number=12, api_name="open", path_arg_index=0,
            requested_path="/dev/example", path_value="/dev/example", path_kind="concrete",
            resolution_source="literal_static", resource_class="pseudo_fs_dev",
        ) for name in ("open_a", "open_b")],
    )


class _View:
    root = SimpleNamespace(name="daemon")
    adg = SimpleNamespace(get_binary_callgraphs=lambda: {})

    def collect_effective_callsites(self, binary_name, function_name):
        return [EffectiveCallsite(
            binary="daemon", function=f"entry_for_{function_name}",
            representative_line=7, reached_via=function_name,
            context_snippet=f"L7: if ({function_name}() < 0) return -1;",
        )], 1


def _draft(callsite):
    return dict(callsite_id=callsite.callsite_id, containing_function_purpose="Open resource.",
                setup_details="The descriptor is returned to the caller.", usage_reports=[])


def _semantics(index=0):
    ref = f"/callsite_reports/{index}/resource_usage_sites/0"
    return dict(
        summary="The entry caller checks the open failure.",
        claims=[dict(kind="guarantee", statement="The caller returns -1 when open fails.",
                     evidence_refs=[ref], unknown_kind=None)],
        reachability_refs=[ref], coverage_refs=[],
    )


def _fields():
    return dict(
                coverage_flows=[], summary="Caller error propagation.")


@pytest.mark.parametrize("chunk_size", [1, 10])
def test_canonical_evidence_is_bound_before_validation_even_with_reordered_reports(monkeypatch, chunk_size):
    resource = _resource()
    messages = []

    class Agent:
        def __init__(self, *, output_format, **kwargs):
            self.format = output_format

        async def analyze(self, *, user_message, output_validator, function_name=None, **kwargs):
            messages.append(user_message)
            if self.format is module.FileResourceMapResult:
                payload = dict(callsite_reports=[_draft(cs) for cs in resource.callsites
                                                 if cs.function_name == function_name])
            elif self.format is module.FileResourceReduceResult:
                payload = dict(**_fields(), finding=_semantics(1))
            else:
                payload = dict(**_fields(), finding=_semantics(),
                               callsite_reports=[_draft(cs) for cs in reversed(resource.callsites)])
            output = self.format.model_validate(payload)
            output_validator(output)
            return output

    monkeypatch.setattr(module, "CodeAnalyzerAgent", Agent)
    config = SimpleNamespace(diagnosis_model="unused", agent_provider="unused",
                             file_resolver_resource_chunk_size=chunk_size)
    analysis = asyncio.run(module.FileResourceAnalysisAgent(config, asyncio.Semaphore(1)).analyze_resource(
        _View(), resource, phase="full",
    ))
    cited = resolve_evidence_ref(analysis.report.model_dump(mode="json"),
                                analysis.semantics.claims[0].evidence_refs[0])
    assert cited["function"] == "entry_for_open_b"
    assert cited["context_snippet"] == "L7: if (open_b() < 0) return -1;"
    assert any("entry_for_open_b" in message for message in messages)
    assert all(report.total_usage_sites == 1 for report in analysis.report.callsite_reports)


def test_agent_cannot_replace_controller_usage_evidence():
    payload = dict(**_fields(), finding=_semantics(), callsite_reports=[{
        **_draft(_resource().callsites[0]),
        "resource_usage_sites": [dict(binary="daemon", function="invented", representative_line=99,
                                      reached_via="invented", context_snippet="invented")],
        "total_usage_sites": 1,
    }])
    with pytest.raises(ValidationError, match="resource_usage_sites"):
        module.FileResourceAnalysisOutput.model_validate(payload)
