"""Counterexamples for source-only acceptance and unbounded session correction."""
import asyncio
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from fmst_analyzer.analysis.base.output_validation import OutputValidationError
from fmst_analyzer.analysis.base.execution import ExecutionTracker
from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as code_agent


class Answer(BaseModel):
    reference: str


@pytest.mark.parametrize("cancel", [False, True])
def test_reference_corrections_pass_old_cap_and_remain_cancellable(monkeypatch, cancel):
    instances = []
    prompts = []
    ready = asyncio.Event()

    class Agent:
        def __init__(self, **kwargs):
            self.closed = False
            instances.append(self)

        async def ainvoke(self, prompt, **kwargs):
            prompts.append(prompt)
            if len(prompts) == 9 and cancel:
                ready.set()
                await asyncio.Event().wait()
            return SimpleNamespace(structured_response=Answer(reference="known" if len(prompts) == 9 else "foreign"))

        async def aclose(self):
            self.closed = True

    monkeypatch.setattr(code_agent, "create_analysis_agent", Agent)
    def validate(output):
        if output.reference != "known":
            raise OutputValidationError("/reference: foreign does not bind the assigned source known")

    async def run():
        agent = code_agent.CodeAnalyzerAgent("fixture", "Inspect source", Answer, "fixture", include_analyzer_tools=False)
        task = asyncio.create_task(agent.analyze("Source is known", object(), output_validator=validate))
        if cancel:
            await ready.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            assert (await task).reference == "known"
    asyncio.run(run())
    assert len(instances) == 1 and instances[0].closed
    assert len(prompts) == 9
    assert all("/reference" in prompt for prompt in prompts[1:])


def test_implementation_value_error_is_not_relabelled_as_model_output():
    async def run():
        tracker = ExecutionTracker()
        async def broken():
            raise ValueError("internal cache implementation error")
        assert await tracker.call("site", "one", broken) is None
        return tracker.record
    execution = asyncio.run(run())
    assert execution.tasks["site:one"].failure.kind == "internal"


def test_source_access_failure_is_not_model_output():
    async def run():
        tracker = ExecutionTracker()
        async def broken():
            raise FileNotFoundError("known function has no generated artifact")
        await tracker.call("site", "one", broken)
        return tracker.record
    assert asyncio.run(run()).tasks["site:one"].failure.kind == "tool"


def test_process_cast_and_missing_ctree_keep_original_conclusion():
    from test_process_lifecycle_controller import _draft, _source, FakeView
    from fmst_analyzer.analysis.process_lifecycle.controller import validate_agent_result, finalize_analysis
    class View(FakeView):
        def get_full_code(self, *args):
            return "int main() {\n((void (*)(int))exit)(1);\n}"
    output = _draft()
    view = View([])
    validate_agent_result(output, view, _source())
    analysis = finalize_analysis(_source(), output, view)
    assert analysis.assessment.summary == output.summary
    assert analysis.assessment.disposition == output.disposition
    assert analysis.semantics == output.finding
    assert type(analysis.assessment).model_validate_json(analysis.assessment.model_dump_json()) == analysis.assessment


def test_ipc_elf_text_error_identifies_exact_field_and_type(tmp_path):
    from test_ipc_site_resolution import _fact, _negative_finding, _agent, _NeverCalled
    from fmst_analyzer.analysis.ipc_analyzer.agent_schema import SiteResolutionOutput
    from fmst_analyzer.analysis.ipc_analyzer.schema import IPCMechanism, EvidenceCitation
    fact = _fact()
    source = tmp_path / fact.location.binary_path
    source.parent.mkdir(parents=True)
    source.write_bytes(b"\x7fELF\xff")
    finding = _negative_finding(fact, IPCMechanism.EXTERNAL_NETWORK, "Conditional external endpoint")
    finding.evidence = [EvidenceCitation(claim="startup", binary_path=fact.location.binary_path, function_name="<config>", line_number=1)]
    agent = _agent(_NeverCalled())
    agent.global_config.fw_rootfs_path = tmp_path
    with pytest.raises(OutputValidationError) as failure:
        agent._validate_echoed_identities([fact], SiteResolutionOutput(callsite_findings=[finding]), view=object())
    message = str(failure.value)
    assert "/callsite_findings/0/evidence/0" in message
    assert fact.location.binary_path in message and "ELF, not text" in message
    assert "view_function/view_disassembly" in message


def test_file_source_outside_call_index_is_accepted_without_api_matching():
    from fmst_analyzer.analysis.file_resolver.resource_analysis_agent import _validate_report_positions
    from fmst_analyzer.analysis.base.report_schema import UsageReport
    view = SimpleNamespace(lib_dep_graph=SimpleNamespace(get_node_by_name=lambda _: object()),
        get_function_ea=lambda *_: 0x1000, get_full_code=lambda *_: "int callback(void) {\nreturn target(fd);\n}")
    report = SimpleNamespace(usage_reports=[UsageReport(binary_name="service", function_name="callback",
        line_number=2, api_name="read", details="Indirect descriptor read")])
    _validate_report_positions([report], [], view)
    report.usage_reports[0].line_number = 4
    with pytest.raises(OutputValidationError, match="/callsite_reports/0/usage_reports/0"):
        _validate_report_positions([report], [], view)


def test_init_correction_after_eight_rejections_preserves_history(tmp_path, monkeypatch):
    from test_init_correction_history import _fixture, _run_agent
    from fmst_analyzer.analysis.init_launch.analyzer_schema import LaunchRecipeAgentOutput
    rootfs, good, invalid = _fixture(tmp_path)
    agent, invocation, prompts = _run_agent(monkeypatch, rootfs, [
        *[LaunchRecipeAgentOutput(launch_recipes=[invalid]) for _ in range(8)],
        LaunchRecipeAgentOutput(launch_recipes=[good]),
    ])
    result = asyncio.run(invocation)
    assert len(prompts) == 9 and len(result.correction_history) == 8
    assert next(iter(result.planning_findings.values())).claims[0].statement == good.finding.claims[0].statement


def test_ipc_callsite_source_accepts_a_guest_file_alias(tmp_path):
    from test_ipc_site_resolution import _fact, _negative_finding, _agent, _NeverCalled
    from fmst_analyzer.analysis.ipc_analyzer.agent_schema import SiteResolutionOutput
    from fmst_analyzer.analysis.ipc_analyzer.schema import IPCMechanism
    fact = _fact()
    source = tmp_path / fact.location.binary_path
    source.parent.mkdir(parents=True)
    source.write_bytes(b"\x7fELFfixture")
    alias = tmp_path / "bin/httpd"
    alias.parent.mkdir()
    alias.symlink_to("/" + fact.location.binary_path)
    finding = _negative_finding(fact, IPCMechanism.EXTERNAL_NETWORK, "Keep the same observed source")
    finding.evidence[0].binary_path = "bin/httpd"
    agent = _agent(_NeverCalled())
    agent.global_config.fw_rootfs_path = tmp_path
    agent._validate_echoed_identities([fact], SiteResolutionOutput(callsite_findings=[finding]))
