"""Site references use the same source/feedback boundary as other Analyzers."""
import asyncio
from types import SimpleNamespace

import pytest

from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as code_agent
from fmst_analyzer.analysis.base.output_validation import OutputValidationError
from fmst_analyzer.analysis.ipc_analyzer.agent_schema import SiteResolutionOutput
from fmst_analyzer.analysis.ipc_analyzer.schema import IPCMechanism, EvidenceCitation
from test_ipc_site_resolution import _fact, _negative_finding, _agent, _NeverCalled


def _source_fixture(rootfs, *, line_number):
    fact = _fact()
    path = rootfs / fact.location.binary_path
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\x7fELFfixture")
    finding = _negative_finding(fact, IPCMechanism.EXTERNAL_NETWORK, "Cite a known function.")
    finding.evidence = [EvidenceCitation(
        claim="Imported function identity", binary_path=fact.location.binary_path,
        function_name="imported_connect", function_ea=0x2000, line_number=line_number,
    )]
    agent = _agent(_NeverCalled())
    agent.global_config.fw_rootfs_path = rootfs

    def read_body(binary, function):
        if function != "main":
            raise FileNotFoundError("Known function has no local C body")
        return "\n" * 9 + "connect(fd, addr, len);"

    view = SimpleNamespace(
        lib_dep_graph=SimpleNamespace(get_node_by_name=lambda _: object()),
        get_function_ea=lambda binary, function: 0x2000 if function == "imported_connect" else 0x1000,
        get_full_code=read_body,
        is_external_function=lambda *args, **kwargs: True,
    )
    return agent, fact, SiteResolutionOutput(callsite_findings=[finding]), view


def test_site_import_line_gets_field_specific_correction(tmp_path):
    agent, fact, output, view = _source_fixture(tmp_path, line_number=9)
    with pytest.raises(OutputValidationError, match="/callsite_findings/0/evidence/0") as failure:
        agent._validate_echoed_identities([fact], output, view=view)
    assert "line_number=9" in str(failure.value)
    assert "caller" in str(failure.value)


@pytest.mark.parametrize("external", [False, True])
def test_site_whole_function_reference_does_not_read_a_c_body(tmp_path, external):
    agent, fact, output, view = _source_fixture(tmp_path, line_number=None)
    view.is_external_function = lambda *args, **kwargs: external
    def no_body_read(*args):
        pytest.fail("A structural reference does not require C")
    view.get_full_code = no_body_read
    agent._validate_echoed_identities([fact], output, view=view)
    output.callsite_findings[0].evidence[0].function_ea = 0x3000
    with pytest.raises(OutputValidationError, match="expected function_ea"):
        agent._validate_echoed_identities([fact], output, view=view)


def test_site_missing_regular_c_body_remains_a_tool_error(tmp_path):
    agent, fact, output, view = _source_fixture(tmp_path, line_number=9)
    view.is_external_function = lambda *args, **kwargs: False
    with pytest.raises(FileNotFoundError):
        agent._validate_echoed_identities([fact], output, view=view)


def test_site_source_feedback_reaches_the_same_agent_session(tmp_path, monkeypatch):
    site, fact, bad, view = _source_fixture(tmp_path, line_number=9)
    good = SiteResolutionOutput(callsite_findings=[
        _negative_finding(fact, IPCMechanism.EXTERNAL_NETWORK, "Cite the actual caller.")
    ])
    prompts = []
    instances = []
    class Backend:
        def __init__(self, **kwargs):
            instances.append(self)
            self.closed = False
        async def ainvoke(self, prompt, **kwargs):
            prompts.append(prompt)
            return SimpleNamespace(structured_response=bad if len(prompts) == 1 else good)
        async def aclose(self):
            self.closed = True
    monkeypatch.setattr(code_agent, "create_analysis_agent", Backend)
    agent = code_agent.CodeAnalyzerAgent("fixture", "Inspect source", SiteResolutionOutput,
                                         "fixture", include_analyzer_tools=False)
    result = asyncio.run(agent.analyze("Resolve the callsite", view,
        output_validator=lambda output: site._validate_echoed_identities([fact], output, view=view)))
    assert result == good
    assert len(instances) == 1 and instances[0].closed
    assert len(prompts) == 2
    assert "/callsite_findings/0/evidence/0" in prompts[1]
    assert "caller" in prompts[1]
