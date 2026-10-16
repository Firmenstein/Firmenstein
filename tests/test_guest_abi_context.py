"""Guest ABI context uses self-contained ELF headers, never host executables."""
import asyncio
import struct
from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer import code_analyzer_agent as module


def _view(tmp_path, machine, byte_order):
    ident = b"\x7fELF" + bytes([1, byte_order, 1]) + bytes(9)
    path = tmp_path / "guest.elf"
    path.write_bytes(struct.pack(
        ("<" if byte_order == 1 else ">") + "16sHHIIIIIHHHHHH",
        ident, 2, machine, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0,
    ))
    graph = SimpleNamespace(get_node_by_name=lambda name: SimpleNamespace(binary_path=path))
    return AnalysisView(SimpleNamespace(
        lib_dep_graph=graph, analysis_level="semantic", root=SimpleNamespace(name="guest"),
    ))


@pytest.mark.parametrize("machine,name,order,endian", [
    (8, "MIPS", 1, "LSB"), (8, "MIPS", 2, "MSB"), (40, "ARM", 1, "LSB"),
])
def test_guest_elf_identity_comes_from_header(tmp_path, machine, name, order, endian):
    view = _view(tmp_path, machine, order)
    assert view.get_binary_elf_identity("guest") == {
        "machine": name, "class": "ELF32", "byte_order": endian, "processor_flags": "0x0",
    }


@pytest.mark.parametrize("machine,name", [(8, "MIPS"), (40, "ARM")])
@pytest.mark.parametrize("explicit_binary", [True, False])
def test_initial_agent_context_identifies_guest_abi(tmp_path, monkeypatch, machine, name, explicit_binary):
    view = _view(tmp_path, machine, 1)
    prompts = []

    class Output(BaseModel):
        value: str

    class Agent:
        async def ainvoke(self, prompt, *, trace=None):
            prompts.append(prompt)
            return SimpleNamespace(structured_response=Output(value="ok"))

        async def aclose(self):
            pass

    monkeypatch.setattr(module, "create_analysis_agent", lambda **kwargs: Agent())
    agent = module.CodeAnalyzerAgent(
        agent_name="GuestAbiTest", task_prompt="Analyze the supplied code.",
        output_format=Output, model="test", include_analyzer_tools=False,
    )
    asyncio.run(agent.analyze(
        user_message="socket(2, 1, 17)", view=view,
        binary_name="guest" if explicit_binary else None,
    ))
    assert f"machine={name}, class=ELF32, byte_order=LSB" in prompts[0]
    assert ("SOCK_DGRAM=1, SOCK_STREAM=2" in prompts[0]) == (machine == 8)
