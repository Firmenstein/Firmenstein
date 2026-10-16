"""The explicit native tool remains lazy, gated, and source-identity scoped."""
import asyncio
from types import SimpleNamespace

import pytest

from fmst_analyzer.analysis.init_launch.code_evidence import LauncherCodeEvidence


def test_static_native_tool_is_gated_even_at_backend_entry(tmp_path, monkeypatch):
    evidence = LauncherCodeEvidence(tmp_path, SimpleNamespace(workdir=tmp_path), "static")
    with pytest.raises(ValueError, match="full phase"):
        asyncio.run(evidence.read("sbin/rc", 0x1000, None))
    with pytest.raises(ValueError, match="full phase"):
        asyncio.run(evidence._view(tmp_path / "sbin/rc"))
    with pytest.raises(ValueError, match="full phase"):
        asyncio.run(evidence.references("sbin/rc", "httpd", None))
    with pytest.raises(ValueError, match="full phase"):
        asyncio.run(evidence._get_view("sbin/rc"))


def test_native_tool_reuses_exact_binary_view_and_returns_complete_code(tmp_path, monkeypatch, elf_wrapper):
    import hashlib
    target = tmp_path / "sbin/rc"
    target.parent.mkdir()
    target.write_bytes(elf_wrapper.read_bytes())
    assembly = tmp_path / "function.s"
    assembly.write_text("; chunk: 0x0-0x1\n0x0: deliberately noncanonical IDA instruction text\n")
    function = SimpleNamespace(semantic_snapshot=SimpleNamespace(snapshot_hash="fixture-snapshot"))
    graph = SimpleNamespace(get_node_by_ea=lambda ea: function)
    view = SimpleNamespace(root=SimpleNamespace(name="rc"),
        get_decompiled_name=lambda *args: "prepare", get_function_ea=lambda *args: 0x1000,
        lib_dep_graph=SimpleNamespace(get_callgraph_by_name=lambda _: graph),
        get_full_code=lambda *args: "int prepare() { return write_config(); }",
        get_disassembly_path=lambda *args: assembly,
        get_binary_elf_identity=lambda _: {"machine": "fixture"})
    calls = []
    async def load(path):
        calls.append(path)
        return view
    evidence = LauncherCodeEvidence(tmp_path, SimpleNamespace(workdir=tmp_path), "full")
    monkeypatch.setattr(evidence, "_view", load)
    first = asyncio.run(evidence.read("sbin/rc", 0x1000, None))
    second = asyncio.run(evidence.read("/sbin/rc", None, "prepare"))
    assert first == second
    assert calls == [target]
    assert first["binary_sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert first["decompiled_code"] == "int prepare() { return write_config(); }"
    assert first["source_snippets"] == [{"path": "sbin/rc", "location": "0x0", "text": "0x0: ret"}]


def test_native_tool_rejects_escape_and_missing_identity_before_loading_backend(tmp_path, monkeypatch):
    evidence = LauncherCodeEvidence(tmp_path, SimpleNamespace(workdir=tmp_path), "full")
    async def unexpected(*args):
        raise AssertionError("native backend must not start")
    monkeypatch.setattr(evidence, "_view", unexpected)
    with pytest.raises(ValueError, match="missing or escapes"):
        asyncio.run(evidence.read("../outside", 0x1000, None))
    with pytest.raises(ValueError, match="exact function"):
        asyncio.run(evidence.read("sbin/rc", None, None))


def test_native_reference_search_reuses_view_and_returns_all_source_matches(tmp_path, monkeypatch):
    import json
    rootfs = tmp_path / "rootfs"
    target = rootfs / "sbin/rc"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"fixture binary; native loader replaced below")
    artifacts = tmp_path / "decompiled"
    (artifacts / "rc").mkdir(parents=True)
    index = {f"start httpd context {i}": [{"func": f"launcher_{i}", "func_ea": hex(0x1000 + i),
                                        "ea": hex(0x2000 + i)}] for i in range(30)}
    index["unrelated daemon"] = [{"func": "other", "func_ea": "0x5000", "ea": "0x5004"}]
    (artifacts / "rc/string_xrefs.json").write_text(json.dumps(index))
    view = SimpleNamespace(root=SimpleNamespace(name="rc"),
        get_function_ea=lambda _, name: 0x1000 if name == "launch" else None,
        get_function_caller_nodes=lambda *_: [SimpleNamespace(ea=0x3000, artifact_stem="boot")])
    calls = []
    async def load(path):
        calls.append(path)
        return view
    evidence = LauncherCodeEvidence(rootfs, SimpleNamespace(workdir=tmp_path, decompiled_code_dir=artifacts), "full")
    monkeypatch.setattr(evidence, "_view", load)
    result = asyncio.run(evidence.references("sbin/rc", "httpd", "launch"))
    assert result["string_references"] == {key: value for key, value in index.items() if "httpd" in key}
    assert result["direct_callers"] == [{"function_name": "boot", "function_ea": 0x3000}]
    assert result["limitations"]
    assert asyncio.run(evidence.references("/sbin/rc", "no match", None))["string_references"] == {}
    assert calls == [target]
    with pytest.raises(ValueError, match="not found"):
        asyncio.run(evidence.references("sbin/rc", "", "missing"))
    with pytest.raises(ValueError, match="nonempty"):
        asyncio.run(evidence.references("sbin/rc", "", None))
