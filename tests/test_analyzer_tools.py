"""Unit tests for the CodeAnalyzer tool layer in
``fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools``.

Fixture-binary round-trips for ``find_global_var_xref``,
``find_string_xref``, and ``view_function`` against the libnvram.so
cached pkl + decompiled artefacts. These guard the regression that
motivated the heads-based extractor rewrite: decompiler-synthesized
auto-names like ``dword_1513C`` were silently missing from the index
because the extractor only iterated ``names.get_all()``.

The fixture-binary tests are skipped when the workdir cache or IDADIR
is unavailable (so the file is still useful in lighter environments).

Usage:
    source src/.venv/bin/activate
    python -m unittest tests.test_analyzer_tools -v
"""
import hashlib
import asyncio
import json
import os
import pickle
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))


# ---------------------------------------------------------------------------
# Fixture paths — guarded with skipUnless when missing
# ---------------------------------------------------------------------------

_FIXTURE_WORKDIR = (
    _REPO_ROOT / "workdir/R6700v3-V1.0.4.120_10.0.91"
)
_LIBNVRAM_PKL = _FIXTURE_WORKDIR / "graph_cache/binary_cache/libnvram.so.pkl"
_LIBNVRAM_IDB = _FIXTURE_WORKDIR / "decompiler_db/libnvram.so.i64"
_LIBNVRAM_DECOMPILED = _FIXTURE_WORKDIR / "decompiled_code/libnvram.so"

_HAS_FIXTURE = (
    _LIBNVRAM_PKL.exists()
    and _LIBNVRAM_IDB.exists()
    and _LIBNVRAM_DECOMPILED.exists()
    and bool(os.environ.get("IDADIR"))
)


def _build_fake_view(decompiled_code_dir: Path) -> SimpleNamespace:
    """Construct the minimum object graph the analyzer-tool factory needs.

    The JSON-backed tools only touch
    ``view.global_config.decompiled_code_dir`` plus
    ``view.get_full_code(binary, function)`` for ``view_function``.
    A SimpleNamespace with that shape is enough
    to round-trip those tools without standing up a real LibDepGraph.
    """
    class _FakeView:
        def __init__(self, root: Path):
            self.global_config = SimpleNamespace(decompiled_code_dir=root)

        def get_full_code(self, binary_name: str, function_name: str) -> str:
            return (
                self.global_config.decompiled_code_dir
                / binary_name
                / f"{function_name}.c"
            ).read_text()

    return _FakeView(decompiled_code_dir)


def _clear_xref_caches() -> None:
    """Drop process-level xref caches between tests."""
    from fmst_analyzer.analysis.base.code_analyzer.code_tools import (
        analyzer_tools,
    )

    analyzer_tools._GLOBAL_VAR_XREF_CACHE.clear()
    analyzer_tools._STRING_XREF_CACHE.clear()


def _get_tool(view, tool_name: str):
    for tool in _get_all_tools(view):
        if tool.name == tool_name:
            return tool
    raise AssertionError(f"tool '{tool_name}' not found in make_analyzer_tools()")


def _get_all_tools(view):
    from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools \
        import make_analyzer_tools

    return make_analyzer_tools(view)


class TestAnalyzerToolContract(unittest.TestCase):
    """Keep the model-visible code-tool prefix stable for prompt caching."""

    EXPECTED_NAMES = [
        "view_function",
        "view_disassembly",
        "view_callers",
        "view_callees",
        "trace_variable",
        "view_code_range",
        "view_global",
        "find_string_xref",
        "find_global_var_xref",
        "evaluate_integer_cases",
    ]
    EXPECTED_CONTEXT_SHA256 = (
        "9fe31e47abbd36a7c01488005536cf955a9bfbf24263553c1ac4b56cf5364389"
    )

    def test_model_visible_tool_contract_is_stable(self):
        from fmst_analyzer.analysis.base.code_analyzer.code_tools.analyzer_tools \
            import make_analyzer_tools

        view = _build_fake_view(Path("/tmp/nonexistent"))
        tools = make_analyzer_tools(view)
        self.assertEqual([tool.name for tool in tools], self.EXPECTED_NAMES)

        from fmst_basic.agent.codex_agent import codex_dynamic_tool_spec

        contract = [codex_dynamic_tool_spec(tool) for tool in tools]
        payload = json.dumps(
            contract,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(payload).hexdigest(),
            self.EXPECTED_CONTEXT_SHA256,
            "model-visible analyzer tool order/schema/description changed; "
            "treat this as an intentional prompt-cache compatibility break",
        )

    def test_trace_variable_switches_to_onboarded_binary_view(self):
        from fmst_analyzer.analysis.base.code_analyzer.analysis_view import (
            AnalysisView,
        )

        peer_adg = SimpleNamespace(analysis_level="semantic")
        anchor_view = SimpleNamespace(
            adg=SimpleNamespace(),
            resolve_view=lambda binary_name: (
                peer_adg if binary_name == "wps_monitor" else None
            ),
        )
        tool = _get_tool(anchor_view, "trace_variable")
        empty_graph = SimpleNamespace(node_count=0)

        with patch.object(
            AnalysisView,
            "trace_variables",
            autospec=True,
            return_value=empty_graph,
        ) as traced:
            result = asyncio.run(tool.ainvoke({
                "variable_name": "fd",
                "function_name": "main",
                "direction": "backward",
                "binary_name": "bin/wps_monitor",
                "max_depth": 2,
            }))

        self.assertIn("No dataflow found", result)
        selected_view = traced.call_args.args[0]
        self.assertIs(selected_view.adg, peer_adg)


class TestXrefCacheIdentity(unittest.TestCase):
    def setUp(self):
        _clear_xref_caches()

    @staticmethod
    def _write_indices(root: Path, function_name: str) -> None:
        binary_dir = root / "httpd"
        binary_dir.mkdir(parents=True, exist_ok=True)
        ref = [{"func": function_name, "ea": "0x1000"}]
        (binary_dir / "string_xrefs.json").write_text(
            json.dumps({"shared-string": ref}), encoding="utf-8",
        )
        (binary_dir / "global_var_xrefs.json").write_text(
            json.dumps({"shared_global": ref}), encoding="utf-8",
        )

    def test_same_basename_in_different_workdirs_does_not_share_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_root = root / "image-a" / "decompiled_code"
            second_root = root / "image-b" / "decompiled_code"
            self._write_indices(first_root, "from_image_a")
            self._write_indices(second_root, "from_image_b")

            first_tools = {
                tool.name: tool
                for tool in _get_all_tools(_build_fake_view(first_root))
            }
            second_tools = {
                tool.name: tool
                for tool in _get_all_tools(_build_fake_view(second_root))
            }

            first_string = first_tools["find_string_xref"].invoke({
                "binary_name": "httpd", "needle": "shared-string",
            })
            second_string = second_tools["find_string_xref"].invoke({
                "binary_name": "httpd", "needle": "shared-string",
            })
            first_global = first_tools["find_global_var_xref"].invoke({
                "binary_name": "httpd", "var_name": "shared_global",
            })
            second_global = second_tools["find_global_var_xref"].invoke({
                "binary_name": "httpd", "var_name": "shared_global",
            })

            self.assertIn("from_image_a", first_string)
            self.assertNotIn("from_image_b", first_string)
            self.assertIn("from_image_b", second_string)
            self.assertNotIn("from_image_a", second_string)
            self.assertIn("from_image_a", first_global)
            self.assertNotIn("from_image_b", first_global)
            self.assertIn("from_image_b", second_global)
            self.assertNotIn("from_image_a", second_global)

    def test_republished_index_at_same_path_invalidates_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            decompiled_root = Path(tmp) / "decompiled_code"
            self._write_indices(decompiled_root, "before_republish")
            tools = {
                tool.name: tool
                for tool in _get_all_tools(_build_fake_view(decompiled_root))
            }

            first = tools["find_string_xref"].invoke({
                "binary_name": "httpd", "needle": "shared-string",
            })
            self._write_indices(decompiled_root, "after_republish_longer")
            second = tools["find_string_xref"].invoke({
                "binary_name": "httpd", "needle": "shared-string",
            })

            self.assertIn("before_republish", first)
            self.assertIn("after_republish_longer", second)
            self.assertNotIn("before_republish", second)

    def test_code_tools_accept_canonical_guest_binary_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            decompiled_root = Path(tmp) / "decompiled_code"
            self._write_indices(decompiled_root, "uses_shared_value")
            (decompiled_root / "httpd" / "main.c").write_text(
                "int main(void) { return 0; }\n", encoding="utf-8",
            )
            tools = {
                tool.name: tool
                for tool in _get_all_tools(_build_fake_view(decompiled_root))
            }

            function = tools["view_function"].invoke({
                "binary_name": "usr/sbin/httpd",
                "function_name": "main",
            })
            string_xref = tools["find_string_xref"].invoke({
                "binary_name": "usr/sbin/httpd",
                "needle": "shared-string",
            })
            global_xref = tools["find_global_var_xref"].invoke({
                "binary_name": "usr/sbin/httpd",
                "var_name": "shared_global",
            })

            self.assertIn("int main(void)", function)
            self.assertIn("uses_shared_value", string_xref)
            self.assertIn("uses_shared_value", global_xref)


# ---------------------------------------------------------------------------
# Fixture-binary tests — gated on workdir cache + IDADIR availability
# ---------------------------------------------------------------------------


@unittest.skipUnless(
    _HAS_FIXTURE,
    "libnvram.so workdir fixture or IDADIR not available; skipping "
    "IDA-dependent regression tests",
)
class TestGlobalVarXrefRegressionLibnvram(unittest.TestCase):
    """End-to-endish regression for the dword_* extraction bug.

    Loads the cached libnvram.so binary pickle, runs
    ``CallGraph.dump_global_var_xrefs`` against a temp dir, and
    re-derives the on-disk index from scratch. Asserts that
    ``dword_1513C`` (the cached ``/dev/nvram`` fd that lives in .bss
    with no user symbol) gets indexed with the expected caller set.
    Pre-fix this set was empty.
    """

    EXPECTED_CALLERS = {
        "nvram_init",
        "nvram_get",
        "nvram_getall",
        "nvram_set_0",
        "nvram_commit",
    }

    def setUp(self):
        from fmst_analyzer.nodes.binary import BinaryNode

        BinaryNode.set_decompiler("ida", _FIXTURE_WORKDIR / "decompiler_db")
        try:
            with open(_LIBNVRAM_PKL, "rb") as fh:
                self.binary = pickle.load(fh)
        except ModuleNotFoundError:
            self.skipTest(
                "graph cache uses an obsolete Python package namespace; "
                "rebuild the graph cache before running this regression test"
            )
        self.assertIsNotNone(
            self.binary._call_graph,
            "fixture pkl missing _call_graph — cache is stale or wrong shape",
        )

    def test_dump_writes_dword_1513c_with_expected_callers(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp)
            self.binary._call_graph.dump_global_var_xrefs(
                out_root, include_semantic_aliases=True,
            )
            json_path = out_root / self.binary.name / "global_var_xrefs.json"
            self.assertTrue(json_path.exists(), msg=f"no JSON written at {json_path}")

            data = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertIsInstance(data, dict)

            refs = data.get("dword_1513C")
            self.assertIsNotNone(
                refs,
                msg=(
                    "dword_1513C missing from index — pre-fix bug regression. "
                    "names.get_all() does not include decompiler auto-names; "
                    "extractor must use heads.get_between + func_globals."
                ),
            )
            self.assertGreater(
                len(refs), 0,
                msg="dword_1513C indexed but with zero refs",
            )

            callers = set(r.get("func") for r in refs)
            self.assertEqual(
                callers, self.EXPECTED_CALLERS,
                msg=(
                    f"caller set drift for dword_1513C: "
                    f"got {sorted(callers)}, expected {sorted(self.EXPECTED_CALLERS)}"
                ),
            )

    def test_dump_includes_decompiler_auto_name_keys(self):
        # Broader invariant: the index should hold *some* dword_/byte_/unk_
        # keys. If this drops to zero we've regressed source 2 (the
        # func_globals alias merge), even if dword_1513C happens to
        # survive via a coincidental user-defined name.
        with tempfile.TemporaryDirectory() as tmp:
            out_root = Path(tmp)
            self.binary._call_graph.dump_global_var_xrefs(
                out_root, include_semantic_aliases=True,
            )
            data = json.loads(
                (out_root / self.binary.name / "global_var_xrefs.json")
                .read_text(encoding="utf-8")
            )

        auto_names = [
            k for k in data
            if k.startswith(("dword_", "byte_", "unk_", "qword_", "word_"))
        ]
        self.assertGreater(
            len(auto_names), 0,
            msg=(
                "no decompiler auto-name keys in index; the func_globals "
                "alias merge is broken"
            ),
        )


@unittest.skipUnless(
    _HAS_FIXTURE,
    "libnvram.so workdir fixture not available; skipping tool round-trip tests",
)
class TestAnalyzerToolRoundTripsLibnvram(unittest.TestCase):
    """One-call smoke per JSON-backed tool against the on-disk libnvram
    fixture artefacts. Catches 'tool silently broken' regressions.

    Uses the in-tree global_var_xrefs.json / string_xrefs.json — which
    have already been built from this binary — instead of regenerating
    them, so these tests don't need IDA to be running."""

    def setUp(self):
        _clear_xref_caches()
        self.view = _build_fake_view(_FIXTURE_WORKDIR / "decompiled_code")

    def test_find_global_var_xref_dword_1513c(self):
        out = _get_tool(self.view, "find_global_var_xref").invoke({
            "binary_name": "libnvram.so",
            "var_name": "dword_1513C",
        })
        self.assertIn("xref(s) to global var 'dword_1513C'", out)
        for caller in TestGlobalVarXrefRegressionLibnvram.EXPECTED_CALLERS:
            self.assertIn(caller, out, msg=f"expected caller {caller!r} missing from output")

    def test_find_global_var_xref_with_gvar_prefix(self):
        # Agents see ``GVar_dword_1513C`` in decompiled code; the tool
        # must strip the GVar_ prefix before lookup.
        tool = _get_tool(self.view, "find_global_var_xref")
        bare = tool.invoke({
            "binary_name": "libnvram.so",
            "var_name": "dword_1513C",
        })
        prefixed = tool.invoke({
            "binary_name": "libnvram.so",
            "var_name": "GVar_dword_1513C",
        })
        # Body lines (per-ref entries) must agree even though the
        # header echoes the looked-up name verbatim.
        bare_body = "\n".join(bare.splitlines()[1:])
        prefixed_body = "\n".join(prefixed.splitlines()[1:])
        self.assertEqual(bare_body, prefixed_body)

    def test_find_global_var_xref_unknown_var_friendly_message(self):
        out = _get_tool(self.view, "find_global_var_xref").invoke({
            "binary_name": "libnvram.so",
            "var_name": "definitely_not_a_real_global_xyz",
        })
        self.assertIn("No functions in 'libnvram.so' reference global var", out)

    def test_find_string_xref_dev_nvram(self):
        out = _get_tool(self.view, "find_string_xref").invoke({
            "binary_name": "libnvram.so",
            "needle": "/dev/nvram",
        })
        # /dev/nvram is the cached fd resource — nvram_init opens it.
        self.assertIn("/dev/nvram", out)
        self.assertIn("nvram_init", out)

    def test_view_function_reads_decompiled_c_file(self):
        out = _get_tool(self.view, "view_function").invoke({
            "function_name": "nvram_init",
            "binary_name": "libnvram.so",
        })
        # The decompiled body for nvram_init mentions the cached fd
        # global with the GVar_ prefix the analyzer renames it to.
        self.assertIn("nvram_init", out)
        self.assertIn("GVar_dword_1513C", out)


if __name__ == "__main__":
    unittest.main()
