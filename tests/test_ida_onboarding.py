"""Focused regressions for IDA onboarding artifacts and cache identity."""

from __future__ import annotations

import pickle
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import MagicMock, PropertyMock, patch

from dotenv import load_dotenv
import pytest

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
pytest.importorskip("idapro", reason="IDA backend contract tests require the optional SDK")
from ida_domain.functions import FunctionFlags
from sortedcontainers import SortedSet

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.graphs.api_dep_graph import ApiDepGraph
from fmst_analyzer.graphs.base_graph import EdgeType
from fmst_analyzer.graphs.call_graph import CallGraph, SemanticExtractionFailure
from fmst_analyzer.graphs.lib_dep_graph import (
    LIB_DEP_GRAPH_TOPOLOGY_SCHEMA_VERSION,
    LibDepGraph,
)
from fmst_analyzer.nodes.binary import BinaryNode
from fmst_analyzer.nodes.common import FunctionAttr
from fmst_analyzer.nodes.function import FunctionNode
from fmst_analyzer.nodes.decompiler.ida.ida_binary import IDABinary
from fmst_analyzer.nodes.decompiler.ida.ida_function import IDAFunction
from fmst_analyzer.nodes.decompiler.ida.idb_manager import IDBManager
from fmst_basic.utils.file_utils import (
    AmbiguousBinaryError,
    find_binary_in_rootfs,
    index_paths_by_basename,
    resolve_unique_basename,
)


class _FakeInstructions:
    def __init__(self, by_chunk, text_by_ea):
        self.by_chunk = by_chunk
        self.text_by_ea = text_by_ea

    def get_between(self, start, end):
        return iter(self.by_chunk[(start, end)])

    def get_disassembly(self, insn, remove_tags=True):
        return self.text_by_ea[insn.ea]


class TestIDAFunctionDisassembly(unittest.TestCase):
    def setUp(self):
        self.function = object.__new__(IDAFunction)
        self.function._concretized = True
        self.function._module_name = "service"
        self.function._name = "sub_1000"
        self.function._decompiled_name = "handle_request"
        self.function._ea = 0x1000
        self.function._binary_identity = "/firmware/service:" + "a" * 64

    def test_listing_preserves_chunks_bytes_and_ida_text(self):
        insns = [
            SimpleNamespace(ea=0x1000, size=4),
            SimpleNamespace(ea=0x1004, size=4),
            SimpleNamespace(ea=0x2000, size=2),
        ]
        fake_db = SimpleNamespace(
            instructions=_FakeInstructions(
                {
                    (0x1000, 0x1008): insns[:2],
                    (0x2000, 0x2002): insns[2:],
                },
                {
                    0x1000: "PUSH            {R4,R5}",
                    0x1004: "ADDIU           $sp, -0x20",
                    0x2000: "push            rbp",
                },
            )
        )
        raw = {
            0x1000: bytes.fromhex("30 00 2d e9"),
            0x1004: bytes.fromhex("e0 ff bd 27"),
            0x2000: bytes.fromhex("55 48"),
        }

        module = "fmst_analyzer.nodes.decompiler.ida.ida_function"
        with (
            patch(f"{module}.ida_funcs.get_func", return_value=object()),
            patch(
                f"{module}.idautils.Chunks",
                return_value=[(0x2000, 0x2002), (0x1000, 0x1008)],
            ),
            patch(
                f"{module}.ida_bytes.get_bytes",
                side_effect=lambda ea, size: raw[ea],
            ),
            patch.object(
                IDAFunction, "idb", new_callable=PropertyMock,
                return_value=fake_db,
            ),
        ):
            listing = self.function.get_disassembly()

        self.assertIn("; binary: service", listing)
        self.assertIn("; function: handle_request", listing)
        self.assertIn("; symbol: sub_1000", listing)
        self.assertIn(f"; source_sha256: {'a' * 64}", listing)
        self.assertLess(
            listing.index("; chunk: 0x1000-0x1008"),
            listing.index("; chunk: 0x2000-0x2002"),
        )
        self.assertIn("0x00001000:  30 00 2d e9", listing)
        self.assertIn("PUSH            {R4,R5}", listing)
        self.assertIn("ADDIU           $sp, -0x20", listing)
        self.assertIn("push            rbp", listing)
        self.assertTrue(listing.endswith("\n"))

    def test_listing_does_not_require_hexrays_concretization(self):
        self.function._concretized = False
        insn = SimpleNamespace(ea=0x1000, size=4)
        fake_db = SimpleNamespace(
            instructions=_FakeInstructions(
                {(0x1000, 0x1004): [insn]},
                {0x1000: "BX              LR"},
            )
        )
        module = "fmst_analyzer.nodes.decompiler.ida.ida_function"
        with (
            patch(f"{module}.ida_funcs.get_func", return_value=object()),
            patch(f"{module}.idautils.Chunks", return_value=[(0x1000, 0x1004)]),
            patch(
                f"{module}.ida_bytes.get_bytes",
                return_value=bytes.fromhex("1e ff 2f e1"),
            ),
            patch.object(
                IDAFunction, "idb", new_callable=PropertyMock,
                return_value=fake_db,
            ),
        ):
            listing = self.function.get_disassembly()

        self.assertIn("0x00001000:  1e ff 2f e1", listing)
        self.assertIn("BX              LR", listing)

    def test_missing_instruction_bytes_fails(self):
        insn = SimpleNamespace(ea=0x1000, size=4)
        fake_db = SimpleNamespace(
            instructions=_FakeInstructions(
                {(0x1000, 0x1004): [insn]},
                {0x1000: "NOP"},
            )
        )
        module = "fmst_analyzer.nodes.decompiler.ida.ida_function"
        with (
            patch(f"{module}.ida_funcs.get_func", return_value=object()),
            patch(f"{module}.idautils.Chunks", return_value=[(0x1000, 0x1004)]),
            patch(f"{module}.ida_bytes.get_bytes", return_value=None),
            patch.object(
                IDAFunction, "idb", new_callable=PropertyMock,
                return_value=fake_db,
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "instruction bytes"):
                self.function.get_disassembly()

    def test_usercall_register_annotation_is_not_part_of_function_name(self):
        function = object.__new__(IDAFunction)
        function._name = "ev_set_io_collect_interval"
        function._ea = 0xA5AC
        function._module_name = "libcm.so"
        cfunc = SimpleNamespace(
            get_pseudocode=lambda: [
                SimpleNamespace(
                    line=(
                        "int __usercall ev_set_io_collect_interval@<$v0>"
                        "(int a1@<$f12>, int a2@<$f13>)"
                    )
                )
            ]
        )
        self.assertEqual(
            function.get_hexrays_displayed_name(cfunc),
            "ev_set_io_collect_interval",
        )

    def test_mips_plt_leading_dot_is_not_part_of_displayed_name(self):
        function = object.__new__(IDAFunction)
        function._name = ".__register_frame_info"
        function._ea = 0x40C220
        function._module_name = "httpd"
        cfunc = SimpleNamespace(
            get_pseudocode=lambda: [
                SimpleNamespace(line="int __register_frame_info(void)")
            ]
        )
        self.assertEqual(
            function.get_hexrays_displayed_name(cfunc),
            "__register_frame_info",
        )

    def test_gcc_clone_dots_follow_hexrays_identifier_normalization(self):
        function = object.__new__(IDAFunction)
        function._name = "cfbr_encrypt_block.part.0"
        function._ea = 0x249724
        function._module_name = "libgo.so"
        cfunc = SimpleNamespace(
            get_pseudocode=lambda: [
                SimpleNamespace(
                    line="int __fastcall cfbr_encrypt_block_part_0("
                )
            ]
        )
        self.assertEqual(
            function.get_hexrays_displayed_name(cfunc),
            "cfbr_encrypt_block_part_0",
        )

    def test_cross_idb_prototype_normalizes_provider_local_scalar_aliases(self):
        function = object.__new__(IDAFunction)
        function._name = "cJSON_CreateBinary"
        function._ea = 0x37D44
        function._module_name = "libmsgapi.so"
        function._saved_predefined_prototypes = SimpleNamespace(
            decl_str=(
                "_DWORD *__fastcall cJSON_CreateBinary"
                "(const void *a1, size_t a2);"
            )
        )
        module = "fmst_analyzer.nodes.decompiler.ida.ida_function"
        with (
            patch.object(IDAFunction, "activate"),
            patch(f"{module}.ida_typeinf.tinfo_t", return_value=object()),
            patch(f"{module}.ida_ida.inf_is_64bit", return_value=False),
            patch(f"{module}.ida_typeinf.parse_decl", return_value=True) as parse,
            patch(f"{module}.ida_typeinf.apply_tinfo", return_value=True),
        ):
            self.assertTrue(function.apply_predefined_prototype())

        self.assertEqual(
            parse.call_args.args[2],
            "unsigned int *__fastcall cJSON_CreateBinary"
            "(const void *a1, unsigned int a2);",
        )

    def test_cross_idb_prototype_uses_64_bit_size_type(self):
        function = object.__new__(IDAFunction)
        function._name = "consume"
        function._ea = 0x1000
        function._module_name = "libconsumer.so"
        function._saved_predefined_prototypes = SimpleNamespace(
            decl_str="void consume(const void *data, size_t size);"
        )
        module = "fmst_analyzer.nodes.decompiler.ida.ida_function"
        with (
            patch.object(IDAFunction, "activate"),
            patch(f"{module}.ida_ida.inf_is_64bit", return_value=True),
            patch(f"{module}.ida_typeinf.tinfo_t", return_value=object()),
            patch(f"{module}.ida_typeinf.parse_decl", return_value=True) as parse,
            patch(f"{module}.ida_typeinf.apply_tinfo", return_value=True),
        ):
            self.assertTrue(function.apply_predefined_prototype())

        self.assertEqual(
            parse.call_args.args[2],
            "void consume(const void *data, unsigned long size);",
        )

    def test_cross_idb_private_typedef_keeps_caller_local_type(self):
        function = object.__new__(IDAFunction)
        function._name = "start_thread"
        function._ea = 0x2000
        function._module_name = "consumer"
        function._saved_predefined_prototypes = SimpleNamespace(
            decl_str=(
                "pthread_t __cdecl start_thread"
                "(thread_body_t handler, void *args);"
            )
        )
        module = "fmst_analyzer.nodes.decompiler.ida.ida_function"
        with (
            patch.object(IDAFunction, "activate"),
            patch(f"{module}.ida_ida.inf_is_64bit", return_value=False),
            patch(f"{module}.ida_typeinf.tinfo_t", return_value=object()),
            patch(f"{module}.ida_typeinf.parse_decl", return_value=False),
            patch(f"{module}.ida_typeinf.apply_tinfo") as apply,
        ):
            self.assertFalse(function.apply_predefined_prototype())

        apply.assert_not_called()


class TestDisassemblyDumpLifecycle(unittest.TestCase):
    @staticmethod
    def _function(
        name: str,
        *,
        ea: int = 0x1000,
        external: bool = False,
        listing: str = "NOP\n",
    ):
        function = MagicMock()
        function.name = name
        function.module = "service"
        function.ea = ea
        function.decompiled_name = name
        function.artifact_stem = name
        function.structural_artifact_stem = f"{name}@{ea:x}"
        function.has_attr.side_effect = (
            lambda attr: external and attr == FunctionAttr.EXTERNAL
        )
        function.get_disassembly.return_value = listing
        return function

    def test_dump_pairs_functions_skips_external_and_is_idempotent(self):
        binary = MagicMock()
        graph = CallGraph(binary)
        included = self._function("included")
        external = self._function("external", external=True)
        graph._nodes_for_analysis = [included, external]

        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            graph.dump_disassembled_code(output)
            self.assertEqual(
                (output / "service/included.s").read_text(), "NOP\n"
            )
            self.assertFalse((output / "service/external.s").exists())
            binary.activate.assert_called_once_with()
            binary.deactivate.assert_called_once_with()

            binary.reset_mock()
            graph.dump_disassembled_code(output)
            binary.activate.assert_not_called()
            binary.deactivate.assert_not_called()

    def test_dump_closes_idb_when_rendering_fails(self):
        binary = MagicMock()
        graph = CallGraph(binary)
        failing = self._function("failing")
        failing.get_disassembly.side_effect = RuntimeError("decode failed")
        graph._nodes_for_analysis = [failing]

        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "decode failed"):
                graph.dump_disassembled_code(Path(temporary))
        binary.activate.assert_called_once_with()
        binary.deactivate.assert_called_once_with()

    def test_dump_replaces_listing_from_another_source_binary(self):
        binary = MagicMock()
        binary._source_sha256 = "b" * 64
        graph = CallGraph(binary)
        included = self._function(
            "included",
            listing=f"; source_sha256: {'b' * 64}\nNOP\n",
        )
        graph._nodes_for_analysis = [included]

        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            path = output / "service/included.s"
            path.parent.mkdir(parents=True)
            path.write_text(
                f"; source_sha256: {'a' * 64}\nOLD\n",
                encoding="utf-8",
            )

            graph.dump_disassembled_code(output)

            self.assertEqual(
                path.read_text(encoding="utf-8"),
                f"; source_sha256: {'b' * 64}\nNOP\n",
            )
        included.get_disassembly.assert_called_once_with()

    def test_structural_dump_needs_no_ctree_or_decompiled_name(self):
        binary = MagicMock()
        binary.name = "service"
        graph = CallGraph(binary)
        first = self._function("sub_1000", ea=0x1000, listing="first\n")
        second = self._function("sub_2000", ea=0x2000, listing="second\n")
        external = self._function("socket", ea=0x3000, external=True)
        binary.all_funcs = {
            first.ea: first,
            second.ea: second,
            external.ea: external,
        }

        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            graph.dump_disassembled_code(output, artifact_level="structural")

            self.assertEqual(
                (output / "service/sub_1000@1000.s").read_text(), "first\n"
            )
            self.assertEqual(
                (output / "service/sub_2000@2000.s").read_text(), "second\n"
            )
            self.assertFalse((output / "service/socket@3000.s").exists())

        first.get_disassembly.assert_called_once_with()
        second.get_disassembly.assert_called_once_with()
        binary.activate.assert_called_once_with()
        binary.deactivate.assert_called_once_with()

    def test_raw_global_xrefs_do_not_read_ctree_aliases(self):
        binary = MagicMock()
        binary.name = "service"
        binary.extract_global_var_xrefs.return_value = {"state": []}
        graph = CallGraph(binary)
        semantic_node = MagicMock()
        semantic_node.concretized = True
        semantic_node._global_vars = AssertionError("CTree aliases must not be read")
        graph._nodes_for_analysis = [semantic_node]

        with TemporaryDirectory() as temporary:
            graph.dump_global_var_xrefs(
                Path(temporary), include_semantic_aliases=False,
            )

        binary.extract_global_var_xrefs.assert_called_once_with({})

    def test_legacy_string_xref_without_function_ea_is_rebuilt(self):
        binary = MagicMock()
        binary.name = "service"
        binary.extract_string_xrefs.return_value = {
            "/tmp/demo.sock": [{
                "func": "open_channel",
                "func_ea": "0x1000",
                "ea": "0x1010",
            }],
        }
        graph = CallGraph(binary)

        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            module = output / "service"
            module.mkdir()
            path = module / "string_xrefs.json"
            path.write_text(
                '{"/tmp/demo.sock": [{"func": "open_channel", "ea": "0x1010"}]}',
                encoding="utf-8",
            )

            graph.dump_string_xrefs(output)

            self.assertIn("func_ea", path.read_text(encoding="utf-8"))
        binary.extract_string_xrefs.assert_called_once_with()


class TestDecompileAnalysisNaming(unittest.TestCase):
    def test_old_onboarding_api_is_removed(self):
        self.assertTrue(hasattr(LibDepGraph, "decompile_analysis"))
        self.assertFalse(hasattr(LibDepGraph, "onboard_binary"))


class TestDecompileAnalysisBoundary(unittest.IsolatedAsyncioTestCase):
    def test_structural_publication_writes_only_assembly(self):
        graph = object.__new__(LibDepGraph)
        graph._global_config = SimpleNamespace(
            disassembled_code_dir=Path("/tmp/disassembled"),
            decompiled_code_dir=Path("/tmp/decompiled"),
        )
        call_graph = MagicMock()
        binary = SimpleNamespace(
            structural_ready=True,
            semantic_ready=False,
            call_graph=call_graph,
        )

        graph._publish_structural_artifacts(binary)

        call_graph.dump_disassembled_code.assert_called_once_with(
            Path("/tmp/disassembled"), artifact_level="structural",
        )
        call_graph.dump_string_xrefs.assert_not_called()
        call_graph.dump_global_var_xrefs.assert_not_called()

    def test_structural_publication_restores_assembly_from_semantic_cache(self):
        graph = object.__new__(LibDepGraph)
        graph._global_config = SimpleNamespace(
            disassembled_code_dir=Path("/tmp/disassembled"),
            decompiled_code_dir=Path("/tmp/decompiled"),
        )
        call_graph = MagicMock()
        binary = SimpleNamespace(
            structural_ready=True,
            semantic_ready=True,
            call_graph=call_graph,
        )

        graph._publish_structural_artifacts(binary)

        call_graph.dump_disassembled_code.assert_called_once_with(
            Path("/tmp/disassembled"), artifact_level="semantic",
        )
        call_graph.dump_decompiled_code.assert_not_called()
        call_graph.dump_string_xrefs.assert_not_called()
        call_graph.dump_global_var_xrefs.assert_not_called()

    async def test_cpp_rejection_belongs_to_semantic_analysis(self):
        graph = object.__new__(LibDepGraph)
        binary = SimpleNamespace(name="peer_cpp", is_cxx_unsupported=True)
        with self.assertRaisesRegex(RuntimeError, "Structural IDA analysis is available"):
            await graph.decompile_analysis(binary)


class TestSemanticCacheLifecycle(unittest.TestCase):
    def test_sectionless_executable_load_segment_is_code(self):
        binary = object.__new__(IDABinary)
        binary._name = "sectionless"
        binary.idb_path = Path("/tmp/sectionless.i64")
        binary._binary_identity = "sectionless:sha"
        binary.segments = [
            ("LOAD", 0x400000, 0x410000, 5),
            ("LOAD", 0x420000, 0x430000, 6),
            ("extern", 0x500000, 0x501000, 0),
        ]
        binary._name_to_ea = {}
        binary._ea_to_func = {}
        binary._external_funcs = {}
        binary._text_funcs = {}
        binary._exported_funcs = {}
        binary._thunk_funcs = {}
        binary._plt_funcs = {}
        binary._thunk_to_target = {}
        binary._target_to_thunks = {}
        code = SimpleNamespace(name="entry", start_ea=0x401000)
        data = SimpleNamespace(name="data_label", start_ea=0x421000)
        external = SimpleNamespace(name="socket", start_ea=0x500100)
        functions = MagicMock()
        functions.get_between.side_effect = lambda start, _end: {
            0x400000: [code],
            0x420000: [data],
            0x500000: [external],
        }[start]
        functions.get_flags.return_value = FunctionFlags(0)
        database = SimpleNamespace(
            module="sectionless",
            functions=functions,
        )
        created = {}

        def create(_module, ea, name, attr, _idb_path, _identity):
            value = SimpleNamespace(ea=ea, name=name, attr=attr)
            created[ea] = value
            return value

        with (
            patch.object(IDABinary, "idb", new_callable=PropertyMock, return_value=database),
            patch.object(IDAFunction, "create", side_effect=create),
            patch("fmst_analyzer.nodes.decompiler.ida.ida_binary.ida_name.is_public_name", return_value=False),
        ):
            binary.traverse_functions()

        self.assertEqual(set(binary._text_funcs), {0x401000})
        self.assertEqual(set(binary._external_funcs), {0x500100})
        self.assertNotIn(0x421000, created)

    @staticmethod
    def _semantic_function(code: str = "int func(void)\n{\n  return 1;\n}"):
        function = MagicMock()
        function.name = "func"
        function.module = "service"
        function.decompiled_name = "func"
        function.artifact_stem = "func"
        function.has_attr.return_value = False
        function.semantic_snapshot = SimpleNamespace(rendered_code=code)
        function.get_processed_decompiled_code.return_value = code
        return function

    def test_same_decompiled_name_gets_stable_unique_artifact_stems(self):
        binary = MagicMock()
        binary.name = "service"
        graph = CallGraph(binary)
        first = MagicMock()
        first.ea = 0x1000
        first.decompiled_name = "duplicate"
        first.has_attr.return_value = False
        first.set_artifact_stem.side_effect = (
            lambda value: setattr(first, "artifact_stem", value)
        )
        second = MagicMock()
        second.ea = 0x2000
        second.decompiled_name = "duplicate"
        second.has_attr.return_value = False
        second.set_artifact_stem.side_effect = (
            lambda value: setattr(second, "artifact_stem", value)
        )
        graph._nodes_for_analysis = [second, first]

        graph._assign_artifact_stems()

        self.assertEqual(first.artifact_stem, "duplicate")
        self.assertEqual(second.artifact_stem, "duplicate@2000")

    def test_binary_cache_restore_rebuilds_stems_and_name_map(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "service"
            source.write_bytes(b"ELF")
            idb = root / "service.i64"
            idb.touch()

            def restored_function(ea: int):
                function = object.__new__(IDAFunction)
                function._module_name = "service"
                function._name = f"sub_{ea:x}"
                function._decompiled_name = "duplicate"
                function._ea = ea
                function._attr = FunctionAttr.TEXT
                function._concretized = True
                return function

            first = restored_function(0x1000)
            second = restored_function(0x2000)
            graph = CallGraph(None)
            graph._nodes_for_analysis = [second, first]
            graph._decompiled_name_map = {"stale": first}

            state = {
                "binary_path_str": str(source),
                "idb_path_str": str(idb),
                "arch": "arm",
                "_dyn_libs": [],
                "_default_libs": False,
                "_is_cxx_unsupported": False,
                "_name": "service",
                "segments": {},
                "_name_to_ea": {},
                "_ea_to_func": {first.ea: first, second.ea: second},
                "_external_funcs": {},
                "_text_funcs": {first.ea: first, second.ea: second},
                "_exported_funcs": {},
                "_thunk_funcs": {},
                "_plt_funcs": {},
                "_thunk_to_target": {},
                "_target_to_thunks": {},
                "_global_var_values": {},
                "_source_sha256": IDABinary._sha256_file(source),
                "_binary_identity": str(source),
                "_call_graph": graph,
            }

            binary = object.__new__(IDABinary)
            with patch.object(IDABinary, "_idb_matches_source", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "does not belong to source ELF"):
                    binary.__setstate__(state)
            with patch.object(IDABinary, "_idb_matches_source", return_value=True):
                binary.__setstate__(state)

            self.assertEqual(first.artifact_stem, "duplicate")
            self.assertEqual(second.artifact_stem, "duplicate@2000")
            self.assertIs(
                binary.call_graph.get_node_by_name("duplicate"), first,
            )
            self.assertIs(
                binary.call_graph.get_node_by_name("duplicate@2000"), second,
            )
            self.assertNotIn("stale", binary.call_graph._decompiled_name_map)

    def test_missing_or_stale_c_is_restored_from_snapshot(self):
        binary = MagicMock()
        binary.name = "service"
        graph = CallGraph(binary)
        function = self._semantic_function()
        graph._nodes_for_analysis = [function]

        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            path = output / "service/func.c"
            graph.dump_decompiled_code(output)
            self.assertEqual(path.read_text(encoding="utf-8"), function.semantic_snapshot.rendered_code)

            path.write_text("stale", encoding="utf-8")
            graph.dump_decompiled_code(output)
            self.assertEqual(path.read_text(encoding="utf-8"), function.semantic_snapshot.rendered_code)

    def test_old_callgraph_schema_is_not_semantic_ready(self):
        import ida_domain
        import idaapi

        with TemporaryDirectory() as temporary:
            binary = MagicMock()
            binary._binary_identity = "binary-id"
            binary.idb_path = Path(temporary) / "service.i64"
            graph = CallGraph(binary)
            function = MagicMock()
            function.has_attr.return_value = False
            function._semantic_snapshot = SimpleNamespace(
                is_current=True,
                binary_identity="binary-id",
                idb_identity=str(binary.idb_path.absolute().resolve()),
                ida_version=str(idaapi.get_kernel_version()),
                ida_domain_version=str(ida_domain.__version__),
            )
            graph._nodes_for_analysis = [function]
            graph._structural_complete = True
            graph._semantic_complete = True
            self.assertTrue(graph.semantic_ready)
            graph._cache_schema_version = 0
            self.assertFalse(graph.semantic_ready)

    def test_exact_hexrays_failure_is_accounted_as_semantic_frontier(self):
        import ida_domain
        import idaapi

        with TemporaryDirectory() as temporary:
            binary = MagicMock()
            binary.name = "service"
            binary._binary_identity = "binary-id"
            binary.idb_path = Path(temporary) / "service.i64"
            function = MagicMock()
            function.ea = 0x1000
            function.has_attr.return_value = False
            function._semantic_snapshot = None

            graph = CallGraph(binary)
            graph._nodes_for_analysis = [function]
            graph._semantic_failures[function.ea] = SemanticExtractionFailure(
                binary_name="service",
                function_ea=function.ea,
                function_name="uloop_run",
                error="Hex-Rays failed to decompile",
                binary_identity="binary-id",
                idb_identity=str(binary.idb_path.absolute().resolve()),
                ida_version=str(idaapi.get_kernel_version()),
                ida_domain_version=str(ida_domain.__version__),
            )
            graph._structural_complete = True
            graph._semantic_complete = True

            self.assertTrue(graph.semantic_ready)

    def test_failed_snapshot_omits_c_but_keeps_assembly(self):
        binary = MagicMock()
        binary.name = "service"
        graph = CallGraph(binary)
        function = MagicMock()
        function.ea = 0x1000
        function.name = "uloop_run"
        function.module = "service"
        function.decompiled_name = "uloop_run"
        function.artifact_stem = "uloop_run"
        function.has_attr.return_value = False
        function.get_disassembly.return_value = "; function: uloop_run\nNOP\n"
        graph._nodes_for_analysis = [function]
        graph._semantic_failures[function.ea] = MagicMock()

        with TemporaryDirectory() as temporary:
            output = Path(temporary)
            graph.dump_decompiled_code(output / "c")
            graph.dump_disassembled_code(output / "s")

            self.assertFalse((output / "c/service/uloop_run.c").exists())
            self.assertEqual(
                (output / "s/service/uloop_run.s").read_text(encoding="utf-8"),
                "; function: uloop_run\nNOP\n",
            )

    def test_artifact_ready_is_not_serialized(self):
        binary = object.__new__(IDABinary)
        binary.binary_path = Path("/tmp/service")
        binary.idb_path = Path("/tmp/service.i64")
        binary.arch = "metapc"
        binary._dyn_libs = []
        binary._default_libs = False
        binary._is_cxx_unsupported = False
        binary._name = "service"
        binary.segments = {}
        binary._name_to_ea = {}
        binary._ea_to_func = {}
        binary._external_funcs = {}
        binary._text_funcs = {}
        binary._exported_funcs = {}
        binary._thunk_funcs = {}
        binary._plt_funcs = {}
        binary._thunk_to_target = {}
        binary._target_to_thunks = {}
        binary._global_var_values = {}
        binary._source_sha256 = "sha"
        binary._binary_identity = "identity"
        binary._call_graph = None
        binary._artifacts_ready = True
        self.assertNotIn("_artifacts_ready", binary.__getstate__())

    def test_changed_source_rejects_cached_binary_state(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "service"
            source.write_bytes(b"original")
            cached_hash = IDABinary._sha256_file(source)
            source.write_bytes(b"changed")
            state = {
                "binary_path_str": str(source),
                "idb_path_str": str(root / "service.i64"),
                "_source_sha256": cached_hash,
            }
            binary = object.__new__(IDABinary)
            with self.assertRaisesRegex(RuntimeError, "Source ELF changed"):
                binary.__setstate__(state)

    def test_semantic_enrichment_closes_idb_after_failure(self):
        binary = MagicMock()
        binary.name = "service"
        binary.external_funcs = {}
        binary.all_funcs = {}
        with patch.object(CallGraph, "topological_sort", return_value=[]):
            graph = CallGraph.build_structural(binary, "ida", MagicMock())
        with (
            patch.object(
                graph,
                "deep_analysis",
                side_effect=RuntimeError("decompile failed"),
            ),
            patch.object(FunctionNode, "close_database") as close_database,
        ):
            with self.assertRaisesRegex(RuntimeError, "decompile failed"):
                graph.enrich_semantics(MagicMock())
        close_database.assert_called_once_with()

    def test_structural_build_never_invokes_deep_analysis(self):
        binary = MagicMock()
        binary.name = "service"
        binary.external_funcs = {}
        binary.all_funcs = {}

        with (
            patch.object(CallGraph, "topological_sort", return_value=[]),
            patch.object(CallGraph, "deep_analysis") as deep_analysis,
        ):
            graph = CallGraph.build_structural(
                binary_node=binary,
                decompiler="ida",
                global_config=MagicMock(),
            )

        self.assertTrue(graph.structural_ready)
        self.assertFalse(graph.semantic_ready)
        deep_analysis.assert_not_called()

    def test_semantic_enrichment_upgrades_the_existing_structural_graph(self):
        binary = MagicMock()
        binary.name = "service"
        graph = CallGraph(binary)
        graph._structural_complete = True

        with (
            patch.object(graph, "deep_analysis") as deep_analysis,
            patch.object(FunctionNode, "close_database") as close_database,
        ):
            graph.enrich_semantics(MagicMock())

        self.assertTrue(graph.semantic_ready)
        deep_analysis.assert_called_once_with(unittest.mock.ANY)
        close_database.assert_called_once_with()

    def test_semantic_invalidation_clears_external_prototype_state(self):
        function = object.__new__(IDAFunction)
        function._name = "connect"
        function._decompiled_name = "renamed_connect"
        function._semantic_snapshot = object()
        function._callsites = {1: object()}
        function._linenum_to_callsite = {1: [object()]}
        function._global_vars = {0x1000: "value"}
        function._gvar_name_to_original = {"GVar_value": "value"}
        function._original_to_gvar_name = {"value": "GVar_value"}
        function._prototype_info = object()
        function._saved_predefined_prototypes = object()
        function._artifact_stem = "renamed_connect"
        function._concretized = True
        function._structural_callee_addrs = SortedSet([0x2000])
        function._callee_addrs = SortedSet([0x2000, 0x3000])

        function.invalidate_semantic_snapshot()

        self.assertFalse(function._concretized)
        self.assertIsNone(function._prototype_info)
        self.assertIsNone(function._saved_predefined_prototypes)
        self.assertEqual(function._decompiled_name, "connect")
        self.assertEqual(function._callee_addrs, SortedSet([0x2000]))
        self.assertNotIn("_artifact_stem", function.__dict__)

    def test_fast_callgraph_skips_unregistered_callee_ea(self):
        binary = MagicMock()
        binary.name = "service"
        binary.external_funcs = {}
        function = MagicMock(spec=FunctionNode)
        function.name = "caller"
        function.get_structural_callees.return_value = [0x2000]
        binary.all_funcs = {0x1000: function}

        with patch.object(CallGraph, "topological_sort", return_value=[]):
            graph = CallGraph.build_structural(binary, "ida", MagicMock())

        self.assertEqual(graph.get_edges(), set())

    def test_structural_adg_excludes_ctree_supplemented_call_edge(self):
        binary = MagicMock()
        binary.name = "service"

        caller = MagicMock(spec=FunctionNode)
        caller.module = "service"
        caller.ea = 0x1000
        caller.get_structural_callees.return_value = SortedSet([0x2000])
        structural_callee = MagicMock(spec=FunctionNode)
        structural_callee.module = "service"
        structural_callee.ea = 0x2000
        semantic_only_callee = MagicMock(spec=FunctionNode)
        semantic_only_callee.module = "service"
        semantic_only_callee.ea = 0x3000
        binary.all_funcs = {
            0x1000: caller,
            0x2000: structural_callee,
            0x3000: semantic_only_callee,
        }

        graph = CallGraph(binary)
        for function in binary.all_funcs.values():
            graph.add_node(function)
        graph.add_edge(caller, structural_callee, EdgeType.CALL)
        graph.add_edge(caller, semantic_only_callee, EdgeType.CALL)

        adg = ApiDepGraph(
            lib_dep_graph=MagicMock(),
            root=binary,
            scope={binary},
            global_config=MagicMock(),
            analysis_level="structural",
        )
        adg.binary_callgraphs[binary] = graph
        adg._integrate_callgraphs()

        self.assertTrue(adg.has_edge(caller, structural_callee))
        self.assertFalse(adg.has_edge(caller, semantic_only_callee))

    def test_semantic_invalidation_removes_ctree_only_call_edge(self):
        binary = MagicMock()
        binary.name = "service"
        caller = MagicMock(spec=FunctionNode)
        structural_callee = MagicMock(spec=FunctionNode)
        semantic_only_callee = MagicMock(spec=FunctionNode)
        caller.get_structural_callees.return_value = SortedSet([0x2000])
        structural_callee.get_structural_callees.return_value = SortedSet()
        semantic_only_callee.get_structural_callees.return_value = SortedSet()
        binary.all_funcs = {
            0x1000: caller,
            0x2000: structural_callee,
            0x3000: semantic_only_callee,
        }

        graph = CallGraph(binary)
        graph._structural_complete = True
        for function in binary.all_funcs.values():
            graph.add_node(function)
        graph.add_edge(caller, structural_callee, EdgeType.CALL)
        graph.add_edge(caller, semantic_only_callee, EdgeType.CALL)

        graph.invalidate_semantics()

        self.assertTrue(graph.has_edge(caller, structural_callee))
        self.assertFalse(graph.has_edge(caller, semantic_only_callee))

    def test_ctree_direct_callee_without_function_node_keeps_no_edge(self):
        binary = MagicMock()
        binary.name = "service"
        binary.resolve_all_global_values.return_value = None
        binary.find_thunk_funcs.return_value = []

        function = MagicMock(spec=FunctionNode)
        function.name = "caller"
        function.module = "service"
        function.ea = 0x1000
        function.concretized = True
        function._global_vars = {}
        function.has_attr.side_effect = lambda attr: attr == FunctionAttr.TEXT
        function.get_callees.return_value = [0x2000]
        binary.get_function_by_ea.side_effect = RuntimeError(
            "Function at address 0x2000 not found"
        )

        graph = CallGraph(binary, MagicMock(DEFAULT_LIB=[]))
        graph.add_node(function)
        graph._reverse_topological_sorted_nodes = [function]
        lib_dep_graph = MagicMock()
        lib_dep_graph.transitive_closure_from.return_value = {binary}

        with patch.object(FunctionNode, "close_database"):
            graph.deep_analysis(lib_dep_graph)

        self.assertEqual(graph.get_edges(), set())
        self.assertEqual(graph._nodes_for_analysis, [function])

    def test_failed_custom_implementation_prototype_does_not_block_caller(self):
        binary = MagicMock()
        binary.name = "libcaller.so"
        binary.resolve_all_global_values.return_value = None
        binary.find_thunk_funcs.return_value = []

        external = MagicMock(spec=FunctionNode)
        external.name = "uloop_run"
        external.ea = 0x2000
        external.has_attr.side_effect = (
            lambda attr: attr == FunctionAttr.EXTERNAL
        )

        implementation = MagicMock(spec=FunctionNode)
        implementation.name = "uloop_run"
        implementation.concretized = False
        implementation_library = MagicMock()
        implementation_library.name = "libubox.so"
        implementation_library.get_function_by_ea.return_value = implementation

        graph = CallGraph(binary, MagicMock(DEFAULT_LIB=[]))
        graph.add_node(external)
        graph._reverse_topological_sorted_nodes = [external]
        lib_dep_graph = MagicMock()
        lib_dep_graph.transitive_closure_from.return_value = {binary}
        lib_dep_graph.find_implementation_in_scope.return_value = (
            implementation_library,
            0x3000,
        )

        with patch.object(FunctionNode, "close_database"):
            graph.deep_analysis(lib_dep_graph)

        implementation.get_prototype_info.assert_not_called()
        external.save_predefined_prototype.assert_not_called()
        self.assertEqual(graph._nodes_for_analysis, [])


class TestIDARuntimeCacheIdentity(unittest.TestCase):
    def tearDown(self):
        IDABinary.clear_cache()
        IDABinary.workdir = None
        IDAFunction.clear_cache()

    def test_function_cache_is_scoped_by_idb_path(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(IDAFunction, "__init__", return_value=None):
                first = IDAFunction.create(
                    "service", 0x1000, "func", FunctionAttr.TEXT,
                    root / "a.i64",
                )
                same = IDAFunction.create(
                    "service", 0x1000, "func", FunctionAttr.TEXT,
                    root / "a.i64",
                )
                other = IDAFunction.create(
                    "service", 0x1000, "func", FunctionAttr.TEXT,
                    root / "b.i64",
                )
        self.assertIs(first, same)
        self.assertIsNot(first, other)

    def test_function_cache_preserves_distinct_source_owners_of_identical_code(self):
        with TemporaryDirectory() as temporary:
            idb = Path(temporary) / "shared.i64"
            with patch.object(IDAFunction, "__init__", return_value=None):
                first = IDAFunction.create("service", 0x1000, "func", FunctionAttr.TEXT, idb, "source-a:hash")
                second = IDAFunction.create("service", 0x1000, "func", FunctionAttr.TEXT, idb, "source-b:hash")
                self.assertIsNot(first, second)

    def test_same_basename_different_sources_get_distinct_idbs(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "sbin/service"
            second = root / "usr/sbin/service"
            for path, data in ((first, b"first ELF"), (second, b"second ELF")):
                path.parent.mkdir(parents=True)
                path.write_bytes(data)
            IDABinary.set_workdir(root / "databases")
            with patch.object(IDABinary, "__init__", return_value=None) as init:
                IDABinary.create(first)
                IDABinary.create(second)
            first_idb, second_idb = (call.args[1] for call in init.call_args_list)
            self.assertNotEqual(first_idb, second_idb)
            self.assertEqual(first_idb.name, second_idb.name)
            self.assertTrue(first_idb.parent.is_dir())
            self.assertTrue(second_idb.parent.is_dir())

    def test_binary_cache_is_scoped_by_workdir(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_path = root / "rootfs/usr/sbin/service"
            binary_path.parent.mkdir(parents=True)
            binary_path.write_bytes(b"ELF fixture")
            with patch.object(IDABinary, "__init__", return_value=None):
                IDABinary.set_workdir(root / "work-a")
                first = IDABinary.create(binary_path)
                same = IDABinary.create(binary_path)
                IDABinary.set_workdir(root / "work-b")
                other = IDABinary.create(binary_path)
        self.assertIs(first, same)
        self.assertIsNot(first, other)


class TestIDBManagerLifecycle(unittest.TestCase):
    def tearDown(self):
        IDBManager._current_idb = None
        IDBManager._current_idb_path = None

    def test_close_failure_still_clears_global_state(self):
        database = MagicMock()
        database.is_open.return_value = True
        database.close.side_effect = RuntimeError("native close failed")
        IDBManager._current_idb = database
        IDBManager._current_idb_path = "/tmp/service.i64"

        with (
            patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.ida_nalt.retrieve_input_file_sha256", return_value=b"a" * 32),
            self.assertRaisesRegex(RuntimeError, "native close failed"),
        ):
            IDBManager.close_current_idb()

        self.assertIsNone(IDBManager.get_current_idb())
        self.assertIsNone(IDBManager.get_current_idb_path())

    def test_missing_native_identity_discards_without_overwriting_idb(self):
        database = MagicMock()
        database.is_open.return_value = True
        IDBManager._current_idb = database
        IDBManager._current_idb_path = "/tmp/service.i64"
        with (
            patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.ida_nalt.retrieve_input_file_sha256", return_value=None),
            self.assertRaisesRegex(RuntimeError, "lost its input SHA256"),
        ):
            IDBManager.close_current_idb()
        database.close.assert_called_once_with(save=False)
        self.assertIsNone(IDBManager.get_current_idb())
        self.assertIsNone(IDBManager.get_current_idb_path())

    def test_open_rejects_incomplete_native_state_without_saving(self):
        database = MagicMock()
        database.is_open.return_value = True
        with (
            patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.Database.open", return_value=database),
            patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.ida_nalt.retrieve_input_file_sha256", return_value=None),
            self.assertRaisesRegex(RuntimeError, "lost its input SHA256"),
        ):
            IDBManager.open_idb(Path("/tmp/service.i64"), object())
        database.close.assert_called_once_with(save=False)
        self.assertIsNone(IDBManager.get_current_idb())
        self.assertIsNone(IDBManager.get_current_idb_path())

    def test_existing_idb_open_failure_preserves_file_without_rebuilding(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_path = root / "service"
            binary_path.write_bytes(b"ELF fixture")
            idb_path = root / "service.i64"
            original_idb = b"existing healthy database fixture"
            idb_path.write_bytes(original_idb)

            with (
                patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.Database.open",
                      side_effect=RuntimeError("native load failed")),
                patch.object(IDBManager, "create_idb") as create_idb,
                self.assertRaisesRegex(RuntimeError, "native load failed"),
            ):
                IDABinary(binary_path, idb_path)

            self.assertEqual(idb_path.read_bytes(), original_idb)
            create_idb.assert_not_called()

    def test_existing_idb_hash_read_failure_propagates_and_closes(self):
        binary = object.__new__(IDABinary)
        binary.idb_path = Path("service.i64")
        binary.ida_cmd_options = object()
        binary._source_sha256 = "ab" * 32
        with (
            patch.object(IDBManager, "open_idb"),
            patch.object(IDBManager, "close_current_idb") as close_idb,
            patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.ida_nalt.retrieve_input_file_sha256",
                  side_effect=RuntimeError("native hash read failed")),
            self.assertRaisesRegex(RuntimeError, "native hash read failed"),
        ):
            binary._idb_matches_source()
        close_idb.assert_called_once_with()

    def test_existing_idb_with_valid_different_hash_is_a_mismatch(self):
        binary = object.__new__(IDABinary)
        binary.idb_path = Path("service.i64")
        binary.ida_cmd_options = object()
        binary._source_sha256 = "ab" * 32
        with (
            patch.object(IDBManager, "open_idb"),
            patch.object(IDBManager, "close_current_idb") as close_idb,
            patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.ida_nalt.retrieve_input_file_sha256",
                  return_value=b"\xcd" * 32),
        ):
            self.assertFalse(binary._idb_matches_source())
        close_idb.assert_called_once_with()

    def test_existing_idb_without_readable_identity_is_not_a_mismatch(self):
        binary = object.__new__(IDABinary)
        binary.idb_path = Path("service.i64")
        binary.ida_cmd_options = object()
        binary._source_sha256 = "ab" * 32
        with (
            patch.object(IDBManager, "open_idb"),
            patch.object(IDBManager, "close_current_idb") as close_idb,
            patch("fmst_analyzer.nodes.decompiler.ida.idb_manager.ida_nalt.retrieve_input_file_sha256",
                  return_value=None),
            self.assertRaisesRegex(RuntimeError, "lost its input SHA256"),
        ):
            binary._idb_matches_source()
        close_idb.assert_called_once_with()

    def test_binary_initialization_failure_closes_database(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_path = root / "service"
            binary_path.write_bytes(b"ELF")
            idb_path = root / "service.i64"
            idb_path.touch()
            database = SimpleNamespace(architecture="arm", module="service")

            with (
                patch.object(IDABinary, "_idb_matches_source", return_value=True),
                patch.object(IDABinary, "idb", new_callable=PropertyMock, return_value=database),
                patch.object(IDABinary, "_IDABinary__get_dynamic_libraries", return_value=[]),
                patch.object(BinaryNode, "_detect_cxx_unsupported", return_value=False),
                patch.object(IDABinary, "traverse_segments", side_effect=RuntimeError("traversal failed")),
                patch.object(IDBManager, "close_current_idb") as close_database,
            ):
                with self.assertRaisesRegex(RuntimeError, "traversal failed"):
                    IDABinary(binary_path, idb_path)

            close_database.assert_called_once_with()

    def test_source_basename_binds_binary_when_ida_module_is_missing_or_stale(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_path = root / "libcrypto.so.1.0.0"
            binary_path.write_bytes(b"ELF fixture")
            idb_path = root / "library.i64"
            idb_path.touch()
            for module in [None, "old-input-name"]:
                with (
                    self.subTest(module=module),
                    patch.object(IDABinary, "_idb_matches_source", return_value=True),
                    patch.object(IDABinary, "idb", new_callable=PropertyMock,
                                 return_value=SimpleNamespace(architecture="mips", module=module)),
                    patch.object(IDABinary, "_IDABinary__get_dynamic_libraries", return_value=[]),
                    patch.object(BinaryNode, "_detect_cxx_unsupported", return_value=False),
                    patch.object(IDABinary, "traverse_segments"),
                    patch.object(IDABinary, "traverse_functions"),
                    patch.object(IDBManager, "close_current_idb"),
                ):
                    binary = IDABinary(binary_path, idb_path)
                    self.assertEqual(binary.name, "libcrypto.so.1.0.0")

    def test_empty_non_default_binary_analysis_fails_closed(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary_path = root / "service"
            binary_path.write_bytes(b"ELF")
            idb_path = root / "service.i64"
            idb_path.touch()
            database = SimpleNamespace(architecture="mips", module="service")

            def no_functions(binary):
                binary._text_funcs.clear()

            with (
                patch.object(IDABinary, "_idb_matches_source", return_value=True),
                patch.object(IDABinary, "idb", new_callable=PropertyMock, return_value=database),
                patch.object(IDABinary, "_IDABinary__get_dynamic_libraries", return_value=[]),
                patch.object(BinaryNode, "_detect_cxx_unsupported", return_value=False),
                patch.object(IDABinary, "traverse_segments"),
                patch.object(IDABinary, "traverse_functions", autospec=True, side_effect=no_functions),
                patch.object(IDBManager, "close_current_idb") as close_database,
            ):
                with self.assertRaisesRegex(RuntimeError, "no executable functions"):
                    IDABinary(binary_path, idb_path)

            close_database.assert_called_once_with()
class TestWorkdirInvalidation(unittest.TestCase):
    _DIRS = {
        "graph": "graph_cache",
        "idb": "decompiler_db",
        "c": "decompiled_code",
        "s": "disassembled_code",
    }

    def _exercise(self, flag: str, expected_cleared: set[str]):
        with TemporaryDirectory() as temporary:
            workdir = Path(temporary) / "image"
            config = GlobalConfig()
            config.setup_workdir(workdir)
            markers = {}
            for name, relative in self._DIRS.items():
                marker = workdir / relative / "marker"
                marker.write_text(name)
                markers[name] = marker

            kwargs = {flag: True}
            with patch.object(IDABinary, "clear_cache") as clear_ida:
                config.setup_workdir(workdir, **kwargs)

            for name, marker in markers.items():
                self.assertEqual(
                    marker.exists(),
                    name not in expected_cleared,
                    f"unexpected invalidation state for {flag}: {name}",
                )
            if flag in {
                "clear_graph_cache",
                "clear_decompiler_db_cache",
                "clear_all",
            }:
                clear_ida.assert_called_once()
            else:
                clear_ida.assert_not_called()

    def test_clear_decompiler_db_cascades(self):
        self._exercise(
            "clear_decompiler_db_cache",
            {"graph", "idb", "c", "s"},
        )

    def test_clear_graph_cascades(self):
        self._exercise(
            "clear_graph_cache", {"graph", "c", "s"}
        )

    def test_clear_decompiled_code_cascades(self):
        self._exercise(
            "clear_decompiled_code", {"c", "s"}
        )

    def test_clear_all_removes_everything(self):
        self._exercise(
            "clear_all", {"graph", "idb", "c", "s"}
        )


class TestBinaryAmbiguity(unittest.TestCase):
    def test_metadata_index_never_overwrites_duplicate_basename(self):
        paths = [Path("/root/bin/service"), Path("/root/usr/sbin/service")]
        index = index_paths_by_basename(paths)
        self.assertEqual(index["service"], tuple(paths))
        with self.assertRaisesRegex(AmbiguousBinaryError, "bin/service") as error:
            resolve_unique_basename(
                "service", index, Path("/root"), purpose="target binary"
            )
        self.assertIn("usr/sbin/service", str(error.exception))

    def test_dt_needed_identical_copies_are_stable(self):
        with TemporaryDirectory() as temporary:
            rootfs = Path(temporary).resolve()
            first = rootfs / "a/libsame.so"
            second = rootfs / "b/libsame.so"
            first.parent.mkdir()
            second.parent.mkdir()
            contents = b"\x7fELFidentical"
            first.write_bytes(contents)
            second.write_bytes(contents)
            self.assertEqual(find_binary_in_rootfs("libsame.so", rootfs), first)

    def test_dt_needed_different_copies_fail_with_all_candidates(self):
        with TemporaryDirectory() as temporary:
            rootfs = Path(temporary)
            first = rootfs / "a/libsame.so"
            second = rootfs / "b/libsame.so"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_bytes(b"\x7fELFfirst")
            second.write_bytes(b"\x7fELFsecond")
            with self.assertRaises(AmbiguousBinaryError) as error:
                find_binary_in_rootfs("libsame.so", rootfs)
            message = str(error.exception)
            self.assertIn("a/libsame.so", message)
            self.assertIn("b/libsame.so", message)

    def test_lib_dep_graph_rejects_second_same_basename_path(self):
        class FakeBinary:
            def __init__(self, path):
                self.binary_path = path.absolute()
                self.name = path.name
                self.dependencies = []
                self.exported_funcs = {}
                self.external_funcs = {}
                self.is_cxx_unsupported = False
                self.structural_ready = True

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "bin/service"
            second = root / "usr/sbin/service"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            config = SimpleNamespace(
                decompiler_db_dir=root / "idb",
                graph_cache_dir=None,
                binary_cache_dir=None,
                graph_dots_dir=None,
                DEFAULT_LIB=[],
            )
            with (
                patch.object(BinaryNode, "set_decompiler"),
                patch.object(
                    BinaryNode, "create",
                    side_effect=lambda path: FakeBinary(path),
                ),
                patch.object(LibDepGraph, "_publish_structural_artifacts"),
                patch.object(LibDepGraph, "_ensure_structural_adg"),
            ):
                graph = LibDepGraph(root, config, use_cache=False)
                first_node = graph.add_binary(first)
                self.assertIn(first_node, graph.get_nodes())
                with self.assertRaisesRegex(
                    AmbiguousBinaryError, "already represented"
                ):
                    graph.add_binary(second)

    def test_add_binary_allows_cpp_structural_analysis(self):
        class FakeBinary:
            def __init__(self, path):
                self.binary_path = path.absolute()
                self.name = path.name
                self.dependencies = []
                self.exported_funcs = {}
                self.external_funcs = {}
                self.is_cxx_unsupported = True
                self.structural_ready = True

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "bin/peer_cpp"
            target.parent.mkdir(parents=True)
            config = SimpleNamespace(
                decompiler_db_dir=root / "idb",
                graph_cache_dir=None,
                binary_cache_dir=None,
                graph_dots_dir=None,
                DEFAULT_LIB=[],
            )
            with (
                patch.object(BinaryNode, "set_decompiler"),
                patch.object(BinaryNode, "create", return_value=FakeBinary(target)),
                patch.object(LibDepGraph, "_publish_structural_artifacts"),
                patch.object(LibDepGraph, "_ensure_structural_adg"),
            ):
                graph = LibDepGraph(root, config, use_cache=False)
                node = graph.add_binary(target)

        self.assertTrue(node.is_cxx_unsupported)
        self.assertIn(node, graph.get_nodes())

    def test_topology_cache_rejects_duplicate_basename_paths(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            graph_cache = root / "graph-cache"
            graph_cache.mkdir()
            first = root / "bin/service"
            second = root / "usr/sbin/service"
            topology = {
                "schema_version": LIB_DEP_GRAPH_TOPOLOGY_SCHEMA_VERSION,
                "nodes": [
                    ("service", str(first)),
                    ("service", str(second)),
                ],
                "edges": [],
                "roots": ["service"],
                "rootfs_path": str(root),
            }
            with (graph_cache / "LibDepGraph_default.pkl").open("wb") as stream:
                pickle.dump(topology, stream)

            config = SimpleNamespace(
                decompiler_db_dir=root / "idb",
                graph_cache_dir=graph_cache,
                binary_cache_dir=graph_cache / "binary-cache",
                graph_dots_dir=None,
            )
            with patch.object(BinaryNode, "set_decompiler"):
                graph = LibDepGraph(root, config, use_cache=True)

            with self.assertRaises(AmbiguousBinaryError) as error:
                graph._load_from_topology_cache()
            message = str(error.exception)
            self.assertIn(str(first), message)
            self.assertIn(str(second), message)

    def test_legacy_topology_cache_is_deleted_without_invalidating_binary_cache(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            graph_cache = root / "graph-cache"
            graph_cache.mkdir()
            cache_file = graph_cache / "LibDepGraph_default.pkl"
            with cache_file.open("wb") as stream:
                pickle.dump({
                    "nodes": [],
                    "edges": [],
                    "roots": [],
                    "rootfs_path": str(root),
                }, stream)

            config = SimpleNamespace(
                decompiler_db_dir=root / "idb",
                graph_cache_dir=graph_cache,
                binary_cache_dir=graph_cache / "binary-cache",
                graph_dots_dir=None,
            )
            with patch.object(BinaryNode, "set_decompiler"):
                graph = LibDepGraph(root, config, use_cache=True)

            self.assertFalse(graph._load_from_topology_cache())
            self.assertFalse(cache_file.exists())


if __name__ == "__main__":
    unittest.main()
