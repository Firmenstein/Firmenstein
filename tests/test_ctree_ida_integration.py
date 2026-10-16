"""End-to-end CTree semantic extraction against O0 and O2 ELF fixtures."""

from __future__ import annotations

import json
import pickle
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory

from dotenv import load_dotenv
import pytest

pytestmark = pytest.mark.external

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
sys.path.insert(0, str(ROOT / "src"))
pytest.importorskip("idapro", reason="IDA integration requires the optional SDK")

from fmst_analyzer.nodes.decompiler.ida.ida_binary import IDABinary
from fmst_analyzer.nodes.decompiler.ida.idb_manager import IDBManager


class TestCTreeIDAIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.fixture_dir = ROOT / "tests/fixtures/ctree_semantics"
        cls.golden = json.loads(
            (cls.fixture_dir / "golden.json").read_text(encoding="utf-8")
        )
        subprocess.run(
            ["make", f"OUT_DIR={cls.root / 'build'}", "all"],
            cwd=cls.fixture_dir,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        IDABinary.clear_cache()
        IDABinary.set_workdir(cls.root / "idb")
        (cls.root / "idb").mkdir()

    @classmethod
    def tearDownClass(cls) -> None:
        IDABinary.clear_cache()
        IDABinary.workdir = None
        cls.temporary.cleanup()

    def _snapshots(self, optimization: str):
        binary = IDABinary.create(
            self.root / "build" / f"ctree_semantics_{optimization}"
        )
        snapshots = {}
        try:
            for name in self.golden["required_functions"]:
                function = binary.get_function_by_name(name)
                function.activate()
                snapshots[name] = (function, function.post_decompile_analysis())
        finally:
            IDBManager.close_current_idb()
        return binary, snapshots

    def test_golden_semantics_and_identity_at_o0_and_o2(self):
        for optimization in ("O0", "O2"):
            with self.subTest(optimization=optimization):
                binary, records = self._snapshots(optimization)

                for name, (function, snapshot) in records.items():
                    self.assertTrue(snapshot.is_current)
                    self.assertEqual(snapshot.binary_identity, binary._binary_identity)
                    self.assertEqual(
                        snapshot.idb_identity,
                        str(binary.idb_path.absolute().resolve()),
                    )
                    self.assertEqual(
                        len(snapshot.raw_code.splitlines()),
                        len(snapshot.rendered_code.splitlines()),
                    )
                    self.assertEqual(
                        set(snapshot.callsites), set(function.get_callsites())
                    )
                    self.assertEqual(
                        pickle.loads(pickle.dumps(snapshot)), snapshot
                    )

                    rendered_lines = snapshot.rendered_code.splitlines()
                    for ctree_index, info in snapshot.callsites.items():
                        self.assertEqual(ctree_index, info.location.ctree_index)
                        self.assertGreater(info.location.source_ea, 0)
                        self.assertGreaterEqual(info.column_number, 0)
                        line = rendered_lines[info.line_number - 1]
                        expression = info.location.expression_text
                        self.assertEqual(
                            line[info.column_number:info.column_number + len(expression)],
                            expression,
                        )

                direct = next(iter(records["direct_return"][1].callsites.values()))
                self.assertEqual(direct.callee_name, "leaf")
                self.assertEqual(direct.return_info.name, "DIRECT_RET")

                call_shapes = records["call_shapes"][1]
                self.assertGreaterEqual(
                    sum(i.callee_name == "leaf" for i in call_shapes.callsites.values()),
                    self.golden["call_shapes"]["minimum_leaf_calls"],
                )

                same_line = records["same_line_calls"][1]
                leaf_lines = [
                    info.line_number for info in same_line.callsites.values()
                    if info.callee_name == "leaf"
                ]
                self.assertGreaterEqual(
                    len(leaf_lines),
                    self.golden["same_line_calls"]["minimum_leaf_calls"],
                )
                self.assertTrue(any(count > 1 for count in Counter(leaf_lines).values()))

                nested = records["nested_call"][1]
                inner = next(i for i in nested.callsites.values() if i.callee_name == "leaf")
                outer = next(i for i in nested.callsites.values() if i.callee_name == "combine")
                self.assertIsNotNone(inner.return_info)
                self.assertIn(
                    inner.return_info.name,
                    {argument.name for argument in outer.arguments},
                )

                merged = records["merged_tail_call"][1]
                self.assertTrue(
                    all(info.callee_name == "leaf" for info in merged.callsites.values())
                )

                flow = records["flow_cycle"][1].trace_variable_prop(
                    "flow_cycle", self.golden["flow_cycle"]["initial"]
                )
                self.assertEqual(
                    {record.varname for record in flow.variables},
                    set(self.golden["flow_cycle"]["related"]),
                )

                mixed = records["mixed_rhs"][1]
                flow_types = {
                    edge.type
                    for variables in mixed.variables.values()
                    for variable in variables
                    for edge in variable.flows_from
                }
                self.assertTrue(
                    set(self.golden["mixed_rhs"]["required_flow_types"])
                    <= flow_types
                )

                indirect = next(iter(records["indirect_call"][1].callsites.values()))
                self.assertEqual(indirect.call_kind, "indirect")
                self.assertIsNone(indirect.callee_ea)

                aggregate = records["aggregate_ops"][1]
                self.assertIn(
                    self.golden["aggregate_ops"]["required_global"],
                    aggregate.variables,
                )
                for variable_records in aggregate.variables.values():
                    for variable in variable_records:
                        if variable.is_global:
                            self.assertIn(
                                variable.varname,
                                aggregate.rendered_code,
                            )


if __name__ == "__main__":
    unittest.main()
