"""Pure-Python tests for FileResolver exact-resource construction."""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def _make_callsite(
    *,
    path_value,
    resource_class,
    path_kind="concrete",
    api_name="open",
    binary_name="httpd",
    function_name="sub_0",
    line_number=10,
    candidate_idx=0,
):
    from fmst_analyzer.analysis.file_resolver.analyzer_schema import FileCallsite

    callsite_id = f"{binary_name}::{function_name}::L{line_number}::{api_name}"
    return FileCallsite(
        callsite_id=callsite_id,
        candidate_idx=candidate_idx,
        profile_key=f"{callsite_id}#{candidate_idx}",
        binary_name=binary_name,
        function_name=function_name,
        line_number=line_number,
        api_name=api_name,
        path_arg_index=0,
        requested_path=path_value,
        path_value=path_value,
        path_kind=path_kind,
        resolution_source="literal_static",
        resource_class=resource_class,
    )


class TestBuildFileResources(unittest.TestCase):
    def setUp(self):
        from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
            FileResourceClass,
        )
        from fmst_analyzer.analysis.file_resolver.grouping import (
            build_file_resources,
        )

        self.Cls = FileResourceClass
        self.build = build_file_resources
        self.ext_allowlist = {".pid", ".conf", ".key"}

    def _build(self, callsites, scope="pseudo_fs_only"):
        return self.build(
            {cs.profile_key: cs for cs in callsites},
            scope=scope,
            ext_allowlist=self.ext_allowlist,
        )

    def test_same_typed_path_forms_one_resource(self):
        first = _make_callsite(
            path_value="/dev/mtd1",
            resource_class=self.Cls.PSEUDO_FS_DEV,
            function_name="first",
        )
        second = _make_callsite(
            path_value="/dev/mtd1",
            resource_class=self.Cls.PSEUDO_FS_DEV,
            function_name="second",
            line_number=20,
        )
        resources = self._build([first, second])
        self.assertEqual(len(resources), 1)
        resource = next(iter(resources.values()))
        self.assertEqual(resource.path_value, "/dev/mtd1")
        self.assertEqual(resource.path_kind, "concrete")
        self.assertEqual(resource.callsites, [first, second])
        self.assertEqual(first.resource_group_id, resource.resource_group_id)
        self.assertRegex(resource.resource_group_id, r"^file_dev_mtd1_[0-9a-f]{12}$")

    def test_similar_paths_are_not_merged(self):
        resources = self._build([
            _make_callsite(
                path_value="/dev/mtd0",
                resource_class=self.Cls.PSEUDO_FS_DEV,
                line_number=10,
            ),
            _make_callsite(
                path_value="/dev/mtd1",
                resource_class=self.Cls.PSEUDO_FS_DEV,
                line_number=20,
            ),
            _make_callsite(
                path_value="/dev/mtd%d",
                path_kind="pattern",
                resource_class=self.Cls.PSEUDO_FS_DEV,
                line_number=30,
            ),
        ])
        self.assertEqual(len(resources), 3)
        self.assertEqual(
            {resource.path_value for resource in resources.values()},
            {"/dev/mtd0", "/dev/mtd1", "/dev/mtd%d"},
        )

    def test_path_kind_is_part_of_identity(self):
        concrete = _make_callsite(
            path_value="/dev/example",
            path_kind="concrete",
            resource_class=self.Cls.PSEUDO_FS_DEV,
            line_number=10,
        )
        pattern = _make_callsite(
            path_value="/dev/example",
            path_kind="pattern",
            resource_class=self.Cls.PSEUDO_FS_DEV,
            line_number=20,
            candidate_idx=1,
        )
        resources = self._build([concrete, pattern])
        self.assertEqual(len(resources), 2)
        self.assertEqual(len(set(resources)), 2)

    def test_scope_and_extension_gates_are_preserved(self):
        pseudo = _make_callsite(
            path_value="/dev/foo",
            resource_class=self.Cls.PSEUDO_FS_DEV,
        )
        allowed = _make_callsite(
            path_value="/tmp/service.pid",
            resource_class=self.Cls.MISSING_NON_PSEUDO_FS,
            line_number=20,
        )
        denied = _make_callsite(
            path_value="/tmp/cache.state",
            resource_class=self.Cls.MISSING_NON_PSEUDO_FS,
            line_number=30,
        )
        resources = self._build(
            [pseudo, allowed, denied], scope="with_allowlist",
        )
        self.assertEqual(
            {resource.path_value for resource in resources.values()},
            {"/dev/foo", "/tmp/service.pid"},
        )

    def test_query_and_in_rootfs_callsites_are_not_resources(self):
        query = _make_callsite(
            path_value="/dev/foo",
            resource_class=self.Cls.PSEUDO_FS_DEV,
            api_name="stat",
        )
        present = _make_callsite(
            path_value="/etc/passwd",
            resource_class=self.Cls.IN_ROOTFS,
            line_number=20,
        )
        self.assertEqual(self._build([query, present], scope="full"), {})

    def test_resource_order_and_id_are_stable(self):
        left = _make_callsite(
            path_value="/dev/b",
            resource_class=self.Cls.PSEUDO_FS_DEV,
            line_number=20,
        )
        right = _make_callsite(
            path_value="/dev/a",
            resource_class=self.Cls.PSEUDO_FS_DEV,
            line_number=10,
        )
        ids_a = list(self._build([left, right]))
        ids_b = list(self._build([right, left]))
        self.assertEqual(ids_a, ids_b)


class TestResourceAnalysisGate(unittest.IsolatedAsyncioTestCase):
    async def test_static_phase_is_zero_llm(self):
        from fmst_analyzer.analysis.file_resolver.analyzer import FileResolver
        from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
            FileResolverResult,
        )
        from fmst_analyzer.global_config import GlobalConfig

        resolver = FileResolver(GlobalConfig())
        analyses = await resolver._node5_analyze_resources(
            view=None,
            resources={},
            phase="static",
        )
        self.assertEqual(analyses, {})


class TestFileResolverPersistence(unittest.TestCase):
    def test_static_publish_removes_stale_per_resource_pages(self):
        from fmst_analyzer.analysis.file_resolver.analyzer import FileResolver
        from fmst_analyzer.analysis.file_resolver.analyzer_schema import (
            FileResolverResult,
        )

        with tempfile.TemporaryDirectory() as tmp:
            reports_root = Path(tmp)
            out_dir = reports_root / "file_reports"
            out_dir.mkdir()
            stale_md = out_dir / "file_dev_old_deadbeef0000.md"
            stale_json = out_dir / "file_dev_old_deadbeef0000_result.json"
            stale_md.write_text("old", encoding="utf-8")
            stale_json.write_text("{}", encoding="utf-8")
            (out_dir / "file_resolver_result.json").write_text(
                '{"resource_reports":{"file_dev_old_deadbeef0000":{}}}',
                encoding="utf-8",
            )

            resolver = FileResolver(SimpleNamespace(
                agent_concurrency_limit=1,
                target_diagnostic_reports_dir=lambda: reports_root,
            ))
            original = FileResolverResult(execution={"tasks": {}},
                schema_version=12,
                phase="static",
                root_binary="httpd",
                finding_target={"path": "usr/sbin/httpd", "sha256": "a" * 64},
                planning_findings={},
            )
            published = resolver.publish_reports(original)
            reloaded = FileResolverResult.model_validate_json(
                (out_dir / "file_resolver_result.json").read_text(
                    encoding="utf-8"
                )
            )

            self.assertFalse(stale_md.exists())
            self.assertFalse(stale_json.exists())
            self.assertTrue((out_dir / "index.md").exists())
            self.assertTrue((out_dir / "file_resolver_result.json").exists())
            self.assertEqual(published, reloaded)
            self.assertIsNot(published, original)


if __name__ == "__main__":
    unittest.main()
