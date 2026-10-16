"""Unit tests for FileResolver's classifier.

Pure-Python — no firmware fixtures or network access required. Covers
the five FileResourceClass rules and pseudo-fs precedence.

Usage:
    source src/.venv/bin/activate
    python -m unittest tests.test_file_resolver_classifier -v
"""
import sys
import tempfile
import unittest
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


class TestClassifier(unittest.TestCase):
    """Exercises every rule in FileResourceClass.__doc__."""

    def setUp(self):
        from fmst_analyzer.analysis.file_resolver.classifier import classify_resource
        from fmst_analyzer.analysis.file_resolver.classifier import (
            resolve_and_classify_resource,
        )
        from fmst_analyzer.analysis.file_resolver.analyzer_schema import FileResourceClass

        self.classify = classify_resource
        self.resolve = resolve_and_classify_resource
        self.Cls = FileResourceClass

        # Fake rootfs with a single file inside.
        self._tmp = tempfile.TemporaryDirectory()
        self.rootfs = Path(self._tmp.name)
        (self.rootfs / "etc").mkdir()
        (self.rootfs / "etc" / "passwd").write_text("root:x:0:0\n")

    def tearDown(self):
        self._tmp.cleanup()

    # ------------------------------------------------------------------
    # Rule coverage
    # ------------------------------------------------------------------

    def test_rule_1_pseudo_fs_dev(self):
        cls = self.classify(
            path_value="/dev/mtd0",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.PSEUDO_FS_DEV)

    def test_rule_1_pseudo_fs_dev_exact_root(self):
        """/dev (no trailing slash) also matches PSEUDO_FS_DEV."""
        cls = self.classify(
            path_value="/dev",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.PSEUDO_FS_DEV)

    def test_rule_2_pseudo_fs_proc(self):
        cls = self.classify(
            path_value="/proc/cpuinfo",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.PSEUDO_FS_PROC)

    def test_rule_3_pseudo_fs_sys(self):
        cls = self.classify(
            path_value="/sys/class/net/eth0/address",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.PSEUDO_FS_SYS)

    def test_rule_4_in_rootfs(self):
        cls = self.classify(
            path_value="/etc/passwd",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.IN_ROOTFS)

    def test_relative_parent_cannot_escape_rootfs(self):
        outside = self.rootfs.parent / "host-only-file"
        outside.write_text("host", encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                self.classify(
                    path_value="../host-only-file",
                    path_kind="concrete",
                    rootfs_path=self.rootfs,
                )
        finally:
            outside.unlink()

    def test_dangling_rootfs_symlink_classifies_final_target_missing(self):
        link = self.rootfs / "etc" / "runtime.conf"
        link.symlink_to("/var/generated/runtime.conf")
        result = self.resolve(
            path_value="/etc/runtime.conf",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(
            result.resource_class,
            self.Cls.MISSING_NON_PSEUDO_FS,
        )
        self.assertEqual(result.path_value, "/var/generated/runtime.conf")
        self.assertEqual(
            result.symlink_chain,
            ("/etc/runtime.conf", "/var/generated/runtime.conf"),
        )

    def test_normalization_precedes_pseudo_fs_classification(self):
        cls = self.classify(
            path_value="/dev/../etc/passwd",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.IN_ROOTFS)

    def test_rule_5_missing_concrete(self):
        cls = self.classify(
            path_value="/var/run/missing.pid",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.MISSING_NON_PSEUDO_FS)

    def test_ipc_like_path_is_not_suppressed_by_text(self):
        cls = self.classify(
            path_value="/tmp/shm_id",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.MISSING_NON_PSEUDO_FS)

    def test_rule_5_pattern_not_pseudo(self):
        cls = self.classify(
            path_value="/tmp/file%d",
            path_kind="pattern",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.MISSING_NON_PSEUDO_FS)

    def test_pattern_pseudo_fs_dev(self):
        """Pattern paths land in PSEUDO_FS_* if their prefix matches."""
        cls = self.classify(
            path_value="/dev/mtd%d",
            path_kind="pattern",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.PSEUDO_FS_DEV)

    def test_unrooted_pseudo_fs_proc(self):
        with self.assertRaises(ValueError):
            self.classify(
                path_value="proc/net/attadev",
                path_kind="concrete",
                rootfs_path=self.rootfs,
            )

    def test_unrooted_pseudo_fs_dev(self):
        with self.assertRaises(ValueError):
            self.classify(
                path_value="dev/urandom",
                path_kind="concrete",
                rootfs_path=self.rootfs,
            )

    def test_unrooted_bare_dev_is_not_pseudo(self):
        """A bare 'dev' (not 'dev/...') is a relative directory name,
        not an alias for /dev. Must NOT be classified as PSEUDO_FS_DEV."""
        with self.assertRaises(ValueError):
            self.classify(
                path_value="dev",
                path_kind="concrete",
                rootfs_path=self.rootfs,
            )

    def test_existing_relative_symlink_resolves_inside_guest(self):
        (self.rootfs / "var").mkdir()
        (self.rootfs / "var" / "state").write_text("ok")
        (self.rootfs / "etc" / "state").symlink_to("../var/state")
        result = self.resolve(
            path_value="/etc/state",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(result.resource_class, self.Cls.IN_ROOTFS)
        self.assertEqual(result.path_value, "/var/state")

    def test_intermediate_absolute_symlink_uses_guest_root(self):
        (self.rootfs / "run").mkdir()
        (self.rootfs / "run" / "state.db").write_text("ok")
        (self.rootfs / "etc" / "runtime").symlink_to("/run")
        result = self.resolve(
            path_value="/etc/runtime/state.db",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(result.resource_class, self.Cls.IN_ROOTFS)
        self.assertEqual(result.path_value, "/run/state.db")
        self.assertEqual(
            result.symlink_chain,
            ("/etc/runtime/state.db", "/run/state.db"),
        )

    def test_intermediate_relative_symlink_uses_guest_directory(self):
        (self.rootfs / "var").mkdir()
        (self.rootfs / "var" / "runtime").mkdir()
        (self.rootfs / "var" / "runtime" / "state.db").write_text("ok")
        (self.rootfs / "etc" / "runtime").symlink_to("../var/runtime")
        result = self.resolve(
            path_value="/etc/runtime/state.db",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(result.resource_class, self.Cls.IN_ROOTFS)
        self.assertEqual(result.path_value, "/var/runtime/state.db")

    def test_symlink_alias_into_pseudo_fs(self):
        (self.rootfs / "etc" / "device").symlink_to("/dev/nvram")
        result = self.resolve(
            path_value="/etc/device",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(result.resource_class, self.Cls.PSEUDO_FS_DEV)
        self.assertEqual(result.path_value, "/dev/nvram")

    def test_symlink_loop_is_an_explicit_gap(self):
        (self.rootfs / "etc" / "a").symlink_to("b")
        (self.rootfs / "etc" / "b").symlink_to("a")
        result = self.resolve(
            path_value="/etc/a",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertIsNone(result.resource_class)
        self.assertIn("loop", result.error)

    # ------------------------------------------------------------------
    # Precedence
    # ------------------------------------------------------------------

    def test_pseudo_fs_beats_in_rootfs(self):
        """A /dev/* path classified as PSEUDO_FS_DEV even if rootfs
        happened to ship a /dev entry — consumer semantics differ.
        """
        # Place a file under fake rootfs matching a /dev path.
        (self.rootfs / "dev").mkdir()
        (self.rootfs / "dev" / "console").write_text("")
        cls = self.classify(
            path_value="/dev/console",
            path_kind="concrete",
            rootfs_path=self.rootfs,
        )
        self.assertEqual(cls, self.Cls.PSEUDO_FS_DEV)

if __name__ == "__main__":
    unittest.main()
