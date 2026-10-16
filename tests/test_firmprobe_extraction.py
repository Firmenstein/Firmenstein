"""Focused tests for FirmProbe extraction and downstream metadata."""

from __future__ import annotations

import asyncio
import json
import os
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fmst_basic.FirmProbe import FirmProbe
from fmst_basic.FirmProbe.metadata import (
    firmware_workdir_name,
    load_firmware_metadata,
)
from fmst_basic.FirmProbe.extraction import (
    ExtractionAttempt,
    ExtractionOrchestrator,
    _run_container,
    find_root_candidates,
    inspect_root_candidate,
    run_binwalk,
)

def make_rootfs(path: Path, *, extra_dirs: tuple[str, ...] = ()) -> None:
    for name in ("bin", "etc", "lib", *extra_dirs):
        (path / name).mkdir(parents=True, exist_ok=True)
    (path / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
    header = bytearray(52)
    header[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHI", header, 16, 2, 8, 1)
    struct.pack_into("<H", header, 40, 52)
    (path / "bin/app").write_bytes(header)


class FirmwareWorkdirNameTests(unittest.TestCase):
    def test_moves_matching_hash_prefix_to_short_suffix(self):
        digest = "a" * 64
        self.assertEqual(
            firmware_workdir_name(f"{digest}_FW_E2500_3.0.05", digest),
            "FW_E2500_3.0.05__aaaaaaaaaaaa",
        )

    def test_adds_identity_suffix_to_readable_image_name(self):
        digest = "0123456789abcdef" * 4
        self.assertEqual(
            firmware_workdir_name("Archer_C9_V2", digest),
            "Archer_C9_V2__0123456789ab",
        )

class RootfsCandidateTests(unittest.TestCase):
    def test_unix_directories_are_not_aggregated_across_siblings(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "one/bin").mkdir(parents=True)
            (root / "one/bin/sh").write_bytes(b"shell")
            (root / "two/etc").mkdir(parents=True)
            (root / "two/etc/passwd").write_text("root:x:0:0")
            (root / "three/lib").mkdir(parents=True)
            (root / "three/lib/libc.so").write_bytes(b"lib")
            self.assertEqual(find_root_candidates(root), [])

    def test_best_candidate_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            make_rootfs(root / "small")
            make_rootfs(root / "large", extra_dirs=("sbin", "usr", "var"))
            candidates = find_root_candidates(root)
            self.assertEqual(candidates[0].relative_path, "large")
            self.assertEqual(
                [candidate.relative_path for candidate in candidates],
                ["large", "small"],
            )


class RunnerContractTests(unittest.TestCase):
    def test_binwalk_receives_explicit_output_directory(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "firmware.bin"
            source.write_bytes(b"firmware")
            method_dir = root / "binwalk"
            with patch(
                "fmst_basic.FirmProbe.extraction._run_container",
                return_value=(0, None),
            ) as run_container:
                run_binwalk(source, method_dir, 10)
            command = run_container.call_args.args[3]
            self.assertIn("-d", command)
            self.assertEqual(command[command.index("-d") + 1], "/work/extracted")
            self.assertEqual(command[-1], "/input/firmware.bin")

    def test_container_is_isolated_and_input_mount_is_read_only(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "input/firmware.bin"
            source.parent.mkdir()
            source.write_bytes(b"firmware")
            work = root / "work"
            work.mkdir()
            with patch(
                "fmst_basic.FirmProbe.extraction._run_logged",
                return_value=(0, None),
            ) as run_logged:
                _run_container(
                    "extractor-unblob",
                    source,
                    work,
                    ["unblob", "/input/firmware.bin"],
                    work / "log",
                    10,
                )
            docker_command = run_logged.call_args.args[0]
            self.assertIn("none", docker_command)
            self.assertIn("4", docker_command)
            self.assertIn("8g", docker_command)
            self.assertIn(f"{source.parent.resolve()}:/input:ro", docker_command)
            self.assertIn(f"{work.resolve()}:/work:rw", docker_command)

    def test_all_extractor_failures_return_no_selection(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "firmware.bin"
            source.write_bytes(b"not a filesystem")

            def empty(method: str) -> ExtractionAttempt:
                return ExtractionAttempt(method, 1, "no rootfs candidate")

            orchestrator = ExtractionOrchestrator(source, root / "job", 10)
            with (
                patch(
                    "fmst_basic.FirmProbe.extraction.run_unblob",
                    return_value=empty("unblob"),
                ),
                patch(
                    "fmst_basic.FirmProbe.extraction.run_sevenzip",
                    return_value=empty("sevenzip"),
                ),
                patch(
                    "fmst_basic.FirmProbe.extraction.run_binwalk",
                    return_value=empty("binwalkv3"),
                ),
                patch(
                    "fmst_basic.FirmProbe.extraction.run_firmextractor",
                    return_value=empty("FirmAExtractor"),
                ),
            ):
                selected_attempt, selected_candidate, attempts = orchestrator.run()
            self.assertIsNone(selected_attempt)
            self.assertIsNone(selected_candidate)
            self.assertEqual(
                [attempt.method for attempt in attempts],
                ["unblob", "sevenzip", "binwalkv3", "FirmAExtractor"],
            )


class FirmProbeTests(unittest.TestCase):
    def test_prunes_only_extractor_sidecars_with_source_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            rootfs = Path(temporary)
            archive = rootfs / "payload.tar"
            archive.write_bytes(b"archive")
            sidecar = rootfs / "payload.tar_extract"
            sidecar.mkdir()
            (sidecar / "libduplicate.so").write_bytes(b"\x7fELF")
            guest_directory = rootfs / "runtime_extract"
            guest_directory.mkdir()

            FirmProbe._prune_extractor_sidecars(rootfs)

            self.assertTrue(archive.is_file())
            self.assertFalse(sidecar.exists())
            self.assertTrue(guest_directory.is_dir())

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_existing_output_is_not_deleted(self):
        source = self.root / "firmware.bin"
        source.write_bytes(b"firmware")
        output = self.root / "rootfs"
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_text("user data")
        probe = FirmProbe()
        with self.assertRaises(FileExistsError):
            probe.probe(source, output)
        self.assertEqual(sentinel.read_text(), "user data")

        with self.assertRaises(FileExistsError):
            FirmProbe.run_extract(source, output)
        self.assertEqual(sentinel.read_text(), "user data")

    def test_run_extract_returns_probe_rootfs_path(self):
        source = self.root / "firmware.bin"
        source.write_bytes(b"firmware")
        expected = self.root / "rootfs"
        with patch.object(FirmProbe, "probe", return_value=expected):
            self.assertEqual(FirmProbe.run_extract(source, expected), expected)

    def test_probe_publishes_only_selected_candidate(self):
        source = self.root / "firmware.bin"
        source.write_bytes(b"firmware")
        artifact = self.root / "artifact"
        output = artifact / "rootfs"
        metadata_path = artifact / "metadata.json"

        def fake_run(orchestrator):
            better = orchestrator.job_dir / "better"
            other = orchestrator.job_dir / "other"
            make_rootfs(better, extra_dirs=("sbin", "usr"))
            make_rootfs(other)
            (better / "chosen").write_text("yes")
            (better / "dev").mkdir()
            os.mkfifo(better / "dev/initctl")
            (better / "a").mkdir()
            (better / "a/bar").write_bytes(b"\x7fELFnested")
            (better / "a-foo").write_bytes(b"\x7fELFflat")
            (other / "must-not-merge").write_text("no")
            candidates = find_root_candidates(orchestrator.job_dir)
            attempt = ExtractionAttempt("fake", 0, None, candidates)
            return attempt, candidates[0], [attempt]

        probe = FirmProbe()
        with (
            patch(
                "fmst_basic.FirmProbe.FirmProbe.ExtractionOrchestrator.run",
                autospec=True,
                side_effect=fake_run,
            ),
            patch(
                "fmst_basic.FirmProbe.FirmProbe.tempfile.TemporaryDirectory",
                wraps=tempfile.TemporaryDirectory,
            ) as temporary_directory,
        ):
            result = probe.probe(
                source,
                output,
                image_name="sample",
                metadata_path=metadata_path,
            )

        self.assertEqual(
            temporary_directory.call_args.kwargs["dir"],
            output.parent,
        )
        self.assertEqual(result, output.resolve())
        self.assertTrue((output / "chosen").is_file())
        self.assertTrue(stat.S_ISFIFO((output / "dev/initctl").stat().st_mode))
        self.assertFalse((output / "must-not-merge").exists())
        self.assertEqual(
            sorted(path.name for path in self.root.iterdir()),
            ["artifact", "firmware.bin"],
        )
        metadata = json.loads(metadata_path.read_text())
        self.assertEqual(metadata["input"]["path"], str(source.resolve()))
        self.assertEqual(metadata["rootfs_path"], "rootfs")
        self.assertEqual(metadata["status"], "partial_rootfs")
        self.assertEqual({item["kind"] for item in metadata["limitations"]}, {"invalid_elf_header"})
        self.assertEqual(metadata["all_binaries"], ["a-foo", "a/bar", "bin/app"])
        self.assertEqual(metadata["attempts"][0]["candidate_count"], 2)
        loaded = load_firmware_metadata(metadata_path)
        self.assertEqual(loaded["rootfs_path"], str(output.resolve()))

    def test_elf_and_guest_symlink_scan(self):
        rootfs = (self.root / "rootfs").resolve()
        make_rootfs(rootfs)
        elf = rootfs / "bin/httpd"
        elf.write_bytes(b"\x7fELF" + b"payload")
        os.symlink("httpd", rootfs / "bin/httpd-relative")
        os.symlink("/bin/httpd", rootfs / "bin/httpd-absolute")
        os.symlink("/missing", rootfs / "bin/broken")
        os.symlink("../../outside", rootfs / "bin/escape")

        probe = FirmProbe()
        probe.rootfs_path = rootfs.resolve()
        asyncio.run(probe.post_process())

        self.assertEqual(probe.all_binaries, {elf, rootfs / "bin/app"})
        self.assertNotIn(str(rootfs / "bin/httpd-relative"), probe.error_symlinks)
        self.assertNotIn(str(rootfs / "bin/httpd-absolute"), probe.error_symlinks)
        self.assertIn(str(rootfs / "bin/broken"), probe.error_symlinks)
        self.assertIn(str(rootfs / "bin/escape"), probe.error_symlinks)

    def test_partial_status_and_limitations_are_additive_metadata(self):
        rootfs = self.root / "rootfs"
        make_rootfs(rootfs)
        candidate = inspect_root_candidate(rootfs, self.root)
        self.assertIsNotNone(candidate)
        limitation = {"path": "bin/busybox", "reason": "protected block"}
        source = self.root / "vigi.bin"
        source.write_bytes(b"vigi firmware")
        metadata_path = self.root / "metadata.json"
        probe = FirmProbe()
        probe.image_name = "vigi"
        probe.image_path = source.resolve()
        probe.image_sha256 = probe._sha256(source)
        probe.metadata_path = metadata_path
        probe.extractor = "vigi_squashfs"
        probe.rootfs_path = rootfs
        probe.status = "partial_rootfs"
        probe.limitations = [limitation]
        probe.attempts = [
            ExtractionAttempt(
                "vigi_squashfs",
                1,
                None,
                [candidate],
                status="partial_rootfs",
                limitations=[limitation],
            )
        ]
        probe.save_fw_metadata()

        metadata = json.loads(metadata_path.read_text())
        self.assertEqual(metadata["status"], "partial_rootfs")
        self.assertEqual(metadata["limitations"], [limitation])
        self.assertIn("rootfs_path", metadata)
        self.assertIn("all_binaries", metadata)

    def test_failed_probe_writes_terminal_metadata(self):
        source = self.root / "invalid.bin"
        source.write_bytes(b"not firmware")
        output = self.root / "artifact/rootfs"
        metadata_path = self.root / "artifact/metadata.json"
        attempts = [ExtractionAttempt("unblob", 1, "no rootfs candidate")]
        probe = FirmProbe()
        with patch(
            "fmst_basic.FirmProbe.FirmProbe.ExtractionOrchestrator.run",
            return_value=(None, None, attempts),
        ):
            with self.assertRaises(RuntimeError):
                probe.probe(source, output, metadata_path=metadata_path)

        metadata = json.loads(metadata_path.read_text())
        self.assertEqual(metadata["status"], "no_valid_linux_rootfs")
        self.assertIsNone(metadata["rootfs_path"])
        self.assertEqual(metadata["all_binaries"], [])
        self.assertEqual(metadata["attempts"][0]["method"], "unblob")

    def test_archive_source_reference_and_unexpected_failure_are_persisted(self):
        source = self.root / "staged.bin"
        source.write_bytes(b"firmware")
        output = self.root / "artifact/rootfs"
        metadata_path = self.root / "artifact/metadata.json"
        source_reference = "dataset/corpus.zip::corpus/router/vendor/fw.bin"
        probe = FirmProbe()
        with patch(
            "fmst_basic.FirmProbe.FirmProbe.ExtractionOrchestrator.run",
            side_effect=OSError("extractor unavailable"),
        ):
            with self.assertRaises(OSError):
                probe.probe(
                    source,
                    output,
                    metadata_path=metadata_path,
                    source_reference=source_reference,
                )

        metadata = json.loads(metadata_path.read_text())
        self.assertEqual(metadata["input"]["path"], source_reference)
        self.assertEqual(metadata["status"], "failed")
        self.assertIn("extractor unavailable", metadata["error"])


if __name__ == "__main__":
    unittest.main()
