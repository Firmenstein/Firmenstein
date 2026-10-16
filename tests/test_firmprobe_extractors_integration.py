"""Opt-in integration tests for the real FirmProbe extractor cascade.

Run with ``FMST_RUN_FIRMPROBE_INTEGRATION=1`` after building the three
extractor images. The tests use the immutable firmware corpus as input and
write only to temporary directories.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import pytest

pytestmark = pytest.mark.external
import tempfile
import unittest
import zipfile
from pathlib import Path

from fmst_basic.FirmProbe import FirmProbe
from fmst_basic.FirmProbe.metadata import load_firmware_metadata
from fmst_basic.FirmProbe.extraction import (
    run_sevenzip,
    run_squashfs3,
    run_tenda,
    run_unblob,
    run_vigi,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = REPOSITORY_ROOT.parent / "dataset"
CORPUS_ROOT = DATASET_ROOT / "corpus"
NC200 = CORPUS_ROOT / (
    "ipcam/TP-Link/NC200/"
    "ff26d57794269b6fbf6bee79211892271b7644dced4fdc5945cf7bf6cf6cffc7_"
    "NC200_v2.1.8_171109.zip"
)
VIGI_C230 = CORPUS_ROOT / (
    "ipcam/TP-Link/VIGI_C230/"
    "f42159a1e667486850e1f1da0f68dd412206f5771e7ae0f94a07d31b1dd722f0_"
    "VIGI_C230_UN__V1_220924.zip"
)
WAG54G2 = CORPUS_ROOT / (
    "router/linksys/WAG54G2/"
    "39d00a794f18f005d2ba12ef7273d9941990597852aebf6d82781bb5a65f661a_"
    "WAG54G2-EU-AnnexA-ETSI-1.00.17-code.zip"
)
X1000 = CORPUS_ROOT / (
    "router/linksys/X1000/"
    "35ea303d748fbfa7a786503e1f6c6f91b7602f7209fa59db466c9ce95d907e33_"
    "FW_X1000_ANNEX_B_1.0.01.004.bin"
)
TENDA_ARCHIVE = DATASET_ROOT / "tenda.zip"
TENDA_MEMBER = (
    "tenda/ipcam/US_CH9V1.0xs_V23.5.11.64_en+cn_TDC01(TDE01).bin"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

@unittest.skipUnless(
    os.environ.get("FMST_RUN_FIRMPROBE_INTEGRATION") == "1",
    "set FMST_RUN_FIRMPROBE_INTEGRATION=1 to run real extractor tests",
)
class FirmProbeExtractorIntegrationTests(unittest.TestCase):
    TIMEOUT_SECONDS = 300

    @classmethod
    def setUpClass(cls):
        if shutil.which("docker") is None or shutil.which("7z") is None:
            raise unittest.SkipTest("docker and 7z are required")
        missing_images = []
        for image in (
            "extractor-unblob",
            "extractor-binwalkv3",
            "extractor-firmaextractor",
        ):
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode != 0:
                missing_images.append(image)
        if missing_images:
            raise unittest.SkipTest(
                f"missing extractor images: {', '.join(missing_images)}"
            )

    def run_in_temporary_directory(self, runner, source: Path):
        self.assertTrue(source.is_file(), source)
        before = sha256(source)
        input_entries = sorted(source.parent.iterdir())
        with tempfile.TemporaryDirectory() as temporary_directory:
            attempt = runner(
                source,
                Path(temporary_directory) / attempt_name(runner),
                self.TIMEOUT_SECONDS,
            )
            self.assertTrue(attempt.candidates, attempt.error)
        self.assertEqual(sha256(source), before)
        self.assertEqual(sorted(source.parent.iterdir()), input_entries)
        return attempt

    def test_unblob(self):
        attempt = self.run_in_temporary_directory(run_unblob, NC200)
        self.assertEqual(attempt.method, "unblob")

    def test_probe_metadata_remains_downstream_compatible(self):
        before = sha256(NC200)
        input_entries = sorted(NC200.parent.iterdir())
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact = Path(temporary_directory) / "artifact"
            output = artifact / "rootfs"
            metadata_path = artifact / "metadata.json"
            probe = FirmProbe()
            result = probe.probe(
                NC200,
                output,
                image_name="integration-nc200",
                metadata_path=metadata_path,
            )
            metadata = json.loads(metadata_path.read_text())
            self.assertEqual(result, output.resolve())
            self.assertEqual(metadata["rootfs_path"], "rootfs")
            self.assertEqual(metadata["status"], "extracted")
            self.assertEqual(metadata["all_binaries"], sorted(metadata["all_binaries"]))
            self.assertTrue(metadata["all_binaries"])
            self.assertTrue(
                all(not Path(path).is_absolute() for path in metadata["all_binaries"])
            )
            loaded = load_firmware_metadata(metadata_path)
            self.assertEqual(loaded["rootfs_path"], str(result))
            self.assertTrue(
                all(Path(path).is_relative_to(result) for path in loaded["all_binaries"])
            )
        self.assertEqual(sha256(NC200), before)
        self.assertEqual(sorted(NC200.parent.iterdir()), input_entries)

    def test_recursive_sevenzip(self):
        attempt = self.run_in_temporary_directory(run_sevenzip, X1000)
        self.assertEqual(attempt.method, "sevenzip")

    def test_vigi_partial_rootfs(self):
        attempt = self.run_in_temporary_directory(run_vigi, VIGI_C230)
        self.assertEqual(attempt.status, "partial_rootfs")
        self.assertTrue(attempt.limitations)

    def test_old_squashfs3(self):
        attempt = self.run_in_temporary_directory(run_squashfs3, WAG54G2)
        self.assertEqual(attempt.method, "patched_unsquashfs3")

    def test_tenda_partition_assembly(self):
        self.assertTrue(TENDA_ARCHIVE.is_file(), TENDA_ARCHIVE)
        before = sha256(TENDA_ARCHIVE)
        input_entries = sorted(TENDA_ARCHIVE.parent.iterdir())
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            source = temporary_root / Path(TENDA_MEMBER).name
            with zipfile.ZipFile(TENDA_ARCHIVE) as archive, archive.open(
                TENDA_MEMBER
            ) as input_file, source.open("wb") as output_file:
                shutil.copyfileobj(input_file, output_file)
            attempt = run_tenda(
                source,
                temporary_root / "tenda",
                self.TIMEOUT_SECONDS,
            )
            self.assertTrue(attempt.candidates, attempt.error)
            rootfs = attempt.candidates[0].path
            for mounted_path in ("opt/app", "opt/web", "opt/custom", "opt/sav"):
                self.assertTrue((rootfs / mounted_path).is_dir(), mounted_path)
        self.assertEqual(sha256(TENDA_ARCHIVE), before)
        self.assertEqual(sorted(TENDA_ARCHIVE.parent.iterdir()), input_entries)

    def test_all_methods_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            source = temporary_root / "invalid.bin"
            source.write_bytes(b"not a Linux firmware image")
            artifact = temporary_root / "artifact"
            probe = FirmProbe()
            with self.assertRaises(RuntimeError):
                probe.probe(
                    source,
                    artifact / "rootfs",
                    metadata_path=artifact / "metadata.json",
                )
            metadata = json.loads((artifact / "metadata.json").read_text())
            self.assertEqual(metadata["status"], "no_valid_linux_rootfs")
            self.assertEqual(
                [attempt["method"] for attempt in metadata["attempts"]],
                ["unblob", "sevenzip", "binwalkv3", "FirmAExtractor"],
            )


def attempt_name(runner) -> str:
    return runner.__name__.removeprefix("run_")


if __name__ == "__main__":
    unittest.main()
