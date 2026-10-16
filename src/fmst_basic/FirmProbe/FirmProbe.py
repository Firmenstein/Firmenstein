from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import stat
import tempfile
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath
from typing import Dict, List, Set

from loguru import logger

from .config_loader import ConfigLoader
from .extraction import (
    DEFAULT_TIMEOUT_SECONDS,
    ExtractionAttempt,
    ExtractionOrchestrator,
    inspect_root_candidate,
)
from .metadata import write_firmware_metadata


class FirmProbe:
    """Extract one firmware image and publish one validated Linux rootfs."""

    def __init__(self):
        self.config = ConfigLoader()
        self.image_name: str | None = None
        self.extractor: str | None = None
        self.extracted_path: Path | None = None
        self.rootfs_path: Path | None = None
        self.metadata_path: Path | None = None
        self.image_path: Path | None = None
        self.input_reference: str | None = None
        self.image_sha256: str | None = None
        self.status = "failed"
        self.limitations: list[dict] = []
        self.attempts: list[ExtractionAttempt] = []

        self.all_binaries: Set[Path] = set()
        self.target_binaries: Set[Path] = set()
        self.error_symlinks: Dict[str, str] = {}

    def probe(
        self,
        image_path: Path | None = None,
        output_rootfs_path: Path | None = None,
        image_name: str | None = None,
        metadata_path: Path | None = None,
        source_reference: str | None = None,
    ) -> Path:
        if image_path is None:
            raise ValueError("image_path must be provided")
        self.image_path = Path(image_path).absolute().resolve()
        if not self.image_path.is_file():
            raise FileNotFoundError(f"Firmware image file not found: {self.image_path}")

        self.image_name = image_name or self.image_path.stem
        self.input_reference = source_reference or str(self.image_path)
        if output_rootfs_path is None:
            output_rootfs_path = self.image_path.parent / f"_{self.image_name}.rootfs"
        output_rootfs_path = Path(output_rootfs_path).absolute()
        if output_rootfs_path.exists() or output_rootfs_path.is_symlink():
            raise FileExistsError(
                f"Target root filesystem path already exists: {output_rootfs_path}"
            )
        output_rootfs_path.parent.mkdir(parents=True, exist_ok=True)
        if metadata_path is None:
            metadata_path = output_rootfs_path.with_name(
                f"{output_rootfs_path.name}.metadata.json"
            )
        self.metadata_path = Path(metadata_path).absolute()
        if self.metadata_path.exists() or self.metadata_path.is_symlink():
            raise FileExistsError(f"Firmware metadata already exists: {self.metadata_path}")
        self.image_sha256 = self._sha256(self.image_path)

        logger.info(f"Extracting firmware image {self.image_path}")
        with tempfile.TemporaryDirectory(
            prefix=f"fmst-{output_rootfs_path.name}.extract-",
            dir=output_rootfs_path.parent,
        ) as temporary_directory:
            job_dir = Path(temporary_directory)
            orchestrator = ExtractionOrchestrator(
                self.image_path,
                job_dir,
                DEFAULT_TIMEOUT_SECONDS,
            )
            try:
                selected_attempt, selected_candidate, self.attempts = orchestrator.run()
            except Exception as exception:
                self.status = "failed"
                self.save_fw_metadata(error=f"{type(exception).__name__}: {exception}")
                raise
            if selected_attempt is None or selected_candidate is None:
                self.status = "no_valid_linux_rootfs"
                attempt_summary = "; ".join(
                    f"{attempt.method}: {attempt.error or 'no rootfs candidate'}"
                    for attempt in self.attempts
                )
                error = (
                    "No valid Linux root filesystem found in the supplied firmware. "
                    f"Attempts: {attempt_summary}"
                )
                self.save_fw_metadata(error=error)
                raise RuntimeError(error)

            publishing_path = output_rootfs_path.parent / (
                f".{output_rootfs_path.name}.publishing-{uuid.uuid4().hex}"
            )
            try:
                self._prune_extractor_sidecars(selected_candidate.path)
                shutil.move(str(selected_candidate.path), publishing_path)
                validation = inspect_root_candidate(
                    publishing_path, publishing_path.parent
                )
                if validation is None:
                    raise RuntimeError(
                        "Selected rootfs failed validation after relocation"
                    )
                if output_rootfs_path.exists() or output_rootfs_path.is_symlink():
                    raise FileExistsError(
                        "Target root filesystem path appeared during extraction: "
                        f"{output_rootfs_path}"
                    )
                publishing_path.rename(output_rootfs_path)
            except Exception as exception:
                if publishing_path.exists():
                    shutil.rmtree(publishing_path)
                self.status = "failed"
                self.save_fw_metadata(error=f"{type(exception).__name__}: {exception}")
                raise

        self.extractor = selected_attempt.method
        self.status = selected_attempt.status
        self.limitations = [*selected_attempt.limitations, *selected_candidate.limitations]
        if self.limitations:
            self.status = "partial_rootfs"
        self.rootfs_path = output_rootfs_path.resolve()
        # Keep the legacy metadata key valid after the temporary extraction tree
        # has been removed. Downstream code consumes rootfs_path, not this key.
        self.extracted_path = self.rootfs_path

        try:
            asyncio.run(self.post_process())
        except Exception as exception:
            self.status = "post_process_failed"
            self.save_fw_metadata(error=f"{type(exception).__name__}: {exception}")
            raise
        self.save_fw_metadata()
        logger.success(
            f"[{self.extractor}] Root filesystem published at {self.rootfs_path}"
        )
        return self.rootfs_path

    @staticmethod
    def _sha256(file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as input_file:
            for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _prune_extractor_sidecars(rootfs_path: Path) -> None:
        """Remove nested extractor output that is not part of the guest rootfs.

        Recursive extractors may create ``<archive>_extract`` next to an
        archive that legitimately lives inside the firmware. Those directories
        are analysis sidecars, not guest-visible paths, and indexing their ELF
        files creates false duplicate-library ambiguity. An unrelated guest
        directory ending in ``_extract`` is preserved unless its same-directory
        source file exists.
        """
        for current_root, dirs, _ in os.walk(rootfs_path, topdown=False):
            current_path = Path(current_root)
            for name in dirs:
                if not name.endswith("_extract"):
                    continue
                sidecar = current_path / name
                source = current_path / name.removesuffix("_extract")
                if sidecar.is_symlink() or not source.is_file():
                    continue
                logger.debug(
                    f"Removing extractor sidecar from published rootfs: {sidecar}"
                )
                shutil.rmtree(sidecar)

    @staticmethod
    def _has_elf_magic(file_path: Path) -> bool:
        try:
            with file_path.open("rb") as input_file:
                return input_file.read(4) == b"\x7fELF"
        except (OSError, PermissionError):
            return False

    @staticmethod
    def _guest_path_exists(rootfs: Path, path: Path) -> bool:
        """Resolve a guest path without letting absolute links escape rootfs."""
        try:
            relative = path.relative_to(rootfs)
        except ValueError:
            return False

        pending = deque(relative.parts)
        resolved: list[str] = []
        followed_links = 0
        while pending:
            component = pending.popleft()
            if component in {"", ".", "/"}:
                continue
            if component == "..":
                if not resolved:
                    return False
                resolved.pop()
                continue

            candidate = rootfs.joinpath(*resolved, component)
            try:
                mode = candidate.lstat().st_mode
            except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
                return False
            if not stat.S_ISLNK(mode):
                resolved.append(component)
                continue

            followed_links += 1
            if followed_links > 40:
                return False
            try:
                target = PurePosixPath(os.readlink(candidate))
            except OSError:
                return False
            if target.is_absolute():
                resolved.clear()
            target_parts = [part for part in target.parts if part != "/"]
            pending.extendleft(reversed(target_parts))
        return True

    def _scan_rootfs(self) -> None:
        if self.rootfs_path is None:
            raise ValueError("Root filesystem path is not set")

        self.all_binaries.clear()
        self.error_symlinks.clear()
        with ThreadPoolExecutor(max_workers=32) as executor:
            batch: list[Path] = []

            def process_batch() -> None:
                for file_path, is_elf in zip(
                    batch, executor.map(self._has_elf_magic, batch)
                ):
                    if is_elf:
                        self.all_binaries.add(file_path)

            for root, dirs, files in os.walk(self.rootfs_path, followlinks=False):
                root_path = Path(root)
                for name in [*dirs, *files]:
                    path = root_path / name
                    if path.is_symlink():
                        if not self._guest_path_exists(self.rootfs_path, path):
                            try:
                                self.error_symlinks[str(path)] = os.readlink(path)
                            except OSError:
                                self.error_symlinks[str(path)] = "<unreadable>"
                    elif name in files and path.is_file():
                        batch.append(path)
                        if len(batch) == 512:
                            process_batch()
                            batch.clear()
            if batch:
                process_batch()

        logger.info(f"Total ELF binaries found: {len(self.all_binaries)}")
        if self.error_symlinks:
            logger.warning(
                f"Found {len(self.error_symlinks)} unresolved guest symlinks"
            )

    async def post_process(self) -> bool:
        await asyncio.to_thread(self._scan_rootfs)
        return True

    def save_fw_metadata(self, error: str | None = None) -> Path:
        if self.image_path is None or self.image_sha256 is None:
            raise ValueError("Firmware input identity is not set")
        if self.metadata_path is None:
            raise ValueError("Firmware metadata path is not set")

        rootfs_path: str | None = None
        all_binaries: list[str] = []
        error_symlinks: dict[str, str] = {}
        if self.rootfs_path is not None:
            # Compare canonical host paths so macOS's /var symlink cannot turn
            # a sibling rootfs into a long ../../.. relative path.
            rootfs_path = os.path.relpath(
                self.rootfs_path.resolve(),
                self.metadata_path.parent.resolve(),
            )
            all_binaries = sorted(
                path.relative_to(self.rootfs_path).as_posix()
                for path in self.all_binaries
            )
            error_symlinks = {
                Path(path).relative_to(self.rootfs_path).as_posix(): target
                for path, target in sorted(self.error_symlinks.items())
            }

        metadata = {
            "image_name": self.image_name,
            "sha256": self.image_sha256,
            "input": {
                "path": self.input_reference or str(self.image_path),
                "size_bytes": self.image_path.stat().st_size,
            },
            "extractor": self.extractor,
            "rootfs_path": rootfs_path,
            "all_binaries": all_binaries,
            "error_symlinks": error_symlinks,
            "status": self.status,
            "limitations": self.limitations,
            "attempts": [attempt.as_metadata() for attempt in self.attempts],
            "error": error,
        }
        written_path = write_firmware_metadata(self.metadata_path, metadata)
        logger.success(f"Saved firmware metadata to {written_path}")
        return written_path

    def find_target_binary(self, rehost_type: str) -> Set[Path]:
        service_names: List[str]
        if rehost_type == "HTTP":
            service_names = self.config.http_servers
        elif rehost_type == "UPNP":
            service_names = self.config.upnp_servers
        elif rehost_type == "DNS":
            service_names = self.config.dns_servers
        elif rehost_type == "DHCP":
            service_names = self.config.dhcp_servers
        else:
            service_names = []
        self.target_binaries = {
            binary
            for binary in self.all_binaries
            if any(name in binary.name for name in service_names)
        }
        return self.target_binaries

    def get_arch_from_file_command(self, outline: bytes) -> str | None:
        if b"64-bit" in outline:
            if b" ARM" in outline and b" LSB" in outline:
                return "arm64"
            if b" x86-64" in outline:
                return "x86_64"
            if b" MIPS" in outline and b" MSB" in outline:
                return "mips64"
            if b" MIPS" in outline and b" LSB" in outline:
                return "mips64el"
        else:
            if b" ARM" in outline and b" MSB" in outline:
                return "armeb"
            if b" ARM" in outline and b" LSB" in outline:
                return "arm"
            if b" 80386" in outline:
                return "x86"
            if b" MIPS" in outline and b" MSB" in outline:
                return "mips"
            if b" MIPS" in outline and b" LSB" in outline:
                return "mipsel"
        return None

    @staticmethod
    def run_extract(
        image_path: Path,
        rootfs_path: Path | None = None,
        metadata_path: Path | None = None,
    ) -> Path:
        locator = FirmProbe()
        try:
            return locator.probe(
                image_path=image_path,
                output_rootfs_path=rootfs_path,
                metadata_path=metadata_path,
            )
        except FileExistsError:
            raise
        except Exception as exception:
            raise RuntimeError(
                f"Failed to extract and locate root filesystem: {exception}"
            ) from exception
