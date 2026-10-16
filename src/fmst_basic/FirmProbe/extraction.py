"""Isolated firmware extraction and deterministic rootfs selection.

This module contains only the extraction machinery used by ``FirmProbe``.
Every extractor writes below a caller-provided temporary directory; the
firmware input is never used as a work directory.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import time
import uuid
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from loguru import logger

from .vigi_squashfs import VigiSquashfsError, rebuild_vigi_rootfs


UNIX_DIRS = {
    "bin",
    "boot",
    "dev",
    "etc",
    "home",
    "lib",
    "lib32",
    "lib64",
    "mnt",
    "opt",
    "proc",
    "root",
    "run",
    "sbin",
    "srv",
    "sys",
    "tmp",
    "usr",
    "var",
    "www",
}
ROOTFS_MARKERS = (
    "bin/busybox",
    "bin/sh",
    "sbin/init",
    "etc/inittab",
    "etc/init.d",
    "etc/passwd",
)
DEFAULT_TIMEOUT_SECONDS = 1800
MAX_RECURSION_DEPTH = 8


@dataclass(frozen=True)
class RootfsCandidate:
    path: Path
    relative_path: str
    unix_directories: tuple[str, ...]
    markers: tuple[str, ...]
    file_count: int
    directory_count: int
    size_bytes: int
    depth: int
    elf_paths: tuple[str, ...] = ()
    limitations: tuple[dict, ...] = ()

    @property
    def sort_key(self) -> tuple:
        """Best candidate first, with a stable lexical tie-breaker."""
        return (
            -len(self.unix_directories),
            -len(self.markers),
            -self.file_count,
            -self.size_bytes,
            self.depth,
            self.relative_path,
        )

    def as_metadata(self) -> dict:
        return {
            "relative_path": self.relative_path,
            "unix_directories": list(self.unix_directories),
            "markers": list(self.markers),
            "file_count": self.file_count,
            "directory_count": self.directory_count,
            "size_bytes": self.size_bytes,
            "depth": self.depth,
            "elf_paths": list(self.elf_paths),
            "limitations": list(self.limitations),
        }


@dataclass
class ExtractionAttempt:
    method: str
    return_code: int | None
    error: str | None
    candidates: list[RootfsCandidate] = field(default_factory=list)
    status: str = "extracted"
    limitations: list[dict] = field(default_factory=list)

    def as_metadata(self) -> dict:
        return {
            "method": self.method,
            "return_code": self.return_code,
            "error": self.error,
            "candidate_count": len(self.candidates),
            "candidates": [candidate.as_metadata() for candidate in self.candidates],
        }


def _tree_counts(path: Path) -> tuple[int, int, int, int]:
    file_count = 0
    regular_file_count = 0
    directory_count = 0
    size_bytes = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
        directory_count += len(dirs)
        for name in files:
            file_count += 1
            file_path = root_path / name
            try:
                if file_path.is_symlink() or not file_path.is_file():
                    continue
                regular_file_count += 1
                size_bytes += file_path.stat().st_size
            except (OSError, PermissionError):
                continue
    return file_count, regular_file_count, directory_count, size_bytes


def inspect_root_candidate(path: Path, extraction_root: Path) -> RootfsCandidate | None:
    """Validate one directory as a rootfs without aggregating sibling trees."""
    try:
        direct_children = {
            child.name
            for child in path.iterdir()
            if child.is_dir() and not child.is_symlink()
        }
    except (OSError, PermissionError):
        return None

    unix_directories = tuple(sorted(direct_children & UNIX_DIRS))
    markers = tuple(
        marker for marker in ROOTFS_MARKERS if os.path.lexists(path / marker)
    )
    if len(unix_directories) < 3 or not markers:
        return None

    file_count, regular_file_count, directory_count, size_bytes = _tree_counts(path)
    if regular_file_count == 0:
        return None
    from .admission import inspect_root_content
    content = inspect_root_content(path)
    if not content["elf_paths"]:
        return None

    try:
        relative = path.relative_to(extraction_root)
    except ValueError:
        return None
    return RootfsCandidate(
        path=path,
        relative_path=relative.as_posix() or ".",
        unix_directories=unix_directories,
        markers=markers,
        file_count=file_count,
        directory_count=directory_count,
        size_bytes=size_bytes,
        depth=len(relative.parts),
        elf_paths=tuple(content["elf_paths"]),
        limitations=tuple(content["limitations"]),
    )


def find_root_candidates(extraction_root: Path) -> list[RootfsCandidate]:
    candidates: list[RootfsCandidate] = []
    if not extraction_root.is_dir():
        return candidates
    for root, dirs, _ in os.walk(extraction_root, followlinks=False):
        path = Path(root)
        candidate = inspect_root_candidate(path, extraction_root)
        if candidate is not None:
            candidates.append(candidate)
        dirs[:] = [name for name in dirs if not (path / name).is_symlink()]
    return sorted(candidates, key=lambda candidate: candidate.sort_key)


def _run_logged(
    command: list[str],
    log_path: Path,
    timeout_seconds: int,
    container_name: str | None = None,
) -> tuple[int | None, str | None]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("wb") as log_file:
            result = subprocess.run(
                command,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
            )
        error = None if result.returncode == 0 else f"exited with status {result.returncode}"
        return result.returncode, error
    except subprocess.TimeoutExpired:
        if container_name:
            subprocess.run(
                ["docker", "rm", "--force", container_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        error = f"timed out after {timeout_seconds} seconds"
        with log_path.open("ab") as log_file:
            log_file.write(f"\n{error}\n".encode())
        return None, error
    except Exception as exception:
        error = f"{type(exception).__name__}: {exception}"
        with log_path.open("ab") as log_file:
            log_file.write(f"\n{error}\n".encode())
        return None, error


def _run_container(
    image: str,
    source: Path,
    work_dir: Path,
    command: list[str],
    log_path: Path,
    timeout_seconds: int,
    *,
    use_host_user: bool = True,
) -> tuple[int | None, str | None]:
    container_name = f"fmst-extract-{os.getpid()}-{uuid.uuid4().hex[:12]}"
    docker_command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--cpus",
        "4",
        "--memory",
        "8g",
    ]
    if use_host_user:
        docker_command.extend(["--user", f"{os.getuid()}:{os.getgid()}"])
    docker_command.extend(
        [
            "--volume",
            f"{source.parent.resolve()}:/input:ro",
            "--volume",
            f"{work_dir.resolve()}:/work:rw",
            image,
            *command,
        ]
    )
    return _run_logged(docker_command, log_path, timeout_seconds, container_name)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_tenda_container(source: Path) -> bool:
    try:
        with source.open("rb") as input_file:
            header = input_file.read(16)
            input_file.seek(512)
            zip_header = input_file.read(4)
        return header.startswith(b"TD0101XS_7302") and zip_header == b"ZL\x03\x04"
    except OSError:
        return False


def _contains_squashfs3(source: Path) -> bool:
    overlap = b""
    try:
        with source.open("rb") as input_file:
            for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                data = overlap + chunk
                if b"hsqs" in data:
                    return True
                overlap = data[-3:]
    except OSError:
        return False
    return False


def run_unblob(source: Path, method_dir: Path, timeout_seconds: int) -> ExtractionAttempt:
    method_dir.mkdir(parents=True)
    return_code, error = _run_container(
        "extractor-unblob",
        source,
        method_dir,
        [
            "unblob",
            "-e",
            "/work/extracted",
            "-d",
            "20",
            "-p",
            "4",
            "-n",
            "0",
            "--report",
            "/work/report.json",
            "--log",
            "/work/unblob.log",
            f"/input/{source.name}",
        ],
        method_dir / "stdout.log",
        timeout_seconds,
    )
    return ExtractionAttempt(
        method="unblob",
        return_code=return_code,
        error=error,
        candidates=find_root_candidates(method_dir / "extracted"),
    )


def _parse_7z_listing(text: str) -> tuple[str | None, list[dict[str, str]]]:
    archive_type: str | None = None
    header, separator, entries_text = text.partition("----------\n")
    for line in header.splitlines():
        if line.startswith("Type = "):
            archive_type = line.removeprefix("Type = ").strip()
            break
    entries: list[dict[str, str]] = []
    if separator:
        for block in entries_text.split("\n\n"):
            entry: dict[str, str] = {}
            for line in block.splitlines():
                key, delimiter, value = line.partition(" = ")
                if delimiter:
                    entry[key] = value
            if "Path" in entry:
                entries.append(entry)
    return archive_type, entries


def _restore_7z_symlinks(
    archive: Path,
    extraction_dir: Path,
    entries: list[dict[str, str]],
) -> None:
    for entry in entries:
        if not entry.get("Mode", "").startswith("l"):
            continue
        member = Path(entry["Path"])
        if member.is_absolute() or ".." in member.parts:
            continue
        result = subprocess.run(
            ["7z", "x", "-so", str(archive), entry["Path"]],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode not in {0, 1, 2} or not result.stdout:
            continue
        destination = extraction_dir / member
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink() or destination.is_file():
            destination.unlink()
        elif destination.is_dir():
            shutil.rmtree(destination)
        os.symlink(os.fsdecode(result.stdout.rstrip(b"\0")), destination)


def run_sevenzip(source: Path, method_dir: Path, timeout_seconds: int) -> ExtractionAttempt:
    method_dir.mkdir(parents=True)
    started = time.monotonic()
    deadline = started + timeout_seconds
    queue = deque([(source, 0)])
    seen_hashes: set[str] = set()
    candidates: list[RootfsCandidate] = []
    error: str | None = None
    return_code: int | None = 0

    with (method_dir / "sevenzip.log").open("w", encoding="utf-8") as log_file:
        while queue and not candidates:
            remaining = max(0, int(deadline - time.monotonic()))
            if remaining == 0:
                return_code = None
                error = f"timed out after {timeout_seconds} seconds"
                break
            path, depth = queue.popleft()
            if not path.is_file() or path.is_symlink():
                continue
            digest = _sha256(path)
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            if depth >= MAX_RECURSION_DEPTH:
                continue
            try:
                listing = subprocess.run(
                    ["7z", "l", "-slt", str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=min(600, remaining),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                continue
            archive_type, entries = _parse_7z_listing(listing.stdout)
            log_file.write(listing.stdout)
            if listing.returncode not in {0, 1, 2} or not archive_type:
                continue

            extraction_dir = method_dir / f"node-{len(seen_hashes):06d}" / "files"
            extraction_dir.mkdir(parents=True)
            extract_code, extract_error = _run_logged(
                ["7z", "x", "-y", f"-o{extraction_dir}", str(path)],
                extraction_dir.parent / "extract.log",
                min(600, remaining),
            )
            if extract_code not in {0, 1, 2}:
                error = extract_error
                continue
            _restore_7z_symlinks(path, extraction_dir, entries)
            candidates = find_root_candidates(extraction_dir)
            if candidates:
                break
            output_files = sorted(
                (
                    item
                    for item in extraction_dir.rglob("*")
                    if item.is_file() and not item.is_symlink()
                ),
                key=lambda item: item.as_posix(),
            )
            queue.extend((item, depth + 1) for item in output_files)

    if not candidates and error is None:
        error = "no supported archive produced a rootfs candidate"
    return ExtractionAttempt("sevenzip", return_code, error, candidates)


def run_binwalk(source: Path, method_dir: Path, timeout_seconds: int) -> ExtractionAttempt:
    method_dir.mkdir(parents=True)
    return_code, error = _run_container(
        "extractor-binwalkv3",
        source,
        method_dir,
        [
            "-M",
            "-e",
            "-a",
            "-t",
            "4",
            "-d",
            "/work/extracted",
            "-l",
            "/work/report.json",
            f"/input/{source.name}",
        ],
        method_dir / "stdout.log",
        timeout_seconds,
    )
    return ExtractionAttempt(
        "binwalkv3",
        return_code,
        error,
        find_root_candidates(method_dir / "extracted"),
    )


def run_firmextractor(
    source: Path, method_dir: Path, timeout_seconds: int
) -> ExtractionAttempt:
    method_dir.mkdir(parents=True)
    return_code, error = _run_container(
        "extractor-firmaextractor",
        source,
        method_dir,
        [
            "fakeroot",
            "python3",
            "./FirmAExtractor.py",
            "-np",
            f"/input/{source.name}",
            "/work",
        ],
        method_dir / "stdout.log",
        timeout_seconds,
        use_host_user=False,
    )
    extracted_dir = method_dir / "extracted"
    extracted_dir.mkdir(exist_ok=True)
    for archive in sorted(method_dir.glob(f"{source.name}_*.tar.gz")):
        tar_code, tar_error = _run_logged(
            [
                "tar",
                "-xzf",
                str(archive),
                "--no-same-owner",
                "--no-same-permissions",
                "-C",
                str(extracted_dir),
            ],
            method_dir / f"{archive.name}.extract.log",
            timeout_seconds,
        )
        if tar_code != 0:
            error = tar_error
    return ExtractionAttempt(
        "FirmAExtractor",
        return_code,
        error,
        find_root_candidates(extracted_dir),
    )


def run_tenda(source: Path, method_dir: Path, timeout_seconds: int) -> ExtractionAttempt:
    method_dir.mkdir(parents=True)
    patched_source = method_dir / "container.bin"
    shutil.copy2(source, patched_source)
    with patched_source.open("r+b") as output_file:
        output_file.seek(512)
        output_file.write(b"PK")

    payload_dir = method_dir / "payload"
    payload_dir.mkdir()
    archive_code, archive_error = _run_logged(
        ["7z", "x", "-y", f"-o{payload_dir}", str(patched_source)],
        method_dir / "archive.log",
        timeout_seconds,
    )
    if archive_code not in {0, 1, 2}:
        return ExtractionAttempt("tenda_ipcam", archive_code, archive_error)

    partition_mounts = {
        "romfs-x.squash.img": None,
        "user-x.squash.img": Path("opt/app"),
        "web-x.squash.img": Path("opt/web"),
        "custom-x.squash.img": Path("opt/custom"),
        "slave-x.jffs2.img": Path("opt/sav"),
    }
    extracted_partitions: dict[str, Path] = {}
    partitions_dir = method_dir / "partitions"
    partitions_dir.mkdir()
    for image_name in partition_mounts:
        matches = sorted(payload_dir.rglob(image_name))
        if len(matches) != 1:
            continue
        image = matches[0]
        with image.open("rb") as input_file:
            partition_header = input_file.read(68)
        if (
            len(partition_header) < 68
            or partition_header[:4] != b"\x27\x05\x19\x56"
            or partition_header[64:68] != b"\x85\x19\x03\x20"
        ):
            continue
        carve_dir = method_dir / "carves"
        carve_dir.mkdir(exist_ok=True)
        carved_image = carve_dir / f"{image_name}.jffs2"
        with image.open("rb") as input_file, carved_image.open("wb") as output_file:
            input_file.seek(64)
            shutil.copyfileobj(input_file, output_file)
        partition_name = image_name.split("-", 1)[0]
        extraction_dir = partitions_dir / partition_name
        work_dir = method_dir / f"jefferson-{partition_name}"
        work_dir.mkdir()
        return_code, _ = _run_container(
            "extractor-unblob",
            carved_image,
            work_dir,
            ["jefferson", "-d", "/work/rootfs", f"/input/{carved_image.name}"],
            method_dir / f"{partition_name}.log",
            timeout_seconds,
        )
        container_root = work_dir / "rootfs"
        if return_code == 0 and container_root.is_dir():
            container_root.rename(extraction_dir)
            extracted_partitions[image_name] = extraction_dir

    base_root = extracted_partitions.get("romfs-x.squash.img")
    if base_root is None:
        return ExtractionAttempt(
            "tenda_ipcam", 1, "the base romfs JFFS2 partition could not be extracted"
        )
    assembled_root = method_dir / "assembled_rootfs"
    shutil.copytree(base_root, assembled_root, symlinks=True)
    for image_name, mount_path in partition_mounts.items():
        if mount_path is None or image_name not in extracted_partitions:
            continue
        destination = assembled_root / mount_path
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            extracted_partitions[image_name],
            destination,
            symlinks=True,
            dirs_exist_ok=True,
        )
    candidate = inspect_root_candidate(assembled_root, method_dir)
    return ExtractionAttempt(
        "tenda_ipcam", 0, None, [candidate] if candidate is not None else []
    )


def run_vigi(source: Path, method_dir: Path, timeout_seconds: int) -> ExtractionAttempt:
    method_dir.mkdir(parents=True)
    try:
        report = rebuild_vigi_rootfs(source, method_dir, timeout_seconds)
    except (OSError, VigiSquashfsError, zipfile.BadZipFile) as exception:
        return ExtractionAttempt(
            "vigi_squashfs", 1, f"{type(exception).__name__}: {exception}"
        )
    rootfs = method_dir / "rootfs"
    candidate = inspect_root_candidate(rootfs, method_dir)
    limitations = [report["protected_file"]]
    return ExtractionAttempt(
        "vigi_squashfs",
        report["extraction"]["return_code"],
        None,
        [candidate] if candidate is not None else [],
        status="partial_rootfs",
        limitations=limitations,
    )


def _squashfs3_offsets(source: Path) -> list[int]:
    offsets: list[int] = []
    overlap = b""
    absolute = 0
    with source.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            data = overlap + chunk
            start = 0
            while True:
                index = data.find(b"hsqs", start)
                if index < 0:
                    break
                offset = absolute - len(overlap) + index
                if offset >= 0:
                    offsets.append(offset)
                start = index + 1
            absolute += len(chunk)
            overlap = data[-3:]
    return sorted(set(offsets))


def run_squashfs3(
    source: Path, method_dir: Path, timeout_seconds: int
) -> ExtractionAttempt:
    method_dir.mkdir(parents=True)
    carve_dir = method_dir.parent / "squashfs3-carves"
    carve_dir.mkdir()
    candidates: list[RootfsCandidate] = []
    last_code: int | None = None
    errors: list[str] = []
    source_offsets = _squashfs3_offsets(source)
    scan_sources: list[Path] = []
    if not source_offsets and zipfile.is_zipfile(source):
        container_dir = method_dir / "container"
        container_dir.mkdir()
        archive_code, archive_error = _run_logged(
            ["7z", "x", "-y", f"-o{container_dir}", str(source)],
            method_dir / "container.log",
            timeout_seconds,
        )
        if archive_code in {0, 1, 2}:
            scan_sources.extend(
                sorted(
                    (
                        path
                        for path in container_dir.rglob("*")
                        if path.is_file() and not path.is_symlink()
                    ),
                    key=lambda path: path.as_posix(),
                )
            )
        elif archive_error:
            errors.append(archive_error)

    located_images: list[tuple[Path, int]] = [
        (source, offset) for offset in source_offsets
    ]
    for scan_source in scan_sources:
        located_images.extend(
            (scan_source, offset) for offset in _squashfs3_offsets(scan_source)
        )

    for index, (scan_source, offset) in enumerate(located_images[:16]):
        carved = carve_dir / f"carved-{index:03d}.squashfs"
        with scan_source.open("rb") as input_file, carved.open("wb") as output_file:
            input_file.seek(offset)
            shutil.copyfileobj(input_file, output_file)
        output_name = f"rootfs-{index:03d}"
        last_code, error = _run_container(
            "extractor-unblob",
            carved,
            method_dir,
            [
                "unsquashfs-recovery",
                "-no-progress",
                "-d",
                f"/work/{output_name}",
                f"/input/{carved.name}",
            ],
            method_dir / f"unsquashfs-{index:03d}.log",
            timeout_seconds,
        )
        if error:
            errors.append(error)
        candidates.extend(find_root_candidates(method_dir / output_name))
        if candidates:
            break
    return ExtractionAttempt(
        "patched_unsquashfs3",
        last_code,
        "; ".join(errors) or None,
        sorted(candidates, key=lambda candidate: candidate.sort_key),
    )


class ExtractionOrchestrator:
    def __init__(
        self,
        source: Path,
        job_dir: Path,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.source = source
        self.job_dir = job_dir
        self.timeout_seconds = timeout_seconds

    def run(
        self,
    ) -> tuple[ExtractionAttempt | None, RootfsCandidate | None, list[ExtractionAttempt]]:
        attempts: list[ExtractionAttempt] = []

        runners: list[
            tuple[str, Callable[[Path, Path, int], ExtractionAttempt]]
        ] = []
        if _is_tenda_container(self.source):
            runners.append(("tenda_ipcam", run_tenda))
        runners.append(("unblob", run_unblob))
        if zipfile.is_zipfile(self.source):
            runners.append(("vigi_squashfs", run_vigi))
        if _contains_squashfs3(self.source) or zipfile.is_zipfile(self.source):
            runners.append(("patched_unsquashfs3", run_squashfs3))
        runners.extend(
            [
                ("sevenzip", run_sevenzip),
                ("binwalkv3", run_binwalk),
                ("FirmAExtractor", run_firmextractor),
            ]
        )

        for method, runner in runners:
            logger.info(f"Trying firmware extraction with {method}")
            method_dir = self.job_dir / method
            try:
                attempt = runner(self.source, method_dir, self.timeout_seconds)
            except Exception as exception:
                attempt = ExtractionAttempt(
                    method,
                    None,
                    f"{type(exception).__name__}: {exception}",
                )
            attempts.append(attempt)
            if attempt.candidates:
                selected = min(attempt.candidates, key=lambda item: item.sort_key)
                return attempt, selected, attempts
        return None, None, attempts
