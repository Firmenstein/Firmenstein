"""Rebuild the partially protected SquashFS images in early VIGI firmware.

The VIGI images handled here retain standard SquashFS inode, directory,
fragment, export, and id tables.  The on-disk superblock and the first
compressed data block are protected, which prevents ordinary signature-based
extractors from recognising the filesystem.  This module derives a replacement
superblock only from the surviving SquashFS metadata.  It deliberately does not
invent replacement contents for the protected file block.
"""

from __future__ import annotations

import hashlib
import json
import lzma
import math
import shutil
import struct
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path


XZ_MAGIC = b"\xfd7zXZ\x00"
SQUASHFS_MAGIC = 0x73717368
SQUASHFS_INVALID_BLOCK = 0xFFFFFFFFFFFFFFFF
SQUASHFS_INVALID_FRAGMENT = 0xFFFFFFFF
SQUASHFS_METADATA_SIZE = 8192
SQUASHFS_BLOCK_SIZE = 65536


class VigiSquashfsError(RuntimeError):
    """Raised when a VIGI image does not match the recoverable format."""


@dataclass(frozen=True)
class XzStream:
    start: int
    consumed: int
    raw: bytes

    @property
    def end(self) -> int:
        return self.start + self.consumed

    @property
    def header_start(self) -> int:
        return self.start - 2


@dataclass(frozen=True)
class InodeRecord:
    start: int
    inode_type: int
    inode_number: int
    mtime: int
    size: int
    start_block: int | None = None
    file_size: int | None = None
    fragment: int | None = None
    block_sizes: tuple[int, ...] = ()


def _scan_xz_streams(data: bytes) -> list[XzStream]:
    streams: list[XzStream] = []
    offset = 0
    while True:
        offset = data.find(XZ_MAGIC, offset)
        if offset < 0:
            break
        try:
            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            raw = decompressor.decompress(data[offset:])
            consumed = len(data) - offset - len(decompressor.unused_data)
            if decompressor.eof:
                streams.append(XzStream(offset, consumed, raw))
        except lzma.LZMAError:
            pass
        offset += 1
    return streams


def _is_metadata_stream(data: bytes, stream: XzStream) -> bool:
    if stream.start < 2 or len(stream.raw) > SQUASHFS_METADATA_SIZE:
        return False
    header = struct.unpack_from("<H", data, stream.header_start)[0]
    return header & 0x8000 == 0 and header == stream.consumed


def _metadata_runs(data: bytes, streams: list[XzStream]) -> list[list[XzStream]]:
    metadata = [stream for stream in streams if _is_metadata_stream(data, stream)]
    runs: list[list[XzStream]] = []
    current: list[XzStream] = []
    for stream in metadata:
        if current and stream.header_start != current[-1].end:
            if current:
                runs.append(current)
            current = []
        current.append(stream)
    if current:
        runs.append(current)
    return runs


def _parse_inodes(data: bytes) -> list[InodeRecord] | None:
    records: list[InodeRecord] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 16:
            return None
        inode_type, _mode, _uid, _gid, mtime, inode_number = struct.unpack_from(
            "<HHHHII", data, offset
        )
        start = offset
        start_block: int | None = None
        file_size: int | None = None
        fragment: int | None = None
        block_sizes: tuple[int, ...] = ()

        try:
            if inode_type == 1:
                size = 32
            elif inode_type == 2:
                start_block, fragment, _fragment_offset, file_size = (
                    struct.unpack_from("<IIII", data, offset + 16)
                )
                block_count = file_size // SQUASHFS_BLOCK_SIZE
                if (
                    fragment == SQUASHFS_INVALID_FRAGMENT
                    and file_size % SQUASHFS_BLOCK_SIZE
                ):
                    block_count += 1
                block_sizes = struct.unpack_from(
                    f"<{block_count}I", data, offset + 32
                )
                size = 32 + block_count * 4
            elif inode_type == 3:
                symlink_size = struct.unpack_from("<I", data, offset + 20)[0]
                size = 24 + symlink_size
            elif inode_type in (4, 5):
                size = 24
            elif inode_type in (6, 7):
                size = 20
            elif inode_type == 8:
                index_count = struct.unpack_from("<H", data, offset + 32)[0]
                size = 40
                for _ in range(index_count):
                    name_size = struct.unpack_from("<I", data, offset + size + 8)[0]
                    size += 13 + name_size
            elif inode_type == 9:
                start_block, file_size = struct.unpack_from(
                    "<QQ", data, offset + 16
                )
                fragment = struct.unpack_from("<I", data, offset + 44)[0]
                block_count = file_size // SQUASHFS_BLOCK_SIZE
                if (
                    fragment == SQUASHFS_INVALID_FRAGMENT
                    and file_size % SQUASHFS_BLOCK_SIZE
                ):
                    block_count += 1
                block_sizes = struct.unpack_from(
                    f"<{block_count}I", data, offset + 56
                )
                size = 56 + block_count * 4
            elif inode_type == 10:
                symlink_size = struct.unpack_from("<I", data, offset + 20)[0]
                size = 28 + symlink_size
            elif inode_type in (11, 12):
                size = 28
            elif inode_type in (13, 14):
                size = 24
            else:
                return None
        except struct.error:
            return None

        if offset + size > len(data):
            return None
        records.append(
            InodeRecord(
                start=start,
                inode_type=inode_type,
                inode_number=inode_number,
                mtime=mtime,
                size=size,
                start_block=start_block,
                file_size=file_size,
                fragment=fragment,
                block_sizes=tuple(block_sizes),
            )
        )
        offset += size
    return records


def _locate_inode_table(
    data: bytes, runs: list[list[XzStream]]
) -> tuple[list[XzStream], int, list[InodeRecord]]:
    for run in runs:
        if len(run) < 3:
            continue
        concatenated = b""
        for count, stream in enumerate(run, start=1):
            concatenated += stream.raw
            records = _parse_inodes(concatenated)
            if (
                records
                and len(records) >= 100
                and max(record.inode_number for record in records) == len(records)
            ):
                return run, count, records
    raise VigiSquashfsError("No internally consistent SquashFS inode table found")


def _locate_image_base(
    data: bytes, streams: list[XzStream], records: list[InodeRecord]
) -> tuple[int, InodeRecord]:
    regular = next(
        (
            record
            for record in records
            if record.inode_type in (2, 9)
            and record.start_block is not None
            and record.start_block < 4096
            and record.file_size is not None
            and record.file_size > SQUASHFS_BLOCK_SIZE
            and len(record.block_sizes) >= 2
        ),
        None,
    )
    if regular is None or regular.start_block is None:
        raise VigiSquashfsError("No suitable initial regular inode found")

    candidates = []
    for stream in streams:
        if (
            stream.consumed != regular.block_sizes[1]
            or len(stream.raw) != SQUASHFS_BLOCK_SIZE
        ):
            continue
        image_base = (
            stream.start - regular.start_block - regular.block_sizes[0]
        )
        if image_base < 0:
            continue
        cursor = stream.start
        valid = True
        for index, packed_size in enumerate(regular.block_sizes[1:], start=1):
            matching = next(
                (
                    item
                    for item in streams
                    if item.start == cursor and item.consumed == packed_size
                ),
                None,
            )
            expected_size = min(
                SQUASHFS_BLOCK_SIZE,
                regular.file_size - index * SQUASHFS_BLOCK_SIZE,
            )
            if matching is None or len(matching.raw) != expected_size:
                valid = False
                break
            cursor += packed_size
        if valid:
            candidates.append(image_base)
    if len(set(candidates)) != 1:
        raise VigiSquashfsError(
            f"Expected one image base, found {sorted(set(candidates))}"
        )
    return candidates[0], regular


def _find_stream(
    streams_by_start: dict[int, XzStream], start: int
) -> XzStream:
    stream = streams_by_start.get(start)
    if stream is None:
        raise VigiSquashfsError(f"Expected XZ metadata stream at offset {start}")
    return stream


def _derive_layout(data: bytes) -> dict:
    streams = _scan_xz_streams(data)
    runs = _metadata_runs(data, streams)
    run, inode_chunk_count, records = _locate_inode_table(data, runs)
    image_base, protected_inode = _locate_image_base(data, streams, records)
    streams_by_start = {stream.start: stream for stream in streams}

    inode_chunks = run[:inode_chunk_count]
    if inode_chunk_count >= len(run):
        raise VigiSquashfsError("Inode metadata is not followed by directory data")
    fragment_stream = run[-1]
    if len(fragment_stream.raw) % 16:
        raise VigiSquashfsError("Fragment table has an invalid byte length")
    fragment_count = len(fragment_stream.raw) // 16
    fragment_index_start = fragment_stream.end
    fragment_pointer = struct.unpack_from("<Q", data, fragment_index_start)[0]
    if fragment_pointer != fragment_stream.header_start - image_base:
        raise VigiSquashfsError("Fragment index does not point to its metadata")

    inode_count = len(records)
    lookup_metadata_start = fragment_index_start + 8
    lookup_streams: list[XzStream] = []
    lookup_raw_size = 0
    cursor = lookup_metadata_start
    while lookup_raw_size < inode_count * 8:
        stream = _find_stream(streams_by_start, cursor + 2)
        if not _is_metadata_stream(data, stream):
            raise VigiSquashfsError("Export table metadata header is invalid")
        lookup_streams.append(stream)
        lookup_raw_size += len(stream.raw)
        cursor = stream.end
    if lookup_raw_size != inode_count * 8:
        raise VigiSquashfsError("Export table size does not match inode count")

    lookup_index_start = cursor
    for index, stream in enumerate(lookup_streams):
        pointer = struct.unpack_from("<Q", data, lookup_index_start + index * 8)[0]
        if pointer != stream.header_start - image_base:
            raise VigiSquashfsError("Export index does not point to its metadata")

    id_metadata_start = lookup_index_start + len(lookup_streams) * 8
    id_header = struct.unpack_from("<H", data, id_metadata_start)[0]
    if id_header & 0x8000 == 0:
        raise VigiSquashfsError("Expected an uncompressed SquashFS id table")
    id_data_size = id_header & 0x7FFF
    if id_data_size == 0 or id_data_size % 4:
        raise VigiSquashfsError("SquashFS id table has an invalid byte length")
    id_count = id_data_size // 4
    id_index_count = math.ceil(id_data_size / SQUASHFS_METADATA_SIZE)
    id_index_start = id_metadata_start + 2 + id_data_size
    for index in range(id_index_count):
        pointer = struct.unpack_from("<Q", data, id_index_start + index * 8)[0]
        if pointer != id_metadata_start - image_base:
            raise VigiSquashfsError("Id index does not point to its metadata")
    bytes_used = id_index_start + id_index_count * 8 - image_base

    inode_table_start = inode_chunks[0].header_start - image_base
    directory_table_start = run[inode_chunk_count].header_start - image_base
    root_record = records[-1]
    cumulative = 0
    root_chunk = None
    root_offset = None
    for stream in inode_chunks:
        if cumulative <= root_record.start < cumulative + len(stream.raw):
            root_chunk = stream
            root_offset = root_record.start - cumulative
            break
        cumulative += len(stream.raw)
    if root_chunk is None or root_offset is None:
        raise VigiSquashfsError("Root inode is outside the inode metadata")
    root_inode = (
        (root_chunk.header_start - inode_chunks[0].header_start) << 16
    ) | root_offset

    protected_start = image_base
    protected_end = (
        image_base
        + protected_inode.start_block
        + protected_inode.block_sizes[0]
    )
    if protected_end > inode_chunks[0].header_start:
        raise VigiSquashfsError("Protected data range overlaps SquashFS metadata")

    return {
        "streams": streams,
        "image_base": image_base,
        "inode_count": inode_count,
        "fragment_count": fragment_count,
        "id_count": id_count,
        "mkfs_time": records[0].mtime,
        "root_inode": root_inode,
        "bytes_used": bytes_used,
        "id_table_start": id_index_start - image_base,
        "inode_table_start": inode_table_start,
        "directory_table_start": directory_table_start,
        "fragment_table_start": fragment_index_start - image_base,
        "lookup_table_start": lookup_index_start - image_base,
        "protected_start": protected_start,
        "protected_end": protected_end,
        "protected_inode_number": protected_inode.inode_number,
        "protected_file_size": protected_inode.file_size,
        "protected_first_block_size": protected_inode.block_sizes[0],
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _extract_inner_firmware(source: Path, destination: Path) -> Path:
    try:
        with zipfile.ZipFile(source) as archive:
            members = [
                item
                for item in archive.infolist()
                if not item.is_dir() and item.filename.lower().endswith(".bin")
            ]
            if not members:
                raise VigiSquashfsError("ZIP contains no firmware .bin payload")
            member = max(members, key=lambda item: item.file_size)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as input_file, destination.open("wb") as output_file:
                shutil.copyfileobj(input_file, output_file)
            return destination
    except zipfile.BadZipFile as error:
        raise VigiSquashfsError("Source is not a ZIP-based VIGI update") from error


def rebuild_vigi_rootfs(
    source: Path,
    method_dir: Path,
    timeout_seconds: int,
) -> dict:
    """Rebuild and extract a VIGI SquashFS, returning an audit report."""
    method_dir.mkdir(parents=True, exist_ok=True)
    inner = _extract_inner_firmware(source, method_dir / "firmware.bin")
    data = inner.read_bytes()
    layout = _derive_layout(data)

    superblock = struct.pack(
        "<5I6H8Q",
        SQUASHFS_MAGIC,
        layout["inode_count"],
        layout["mkfs_time"],
        SQUASHFS_BLOCK_SIZE,
        layout["fragment_count"],
        4,
        16,
        0x00C0,
        layout["id_count"],
        4,
        0,
        layout["root_inode"],
        layout["bytes_used"],
        layout["id_table_start"],
        SQUASHFS_INVALID_BLOCK,
        layout["inode_table_start"],
        layout["directory_table_start"],
        layout["fragment_table_start"],
        layout["lookup_table_start"],
    )
    image_start = layout["image_base"]
    image_end = image_start + layout["bytes_used"]
    if image_end > len(data):
        raise VigiSquashfsError("Derived SquashFS image extends beyond firmware")
    rebuilt = bytearray(data[image_start:image_end])
    rebuilt[: len(superblock)] = superblock
    rebuilt_path = method_dir / "rebuilt.squashfs"
    rebuilt_path.write_bytes(rebuilt)

    rootfs = method_dir / "rootfs"
    rootfs.mkdir()
    log_path = method_dir / "unsquashfs.log"
    with log_path.open("wb") as log_file:
        try:
            result = subprocess.run(
                [
                    "unsquashfs",
                    "-ignore-errors",
                    "-d",
                    str(rootfs),
                    str(rebuilt_path),
                ],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
            )
            return_code = result.returncode
            timeout_error = None
        except subprocess.TimeoutExpired:
            return_code = None
            timeout_error = f"(timed out after {timeout_seconds} seconds)"
            log_file.write(f"\n{timeout_error}\n".encode())

    protected_path = "bin/busybox"
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    if protected_path not in log_text:
        raise VigiSquashfsError(
            "Extraction did not identify bin/busybox as the protected file"
        )
    if not (rootfs / "bin/main").is_file() or not (rootfs / "etc").is_dir():
        raise VigiSquashfsError("Rebuilt filesystem failed rootfs validation")

    file_count = sum(1 for path in rootfs.rglob("*") if path.is_file())
    directory_count = sum(1 for path in rootfs.rglob("*") if path.is_dir())
    symlink_count = sum(1 for path in rootfs.rglob("*") if path.is_symlink())
    report = {
        "format": "TP-Link VIGI protected SquashFS",
        "status": "partial_rootfs",
        "source_sha256": _sha256(source),
        "inner_firmware": {
            "size_bytes": inner.stat().st_size,
            "sha256": _sha256(inner),
        },
        "reconstruction": {
            key: value
            for key, value in layout.items()
            if key != "streams"
        },
        "superblock_sha256": hashlib.sha256(superblock).hexdigest(),
        "rebuilt_squashfs_sha256": _sha256(rebuilt_path),
        "protected_file": {
            "path": protected_path,
            "reason": (
                "The vendor-protected first SquashFS data block cannot be "
                "decompressed without the device key; no substitute was added."
            ),
            "inode_number": layout["protected_inode_number"],
            "file_size": layout["protected_file_size"],
            "protected_first_block_size": layout[
                "protected_first_block_size"
            ],
        },
        "extraction": {
            "return_code": return_code,
            "timeout_error": timeout_error,
            "file_count": file_count,
            "directory_count": directory_count,
            "symlink_count": symlink_count,
        },
    }
    (method_dir / "vigi_squashfs.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report
