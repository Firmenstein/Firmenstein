"""Read and write the local FirmProbe metadata contract."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path


SUCCESS_STATUSES = {"extracted", "partial_rootfs"}
_LEADING_SHA256 = re.compile(r"^(?P<sha>[0-9a-fA-F]{64})_+(?P<label>.+)$")


def firmware_workdir_name(image_name: str, firmware_sha256: str) -> str:
    """Return a readable, identity-stable workdir basename.

    Corpus filenames sometimes start with their full SHA-256.  Put the human
    label first and retain a short identity suffix; the complete hash remains
    in metadata and analyzer results.
    """
    if not image_name:
        raise ValueError("Firmware image_name must be non-empty")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", firmware_sha256):
        raise ValueError("Firmware sha256 must contain exactly 64 hexadecimal characters")

    label = image_name
    match = _LEADING_SHA256.fullmatch(image_name)
    if match and match.group("sha").lower() == firmware_sha256.lower():
        label = match.group("label")
    return f"{label}__{firmware_sha256[:12].lower()}"


def write_firmware_metadata(metadata_path: Path, metadata: dict) -> Path:
    """Atomically write one firmware artifact's complete metadata."""
    metadata_path = Path(metadata_path).absolute()
    if metadata_path.exists() or metadata_path.is_symlink():
        raise FileExistsError(f"Firmware metadata already exists: {metadata_path}")
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = metadata_path.parent / (
        f".{metadata_path.name}.writing-{uuid.uuid4().hex}"
    )
    try:
        temporary_path.write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.link(temporary_path, metadata_path)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return metadata_path


def load_firmware_metadata(metadata_path: Path) -> dict:
    """Load JSON metadata and resolve artifact-relative paths in memory."""
    metadata_path = Path(metadata_path).absolute().resolve()
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exception:
        raise FileNotFoundError(f"Firmware metadata not found: {metadata_path}") from exception
    except json.JSONDecodeError as exception:
        raise ValueError(f"Invalid firmware metadata JSON: {metadata_path}: {exception}") from exception

    for field in ("image_name", "status", "rootfs_path", "all_binaries"):
        if field not in metadata:
            raise ValueError(f"Firmware metadata is missing required field {field!r}: {metadata_path}")
    if not isinstance(metadata["image_name"], str) or not metadata["image_name"]:
        raise ValueError("Firmware metadata image_name must be a non-empty string")
    if metadata["status"] not in SUCCESS_STATUSES:
        raise ValueError(
            f"Firmware metadata has no analyzable rootfs: status={metadata['status']!r}"
        )
    if not isinstance(metadata["rootfs_path"], str):
        raise ValueError("Firmware metadata rootfs_path must be a string")
    if not isinstance(metadata["all_binaries"], list):
        raise ValueError("Firmware metadata all_binaries must be a list")

    rootfs = Path(metadata["rootfs_path"])
    if not rootfs.is_absolute():
        rootfs = metadata_path.parent / rootfs
    rootfs = rootfs.resolve()
    if not rootfs.is_dir():
        raise FileNotFoundError(f"Firmware rootfs not found: {rootfs}")

    binaries: list[str] = []
    for entry in metadata["all_binaries"]:
        if not isinstance(entry, str):
            raise ValueError("Firmware metadata all_binaries entries must be strings")
        binary = Path(entry)
        if not binary.is_absolute():
            binary = rootfs / binary
        binary = binary.resolve()
        try:
            binary.relative_to(rootfs)
        except ValueError as exception:
            raise ValueError(f"Indexed binary escapes rootfs: {entry}") from exception
        binaries.append(str(binary))

    resolved = dict(metadata)
    resolved["rootfs_path"] = str(rootfs)
    resolved["all_binaries"] = binaries
    return resolved
