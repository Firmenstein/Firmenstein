"""Atomic persistence helpers for report sources of truth and renderings."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def model_content_sha256(value: BaseModel) -> str:
    """Digest validated content, independent of JSON indentation and key order."""
    payload = json.dumps(value.model_dump(mode="json"), ensure_ascii=False,
                         sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _atomic_write_text(path: Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def write_model_json(path: Path, value: BaseModel) -> None:
    """Always atomically publish a complete Pydantic JSON artifact."""
    _atomic_write_text(Path(path), value.model_dump_json(indent=2))


def load_model_json(path: Path, model: type[_ModelT]) -> _ModelT:
    """Parse one persisted JSON source into its authoritative model type."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"required JSON artifact is missing: {path}")
    try:
        return model.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise ValueError(f"invalid JSON artifact {path}: {error}") from error


def write_text(path: Path, text: str) -> None:
    """Atomically publish a human-readable rendering."""
    _atomic_write_text(Path(path), text)


__all__ = ["load_model_json", "model_content_sha256", "write_model_json", "write_text"]
