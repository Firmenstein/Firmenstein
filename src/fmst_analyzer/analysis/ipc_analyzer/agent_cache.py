"""Content-addressed cache for validated IPC Agent deltas."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel

from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.analysis.base.input_provenance import active_input_digest
from fmst_analyzer.analysis.base.semantic_identity import view_semantic_identity


# Task contracts now belong to the first user message. Entries produced with
# a developer-level task contract must not count as a run of this layout.
IPC_AGENT_CACHE_VERSION = 7
_OutputT = TypeVar("_OutputT", bound=BaseModel)


def agent_cache_key(
    *,
    stage: str,
    model: str,
    task_prompt: str,
    output_type: type[BaseModel],
    payload: Any,
    semantic_identity: Any,
) -> str:
    encoded = json.dumps(
        {
            "cache_version": IPC_AGENT_CACHE_VERSION,
            "analysis_input_digest": active_input_digest(),
            "stage": stage,
            "model": model,
            "task_prompt": task_prompt,
            "output_schema": output_type.model_json_schema(),
            "payload": payload,
            "semantic_identity": semantic_identity,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_agent_cache(
    global_config: GlobalConfig,
    stage: str,
    key: str,
    output_type: type[_OutputT],
) -> _OutputT | None:
    if getattr(global_config, "resume_analyzer_tasks", False):
        # Explicit recovery uses shared checkpoints with source-attempt receipts.
        return None
    path = _cache_path(global_config, stage, key)
    if path is None or not path.is_file():
        return None
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if (
            envelope.get("cache_version") != IPC_AGENT_CACHE_VERSION
            or envelope.get("key") != key
        ):
            return None
        return output_type.model_validate(envelope["output"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def store_agent_cache(
    global_config: GlobalConfig,
    stage: str,
    key: str,
    output: BaseModel,
) -> None:
    path = _cache_path(global_config, stage, key)
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    contents = json.dumps(
        {
            "cache_version": IPC_AGENT_CACHE_VERSION,
            "key": key,
            "output": output.model_dump(mode="json"),
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _cache_path(
    global_config: GlobalConfig,
    stage: str,
    key: str,
) -> Path | None:
    graph_cache_dir = getattr(global_config, "graph_cache_dir", None)
    if graph_cache_dir is None or active_input_digest() is None:
        return None
    return Path(graph_cache_dir) / "ipc_agent_cache" / stage / f"{key}.json"


__all__ = [
    "agent_cache_key",
    "load_agent_cache",
    "store_agent_cache",
    "view_semantic_identity",
]
