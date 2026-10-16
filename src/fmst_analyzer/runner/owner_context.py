"""Attempt-local configured ownership, distinct from execution or causality."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def persist_runtime_owners(path: Path, *, units: dict, enabled_ids: set[str],
                           manifest: Path, adaptation_ids: list[str],
                           environment_script: Path | None) -> None:
    payload = {
        "schema_version": 1,
        "notice": "Configured definitions before this execution, including admitted runtime revisions. Configuration is not proof an owner ran or caused the failure.",
        "adaptation_ids": adaptation_ids,
        "units": {key: {"configured": key in enabled_ids, "definition": unit.model_dump(mode="json")}
                  for key, unit in sorted(units.items())},
        "manifest": json.loads(manifest.read_text()) if manifest.is_file() else None,
        "environment_script": ({"path": str(environment_script),
            "sha256": hashlib.sha256(environment_script.read_bytes()).hexdigest()}
            if environment_script and environment_script.is_file() else None),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_runtime_owners(path: Path) -> dict[str, object]:
    """Return small exact-ID associations and the full frozen definitions pointer."""
    try:
        raw = path.read_bytes()
        payload = json.loads(raw)
        if payload["schema_version"] != 1:
            raise ValueError("unsupported runtime owner context schema")
        owners = [{"unit_id": key, "configured": item["configured"],
                   "strategy": item["definition"]["strategy"]}
                  for key, item in payload["units"].items()]
        return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
                "notice": payload["notice"], "units": owners,
                "adaptation_ids": payload["adaptation_ids"],
                "environment_script": payload["environment_script"]}
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return {"path": str(path), "error": str(error),
                "notice": "Active definitions unavailable; do not substitute the original Plan as current ownership."}
