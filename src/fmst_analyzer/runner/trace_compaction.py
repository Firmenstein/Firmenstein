"""Lossless presentation of retained trace records, never a new observation.

Locations and identical records are interned. Adjacent exact repetitions of a
record-ID pattern retain order and multiplicity. Timestamps, snapshots and drop
counters are not normalized. This cannot recover data the collector dropped.
"""
from __future__ import annotations

from copy import deepcopy
import json


def _key(value: object) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _runs(ids: list[int]) -> list[dict[str, object]]:
    runs: list[dict[str, object]] = []
    literals: list[int] = []
    index = 0
    while index < len(ids):
        best_width, best_count, best_saving = 0, 0, 0
        # Bounded work for nonrepetitive inputs; longer motifs remain literals.
        for width in range(1, min(64, (len(ids) - index) // 2) + 1):
            pattern = ids[index:index + width]
            count = 1
            while ids[index + count * width:index + (count + 1) * width] == pattern:
                count += 1
            saving = width * (count - 1) - 2
            if saving > best_saving:
                best_width, best_count, best_saving = width, count, saving
        if best_count:
            if literals:
                runs.append({"pattern": literals, "repeat": 1})
                literals = []
            runs.append({"pattern": ids[index:index + best_width], "repeat": best_count})
            index += best_width * best_count
        else:
            literals.append(ids[index])
            index += 1
    if literals:
        runs.append({"pattern": literals, "repeat": 1})
    return runs


def compact_trace_context(context: dict[str, object]) -> dict[str, object]:
    """Encode every supplied context field; leave the input untouched."""
    fields = ("events", "recent_blocks", "recent_focus_blocks")
    metadata = deepcopy({k: v for k, v in context.items() if k not in fields})
    locations: list[object] = []
    location_ids: dict[str, int] = {}
    streams = {}
    for field in fields:
        records: list[object] = []
        record_ids: dict[str, int] = {}
        ids = []
        for original in context[field]:
            record = deepcopy(original)
            if record.get("location") is not None:
                location = record.pop("location")
                key = _key(location)
                if key not in location_ids:
                    location_ids[key] = len(locations)
                    locations.append(location)
                record["location_ref"] = location_ids[key]
            key = _key(record)
            if key not in record_ids:
                record_ids[key] = len(records)
                records.append(record)
            ids.append(record_ids[key])
        streams[field] = {"count": len(ids), "records": records, "runs": _runs(ids)}
    return {
        "encoding": "core-trace-dictionary-v1",
        "notice": "Lossless for the retained context. Expand each runs.pattern repeat times in order, index records, then replace location_ref with locations[index]. Counts refer to retained records, not total guest execution. Collector drop counters and checkpoint identity remain in metadata; a repeated pattern is not proof of a stuck loop.",
        "metadata": metadata, "locations": locations, "streams": streams,
    }


def expand_trace_context(encoded: dict[str, object]) -> dict[str, object]:
    """Decode the trusted, locally produced presentation for round-trip checks."""
    if encoded["encoding"] != "core-trace-dictionary-v1":
        raise ValueError("unsupported trace presentation encoding")
    result = deepcopy(encoded["metadata"])
    for field, stream in encoded["streams"].items():
        result[field] = []
        for run in stream["runs"]:
            for _ in range(run["repeat"]):
                for index in run["pattern"]:
                    record = deepcopy(stream["records"][index])
                    if "location_ref" in record:
                        record["location"] = deepcopy(encoded["locations"][record.pop("location_ref")])
                    result[field].append(record)
        if len(result[field]) != stream["count"]:
            raise ValueError("trace presentation record count mismatch")
    return result
