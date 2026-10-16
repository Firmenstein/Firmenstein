"""Attempt-local failed requests; separate from the accepted Plan draft."""
from datetime import datetime, timezone
import hashlib
import json
from uuid import UUID, uuid4

from fmst_basic.agent.tool import tool


def failed_batch_access(store):
    state = store.state
    identity = {"catalog_digest": state.catalog_digest,
                "planning_context": state.planning_context.model_dump(mode="json"),
                "service_goal": state.service_goal}
    identity_digest = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    directory = store.path.parent / (store.path.stem + ".failed_batches") / identity_digest

    def retain(arguments, error):
        batch_id = uuid4().hex
        record = {"failed_batch_id": batch_id, "input_identity": identity_digest,
                  "created_at": datetime.now(timezone.utc).isoformat(),
                  "observed_draft_revision": store.state.revision,
                  "error_type": type(error).__name__, "error": str(error),
                  "arguments": arguments}
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / f"{batch_id}.json").open("x", encoding="utf-8") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        return (f"Original request saved as failed_batch_id={batch_id}. "
                f'Read it with read_failed_batches(batch_ids=["{batch_id}"]) before correcting the reported issue. '
                "This record is not an accepted decision; read_plan shows the current accepted revision.")

    @tool
    def read_failed_batches(batch_ids: list[str] | None = None, offset: int = 0, limit: int = 20) -> dict:
        """Recover failed submissions without rebuilding their contents from memory.

        With IDs, return original arguments and full errors unchanged, including
        any provider JSON-string envelope. Without IDs, list attempt-local
        handles with pagination. Recovered inputs remain unaccepted proposals,
        not evidence or frozen conclusions. Correct the reported issue and
        submit a new batch; use read_plan for accepted work/current revision.

        Args:
            batch_ids: Exact failed_batch_id values from error feedback, or omit to list saved failures.
            offset: Zero-based offset into the failure listing.
            limit: Number of failure handles per page, between 1 and 100.
        """
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("offset must be nonnegative and limit must be between 1 and 100")
        if batch_ids is not None:
            records = {}
            for batch_id in batch_ids:
                try:
                    valid = UUID(batch_id).hex == batch_id
                except ValueError:
                    valid = False
                path = directory / f"{batch_id}.json" if valid else None
                if path is None or not path.is_file():
                    raise ValueError(f"unknown failed_batch_id: {batch_id!r}; omit batch_ids to list this attempt's failures")
                records[batch_id] = json.loads(path.read_text(encoding="utf-8"))
            return {"records": records}
        paths = sorted(directory.glob("*.json"), key=lambda path: path.stat().st_mtime_ns)
        page = paths[offset:offset + limit]
        records = [json.loads(path.read_text(encoding="utf-8")) for path in page]
        return {"failures": [{key: value for key, value in record.items() if key not in {"arguments", "error"}}
                             for record in records],
                "showing": len(page), "total": len(paths), "offset": offset,
                "next_offset": offset + len(page) if offset + len(page) < len(paths) else None}

    return retain, read_failed_batches
