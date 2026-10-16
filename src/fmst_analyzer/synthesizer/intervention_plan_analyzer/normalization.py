"""Resolve one Unit's concrete anchors against the fixed source evidence."""
from __future__ import annotations

import json
import posixpath
from pathlib import PurePosixPath

from .schema import (
    CallsiteAnchorDraft, FunctionAnchorDraft, InterventionUnit, InterventionUnitDraft,
    LaunchChoice, ResolvedFunctionAnchor, ResourceAnchor,
)


def normalize_unit(unit_id: str, draft: InterventionUnitDraft, *, catalog, resolver,
                   view, launch_choice: LaunchChoice | None) -> InterventionUnit:
    """Validate source membership and anchor identity without judging semantics."""
    refs = set(draft.finding_refs)
    if unknown := refs - catalog.finding_index.keys():
        raise ValueError(f"units/{unit_id}: unknown finding references: {sorted(unknown)!r}")
    allowed = refs | resolver.evidence_identities(refs)
    if launch_choice and launch_choice.recipe_id is not None:
        allowed.add(launch_choice.recipe_id)
    anchors = {}
    for index, anchor in enumerate(draft.anchors):
        location = f"units/{unit_id}/anchors/{index}"
        if isinstance(anchor, FunctionAnchorDraft):
            binary = PurePosixPath(anchor.binary_name.strip()).name
            if not binary:
                raise ValueError(f"{location}: binary_name must not be blank")
            try:
                name = view.get_decompiled_name(binary, anchor.function_ea)
            except (RuntimeError, ValueError) as error:
                raise ValueError(f"{location}: use the exact function entry EA in {binary}, not an instruction or callsite: 0x{anchor.function_ea:x}") from error
            if not name:
                raise ValueError(f"{location}: cannot resolve function {binary}:0x{anchor.function_ea:x}")
            resolved = ResolvedFunctionAnchor(binary_name=binary, function_name=name, function_ea=anchor.function_ea)
        elif isinstance(anchor, CallsiteAnchorDraft):
            resolved = resolver.resolve_callsite(anchor.callsite_id, refs)
        else:
            source_ref = anchor.source_ref.strip()
            if source_ref not in allowed:
                raise ValueError(f"{location}/source_ref: {source_ref!r} is outside this Unit's source evidence; use an exact allowed ID: {sorted(allowed)!r}")
            value = anchor.value.strip()
            if not value:
                raise ValueError(f"{location}/value: resource value must not be blank")
            if anchor.resource_kind in {"path", "path_pattern"}:
                if not value.startswith("/"):
                    raise ValueError(f"{location}/value: requires an absolute guest path")
                value = posixpath.normpath(value)
            resolved = ResourceAnchor(resource_kind=anchor.resource_kind, value=value, source_ref=source_ref)
        payload = json.dumps(resolved.model_dump(mode="json"), ensure_ascii=False, sort_keys=True)
        anchors[payload] = resolved
    return InterventionUnit(unit_id=unit_id, behavior_scopes=draft.behavior_scopes,
        strategy=draft.strategy, anchors=[anchors[key] for key in sorted(anchors)],
        summary=draft.summary.strip(), contract=draft.contract)
