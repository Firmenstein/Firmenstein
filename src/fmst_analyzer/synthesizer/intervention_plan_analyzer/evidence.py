"""Task-scoped evidence access over persisted analyzer JSON sources."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from fmst_basic.agent.tool import AgentTool, tool
from fmst_analyzer.analysis.base.analysis_finding import AnalysisFinding, resolve_evidence_ref
from fmst_analyzer.analysis.base.finding_binding import pointer
from fmst_analyzer.analysis.base.input_provenance import file_digest, require_receipt
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    PlanningEvidenceCatalog,
    SourceKind,
)

from .schema import ResolvedCallsiteAnchor
from .catalog.assembler import PlanningEvidenceAssembler, SOURCE_MODELS, index_finding, source_binary_paths


_IDENTITY_KEYS = {
    "resource_id",
    "interaction_id",
    "dependency_id",
    "channel_id",
    "endpoint_id",
    "callsite_id",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _parse_int(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"invalid {field}: {value!r}") from error
    raise ValueError(f"missing or invalid {field}: {value!r}")


def _walk_objects(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_objects(child)


def _first(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in record and record[name] is not None:
            return record[name]
    return None


def _callsite_candidate(
    record: dict[str, Any], callsite_id: str,
) -> ResolvedCallsiteAnchor | None:
    if record.get("callsite_id") != callsite_id:
        return None
    location = record.get("location")
    identity = {
        **(location if isinstance(location, dict) else {}),
        **record,
    }
    binary_name = _first(identity, "binary_name", "binary")
    function_name = _first(
        identity,
        "function_name",
        "function",
        "caller_name",
    )
    snapshot_hash = identity.get("snapshot_hash")
    api_name = _first(identity, "api_name", "callee_name")
    if not all(isinstance(item, str) and item for item in (
        binary_name,
        function_name,
        snapshot_hash,
        api_name,
    )):
        return None
    required = ("function_ea", "ctree_index")
    if any(identity.get(name) is None for name in required):
        return None
    line = _first(identity, "line_number", "line")
    column = _first(identity, "column_number", "column")
    if line is None or column is None:
        return None
    source_ea = _first(identity, "source_ea", "callsite_ea")
    return ResolvedCallsiteAnchor(
        callsite_id=callsite_id,
        binary_name=binary_name,
        function_name=function_name,
        function_ea=_parse_int(identity["function_ea"], field="function_ea"),
        snapshot_hash=snapshot_hash,
        ctree_index=_parse_int(identity["ctree_index"], field="ctree_index"),
        source_ea=(
            _parse_int(source_ea, field="source_ea")
            if source_ea is not None else None
        ),
        line_number=_parse_int(line, field="line_number"),
        column_number=_parse_int(column, field="column_number"),
        api_name=api_name,
    )


@dataclass(frozen=True)
class _EvidenceScope:
    identities: frozenset[str]
    callsites: dict[str, tuple[ResolvedCallsiteAnchor, ...]]


class FindingEvidenceResolver:
    """Load immutable analyzer sources and expose only selected findings."""

    def __init__(
        self,
        diagnostic_reports_root: Path,
        catalog: PlanningEvidenceCatalog,
    ) -> None:
        self.reports_root = Path(diagnostic_reports_root).resolve()
        self.catalog = catalog
        self._documents: dict[SourceKind, Any] = {}
        self._finding_evidence_cache: dict[str, dict[str, Any]] = {}
        self._scope_cache: dict[tuple[str, ...], _EvidenceScope] = {}
        results = {}
        for kind, artifact in catalog.source_artifacts.items():
            relative, model = SOURCE_MODELS[kind]
            if artifact.relative_path != relative:
                raise ValueError(f"unexpected {kind.value} source artifact path")
            path = (self.reports_root / artifact.relative_path).resolve()
            if not path.is_relative_to(self.reports_root):
                raise ValueError(
                    f"source artifact escapes diagnostic reports root: {path}"
                )
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != artifact.content_sha256:
                raise ValueError(f"source content digest changed: {artifact.relative_path}; rebuild Catalog/Plan")
            try:
                self._documents[kind] = json.loads(raw)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"invalid analyzer JSON: {artifact.relative_path}: {error}"
                ) from error
            result = model.model_validate_json(raw)
            phase = result.phase.value if hasattr(result.phase, "value") else result.phase
            result.execution.require_complete()
            require_receipt(path, result=result)
            if file_digest(path.parent / "input_provenance.json") != artifact.provenance_sha256:
                raise ValueError(f"source input provenance digest changed: {artifact.relative_path}; rebuild Catalog/Plan")
            if (result.schema_version, phase) != (artifact.schema_version, artifact.phase) or phase != "full":
                raise ValueError(f"source schema/phase changed: {artifact.relative_path}")
            results[kind] = result
        if PlanningEvidenceAssembler._validate_target_identity(results) != catalog.target_identity:
            raise ValueError("catalog target identity disagrees with source Results")
        binary_paths = source_binary_paths(self._documents.values())
        expected = {ref: index_finding(kind, finding, self._documents[kind], binary_paths=binary_paths)
                    for kind, result in results.items() for ref, finding in result.planning_findings.items()}
        if expected != catalog.finding_index:
            raise ValueError("catalog finding_index differs from the pinned source findings")
        if results[SourceKind.INIT_LAUNCH].launch_recipes != catalog.launch_candidates:
            raise ValueError("catalog launch_candidates differ from the pinned source recipes")

    def finding_evidence(self, finding_ref: str) -> dict[str, Any]:
        cached = self._finding_evidence_cache.get(finding_ref)
        if cached is not None:
            return deepcopy(cached)
        entry = self.catalog.finding_index.get(finding_ref)
        if entry is None:
            raise ValueError(f"unknown finding_ref: {finding_ref}")
        document = self._documents[entry.source_kind]
        finding = AnalysisFinding.model_validate(document["planning_findings"][finding_ref])
        records = {}
        record_roots = {"resources", "resource_reports", "analyses", "callsites", "channels",
                        "dependency_assessments", "assessments", "launch_recipes"}
        for ref in entry.evidence_refs:
            parts = ref.split("/")
            owner = "/".join(parts[:3]) if len(parts) >= 3 and parts[1] in record_roots else ref
            records[owner] = resolve_evidence_ref(document, owner)
        # IPC endpoint references link to a list of immutable callsite facts.
        # Follow only explicitly referenced endpoint callsites, never a global
        # recursive search for arbitrary matching identity strings.
        if entry.source_kind is SourceKind.IPC:
            ids = {child["callsite_id"] for value in records.values() for child in _walk_objects(value)
                   if isinstance(child.get("callsite_id"), str)}
            for index, fact in enumerate(document["callsites"]):
                if fact["callsite_id"] in ids:
                    records[pointer("callsites", index)] = fact
        evidence = {
            "finding": finding.model_dump(mode="json"),
            "source_artifact": self.catalog.source_artifacts[
                entry.source_kind
            ].model_dump(mode="json"),
            "records": records,
        }
        self._finding_evidence_cache[finding_ref] = evidence
        return deepcopy(evidence)

    def read_finding(self, finding_ref: str, record_refs: list[str] | None = None) -> dict[str, Any]:
        """Return all claims, with exact supporting records only when requested."""
        evidence = self.finding_evidence(finding_ref)
        entry = self.catalog.finding_index[finding_ref]
        available = set(entry.evidence_refs) | set(evidence["records"])
        requested = set(record_refs or [])
        if unknown := requested - available:
            raise ValueError(f"unknown evidence references for {finding_ref}: {sorted(unknown)!r}; available: {sorted(available)!r}")
        document = self._documents[entry.source_kind]
        return {"finding": evidence["finding"], "source_artifact": evidence["source_artifact"],
                "available_record_refs": sorted(available),
                "records": {ref: deepcopy(resolve_evidence_ref(document, ref)) for ref in sorted(requested)}}

    @staticmethod
    def _scope_key(allowed_finding_refs: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted(set(allowed_finding_refs)))

    def _scope_evidence(
        self, allowed_finding_refs: Iterable[str],
    ) -> _EvidenceScope:
        scope = self._scope_key(allowed_finding_refs)
        cached = self._scope_cache.get(scope)
        if cached is not None:
            return cached
        identities = set(scope)
        records: list[dict[str, Any]] = []
        seen_records: set[str] = set()
        for finding_ref in scope:
            evidence = self.finding_evidence(finding_ref)
            finding = self.catalog.finding_index[finding_ref]
            identities.add(finding.source_id)
            for record in evidence["records"].values():
                payload = _canonical_json(record)
                if payload not in seen_records:
                    seen_records.add(payload)
                    records.append(record)

        callsites: dict[str, dict[str, ResolvedCallsiteAnchor]] = {}
        for record in records:
            for child in _walk_objects(record):
                for key in _IDENTITY_KEYS:
                    value = child.get(key)
                    if isinstance(value, str) and value:
                        identities.add(value)
                callsite_id = child.get("callsite_id")
                if not isinstance(callsite_id, str) or not callsite_id:
                    continue
                candidate = _callsite_candidate(child, callsite_id)
                if candidate is None:
                    continue
                payload = _canonical_json(candidate.model_dump(mode="json"))
                callsites.setdefault(callsite_id, {})[payload] = candidate

        result = _EvidenceScope(
            identities=frozenset(identities),
            callsites={
                callsite_id: tuple(candidates.values())
                for callsite_id, candidates in callsites.items()
            },
        )
        self._scope_cache[scope] = result
        return result

    def evidence_identities(
        self,
        allowed_finding_refs: Iterable[str],
    ) -> set[str]:
        """Return identities present in the selected findings' evidence trees."""
        return set(self._scope_evidence(allowed_finding_refs).identities)

    def resolve_callsite(
        self,
        callsite_id: str,
        allowed_finding_refs: Iterable[str],
    ) -> ResolvedCallsiteAnchor:
        scope = self._scope_evidence(allowed_finding_refs)
        if callsite_id not in scope.identities:
            raise ValueError(
                f"callsite anchor {callsite_id!r} is outside the current "
                "allowed finding evidence"
            )
        candidates = scope.callsites.get(callsite_id, ())
        if not candidates:
            raise ValueError(
                f"callsite anchor {callsite_id!r} has no stable source identity"
            )
        if len(candidates) != 1:
            raise ValueError(
                f"callsite anchor {callsite_id!r} resolves ambiguously to "
                f"{len(candidates)} stable identities"
            )
        return candidates[0]


def make_finding_evidence_tool(
    resolver: FindingEvidenceResolver,
    allowed_finding_refs: set[str],
) -> AgentTool:
    """Create one tool that cannot inspect findings outside its allowed finding scope."""

    @tool
    def view_finding_evidence(finding_refs: list[str], record_refs: dict[str, list[str]] | None = None) -> str:
        """Read complete findings and optionally their exact supporting records.

        The default returns every claim and the available evidence references;
        it does not duplicate large parent reports. Request record_refs when a
        material premise needs its underlying callsite, caller, resource or peer
        facts. Source records are immutable and their conclusions may be wrong.

        Args:
            finding_refs: Exact references from the allowed finding scope; a one-element list reads one finding. Results are keyed by reference.
            record_refs: Optional mapping from a requested finding reference to its available_record_refs to retrieve in full; omitted entries return claims and references only.
        """
        requested = set(finding_refs)
        if unknown := requested - allowed_finding_refs:
            raise ValueError(
                f"finding_refs {sorted(unknown)!r} are outside the allowed finding scope; "
                "copy exact finding references from the allowed scope in the task input."
            )
        records = record_refs or {}
        if extra := records.keys() - requested:
            raise ValueError(f"record_refs name findings not requested: {sorted(extra)!r}")
        return json.dumps(
            {ref: resolver.read_finding(ref, records.get(ref)) for ref in dict.fromkeys(finding_refs)},
            ensure_ascii=False,
            indent=2,
        )

    return view_finding_evidence


__all__ = ["FindingEvidenceResolver", "make_finding_evidence_tool"]
