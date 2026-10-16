"""Deterministic finding index over exact, persisted Analyzer JSON bytes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

from fmst_analyzer.analysis.base.analysis_finding import AnalysisFinding, resolve_evidence_ref
from fmst_analyzer.analysis.base.finding_binding import pointer
from fmst_analyzer.analysis.base.report_io import load_model_json, write_model_json, write_text
from fmst_analyzer.analysis.base.artifact_lifecycle import stage_attempt
from fmst_analyzer.analysis.base.input_provenance import file_digest, require_receipt, rootfs_digest
from fmst_analyzer.analysis.file_resolver import FileResolverResult
from fmst_analyzer.analysis.init_launch import InitLaunchAnalysisResult
from fmst_analyzer.analysis.ipc_analyzer import IPCAnalysisResult
from fmst_analyzer.analysis.ipc_analyzer.identity import canonical_sysv_key
from fmst_analyzer.analysis.network_analyzer import NetworkAnalysisResult
from fmst_analyzer.analysis.process_lifecycle import ProcessLifecycleAnalysisResult

from .schema import (
    FindingIndexEntry, PlanningEvidenceCatalog, PlanningEvidenceGap,
    PlanningTargetIdentity, SourceArtifact, SourceKind,
)


SOURCE_MODELS = {
    SourceKind.IPC: ("ipc_reports/ipc_analysis_result.json", IPCAnalysisResult),
    SourceKind.FILE: ("file_reports/file_resolver_result.json", FileResolverResult),
    SourceKind.NETWORK: ("network_reports/network_analysis_result.json", NetworkAnalysisResult),
    SourceKind.PROCESS: ("process_lifecycle_reports/process_lifecycle_analysis_result.json", ProcessLifecycleAnalysisResult),
    SourceKind.INIT_LAUNCH: ("init_launch_reports/init_launch_analysis_result.json", InitLaunchAnalysisResult),
}


def _normalize_guest_path(value: str) -> str:
    path = PurePosixPath(value.lstrip("/"))
    if not path.parts or ".." in path.parts:
        raise ValueError(f"invalid rootfs-relative target path: {value!r}")
    return path.as_posix()


def source_binary_paths(documents) -> dict[str, str]:
    """Resolve module names only from unambiguous persisted source identities."""
    candidates: dict[str, set[str]] = {}

    def add(name, path):
        path = _normalize_guest_path(path)
        for alias in (name, PurePosixPath(path).name):
            if alias:
                candidates.setdefault(alias, set()).add(path)

    for document in documents:
        target = document.get("finding_target") or document.get("target_process", {})
        path = target.get("path") or target.get("executable_path")
        if path:
            add(document.get("root_binary") or target.get("argv0"), path)
        callsites = document.get("callsites", {})
        for site in callsites.values() if isinstance(callsites, dict) else callsites:
            location = site.get("location", site)
            if location.get("binary_path") and location.get("binary_sha256"):
                add(location.get("binary_name"), location["binary_path"])
    return {name: next(iter(paths)) for name, paths in candidates.items() if len(paths) == 1}


def _anchor_keys(value, *, binary_paths=None, callsites=None) -> set[str]:
    """Mechanical overlap hints only; equal keys prove no semantic equivalence."""
    if isinstance(value, str):
        return {"path:" + value} if value.startswith("/") else set()
    if isinstance(value, list):
        return set().union(*(_anchor_keys(item, binary_paths=binary_paths, callsites=callsites) for item in value))
    if not isinstance(value, dict):
        return set()
    identity = {**value, **value.get("location", {})} if isinstance(value.get("location"), dict) else value
    binary = identity.get("binary_path")
    if binary:
        binary = _normalize_guest_path(binary)
    else:
        binary = (binary_paths or {}).get(identity.get("binary_name") or identity.get("binary"))
    keys = set()
    source = (callsites or {}).get(value.get("callsite_id"))
    if source is not None:
        keys.update(_anchor_keys(source, binary_paths=binary_paths))
    mechanism = value.get("mechanism", "")
    if isinstance(mechanism, str) and mechanism.startswith("sysv_"):
        for resource in value.get("resources", []):
            kind = resource.get("kind")
            kind = mechanism + "_key" if kind == "sysv_key" else kind
            if kind in {"sysv_shm_key", "sysv_sem_key", "sysv_msg_key"}:
                number = canonical_sysv_key(resource.get("canonical_value"))
                if number is not None and number != "0":
                    keys.add("ipc:" + kind + ":" + number)
    if binary and all(identity.get(key) is not None for key in ("function_ea", "snapshot_hash", "ctree_index")):
        keys.add("ctree:" + json.dumps([binary, identity["function_ea"], identity["snapshot_hash"], identity["ctree_index"]], separators=(",", ":")))
    for key in ("path_value", "canonical_value", "primary_path"):
        if isinstance(value.get(key), str) and value[key].startswith("/"):
            keys.add("path:" + value[key])
    for child in value.values():
        if isinstance(child, (dict, list)):
            keys.update(_anchor_keys(child, binary_paths=binary_paths, callsites=callsites))
    return keys


def index_finding(kind: SourceKind, finding: AnalysisFinding, document: dict, *, binary_paths=None) -> FindingIndexEntry:
    refs = {anchor.ref for anchor in finding.boundary.anchors}
    refs.update(finding.boundary.reachability_refs)
    refs.update(finding.boundary.coverage_refs)
    for claim in finding.claims:
        refs.update(claim.evidence_refs)
    domain = finding.domain
    id_field = {SourceKind.FILE: "resource_id", SourceKind.NETWORK: "interaction_id",
                SourceKind.IPC: "channel_id", SourceKind.PROCESS: "callsite_id",
                SourceKind.INIT_LAUNCH: "recipe_id"}[kind]
    source_id = getattr(domain, id_field) if domain is not None else finding.finding_ref
    if binary_paths is None:
        binary_paths = source_binary_paths([document])
    source_callsites = document.get("callsites", {})
    callsites = {site["callsite_id"]: site for site in
                (source_callsites.values() if isinstance(source_callsites, dict) else source_callsites)}
    keys = set()
    for ref in refs:
        keys.update(_anchor_keys(resolve_evidence_ref(document, ref), binary_paths=binary_paths, callsites=callsites))
    return FindingIndexEntry(
        finding_ref=finding.finding_ref, source_kind=kind, source_id=source_id,
        summary=finding.summary, boundary_kind=finding.boundary.kind,
        anchor_keys=sorted(keys), evidence_refs=sorted(refs),
        source_locator=pointer("planning_findings", finding.finding_ref),
    )


class PlanningEvidenceAssembler:
    """Read only source JSON; never invoke or silently repair an Analyzer."""

    def __init__(self, diagnostic_reports_root: Path, *, global_config=None):
        self.reports_root = Path(diagnostic_reports_root)
        self.global_config = global_config

    def run(self) -> PlanningEvidenceCatalog:
        config = SimpleNamespace(target_diagnostic_reports_dir=lambda: self.reports_root)
        with stage_attempt(config, "catalog") as attempt:
            catalog = self.assemble()
            attempt["consumed_artifacts"] = {
                key.value: artifact.model_dump(mode="json") for key, artifact in catalog.source_artifacts.items()
            }
            return self.persist(catalog)

    def assemble(self) -> PlanningEvidenceCatalog:
        results, documents, artifacts, receipts = {}, {}, {}, {}
        rootfs = Path(self.global_config.fw_rootfs_path).resolve() if self.global_config is not None else None
        current_rootfs_digest = rootfs_digest(rootfs) if rootfs is not None else None
        for kind, (relative, model) in SOURCE_MODELS.items():
            path = self.reports_root / relative
            if not path.is_file():
                raise FileNotFoundError(f"required JSON artifact is missing: {path}")
            raw = path.read_bytes()
            result = model.model_validate_json(raw)
            phase = result.phase.value if hasattr(result.phase, "value") else result.phase
            if phase != "full":
                raise ValueError(f"PlanningEvidenceAssembler requires full analyzer results: {kind.value}={phase}")
            receipt = require_receipt(path, result=result)
            target_sha = result.target_process.executable_sha256 if kind is SourceKind.IPC else result.finding_target.sha256
            target_path = result.target_process.executable_path if kind is SourceKind.IPC else result.finding_target.path
            if (receipt.inputs.stage, receipt.inputs.phase, receipt.inputs.target_sha256,
                    _normalize_guest_path(receipt.inputs.target_path)) != (
                    kind.value, phase, target_sha, _normalize_guest_path(target_path)):
                raise ValueError(f"Analyzer input receipt identity disagrees with Result: {path}")
            # Consumer admission pins the original producing receipt. A new
            # Planner/model does not invalidate a complete historical analysis;
            # Analyzer cache reuse separately requires current implementation
            # and settings. The actual firmware input must still be identical.
            if rootfs is not None:
                target_file = rootfs / _normalize_guest_path(receipt.inputs.target_path)
                if (receipt.inputs.rootfs_sha256 != current_rootfs_digest
                        or file_digest(target_file) != receipt.inputs.target_sha256):
                    raise ValueError(f"Analyzer source firmware differs from current target/rootfs: {path}")
            receipts[kind] = receipt
            results[kind], documents[kind] = result, json.loads(raw)
            artifacts[kind] = SourceArtifact(source_kind=kind, relative_path=relative,
                schema_version=result.schema_version, phase=phase,
                content_sha256=hashlib.sha256(raw).hexdigest(),
                provenance_sha256=file_digest(path.parent / "input_provenance.json"))

        target = self._validate_target_identity(results)
        if len({receipt.inputs.rootfs_sha256 for receipt in receipts.values()}) != 1:
            raise ValueError("Analyzer inputs came from different rootfs contents")
        findings = {}
        binary_paths = source_binary_paths(documents.values())
        for kind, result in results.items():
            for ref, finding in result.planning_findings.items():
                if ref in findings:
                    raise ValueError(f"duplicate source finding_ref: {ref}")
                findings[ref] = index_finding(kind, finding, documents[kind], binary_paths=binary_paths)
        init = results[SourceKind.INIT_LAUNCH]
        return PlanningEvidenceCatalog(target_identity=target, source_artifacts=artifacts,
            finding_index=dict(sorted(findings.items())),
            launch_candidates=dict(sorted(init.launch_recipes.items())),
            gaps=self._source_gaps(documents))

    @staticmethod
    def _validate_target_identity(results) -> PlanningTargetIdentity:
        ipc, init = results[SourceKind.IPC], results[SourceKind.INIT_LAUNCH]
        selected = _normalize_guest_path(init.target_identity.selected_rootfs_path)
        if selected != _normalize_guest_path(ipc.target_process.executable_path):
            raise ValueError("InitLaunch and IPC target paths disagree")
        for kind, result in results.items():
            if kind is SourceKind.IPC:
                continue
            if (result.finding_target.path, result.finding_target.sha256) != (selected, ipc.target_process.executable_sha256):
                raise ValueError(f"{kind.value} target path or executable digest disagrees with IPC/InitLaunch")
        return PlanningTargetIdentity(target_basename=init.target_identity.target_basename,
            selected_rootfs_path=selected, executable_sha256=ipc.target_process.executable_sha256,
            argv0=ipc.target_process.argv0, firmware_sha256=ipc.firmware_sha256,
            target_aliases=sorted({_normalize_guest_path(path) for path in init.target_identity.target_aliases}))

    @staticmethod
    def _source_gaps(documents) -> dict[str, PlanningEvidenceGap]:
        """Index explicit source gaps; classifications never turn into handoffs."""
        gaps = {}

        def add(kind, locator, reasons, source_id=None):
            if not reasons:
                return
            ref = f"gap:{kind.value}:" + hashlib.sha256(locator.encode()).hexdigest()
            gaps[ref] = PlanningEvidenceGap(gap_ref=ref, source_kind=kind,
                source_id=source_id, subject=locator, reasons=list(reasons))

        for kind, doc in documents.items():
            if kind is SourceKind.FILE:
                for field in ("path_resolution_gaps",):
                    for key, reasons in doc[field].items():
                        add(kind, pointer(field, key), reasons, key)
                for key in doc["queued_for_path_agent"]:
                    add(kind, pointer("queued_for_path_agent"), ["Full result still queues path analysis: " + key], key)
            elif kind is SourceKind.NETWORK:
                for i, item in enumerate(doc["analyses"]):
                    add(kind, pointer("analyses", i, "missing_evidence"), item["missing_evidence"], item["interaction_id"])
            elif kind is SourceKind.PROCESS:
                for key, item in doc["assessments"].items():
                    add(kind, pointer("assessments", key, "missing_evidence"), item["missing_evidence"], key)
            elif kind is SourceKind.IPC:
                for field in ("channels", "dependency_assessments"):
                    for i, item in enumerate(doc[field]):
                        add(kind, pointer(field, i, "missing_evidence"), item["missing_evidence"], item.get("channel_id"))
                for i, item in enumerate(doc["unresolved_items"]):
                    add(kind, pointer("unresolved_items", i), [item["reason"], *item["missing_evidence"]], item["subject_id"])
            else:
                for i, item in enumerate(doc["analysis_gaps"]):
                    add(kind, pointer("analysis_gaps", i), [item["reason"]])
        return dict(sorted(gaps.items()))

    def persist(self, catalog: PlanningEvidenceCatalog) -> PlanningEvidenceCatalog:
        from .reports import render_index
        out = self.reports_root / "intervention_planner_inputs"
        out.mkdir(parents=True, exist_ok=True)
        path = out / "planner_input_catalog.json"
        write_model_json(path, catalog)
        catalog = load_model_json(path, PlanningEvidenceCatalog)
        write_text(out / "index.md", render_index(catalog))
        return catalog


__all__ = ["PlanningEvidenceAssembler"]
