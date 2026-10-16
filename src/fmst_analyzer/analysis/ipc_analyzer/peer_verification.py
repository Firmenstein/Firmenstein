"""Source-backed direct-peer verification for one logical IPC channel."""

from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError

import hashlib
import json
from pathlib import Path
from typing import Callable

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import CodeAnalyzerAgent
from fmst_basic.agent.tool import AgentTool, tool
from fmst_analyzer.global_config import GlobalConfig
from fmst_analyzer.nodes.function import _bounded_artifact_stem
from fmst_analyzer.nodes.function import FunctionNode

from .agent_cache import agent_cache_key, load_agent_cache, store_agent_cache
from .agent_schema import PeerVerificationOutput
from .peer.firmware_import_index import FirmwareImportIndex
from .peer_verification_prompt import (
    PEER_VERIFICATION_TASK_PROMPT,
    PEER_VERIFICATION_USER_PROMPT,
)
from .rootfs_tools import resolve_guest_file, make_rootfs_tools
from .schema import AnalysisPhase, IPCChannel, PeerCandidateEvidence, TargetProcess


PEER_VERIFICATION_TOOL_VERSION = 4


def _make_assembly_reader(
    assembly_root: Path,
    allowed_files: set[str],
    *, allow_published_sources: bool = False,
) -> AgentTool:
    """Read supplied or published assembly without leaving this run's source root."""
    root = assembly_root.resolve()
    allowed = frozenset(allowed_files)

    @tool
    def read_file(path: str, offset: int = 1, limit: int = 2000) -> str:
        """Read one controller-supplied IDA assembly listing.

        Read a supplied assembly_files path or another published .s file within
        this run's assembly root. Its metadata identifies the source ELF and function.
        This reader does not generate missing assembly or interpret its contents.

        Args:
            path: Exact assembly_files path supplied for this Channel.
            offset: First one-based line to return.
            limit: Maximum lines to return, capped at 2000.
        """
        requested = Path(path)
        target = (requested if requested.is_absolute() else root / requested).resolve()
        try:
            normalized = target.relative_to(root).as_posix()
        except ValueError:
            return f"Assembly path escapes the listing root: {path}"
        if normalized not in allowed and not allow_published_sources:
            return f"Assembly path is outside this Channel evidence set: {path}"
        if target.suffix != ".s":
            return "Expected a published .s assembly source"
        if not target.is_file():
            return f"Assembly file not found: {path}"
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(offset - 1, 0)
        bounded_limit = min(max(limit, 0), 2000)
        shown = lines[start:start + bounded_limit]
        rendered = "\n".join(shown)
        if start > 0 or start + len(shown) < len(lines):
            rendered += (
                f"\n(showing lines {start + 1}-{start + len(shown)} "
                f"of {len(lines)})"
            )
        return rendered

    return read_file


def _candidate_assembly_files(
    candidate: PeerCandidateEvidence,
    view: AnalysisView,
    assembly_root: Path,
    rootfs: Path,
) -> list[str]:
    """Resolve controller structural locations to workdir-relative listings."""
    locations: set[tuple[str, int]] = set()
    function_names: dict[tuple[str, int], str] = {}
    for evidence in candidate.call_paths:
        for hop in evidence.call_path:
            location = (hop.binary_path, hop.function_ea)
            locations.add(location)
            function_names[location] = hop.function_name

    files: set[str] = set()
    for binary_path, function_ea in locations:
        resolved = resolve_guest_file(rootfs, binary_path)
        if resolved is None:
            raise FileNotFoundError(f"Candidate assembly source is missing: {binary_path}")
        source = resolved[1]
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        binary = view.lib_dep_graph.get_node_by_name(Path(binary_path).name)
        binary_name = Path(binary_path).name
        paths: list[Path] = []
        if binary is not None and binary.binary_path.resolve() == source.resolve():
            try:
                function = binary.get_function_by_ea(function_ea)
            except (AttributeError, RuntimeError):
                function = None
            if function is not None:
                paths.append(
                    assembly_root
                    / binary.name
                    / f"{function.structural_artifact_stem}.s"
                )
                if binary.semantic_ready:
                    paths.insert(
                        0,
                        assembly_root
                        / binary.name
                        / f"{function.artifact_stem}.s",
                    )

        # IPC candidate inspection deliberately uses ephemeral BinaryNodes.
        # Such candidates are not registered in the target LibDepGraph, so
        # resolving the listing through ``view`` alone loses the evidence.
        # StructuralFunctionRef is already the controller-owned identity;
        # derive the same deterministic listing stems directly from it.
        function_name = function_names[(binary_path, function_ea)]
        structural_stem = _bounded_artifact_stem(
            f"{function_name}@{function_ea:x}"
        )
        semantic_stem = _bounded_artifact_stem(function_name)
        paths.insert(
            0,
            assembly_root / "ipc" / source_hash / binary_name / f"{structural_stem}.s",
        )
        paths.extend([
            assembly_root / binary_name / f"{structural_stem}.s",
            assembly_root / binary_name / f"{semantic_stem}.s",
        ])
        for path in paths:
            if path.is_file() and (
                f"; source_sha256: {source_hash}"
                in path.read_text(encoding="utf-8").splitlines()
            ):
                files.add(path.relative_to(assembly_root).as_posix())
                break
    return sorted(files)


class PeerVerificationAgent:
    """Verify assigned peers from published assembly and rootfs text evidence."""

    def __init__(self, global_config: GlobalConfig) -> None:
        self.global_config = global_config

    async def verify_channel(
        self,
        *,
        phase: AnalysisPhase,
        view: AnalysisView,
        firmware_index: FirmwareImportIndex,
        firmware_sha256: str,
        rootfs: Path,
        target_process: TargetProcess,
        channel: IPCChannel,
        candidates: list[PeerCandidateEvidence],
        trace_dir: Path | None,
        source_function_lookup: Callable[[Path, str], FunctionNode | None] | None = None,
    ) -> PeerVerificationOutput | None:
        """Run no Agent unless full phase has at least one prepared candidate."""
        if phase is not AnalysisPhase.FULL or not candidates:
            return None

        resolved_rootfs = Path(rootfs).absolute().resolve()
        assembly_root = self.global_config.disassembled_code_dir.resolve()
        candidate_summaries = []
        allowed_assembly_files: set[str] = set()
        for candidate in candidates:
            summary = candidate.model_dump(mode="json")
            assembly_files = _candidate_assembly_files(
                candidate, view, assembly_root, resolved_rootfs,
            )
            if not assembly_files:
                raise RuntimeError(
                    "No assembly artifacts for IPC candidate "
                    f"{candidate.executable_path}"
                )
            allowed_assembly_files.update(assembly_files)
            summary["assembly_files"] = assembly_files
            summary["assembly_sha256"] = {
                path: hashlib.sha256(
                    (assembly_root / path).read_bytes(),
                ).hexdigest()
                for path in assembly_files
            }
            candidate_summaries.append(summary)

        agent = CodeAnalyzerAgent(
            agent_name="IPCPeerVerificationAgent",
            task_prompt=PEER_VERIFICATION_TASK_PROMPT,
            output_format=PeerVerificationOutput,
            model=self.global_config.diagnosis_model,
            provider=self.global_config.agent_provider,
            extra_tools=[_make_assembly_reader(
                assembly_root, allowed_assembly_files, allow_published_sources=True,
            ), *make_rootfs_tools(resolved_rootfs)],
            workdir=assembly_root,
            include_analyzer_tools=False,
        )
        channel_payload = channel.model_dump(
            mode="json", exclude={"retrieval_candidates"},
        )
        prompt = PEER_VERIFICATION_USER_PROMPT.format(
            channel_json=json.dumps(
                channel_payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            candidate_evidence_json=json.dumps(
                candidate_summaries,
                ensure_ascii=False,
                indent=2,
            ),
        )
        cache_key = agent_cache_key(
            stage="peer_verification",
            model=self.global_config.diagnosis_model,
            task_prompt=PEER_VERIFICATION_TASK_PROMPT,
            output_type=PeerVerificationOutput,
            payload={
                "tool_version": PEER_VERIFICATION_TOOL_VERSION,
                "firmware_sha256": firmware_sha256,
                "channel": channel_payload,
                "candidate_evidence": candidate_summaries,
            },
            semantic_identity={},
        )
        validation = {
            "assembly_root": assembly_root,
            "source_function_lookup": source_function_lookup,
            "channel": channel,
            "firmware_index": firmware_index,
            "rootfs": resolved_rootfs,
            "candidate_paths": {
                item.executable_path for item in candidates
            },
        }
        cached = load_agent_cache(
            self.global_config,
            "peer_verification",
            cache_key,
            PeerVerificationOutput,
        )
        if cached is not None:
            try:
                self._validate_output(cached, **validation)
            except ValueError:
                pass
            else:
                return cached

        result = await agent.analyze(
            user_message=prompt,
            view=view,
            trace_dir=trace_dir,
            trace_name=(
                f"{channel.channel_id.replace(':', '_')}__peer_verification"
            ),
            output_validator=lambda output: self._validate_output(
                PeerVerificationOutput.model_validate(output), **validation,
            ),
        )
        if not isinstance(result, PeerVerificationOutput):
            result = PeerVerificationOutput.model_validate(result)
        self._validate_output(result, **validation)
        store_agent_cache(
            self.global_config, "peer_verification", cache_key, result,
        )
        return result

    @staticmethod
    def _validate_output(
        result: PeerVerificationOutput,
        *,
        channel: IPCChannel,
        firmware_index: FirmwareImportIndex,
        rootfs: Path,
        candidate_paths: set[str],
        assembly_root: Path | None = None,
        source_function_lookup: Callable[[Path, str], FunctionNode | None] | None = None,
    ) -> None:
        indexed_exec_targets = {
            path.absolute()
            for path, kind in firmware_index.elf_kind.items()
            if kind == "exec"
        }
        unknown = {
            raw for raw in (finding.executable_path for finding in result.peer_findings)
            if (resolved := resolve_guest_file(rootfs, raw)) is None
            or resolved[1].absolute() not in indexed_exec_targets
        }
        if unknown:
            raise OutputValidationError(
                f"Peer Verification returned non-indexed executables: {sorted(unknown)}"
            )

        actual_paths = {
            finding.executable_path.lstrip("/")
            for finding in result.peer_findings
        }
        if actual_paths != candidate_paths:
            raise OutputValidationError(
                "Peer Verification must return exactly the controller candidate set: "
                f"missing={sorted(candidate_paths - actual_paths)}, "
                f"unexpected={sorted(actual_paths - candidate_paths)}"
            )

        callsite_ids = {endpoint.callsite_id for endpoint in channel.endpoints}
        invalid_citation_paths = sorted({
            citation.binary_path
            for finding in result.peer_findings
            for citation in finding.evidence
            if resolve_guest_file(rootfs, citation.binary_path) is None
        })
        if invalid_citation_paths:
            raise OutputValidationError(
                "Peer Verification cited paths absent from the frozen rootfs: "
                f"{invalid_citation_paths}"
            )
        unexpected_callsite_ids = sorted({
            citation.callsite_id
            for finding in result.peer_findings
            for citation in finding.evidence
            if citation.callsite_id is not None
            and citation.callsite_id not in callsite_ids
        })
        if unexpected_callsite_ids:
            raise OutputValidationError(
                "Peer Verification cited controller-unknown callsite IDs: "
                f"{unexpected_callsite_ids}"
            )
        invalid_endpoint_paths = sorted({
            location.binary_path
            for finding in result.peer_findings
            for location in finding.endpoint_locations
            if resolve_guest_file(rootfs, location.binary_path) is None
        })
        if invalid_endpoint_paths:
            raise OutputValidationError(
                "Peer Verification endpoint locations are absent from rootfs: "
                f"{invalid_endpoint_paths}"
            )


        if assembly_root is not None:
            # Actual artifact metadata, independent of candidate.call_paths.
            errors = []
            for fi, finding in enumerate(result.peer_findings):
                for field in ("endpoint_locations", "evidence"):
                    for index, position in enumerate(getattr(finding, field)):
                        label = f"/peer_findings/{fi}/{field}/{index}"
                        try:
                            _validate_published_source(
                                rootfs, assembly_root, position, label,
                                source_function_lookup=source_function_lookup,
                            )
                        except OutputValidationError as error:
                            errors.append(str(error))
            if errors:
                raise OutputValidationError("IPC peer source validation failed:\n" + "\n".join(errors))


def _validate_published_source(rootfs, assembly_root, position, label, *, source_function_lookup=None):
    resolved = resolve_guest_file(rootfs, position.binary_path)
    if resolved is None:
        raise OutputValidationError(f"{label}: source path {position.binary_path!r} is absent from the frozen rootfs")
    source = resolved[1]
    data = source.read_bytes()
    if not data.startswith(b"\x7fELF"):
        try:
            text = data.decode("utf-8")
        except UnicodeError as error:
            raise OutputValidationError(f"{label}: {position.binary_path} is not a UTF-8 text source") from error
        line = getattr(position, "line_number", None)
        if line is not None and not 1 <= line <= len(text.splitlines()):
            raise OutputValidationError(f"{label}: line_number={line} is outside 1..{len(text.splitlines())}")
        return
    if position.function_name in {"<config>", "<script>"}:
        raise OutputValidationError(f"{label}: {position.binary_path} is ELF, not text; cite an actual inspected function")
    digest = hashlib.sha256(data).hexdigest()
    directories = [assembly_root / "ipc" / digest / source.name, assembly_root / source.name]
    matching_functions = []
    for directory in directories:
        for path in directory.glob("*.s"):
            metadata = {}
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.startswith(";"):
                    break
                key, separator, value = line[1:].partition(":")
                if separator:
                    metadata[key.strip()] = value.strip()
            if metadata.get("source_sha256") != digest:
                continue
            if position.function_name not in {metadata.get("function"), metadata.get("symbol"), path.stem}:
                continue
            matching_functions.append(int(metadata["entry_ea"], 0))
    if not matching_functions:
        function = None
        if source_function_lookup is not None:
            function = source_function_lookup(source, position.function_name)
            if function is None:
                raise OutputValidationError(
                    f"{label}: {position.binary_path}::{position.function_name} does not identify "
                    "a function in this binary's source index. Cite the exact function name and entry EA "
                    "from the inspected assembly header; preserve the supporting evidence and judgment. "
                    "If no endpoint location is known, leave endpoint_locations empty instead of "
                    "inventing a function identity."
                )
            # A whole-function reference needs a real source identity, not a
            # separate generated listing. Native indexes also establish import
            # entries and aliases whose body may live in another module.
            matching_functions.append(function.ea)
        if not matching_functions:
            # Without a source index, a missing artifact proves no output error.
            raise FileNotFoundError(f"{label}: no published assembly for {position.binary_path}::{position.function_name}; source access is unavailable")
    ea = getattr(position, "function_ea", None)
    if ea is not None and ea not in matching_functions:
        raise OutputValidationError(f"{label}: function_ea={ea:#x} is not the cited function entry; expected {sorted(set(matching_functions))}")


__all__ = ["PeerVerificationAgent"]
