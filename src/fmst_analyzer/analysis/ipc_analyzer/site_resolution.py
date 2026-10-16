"""Function-batched semantic resolution for IPCAnalyzer."""

from __future__ import annotations

from fmst_analyzer.analysis.base.output_validation import OutputValidationError, validate_code_reference

import json
from pathlib import Path


from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.analysis.base.code_analyzer.code_analyzer_agent import CodeAnalyzerAgent
from fmst_analyzer.global_config import GlobalConfig

from .agent_cache import (
    agent_cache_key,
    load_agent_cache,
    store_agent_cache,
    view_semantic_identity,
)
from .agent_schema import SiteResolutionOutput
from .schema import (
    AnalysisPhase,
    CallsiteFact,
    EvidenceCitation,
    TargetProcess,
)
from .rootfs_tools import make_rootfs_tools, resolve_guest_file
from .site_resolution_prompt import SITE_RESOLUTION_TASK_PROMPT, SITE_RESOLUTION_USER_PROMPT














def _clear_auxiliary_citation_ids(
    output: SiteResolutionOutput,
    auxiliary_ids: set[str],
) -> SiteResolutionOutput:
    """Keep auxiliary code evidence without persisting a dangling fact ID."""
    def normalized(citation: EvidenceCitation) -> EvidenceCitation:
        if citation.callsite_id not in auxiliary_ids:
            return citation
        return citation.model_copy(update={"callsite_id": None})

    findings = []
    for finding in output.callsite_findings:
        resources = [
            resource.model_copy(update={
                "evidence": [normalized(item) for item in resource.evidence],
            })
            for resource in finding.resources
        ]
        dependency = finding.dependency
        if dependency is not None:
            dependency = dependency.model_copy(update={
                "evidence": [normalized(item) for item in dependency.evidence],
            })
        findings.append(finding.model_copy(update={
            "resources": resources,
            "evidence": [normalized(item) for item in finding.evidence],
            "dependency": dependency,
        }))
    return SiteResolutionOutput(callsite_findings=findings)




class SiteResolutionAgent:
    """Resolve every interaction candidate in one containing function."""

    def __init__(self, global_config: GlobalConfig) -> None:
        self.global_config = global_config
        self._agent = CodeAnalyzerAgent(
            agent_name="IPCSiteResolutionAgent",
            task_prompt=SITE_RESOLUTION_TASK_PROMPT,
            output_format=SiteResolutionOutput,
            model=global_config.diagnosis_model,
            provider=global_config.agent_provider,
            extra_tools=make_rootfs_tools(global_config.fw_rootfs_path),
            filesystem_access="read",
            workdir=Path(global_config.fw_rootfs_path),
        )

    async def resolve_function(
        self,
        *,
        phase: AnalysisPhase,
        view: AnalysisView,
        target_process: TargetProcess,
        callsites: list[CallsiteFact],
        auxiliary_callsites: list[CallsiteFact] | None = None,
        trace_dir: Path | None,
    ) -> SiteResolutionOutput | None:
        """Return no result in static phase without constructing an agent turn."""
        if phase is not AnalysisPhase.FULL:
            return None
        if not callsites:
            raise OutputValidationError("SiteResolutionAgent requires at least one callsite")
        auxiliary_callsites = auxiliary_callsites or []

        first = callsites[0]
        function_identity = (
            first.location.binary_path,
            first.location.function_ea,
            first.location.snapshot_hash,
        )
        if any(
            (
                fact.location.binary_path,
                fact.location.function_ea,
                fact.location.snapshot_hash,
            ) != function_identity
            for fact in callsites
        ):
            raise OutputValidationError("one Site Resolution task cannot span containing functions")
        if any(
            (
                fact.location.binary_path,
                fact.location.function_ea,
                fact.location.snapshot_hash,
            ) != function_identity
            for fact in auxiliary_callsites
        ):
            raise OutputValidationError("auxiliary context cannot span containing functions")

        prompt = SITE_RESOLUTION_USER_PROMPT.format(
            target_process_json=json.dumps(
                target_process.model_dump(mode="json"),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            callsites_json=json.dumps(
                [fact.model_dump(mode="json") for fact in callsites],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            auxiliary_callsites_json=json.dumps(
                [fact.model_dump(mode="json") for fact in auxiliary_callsites],
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
        )
        task_prompt = SITE_RESOLUTION_TASK_PROMPT
        agent = self._agent
        cache_key = agent_cache_key(
            stage="site_resolution",
            model=self.global_config.diagnosis_model,
            task_prompt=task_prompt,
            output_type=SiteResolutionOutput,
            payload={
                "target_process": target_process.model_dump(mode="json"),
                "callsites": [fact.model_dump(mode="json") for fact in callsites],
                "auxiliary_callsites": [
                    fact.model_dump(mode="json") for fact in auxiliary_callsites
                ],
                "agent_callsite_ids": [fact.callsite_id for fact in callsites],
            },
            semantic_identity=view_semantic_identity(view),
        )
        cached = load_agent_cache(
            self.global_config, "site_resolution", cache_key, SiteResolutionOutput,
        )
        if cached is not None:
            try:
                self._validate_echoed_identities(
                    callsites,
                    cached,
                    auxiliary_callsites=auxiliary_callsites,
                    view=view,
                )
            except ValueError:
                pass
            else:
                return cached

        result = await agent.analyze(
            user_message=prompt,
            view=view,
            binary_name=Path(first.location.binary_path).name,
            function_name=first.location.function_name,
            trace_dir=trace_dir,
            trace_name=(
                f"{Path(first.location.binary_path).name}__"
                f"{first.location.function_name}__site_resolution"
            ),
            output_validator=lambda output: self._validate_echoed_identities(
                callsites,
                SiteResolutionOutput.model_validate(output),
                auxiliary_callsites=auxiliary_callsites,
                view=view,
            ),
            initial_focus_lines=[
                fact.location.line_number
                for fact in [*callsites, *auxiliary_callsites]
            ],
        )
        if not isinstance(result, SiteResolutionOutput):
            result = SiteResolutionOutput.model_validate(result)
        result = _clear_auxiliary_citation_ids(
            result,
            {fact.callsite_id for fact in auxiliary_callsites},
        )
        self._validate_echoed_identities(
            callsites,
            result,
            auxiliary_callsites=auxiliary_callsites,
            view=view,
        )
        store_agent_cache(
            self.global_config, "site_resolution", cache_key, result,
        )
        return result

    def _validate_echoed_identities(
        self,
        callsites: list[CallsiteFact],
        result: SiteResolutionOutput,
        *,
        auxiliary_callsites: list[CallsiteFact] | None = None,
        view: AnalysisView | None = None,
    ) -> None:
        expected = {fact.callsite_id for fact in callsites}
        allowed_citations = {
            *expected,
            *(fact.callsite_id for fact in (auxiliary_callsites or [])),
        }
        actual = {finding.callsite_id for finding in result.callsite_findings}
        if actual != expected:
            raise OutputValidationError(
                "Site Resolution callsite accounting mismatch: "
                f"missing={sorted(expected - actual)}, "
                f"unexpected={sorted(actual - expected)}"
            )
        located = []
        for fi, finding in enumerate(result.callsite_findings):
            prefix = f"/callsite_findings/{fi}"
            located.extend((f"{prefix}/evidence/{i}", item) for i, item in enumerate(finding.evidence))
            for ri, resource in enumerate(finding.resources):
                located.extend((f"{prefix}/resources/{ri}/evidence/{i}", item)
                               for i, item in enumerate(resource.evidence))
            if finding.dependency is not None:
                located.extend((f"{prefix}/dependency/evidence/{i}", item)
                               for i, item in enumerate(finding.dependency.evidence))
        citations = [item for _, item in located]
        unexpected_citations = sorted({
            citation.callsite_id
            for citation in citations
            if citation.callsite_id is not None
            and citation.callsite_id not in allowed_citations
        })
        if unexpected_citations:
            raise OutputValidationError(
                "Site Resolution evidence references controller-unknown callsites: "
                f"{unexpected_citations}"
            )
        auxiliary_ids = {
            fact.callsite_id for fact in (auxiliary_callsites or [])
        }
        unexpected_coverage = sorted({
            identity
            for finding in result.callsite_findings
            for identity in finding.covered_callsite_ids
            if identity not in auxiliary_ids
        })
        if unexpected_coverage:
            raise OutputValidationError(
                "Site Resolution coverage references controller-unknown auxiliary "
                f"callsites: {unexpected_coverage}"
            )
        rootfs = Path(self.global_config.fw_rootfs_path).absolute().resolve()
        referenced_paths = [
            hop.binary_path
            for finding in result.callsite_findings
            for hop in finding.wrapper_path
        ] + [citation.binary_path for citation in citations]
        invalid_paths = sorted({
            raw for raw in referenced_paths
            if not self._is_rootfs_file(rootfs, raw)
        })
        if invalid_paths:
            raise OutputValidationError(
                "Site Resolution references paths absent from the frozen rootfs: "
                f"{invalid_paths}"
            )
        by_id = {fact.callsite_id: fact for fact in [*callsites, *(auxiliary_callsites or [])]}
        errors = []
        for field, citation in located:
            if citation.callsite_id is not None:
                source = by_id[citation.callsite_id].location
                same_function = citation.function_name == source.function_name
                if not same_function and view is not None:
                    binary_name = Path(source.binary_path).name
                    expected_ea = view.get_function_ea(binary_name, source.function_name)
                    actual_ea = view.get_function_ea(binary_name, citation.function_name)
                    same_function = expected_ea is not None and expected_ea == actual_ea
                expected_source = resolve_guest_file(rootfs, source.binary_path)
                if expected_source is None:
                    raise FileNotFoundError(f"Assigned IPC source is unavailable: {source.binary_path}")
                cited_source = resolve_guest_file(rootfs, citation.binary_path)
                if cited_source is None or cited_source[1] != expected_source[1] or not same_function:
                    errors.append(
                        f"{field}: IPC citation {citation.callsite_id} points to another callsite's source object: "
                        f"expected {source.binary_path}::{source.function_name}, "
                        f"got {citation.binary_path}::{citation.function_name}"
                    )
                if citation.line_number is not None and citation.line_number != source.line_number:
                    errors.append(
                        f"{field}: IPC citation {citation.callsite_id} line disagrees with its callsite identity: "
                        f"expected line {source.line_number}, got {citation.line_number}"
                    )
        if view is not None:
            positions = [*located, *((f"/callsite_findings/{fi}/wrapper_path/{hi}", hop)
                for fi, finding in enumerate(result.callsite_findings)
                for hi, hop in enumerate(finding.wrapper_path))]
            for field, position in positions:
                line = position.line_number
                label = f"{field}: {position.binary_path}::{position.function_name}"
                resolved = resolve_guest_file(rootfs, position.binary_path)
                if resolved is None:
                    errors.append(f"{label}: source path is absent from the frozen rootfs")
                    continue
                if position.function_name in {"<config>", "<script>"}:
                    data = resolved[1].read_bytes()
                    if data.startswith(b"\x7fELF"):
                        errors.append(f"{label}: source is ELF, not text. Use view_function/view_disassembly "
                            "with an actual function identity, or cite the script/config that contains the observation. "
                            "Do not invent a function to satisfy this reference.")
                        continue
                    try:
                        code = data.decode("utf-8")
                    except UnicodeError:
                        errors.append(f"{label}: source is not UTF-8 text; use the appropriate binary/source tool")
                        continue
                else:
                    binary = Path(position.binary_path).name
                    ea = view.get_function_ea(binary, position.function_name)
                    if ea is None:
                        errors.append(f"{label}: unknown source function; use an exact function identity returned by the code tools")
                        continue
                    supplied_ea = getattr(position, "function_ea", None)
                    if supplied_ea is not None and supplied_ea != ea:
                        errors.append(f"{label}: expected function_ea {ea} ({ea:#x}), got {supplied_ea} ({supplied_ea:#x})")
                    # Structural evidence names a real function without
                    # claiming that it has a local decompiled C body.
                    if line is not None:
                        try:
                            validate_code_reference(view, binary_name=binary,
                                function_name=position.function_name, line_number=line)
                        except OutputValidationError as error:
                            errors.append(f"{field}: {error}")
                    continue
                if line is not None and not 1 <= line <= len(code.splitlines()):
                    errors.append(f"IPC {label}: line {line} is outside the cited function/text (1..{len(code.splitlines())})")
        if errors:
            raise OutputValidationError("IPC source validation failed:\n" + "\n".join(dict.fromkeys(errors)))

    @staticmethod
    def _is_rootfs_file(rootfs: Path, raw: str) -> bool:
        return resolve_guest_file(rootfs, raw) is not None


__all__ = ["SiteResolutionAgent"]
