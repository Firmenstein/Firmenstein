"""Deterministic merge logic for IPCAnalyzer Agent deltas."""

from __future__ import annotations

from fmst_analyzer.analysis.base.execution import execution_snapshot

import hashlib
import os
from collections import defaultdict
from pathlib import Path

from fmst_analyzer.analysis.base.covered_api_call import (
    CoveredAPICall,
    CoveredAPICallResolver,
)

from .agent_schema import (
    CandidateVerdict,
    PeerVerificationOutput,
    SiteCallsiteFinding,
    SiteResolutionOutput,
)
from .identity import (
    channel_id,
    dependency_id,
    endpoint_id,
    resource_key,
    unresolved_item_id,
)
from .schema import (
    AnalysisPhase,
    CandidateSource,
    CallsiteAccounting,
    CallsiteContext,
    CallsiteDisposition,
    CallsiteFact,
    DependencyAssessment,
    Endpoint,
    IPCAnalysisResult,
    IPCChannel,
    LocalImpact,
    PeerCandidateEvidence,
    PeerCandidateAssessment,
    PeerRequirement,
    ResourceIdentity,
    UnresolvedItem,
    VerificationStatus,
)
from .rootfs_tools import resolve_guest_file
from .findings import build_findings


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _merge_resources(
    existing: list[ResourceIdentity],
    incoming: list[ResourceIdentity],
) -> list[ResourceIdentity]:
    """Merge evidence for one logical Channel resource without first-wins loss."""
    by_key = {resource.resource_key: resource for resource in existing}
    for resource in incoming:
        previous = by_key.get(resource.resource_key)
        if previous is None:
            by_key[resource.resource_key] = resource
            continue
        if (
            previous.kind != resource.kind
            or previous.canonical_value != resource.canonical_value
        ):
            raise ValueError(
                f"conflicting resource identity for {resource.resource_key}"
            )
        evidence = {
            item.model_dump_json(): item
            for item in [*previous.evidence, *resource.evidence]
        }
        by_key[resource.resource_key] = previous.model_copy(update={
            "expressions": sorted({
                *previous.expressions,
                *resource.expressions,
            }),
            "status": (
                VerificationStatus.UNRESOLVED
                if VerificationStatus.UNRESOLVED
                in {previous.status, resource.status}
                else previous.status
            ),
            "evidence": [evidence[key] for key in sorted(evidence)],
            "missing_evidence": sorted({
                *previous.missing_evidence,
                *resource.missing_evidence,
            }),
        })
    return [by_key[key] for key in sorted(by_key)]


class IPCResultController:
    """Validate and merge Site Resolution outputs without semantic guessing."""

    def __init__(self, rootfs: Path) -> None:
        self.rootfs = Path(rootfs).absolute().resolve()
        self._hash_cache: dict[Path, str] = {}

    def merge_site_resolutions(
        self,
        static_result: IPCAnalysisResult,
        outputs: list[SiteResolutionOutput],
        auxiliary_callsites: list[CallsiteFact] | None = None,
        coverage_resolver: CoveredAPICallResolver | None = None,
    ) -> IPCAnalysisResult:
        if static_result.phase is not AnalysisPhase.STATIC:
            raise ValueError("site resolution must merge into a static result")

        callsites = {fact.callsite_id: fact for fact in static_result.callsites}
        auxiliary_by_id: dict[str, CallsiteFact] = {}
        for fact in auxiliary_callsites or []:
            previous = auxiliary_by_id.get(fact.callsite_id)
            if previous is not None and previous != fact:
                raise ValueError(
                    f"conflicting auxiliary facts for callsite {fact.callsite_id}"
                )
            auxiliary_by_id[fact.callsite_id] = fact
        findings: dict[str, list[SiteCallsiteFinding]] = defaultdict(list)
        for output in outputs:
            for finding in output.callsite_findings:
                if finding.callsite_id not in callsites:
                    raise ValueError(f"site finding references unknown callsite {finding.callsite_id}")
                self._validate_site_finding(
                    callsites[finding.callsite_id],
                    finding,
                    callsites,
                    auxiliary_by_id,
                )
                findings[finding.callsite_id].append(finding)
        failed_callsites = execution_snapshot().unsuccessful_subjects("site")
        if set(findings) | failed_callsites != set(callsites):
            raise ValueError(
                "Site Resolution outputs do not cover the static universe: "
                f"missing={sorted(set(callsites) - set(findings))}, "
                f"unexpected={sorted(set(findings) - set(callsites))}"
            )
        # Validate across Agent outputs too, rather than only within each batch.
        SiteResolutionOutput(callsite_findings=[item for variants in findings.values() for item in variants])

        endpoints_by_group: dict[tuple, list[Endpoint]] = defaultdict(list)
        dependencies_by_endpoint = {}
        semantics_by_dependency = {}
        resources_by_group: dict[tuple, list[ResourceIdentity]] = {}
        mechanism_by_group = {}
        accounting: list[CallsiteAccounting] = []
        pending_site_unresolved_ids = {
            unresolved_identity
            for item in static_result.callsite_accounting
            for unresolved_identity in item.unresolved_item_ids
        }
        unresolved_items: list[UnresolvedItem] = [
            item
            for item in static_result.unresolved_items
            if item.unresolved_item_id not in pending_site_unresolved_ids
        ]

        for fact in static_result.callsites:
            if fact.callsite_id in failed_callsites:
                accounting.append(CallsiteAccounting(
                    callsite_id=fact.callsite_id,
                    disposition=CallsiteDisposition.EXECUTION_FAILED,
                    endpoint_ids=[], unresolved_item_ids=[],
                    reason=f"No semantic result; see execution.tasks for site:{fact.callsite_id}.",
                ))
                continue
            variants = findings[fact.callsite_id]
            contexts: list[CallsiteContext] = []
            for finding in sorted(variants, key=lambda item: repr(item.context_identity())):
                context_id = endpoint_id(fact.callsite_id, finding.context_identity())
                resources = [
                    ResourceIdentity(
                        resource_key=resource_key(
                            resource.kind,
                            resource.canonical_value,
                            resource.expression,
                        ),
                        kind=resource.kind,
                        canonical_value=resource.canonical_value,
                        expressions=[resource.expression],
                        status=(
                            VerificationStatus.VERIFIED_AGENT
                            if resource.canonical_value is not None
                            and not resource.missing_evidence
                            else VerificationStatus.UNRESOLVED
                        ),
                        evidence=resource.evidence,
                        missing_evidence=resource.missing_evidence,
                    )
                    for resource in finding.resources
                ]
                context = CallsiteContext(
                    context_id=context_id, disposition=finding.disposition,
                    mechanism=finding.mechanism, context_anchor=finding.context_anchor,
                    wrapper_path=finding.wrapper_path, endpoint_role=finding.endpoint_role,
                    resources=resources, endpoint_ids=[], unresolved_item_ids=[],
                    summary=finding.summary, evidence=finding.evidence,
                    missing_evidence=finding.missing_evidence,
                ) if finding.disposition is CallsiteDisposition.NOT_FIRMWARE_IPC else None
                if finding.disposition is CallsiteDisposition.NOT_FIRMWARE_IPC:
                    contexts.append(context)
                    continue
                if finding.disposition is CallsiteDisposition.UNRESOLVED:
                    unresolved = self._unresolved_item_for_finding(finding, fact, reason_code=context_id)
                    unresolved_items.append(unresolved)
                    contexts.append(CallsiteContext(
                        context_id=context_id, disposition=finding.disposition,
                        mechanism=finding.mechanism, context_anchor=finding.context_anchor,
                        wrapper_path=finding.wrapper_path, endpoint_role=finding.endpoint_role,
                        resources=resources, endpoint_ids=[],
                        unresolved_item_ids=[unresolved.unresolved_item_id],
                        summary=finding.summary, evidence=finding.evidence,
                        missing_evidence=finding.missing_evidence,
                    ))
                    continue
                identity_resources = [resources[i] for i in finding.identity_resource_indices]
                resources.sort(key=lambda item: item.resource_key)
                all_resolved = all(
                    resource.status is VerificationStatus.VERIFIED_AGENT
                    for resource in identity_resources
                )
                # IPC_PRIVATE (key 0) creates a fresh object on each allocation;
                # equal literal keys do not join separate allocation sites.
                private_allocation = (
                    finding.mechanism.value.startswith("sysv_")
                    and finding.resource_identity() == (("key", "0"),)
                )
                if all_resolved and not private_allocation:
                    fingerprint = ("resolved_values", finding.resource_identity())
                else:
                    fingerprint = (
                        "private_allocation" if private_allocation else "provisional",
                        fact.callsite_id,
                        finding.source_context(),
                    )
                group_key = (finding.mechanism.value, fingerprint)
                resources_by_group[group_key] = _merge_resources(
                    resources_by_group.get(group_key, []),
                    resources,
                )
                mechanism_by_group[group_key] = finding.mechanism

                api_binding = fact.api_binding
                context_fingerprint = (
                    finding.mechanism.value,
                    fingerprint,
                    finding.source_context(),
                )
                identity = endpoint_id(
                    fact.callsite_id, context_fingerprint,
                )
                coverage_claims = [CoveredAPICall(
                    binary_name=Path(fact.location.binary_path).name,
                    function_name=fact.location.function_name,
                    api_name=fact.callee_name,
                    line_number=fact.location.line_number,
                    column_number=fact.location.column_number,
                    function_ea=fact.location.function_ea,
                    snapshot_hash=fact.location.snapshot_hash,
                    ctree_index=fact.location.ctree_index,
                    source_ea=fact.location.source_ea,
                    reason=f"IPC {finding.mechanism.value}: {finding.summary}",
                )]
                for covered_id in sorted(finding.covered_callsite_ids):
                    covered = auxiliary_by_id[covered_id]
                    coverage_claims.append(CoveredAPICall(
                        binary_name=Path(covered.location.binary_path).name,
                        function_name=covered.location.function_name,
                        api_name=covered.callee_name,
                        line_number=covered.location.line_number,
                        column_number=covered.location.column_number,
                        function_ea=covered.location.function_ea,
                        snapshot_hash=covered.location.snapshot_hash,
                        ctree_index=covered.location.ctree_index,
                        source_ea=covered.location.source_ea,
                        reason=f"IPC {finding.mechanism.value}: {finding.summary}",
                    ))
                if finding.dependency is not None and coverage_resolver is not None:
                    for termination in finding.dependency.termination_callsites:
                        claim = coverage_resolver.resolve(CoveredAPICall(
                            binary_name=termination.binary_name,
                            function_name=termination.function_name,
                            api_name=termination.api_name,
                            line_number=termination.line_number,
                            column_number=termination.column_number,
                            reason=termination.reason,
                        ))
                        if (
                            claim.function_ea is not None
                            and claim.snapshot_hash is not None
                            and claim.ctree_index is not None
                        ):
                            coverage_claims.append(claim)
                endpoint = Endpoint(
                    identity_resource_keys=sorted(resource.resource_key for resource in identity_resources),
                    context_anchor=finding.context_anchor,
                    endpoint_id=identity,
                    callsite_id=fact.callsite_id,
                    role=finding.endpoint_role,
                    api_binding=api_binding,
                    wrapper_path=finding.wrapper_path,
                    coverage_claims=coverage_claims,
                    status=(
                        VerificationStatus.VERIFIED_AGENT
                        if all_resolved
                        and api_binding.status is VerificationStatus.VERIFIED_STATIC
                        else VerificationStatus.UNRESOLVED
                    ),
                    evidence=finding.evidence,
                    missing_evidence=sorted({
                        *finding.missing_evidence,
                        *(
                            missing
                            for resource in finding.resources
                            for missing in resource.missing_evidence
                        ),
                        *(
                            [api_binding.reason]
                            if api_binding.status is VerificationStatus.UNRESOLVED
                            else []
                        ),
                    }),
                )
                endpoints_by_group[group_key].append(endpoint)
                dependencies_by_endpoint[identity] = finding.dependency
                context_unresolved_ids = []
                if endpoint.status is VerificationStatus.UNRESOLVED:
                    unresolved = self._unresolved_item_for_finding(
                        finding,
                        fact,
                        reason_code=f"provisional_endpoint:{identity}",
                    )
                    unresolved_items.append(unresolved)
                    context_unresolved_ids.append(unresolved.unresolved_item_id)
                contexts.append(CallsiteContext(
                    context_id=context_id, disposition=finding.disposition,
                    mechanism=finding.mechanism, context_anchor=finding.context_anchor,
                    wrapper_path=finding.wrapper_path, endpoint_role=finding.endpoint_role,
                    resources=resources, endpoint_ids=[identity],
                    unresolved_item_ids=context_unresolved_ids,
                    summary=finding.summary, evidence=finding.evidence,
                    missing_evidence=finding.missing_evidence,
                ))

            dispositions = {context.disposition for context in contexts}
            accounting.append(CallsiteAccounting(
                callsite_id=fact.callsite_id,
                disposition=next(iter(dispositions)) if len(dispositions) == 1 else CallsiteDisposition.MIXED,
                contexts=contexts,
                endpoint_ids=sorted({key for context in contexts for key in context.endpoint_ids}),
                unresolved_item_ids=sorted({key for context in contexts for key in context.unresolved_item_ids}),
                reason="\n".join(context.summary for context in contexts),
            ))

        channels: list[IPCChannel] = []
        dependencies: list[DependencyAssessment] = []
        for group_key in sorted(endpoints_by_group, key=repr):
            mechanism, fingerprint = group_key
            channel_identity = channel_id(
                static_result.firmware_sha256,
                mechanism,
                fingerprint,
            )
            endpoints = sorted(
                endpoints_by_group[group_key], key=lambda item: item.endpoint_id,
            )
            resolved = all(
                endpoint.status is not VerificationStatus.UNRESOLVED
                for endpoint in endpoints
            )
            channels.append(IPCChannel(
                channel_id=channel_identity,
                mechanism=mechanism_by_group[group_key],
                resources=resources_by_group[group_key],
                endpoints=endpoints,
                peer_candidates=[],
                status=(
                    VerificationStatus.VERIFIED_AGENT
                    if resolved
                    else VerificationStatus.UNRESOLVED
                ),
                missing_evidence=(
                    [] if resolved else ["resource or endpoint identity remains unresolved"]
                ),
            ))
            for endpoint in endpoints:
                dependency = dependencies_by_endpoint[endpoint.endpoint_id]
                identity = dependency_id(
                    channel_identity, [endpoint.endpoint_id],
                )
                status = (
                    VerificationStatus.VERIFIED_AGENT
                    if dependency.peer_requirement is not PeerRequirement.UNKNOWN
                    and dependency.local_impact is not LocalImpact.UNKNOWN
                    else VerificationStatus.UNRESOLVED
                )
                dependencies.append(DependencyAssessment(
                    dependency_id=identity,
                    channel_id=channel_identity,
                    consumer_endpoint_ids=[endpoint.endpoint_id],
                    peer_requirement=dependency.peer_requirement,
                    local_impact=dependency.local_impact,
                    summary=dependency.summary,
                    status=status,
                    evidence=dependency.evidence,
                    missing_evidence=dependency.missing_evidence,
                ))
                semantics_by_dependency[identity] = dependency.finding
                if status is VerificationStatus.UNRESOLVED:
                    unresolved = unresolved_item_id(
                        "dependency", identity, "local_impact_unresolved",
                    )
                    unresolved_items.append(UnresolvedItem(
                        unresolved_item_id=unresolved,
                        subject_kind="dependency",
                        subject_id=identity,
                        affected_channel_ids=[channel_identity],
                        reason=dependency.summary,
                        missing_evidence=dependency.missing_evidence,
                        runtime_evidence_requests=[],
                    ))

        affected_by_callsite: dict[str, set[str]] = defaultdict(set)
        for channel in channels:
            for endpoint in channel.endpoints:
                affected_by_callsite[endpoint.callsite_id].add(channel.channel_id)
        unresolved_items = [
            item.model_copy(update={
                "affected_channel_ids": sorted({
                    *item.affected_channel_ids,
                    *affected_by_callsite.get(item.subject_id, set()),
                }),
            })
            if item.subject_kind == "callsite"
            else item
            for item in unresolved_items
        ]
        dedup_unresolved = {
            item.unresolved_item_id: item for item in unresolved_items
        }
        channels.sort(key=lambda item: item.channel_id)
        dependencies.sort(key=lambda item: item.dependency_id)
        return IPCAnalysisResult(execution=execution_snapshot(),
            schema_version=static_result.schema_version,
            phase=AnalysisPhase.FULL,
            firmware_sha256=static_result.firmware_sha256,
            target_process=static_result.target_process,
            planning_findings=build_findings(
                static_result.target_process, channels, dependencies, semantics_by_dependency,
            ),
            callsites=static_result.callsites,
            channels=channels,
            dependency_assessments=dependencies,
            unresolved_items=sorted(
                dedup_unresolved.values(),
                key=lambda item: item.unresolved_item_id,
            ),
            callsite_accounting=sorted(accounting, key=lambda item: item.callsite_id),
        )

    def attach_retrieval_candidates(
        self,
        result: IPCAnalysisResult,
        channel_identity: str,
        candidates: list[PeerCandidateEvidence],
    ) -> IPCAnalysisResult:
        """Persist deterministic candidates and structural IDA evidence."""
        channels = {channel.channel_id: channel for channel in result.channels}
        channel = channels.get(channel_identity)
        if channel is None:
            raise ValueError(f"unknown channel {channel_identity}")
        by_path: dict[str, PeerCandidateEvidence] = {
            item.executable_path: item for item in channel.retrieval_candidates
        }
        source_priority = {
            CandidateSource.CONSTANT_INTERSECTION: 0,
            CandidateSource.MECHANISM_FALLBACK: 1,
        }
        for candidate in candidates:
            existing = by_path.get(candidate.executable_path)
            if existing is None:
                by_path[candidate.executable_path] = candidate
            else:
                call_paths = {
                    item.model_dump_json(): item
                    for item in [
                        *existing.call_paths,
                        *candidate.call_paths,
                    ]
                }
                by_path[candidate.executable_path] = existing.model_copy(update={
                    "source": min(
                        (existing.source, candidate.source),
                        key=source_priority.__getitem__,
                    ),
                    "reasons": sorted({*existing.reasons, *candidate.reasons}),
                    "call_paths": sorted(
                        call_paths.values(),
                        key=lambda item: (
                            item.identifier_relation.value,
                            item.identifier or "",
                            tuple(
                                (
                                    hop.binary_path,
                                    hop.function_ea,
                                    hop.function_name,
                                )
                                for hop in item.call_path
                            ),
                            item.endpoint.primitive,
                        ),
                    ),
                })
        channels[channel_identity] = channel.model_copy(update={
            "retrieval_candidates": sorted(
                by_path.values(),
                key=lambda item: (
                    source_priority[item.source], item.executable_path,
                ),
            ),
        })
        data = result.model_dump(exclude={"covered_api_calls"})
        data["channels"] = sorted(
            channels.values(), key=lambda item: item.channel_id,
        )
        return IPCAnalysisResult.model_validate(data)

    def attach_candidate_coverage_gaps(
        self,
        result: IPCAnalysisResult,
        channel_identity: str,
        gaps,
    ) -> IPCAnalysisResult:
        """Persist one candidate-index item and merge affected Channels."""
        if channel_identity not in {channel.channel_id for channel in result.channels}:
            raise ValueError(f"unknown channel {channel_identity}")
        unresolved_items = {
            item.unresolved_item_id: item for item in result.unresolved_items
        }
        for gap in gaps:
            identity = unresolved_item_id(
                "analysis_scope",
                "candidate_index",
                f"candidate_index:{gap.reason_code}:{gap.reason}",
            )
            previous = unresolved_items.get(identity)
            affected = sorted({
                channel_identity,
                *(previous.affected_channel_ids if previous else []),
            })
            unresolved_items[identity] = UnresolvedItem(
                unresolved_item_id=identity,
                subject_kind="analysis_scope",
                subject_id="candidate_index",
                affected_channel_ids=affected,
                reason=gap.reason,
                missing_evidence=sorted({
                    *gap.missing_evidence,
                    *(previous.missing_evidence if previous else []),
                }),
                runtime_evidence_requests=[],
            )
        data = result.model_dump(exclude={"covered_api_calls"})
        data["unresolved_items"] = sorted(
            unresolved_items.values(),
            key=lambda item: item.unresolved_item_id,
        )
        return IPCAnalysisResult.model_validate(data)

    def merge_peer_verification(
        self,
        result: IPCAnalysisResult,
        channel_identity: str,
        output: PeerVerificationOutput,
    ) -> IPCAnalysisResult:
        """Merge one audited peer-verification delta into a full result."""
        if result.phase is not AnalysisPhase.FULL:
            raise ValueError("peer verification requires a full-phase result")

        channels = {channel.channel_id: channel for channel in result.channels}
        if channel_identity not in channels:
            raise ValueError(f"unknown channel {channel_identity}")
        channel = channels[channel_identity]
        peer_assessments = {
            item.executable_path: item for item in channel.peer_candidates
        }
        new_unresolved = {
            item.unresolved_item_id: item for item in result.unresolved_items
        }

        for finding in sorted(
            output.peer_findings, key=lambda item: item.executable_path,
        ):
            relative = self._existing_relative(finding.executable_path)
            if relative in peer_assessments:
                raise ValueError(
                    "Peer Verification returned a verdict for a candidate "
                    f"already decided statically: {relative}"
                )
            for citation in finding.evidence:
                self._validate_citation(
                    citation,
                    {fact.callsite_id: fact for fact in result.callsites},
                )
            if finding.verdict is CandidateVerdict.VERIFIED:
                status = VerificationStatus.VERIFIED_AGENT
                assessment_reason = finding.summary
                assessment_missing_evidence = finding.missing_evidence
            elif finding.verdict is CandidateVerdict.REJECTED:
                status = VerificationStatus.REJECTED
                assessment_reason = finding.summary
                assessment_missing_evidence = finding.missing_evidence
            else:
                status = VerificationStatus.UNRESOLVED
                assessment_reason = finding.summary
                assessment_missing_evidence = finding.missing_evidence
            if status is VerificationStatus.UNRESOLVED:
                identity = unresolved_item_id(
                    "peer",
                    relative,
                    f"peer_verification_unresolved:{assessment_reason}",
                )
                previous = new_unresolved.get(identity)
                new_unresolved[identity] = UnresolvedItem(
                    unresolved_item_id=identity,
                    subject_kind="peer",
                    subject_id=relative,
                    affected_channel_ids=sorted({
                        channel_identity,
                        *(previous.affected_channel_ids if previous else []),
                    }),
                    reason=assessment_reason,
                    missing_evidence=sorted({
                        *assessment_missing_evidence,
                        *(previous.missing_evidence if previous else []),
                    }),
                    runtime_evidence_requests=[],
                )
            peer_assessments[relative] = PeerCandidateAssessment(
                executable_path=relative,
                executable_sha256=self._hash(self.rootfs / relative),
                argv0=finding.argv0,
                role=finding.role,
                endpoint_locations=finding.endpoint_locations,
                status=status,
                reason=assessment_reason,
                evidence=finding.evidence,
                missing_evidence=assessment_missing_evidence,
            )

        channels[channel_identity] = channel.model_copy(update={
            "peer_candidates": [
                peer_assessments[key] for key in sorted(peer_assessments)
            ],
        })
        data = result.model_dump(exclude={"covered_api_calls"})
        data.update({
            "channels": sorted(channels.values(), key=lambda item: item.channel_id),
            "unresolved_items": sorted(
                new_unresolved.values(),
                key=lambda item: item.unresolved_item_id,
            ),
        })
        return IPCAnalysisResult.model_validate(data)

    def mark_peer_verification_unresolved(
        self,
        result: IPCAnalysisResult,
        channel_identity: str,
        *,
        reason: str,
        missing_evidence: list[str],
        reason_code: str = "peer_verification_failed",
    ) -> IPCAnalysisResult:
        """Fail peer verification closed without discarding site dependencies."""
        channels = {channel.channel_id: channel for channel in result.channels}
        channel = channels.get(channel_identity)
        if channel is None:
            raise ValueError(f"unknown channel {channel_identity}")
        channels[channel_identity] = channel
        identity = unresolved_item_id("channel", channel_identity, reason_code)
        unresolved_items = {
            item.unresolved_item_id: item for item in result.unresolved_items
        }
        unresolved_items[identity] = UnresolvedItem(
            unresolved_item_id=identity,
            subject_kind="channel",
            subject_id=channel_identity,
            affected_channel_ids=[channel_identity],
            reason=reason,
            missing_evidence=sorted(set(missing_evidence)),
            runtime_evidence_requests=[],
        )
        data = result.model_dump(exclude={"covered_api_calls"})
        data.update({
            "channels": sorted(channels.values(), key=lambda item: item.channel_id),
            "unresolved_items": sorted(
                unresolved_items.values(),
                key=lambda item: item.unresolved_item_id,
            ),
        })
        return IPCAnalysisResult.model_validate(data)

    def _validate_site_finding(
        self,
        fact,
        finding: SiteCallsiteFinding,
        callsites: dict,
        auxiliary_callsites: dict[str, CallsiteFact],
    ) -> None:
        api_binding = fact.api_binding
        if api_binding.symbol != fact.callee_name:
            raise ValueError(
                f"API binding symbol {api_binding.symbol!r} does not match {fact.callee_name!r}"
            )
        if api_binding.binary_path is not None:
            binding_path = self._existing_relative(api_binding.binary_path)
            if api_binding.binary_sha256 != self._hash(self.rootfs / binding_path):
                raise ValueError(
                    f"Static API binding hash mismatch for {api_binding.binary_path}"
                )
        for hop in finding.wrapper_path:
            self._existing_relative(hop.binary_path)
        for citation in finding.evidence:
            self._validate_citation(citation, callsites)
        for resource in finding.resources:
            for citation in resource.evidence:
                self._validate_citation(citation, callsites)
        if finding.dependency is not None:
            for citation in finding.dependency.evidence:
                self._validate_citation(citation, callsites)
        unknown_coverage = set(finding.covered_callsite_ids) - set(
            auxiliary_callsites
        )
        if unknown_coverage:
            raise ValueError(
                "Site finding references unknown auxiliary callsites: "
                f"{sorted(unknown_coverage)}"
            )
        fact_function = (
            fact.location.binary_path,
            fact.location.function_ea,
            fact.location.snapshot_hash,
        )
        cross_function_coverage = sorted(
            identity
            for identity in finding.covered_callsite_ids
            if (
                auxiliary_callsites[identity].location.binary_path,
                auxiliary_callsites[identity].location.function_ea,
                auxiliary_callsites[identity].location.snapshot_hash,
            ) != fact_function
        )
        if cross_function_coverage:
            raise ValueError(
                "Site finding coverage cannot span containing functions: "
                f"{cross_function_coverage}"
            )

    def _unresolved_item_for_finding(
        self,
        finding: SiteCallsiteFinding,
        fact,
        reason_code: str = "site_resolution_unresolved",
    ) -> UnresolvedItem:
        missing = sorted({
            *finding.missing_evidence,
            *(item for resource in finding.resources for item in resource.missing_evidence),
            *(
                [fact.api_binding.reason]
                if fact.api_binding.status is VerificationStatus.UNRESOLVED
                else []
            ),
        })
        if not missing:
            missing = ["semantic resolution did not produce a complete endpoint"]
        identity = unresolved_item_id(
            "callsite", finding.callsite_id, reason_code,
        )
        return UnresolvedItem(
            unresolved_item_id=identity,
            subject_kind="callsite",
            subject_id=finding.callsite_id,
            reason=finding.summary,
            missing_evidence=missing,
            runtime_evidence_requests=[],
        )

    def _validate_citation(self, citation, callsites: dict) -> None:
        self._existing_relative(citation.binary_path)
        if citation.callsite_id is not None and citation.callsite_id not in callsites:
            raise ValueError(
                f"evidence citation references unknown callsite {citation.callsite_id}"
            )

    def _existing_relative(self, raw: str, *, preserve_alias: bool = False) -> str:
        normalized = os.path.normpath(raw.lstrip("/"))
        if normalized.startswith("..") or os.path.isabs(normalized):
            raise ValueError(f"Agent path escapes rootfs: {raw}")
        resolved = resolve_guest_file(self.rootfs, raw)
        if resolved is None:
            raise ValueError(f"Agent path is not a rootfs file: {raw}")
        chain, _endpoint = resolved
        if preserve_alias:
            return chain[0]
        return chain[-1]

    def _hash(self, path: Path) -> str:
        try:
            raw = path.absolute().relative_to(self.rootfs).as_posix()
        except ValueError as error:
            raise ValueError(f"hash path escapes rootfs: {path}") from error
        resolved = resolve_guest_file(self.rootfs, raw)
        if resolved is None:
            raise ValueError(f"hash path is not a guest file: {path}")
        endpoint = resolved[1]
        if endpoint not in self._hash_cache:
            self._hash_cache[endpoint] = _sha256(endpoint)
        return self._hash_cache[endpoint]


__all__ = ["IPCResultController"]
