"""Pure Markdown renderers and persistence for IPCAnalysisResult."""

from __future__ import annotations

import shutil
from collections import Counter
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from fmst_analyzer.analysis.base.report_io import (
    load_model_json,
    write_model_json,
    write_text,
)

from .schema import (
    AnalysisPhase,
    CallsiteFact,
    IPCAnalysisResult,
    IPCCallsiteReport,
    IPCChannel,
    IPCChannelReport,
    IPCMechanism,
    LocalImpact,
    PeerRequirement,
    VerificationStatus,
)


_MECHANISM_LABELS = {
    IPCMechanism.SYSV_SHM: "System V shared memory",
    IPCMechanism.SYSV_MSG: "System V message queue",
    IPCMechanism.SYSV_SEM: "System V semaphore",
    IPCMechanism.POSIX_SHM: "POSIX shared memory",
    IPCMechanism.POSIX_MQ: "POSIX message queue",
    IPCMechanism.POSIX_SEM: "POSIX semaphore",
    IPCMechanism.UDS: "Unix domain socket",
    IPCMechanism.LOOPBACK_SOCKET: "loopback socket",
    IPCMechanism.FIFO: "named pipe",
    IPCMechanism.KERNEL_CHANNEL: "kernel channel",
    IPCMechanism.EXTERNAL_NETWORK: "external network",
    IPCMechanism.UNKNOWN: "unresolved IPC mechanism",
}

_IMPACT_LABELS = {
    LocalImpact.PROCESS_BLOCKED: "the target cannot start or remain ready",
    LocalImpact.OPERATION_AFFECTED: "the affected operation fails or degrades",
    LocalImpact.NONE: "no target-local effect was identified",
    LocalImpact.UNKNOWN: "the target-local effect remains unresolved",
}


def _rootfs_path(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"


def _channel_resource(channel: IPCChannel) -> str:
    mechanism = _MECHANISM_LABELS[channel.mechanism]
    values = [
        f"`{resource.canonical_value}`"
        if resource.canonical_value is not None
        else "unresolved identifier"
        for resource in channel.resources
    ]
    return f"{mechanism} {', '.join(values)}" if values else mechanism


def _verified_peer_paths(channel: IPCChannel) -> list[str]:
    verified = {
        VerificationStatus.VERIFIED_AGENT,
        VerificationStatus.VERIFIED_STATIC,
    }
    return sorted({
        _rootfs_path(candidate.executable_path)
        for candidate in channel.peer_candidates
        if candidate.status in verified
    })


def _channel_stem(channel_id: str) -> str:
    return channel_id.replace(":", "_")


def _callsite_stem(callsite_id: str) -> str:
    return callsite_id.replace(":", "_")


def _table_text(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def _dependency_sentence(requirement: PeerRequirement, impact: LocalImpact) -> str:
    consequence = _IMPACT_LABELS[impact]
    if requirement is PeerRequirement.DATA:
        return f"The target consumes peer-provided data, shared state, or handles; without the peer, {consequence}."
    if requirement is PeerRequirement.AVAILABILITY:
        return f"The target requires a successful peer interaction; without the peer, {consequence}."
    if requirement is PeerRequirement.NONE:
        return "The call does not consume peer-returned data, state, or success, so no target-side execution dependency was established."
    return f"The target-side dependency remains unresolved; {consequence}."


def _strongest_dependency(dependencies):
    requirement_rank = {
        PeerRequirement.DATA: 3,
        PeerRequirement.AVAILABILITY: 2,
        PeerRequirement.UNKNOWN: 1,
        PeerRequirement.NONE: 0,
    }
    impact_rank = {
        LocalImpact.PROCESS_BLOCKED: 3,
        LocalImpact.OPERATION_AFFECTED: 2,
        LocalImpact.UNKNOWN: 1,
        LocalImpact.NONE: 0,
    }
    return max(
        dependencies,
        key=lambda item: (
            requirement_rank[item.peer_requirement],
            impact_rank[item.local_impact],
        ),
        default=None,
    )


def _render_relationship(result: IPCAnalysisResult, channel: IPCChannel) -> list[str]:
    target = _rootfs_path(result.target_process.executable_path)
    resource = _channel_resource(channel)
    peers = _verified_peer_paths(channel)
    dependencies = [
        item for item in result.dependency_assessments
        if item.channel_id == channel.channel_id
    ]

    dependency = _strongest_dependency(dependencies)
    detail = (
        "  - Channel evidence: "
        f"[`{channel.channel_id}`](channels/{_channel_stem(channel.channel_id)}.md)."
    )
    if len(peers) == 1 and dependency is not None:
        peer = peers[0]
        if dependency.peer_requirement is PeerRequirement.DATA:
            relation = (
                f"`{target}` depends on `{peer}` through {resource} for data, shared state, or handles."
            )
        elif dependency.peer_requirement is PeerRequirement.AVAILABILITY:
            relation = f"`{target}` depends on `{peer}` being available through {resource}."
        elif dependency.peer_requirement is PeerRequirement.NONE:
            relation = (
                f"`{target}` communicates with `{peer}` through {resource}, but this call does not depend on the peer's result."
            )
            return [f"- {relation}", detail]
        else:
            relation = f"`{target}` communicates with `{peer}` through {resource}; the dependency remains unresolved."
        return [
            f"- {relation}",
            f"  - Impact if the peer is unavailable: {_IMPACT_LABELS[dependency.local_impact]}.",
            detail,
        ]

    peer_list = ", ".join(f"`{path}`" for path in peers)
    lines = [f"- `{target}` communicates with {peer_list} through {resource}."]
    if dependency is not None:
        lines.append(
            "  - "
            + _dependency_sentence(
                dependency.peer_requirement, dependency.local_impact,
            )
        )
    else:
        lines.append("  - No verified target-side dependency conclusion is available.")
    lines.append(detail)
    return lines


def _scalar(value: object) -> str:
    if isinstance(value, Enum):
        value = value.value
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "`true`" if value else "`false`"
    return f"`{_table_text(value)}`"


def _render_structured(value: object, *, indent: int = 0) -> list[str]:
    """Render a complete Pydantic value as readable nested Markdown bullets."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="python")
    prefix = "  " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (BaseModel, dict, list)):
                lines.append(f"{prefix}- {key}:")
                lines.extend(_render_structured(item, indent=indent + 1))
            else:
                lines.append(f"{prefix}- {key}: {_scalar(item)}")
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{prefix}- (none)"]
        lines = []
        for item in value:
            if isinstance(item, (BaseModel, dict, list)):
                lines.append(f"{prefix}- item:")
                lines.extend(_render_structured(item, indent=indent + 1))
            else:
                lines.append(f"{prefix}- {_scalar(item)}")
        return lines
    return [f"{prefix}- {_scalar(value)}"]


def _callsite_report(
    result: IPCAnalysisResult,
    fact: CallsiteFact,
) -> IPCCallsiteReport:
    accounting = next(
        item for item in result.callsite_accounting
        if item.callsite_id == fact.callsite_id
    )
    return IPCCallsiteReport(
        phase=result.phase,
        firmware_sha256=result.firmware_sha256,
        target_process=result.target_process,
        callsite=fact,
        callsite_accounting=accounting,
    )


def _channel_report(
    result: IPCAnalysisResult,
    channel: IPCChannel,
) -> IPCChannelReport:
    return IPCChannelReport(
        phase=result.phase,
        firmware_sha256=result.firmware_sha256,
        target_process=result.target_process,
        channel=channel,
        dependency_assessments=[
            item for item in result.dependency_assessments
            if item.channel_id == channel.channel_id
        ],
        unresolved_items=[
            item for item in result.unresolved_items
            if channel.channel_id in item.affected_channel_ids
        ],
    )


def render_index(result: IPCAnalysisResult) -> str:
    from fmst_analyzer.analysis.base.finding_reports import render_fields, render_planning_findings
    lines = [
        "# IPC Analysis",
        "",
        f"Target process: `{_rootfs_path(result.target_process.executable_path)}`.",
        "",
        "## Findings",
        "",
    ]
    if result.phase is AnalysisPhase.STATIC:
        lines.append("This is the static collection phase; IPC peers and target-side dependencies have not been assessed yet.")
    elif result.channels:
        confirmed_channels = [
            channel for channel in result.channels
            if _verified_peer_paths(channel)
        ]
        if confirmed_channels:
            for channel in confirmed_channels:
                lines.extend(_render_relationship(result, channel))
        else:
            lines.append("No direct firmware IPC peer was verified within the current analysis scope.")
        unresolved_channels = [
            channel for channel in result.channels
            if not _verified_peer_paths(channel)
        ]
        if unresolved_channels:
            mechanism_counts = Counter(
                _MECHANISM_LABELS[channel.mechanism]
                for channel in unresolved_channels
            )
            lines.extend([
                "",
                "## Channels Without a Verified Peer",
                "",
                f"`{len(unresolved_channels)}` channels do not yet have a verified peer:",
            ])
            for mechanism, count in sorted(mechanism_counts.items()):
                lines.append(f"- {mechanism}: `{count}`")
            lines.extend([
                "",
                "See the [`channels` index](channels/index.md) for every resource identifier, target-side impact, and candidate audit.",
            ])
    else:
        lines.append("No verified direct IPC channel was identified within the current analysis scope.")

    lines.extend([
        "",
        "## Unresolved Items",
        "",
    ])
    if result.unresolved_items:
        counts = Counter(item.subject_kind for item in result.unresolved_items)
        lines.append(
            "An unresolved item records a specific point where analysis stopped because "
            "required evidence was unavailable. It is neither a verified peer nor a distinct IPC channel."
        )
        lines.extend([
            "",
            f"`{len(result.unresolved_items)}` unresolved items were recorded:",
        ])
        for subject_kind, count in sorted(counts.items()):
            lines.append(f"- `{subject_kind}`: `{count}`")
        lines.extend([
            "",
            "See [`unresolved_items.md`](unresolved_items.md) for complete reasons, affected Channels, missing evidence, and runtime evidence requests. "
            "The structured source is the `unresolved_items` field in [`ipc_analysis_result.json`](ipc_analysis_result.json).",
        ])
    else:
        lines.append("No unresolved analysis boundary was recorded.")

    lines.extend([
        "",
        "## Summary",
        "",
        f"- `phase`: `{result.phase.value}`",
        f"- `callsites`: `{len(result.callsites)}`",
        f"- `channels`: `{len(result.channels)}`",
        f"- `dependency_assessments`: `{len(result.dependency_assessments)}`",
        f"- `unresolved_items`: `{len(result.unresolved_items)}`",
        "",
        "## Artifacts",
        "",
        "- Structured source of truth: [`ipc_analysis_result.json`](ipc_analysis_result.json)",
        "- Callsite evidence: [`callsites/index.md`](callsites/index.md)",
        "- IPC channel and peer evidence: [`channels/index.md`](channels/index.md)",
        f"- `schema_version`: `{result.schema_version}`",
        f"- `firmware_sha256`: `{result.firmware_sha256}`",
        "",
    ])
    lines.extend([
        "## target_process", "", render_fields({"target_process": result.target_process.model_dump(mode="json")}),
        "## covered_api_calls", "", render_fields({"covered_api_calls": [item.model_dump(mode="json") for item in result.covered_api_calls]}),
        render_planning_findings(result.planning_findings),
    ])
    lines.extend(["", "## execution", "", render_fields(result.execution.model_dump(mode="json"))])
    return "\n".join(lines)


def render_unresolved_items(result: IPCAnalysisResult) -> str:
    lines = [
        "# IPC Unresolved Items",
        "",
        "An unresolved item is an explicit analysis boundary, not a verified peer or a distinct IPC channel.",
        "",
        f"This file contains all `{len(result.unresolved_items)}` items without truncation.",
        "",
    ]
    if not result.unresolved_items:
        lines.extend(["No unresolved analysis boundary was recorded.", ""])
        return "\n".join(lines)

    for index, item in enumerate(result.unresolved_items, start=1):
        lines.extend([
            f"## {index}. {item.subject_kind}: {item.subject_id}",
            "",
            f"- `unresolved_item_id`: `{item.unresolved_item_id}`",
            f"- `subject_kind`: `{item.subject_kind}`",
            f"- `subject_id`: `{item.subject_id}`",
            "- `affected_channel_ids`:"
            if item.affected_channel_ids
            else "- `affected_channel_ids`: none",
        ])
        if item.affected_channel_ids:
            lines.extend(
                "  - "
                f"[`{channel_id}`](channels/{_channel_stem(channel_id)}.md)"
                for channel_id in item.affected_channel_ids
            )
        lines.extend([
            f"- `reason`: {item.reason}",
        ])
        if item.missing_evidence:
            lines.append("- `missing_evidence`:")
            lines.extend(f"  - {value}" for value in item.missing_evidence)
        else:
            lines.append("- `missing_evidence`: none")
        if item.runtime_evidence_requests:
            lines.append("- `runtime_evidence_requests`:")
            lines.extend(f"  - {value}" for value in item.runtime_evidence_requests)
        else:
            lines.append("- `runtime_evidence_requests`: none")
        lines.append("")
    return "\n".join(lines)


def render_callsite(report: IPCCallsiteReport) -> str:
    fact = report.callsite
    accounting = report.callsite_accounting
    stem = _callsite_stem(fact.callsite_id)
    lines = [
        f"# IPC Callsite — `{fact.callsite_id}`",
        "",
        f"- schema_version: `{report.schema_version}`",
        f"- phase: `{report.phase.value}`",
        f"- target_process.executable_path: `{report.target_process.executable_path}`",
        f"- structured_source: [`{stem}_result.json`]({stem}_result.json)",
        f"- disposition: `{accounting.disposition.value}`",
        f"- reason: {accounting.reason}",
        "",
        "## callsite",
        "",
    ]
    lines.extend(_render_structured(fact))
    lines.extend([
        "",
        "## callsite_accounting",
        "",
    ])
    lines.extend(_render_structured(accounting))
    return "\n".join(lines).rstrip() + "\n"


def render_channel(report: IPCChannelReport) -> str:
    channel = report.channel
    stem = _channel_stem(channel.channel_id)
    peers = _verified_peer_paths(channel)
    lines = [
        f"# IPC Channel — `{channel.channel_id}`",
        "",
        f"- schema_version: `{report.schema_version}`",
        f"- phase: `{report.phase.value}`",
        f"- target_process.executable_path: `{report.target_process.executable_path}`",
        f"- structured_source: [`{stem}_result.json`]({stem}_result.json)",
        f"- mechanism: `{channel.mechanism.value}`",
        f"- resource: {_channel_resource(channel)}",
        f"- status: `{channel.status.value}`",
        "- verified_peers:",
    ]
    lines.extend(f"  - `{path}`" for path in peers)
    if not peers:
        lines.append("  - (none)")
    lines.extend([
        "",
        "## channel",
        "",
    ])
    lines.extend(_render_structured(channel))
    lines.extend(["", "## dependency_assessments", ""])
    lines.extend(_render_structured(report.dependency_assessments))
    lines.extend(["", "## unresolved_items", ""])
    lines.extend(_render_structured(report.unresolved_items))
    return "\n".join(lines).rstrip() + "\n"


def render_callsites_index(result: IPCAnalysisResult) -> str:
    lines = [
        "# IPC Callsites",
        "",
        "This index links every controller-owned CTree callsite record without truncation.",
        "",
        f"- callsites: `{len(result.callsites)}`",
        "",
        "| callsite_id | mechanism_hint | callee_name | location | reports |",
        "|---|---|---|---|---|",
    ]
    for fact in sorted(result.callsites, key=lambda item: item.callsite_id):
        location = fact.location
        stem = _callsite_stem(fact.callsite_id)
        reports = f"[md]({stem}.md) / [json]({stem}_result.json)"
        lines.append(
            f"| `{fact.callsite_id}` | `{fact.mechanism_hint.value}` | "
            f"`{_table_text(fact.callee_name)}` | "
            f"`{_table_text(location.binary_path)}::"
            f"{_table_text(location.function_name)}:"
            f"L{location.line_number}:C{location.column_number}` | {reports} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def render_channels_index(result: IPCAnalysisResult) -> str:
    lines = [
        "# IPC Channels",
        "",
        "This index links every logical IPC channel, its peer evidence, "
        "target-local dependency assessments, and affected unresolved items.",
        "",
        f"- channels: `{len(result.channels)}`",
        "",
        "| channel_id | mechanism | resource | status | verified_peers | reports |",
        "|---|---|---|---|---:|---|",
    ]
    for channel in sorted(result.channels, key=lambda item: item.channel_id):
        stem = _channel_stem(channel.channel_id)
        reports = f"[md]({stem}.md) / [json]({stem}_result.json)"
        lines.append(
            f"| `{channel.channel_id}` | `{channel.mechanism.value}` | "
            f"{_table_text(_channel_resource(channel))} | "
            f"`{channel.status.value}` | "
            f"{len(_verified_peer_paths(channel))} | {reports} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def persist_result(
    result: IPCAnalysisResult,
    output_dir: Path,
    *,
    persist_json: bool = True,
) -> IPCAnalysisResult:
    """Persist JSON SoT first and render every Markdown file from it."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    callsites_dir = output_dir / "callsites"
    channels_dir = output_dir / "channels"
    if persist_json:
        shutil.rmtree(callsites_dir, ignore_errors=True)
        shutil.rmtree(channels_dir, ignore_errors=True)
    callsites_dir.mkdir(exist_ok=True)
    channels_dir.mkdir(exist_ok=True)
    if not persist_json:
        for path in (*callsites_dir.glob("*.md"), *channels_dir.glob("*.md")):
            path.unlink()

    json_path = output_dir / "ipc_analysis_result.json"
    if persist_json:
        write_model_json(json_path, result)
        result = load_model_json(json_path, IPCAnalysisResult)

    write_text(output_dir / "index.md", render_index(result))
    legacy_frontier = output_dir / "frontier.md"
    legacy_frontier.unlink(missing_ok=True)
    write_text(output_dir / "unresolved_items.md", render_unresolved_items(result))
    for fact in result.callsites:
        stem = _callsite_stem(fact.callsite_id)
        report = _callsite_report(result, fact)
        if persist_json:
            report_path = callsites_dir / f"{stem}_result.json"
            write_model_json(report_path, report)
            report = load_model_json(report_path, type(report))
        write_text(callsites_dir / f"{stem}.md", render_callsite(report))
    for channel in result.channels:
        stem = _channel_stem(channel.channel_id)
        report = _channel_report(result, channel)
        if persist_json:
            report_path = channels_dir / f"{stem}_result.json"
            write_model_json(report_path, report)
            report = load_model_json(report_path, type(report))
        write_text(channels_dir / f"{stem}.md", render_channel(report))
    write_text(callsites_dir / "index.md", render_callsites_index(result))
    write_text(channels_dir / "index.md", render_channels_index(result))
    return result


__all__ = [
    "persist_result",
    "render_callsites_index",
    "render_callsite",
    "render_channels_index",
    "render_channel",
    "render_index",
    "render_unresolved_items",
]
