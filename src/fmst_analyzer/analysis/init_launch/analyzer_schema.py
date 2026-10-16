"""Structured output for InitLaunchAnalyzer.

The Agent reports launch-command candidates only. Target identity and stable
recipe IDs are authoritative Controller data and are never Agent-authored.
"""
from __future__ import annotations

from fmst_analyzer.analysis.base.execution import AnalysisExecution

import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator
from fmst_analyzer.analysis.base.analysis_finding import (
    FindingAnchor, InitLaunchFindingDomain, PlanningFindings, validate_finding_references,
)
from fmst_analyzer.analysis.base.finding_binding import FindingSemantics, FindingTarget, pointer, validate_bound_finding

INIT_LAUNCH_SCHEMA_VERSION = 7
INIT_LAUNCH_EVIDENCE_ROOTS = {"launch_site", "context_anchor", "initialization_chain", "preparation_actions"}


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

__all__ = [
    "AnalysisGap",
    "InitLaunchAnalysisResult",
    "LaunchRecipe",
    "LaunchRecipeAgentOutput",
    "LaunchRecipeDraft",
    "SourceSnippet",
    "TargetIdentity",
]


class TargetIdentity(StrictModel):
    """Authoritative target selected by the outer pipeline."""

    target_basename: str = Field(
        min_length=1,
        description="Selected target ELF basename.",
    )
    selected_rootfs_path: str = Field(
        min_length=1,
        description=(
            "Rootfs-relative path of the exact ELF selected by the pipeline."
        ),
    )
    target_aliases: List[str] = Field(
        default_factory=list,
        description=(
            "Rootfs-relative symlink paths whose chain reaches the selected "
            "target path."
        ),
    )


class SourceSnippet(StrictModel):
    """A verifiable excerpt from a rootfs text file or ELF listing."""

    path: str = Field(
        min_length=1,
        description="Rootfs-relative source path; never a host path.",
    )
    location: str = Field(
        min_length=1,
        description=(
            "Text line (for example 'line 42') or ELF address/section offset "
            "(for example '0x401234' or '.text+0x120')."
        ),
    )
    text: str = Field(
        min_length=1,
        description=(
            "Exact source content at the location: text-file excerpt, raw symlink "
            "target, literal ELF string bytes, or exact canonical assembly lines "
            "returned by read_elf. Non-text ELF data uses 'hex:' followed by exact "
            "lowercase byte pairs; unprefixed hexadecimal is an ordinary string. "
            "Selected assembly lines retain their addresses "
            "in ascending order, starting at location; gaps do not prove control flow. "
            "ELF prose paraphrases are not verifiable evidence."
            "During an Agent attempt, prefer the exact @source: identifier supplied "
            "by read_source or ELF tools: keep its path/location, and the Controller "
            "will substitute the already-read canonical excerpt before validation and persistence."
        ),
    )

    def position_key(self) -> tuple[str, str]:
        location = self.location.strip()
        match = re.search(r"(?:^|\b)(?:line\s*|L)(\d+)$", location, re.IGNORECASE) or re.search(r":(\d+)$", location)
        return self.path, f"line {int(match.group(1))}" if match else location


class LaunchRecipeDraft(StrictModel):
    """One source-backed invocation and its initialization applicability."""

    launch_site: SourceSnippet = Field(
        description="The rootfs location containing the target invocation."
    )
    context_anchor: SourceSnippet = Field(
        description=(
            "Verified source position in initialization_chain distinguishing this invocation "
            "context, such as a caller, event registration or selected branch. For a direct "
            "unconditional invocation it may equal launch_site. Use a minimal source anchor; "
            "additional supporting evidence belongs in the chain, not in this identity. "
            "Different contexts sharing the final launch command require distinct anchors."
        ),
    )
    applicability: str = Field(
        pattern=r"\S",
        description=(
            "Complete conditions under which this invocation and its preparation apply, "
            "including branch polarity, arguments, configuration and runtime guards. "
            "State unproved applicability explicitly and include the corresponding unknown "
            "claim or analysis gap. This describes firmware behavior, not a launch choice."
        ),
    )
    executable_path: str = Field(
        min_length=1,
        description=(
            "Firmware-absolute path of the selected target ultimately reached "
            "by the launch command, normalized to the selected path or one of "
            "its aliases."
        ),
    )
    command_template: List[str] = Field(
        min_length=1,
        description=(
            "Ordered argv-like tokens of the rootfs launch invocation. "
            "Element 0 may be a wrapper that eventually invokes "
            "executable_path. Preserve unresolved shell variables and "
            "placeholders verbatim, but exclude shell control syntax such "
            "as background operators, pipelines, separators and redirects."
        ),
    )
    initialization_chain: List[SourceSnippet] = Field(
        min_length=1,
        description=(
            "Ordered known source evidence toward launch_site. It may begin at a local "
            "caller or context when the path from an initialization entry is unproved; "
            "supplied entries are navigation starting points. The final item must equal "
            "launch_site. If an internal edge remains unproved, "
            "retain the known snippets and identify that edge in an applicability gap "
            "at context_anchor; adjacency alone does not establish reachability."
        ),
    )
    preparation_actions: List[SourceSnippet] = Field(
        default_factory=list,
        description=(
            "Source-backed preparation causally required by this target invocation, "
            "including configuration/auth file generation in helpers, cwd, environment "
            "and cleanup. Preserve conditional applicability; unrelated boot setup is excluded."
        ),
    )

    @model_validator(mode="after")
    def _validate_chain_endpoint(self):
        if self.initialization_chain[-1] != self.launch_site:
            raise ValueError(
                "initialization_chain must end with the exact launch_site"
            )
        return self


class LaunchRecipe(LaunchRecipeDraft):
    """Controller-validated launch recipe persisted for downstream use."""

    recipe_id: str = Field(
        min_length=1,
        description="Opaque identifier assigned by Controller and retained on reload.",
    )

    @model_validator(mode="after")
    def _validate_persisted_sources(self):
        if any(source.text.startswith("@source:") for source in
               [self.launch_site, self.context_anchor, *self.initialization_chain, *self.preparation_actions]):
            raise ValueError("Persisted launch evidence must materialize source identifiers")
        if self.context_anchor.position_key() not in {source.position_key() for source in self.initialization_chain}:
            raise ValueError("context_anchor must belong to the initialization_chain")
        return self


class AnalysisGap(StrictModel):
    """Missing facts about a candidate or an unrecovered launch reference."""

    kind: Literal["applicability", "semantics", "instance_data"] = Field(
        default="applicability", description="Missing invocation applicability, missing observable behavior, or an unknown concrete runtime value."
    )

    source: Optional[SourceSnippet] = Field(
        default=None,
        description="Verifiable candidate location when one is available.",
    )
    reason: str = Field(
        min_length=1,
        description=(
            "Specific missing evidence about invocation, initialization applicability "
            "or preparation. For a known recipe, identify the unresolved edge or effect "
            "without discarding its supported facts."
        ),
    )


class LaunchRecipeAnalysis(LaunchRecipeDraft):
    finding: FindingSemantics = Field(
        description=(
            "Environment semantics of this launch invocation, supported by its "
            "source snippets. Reference /launch_site, /context_anchor, /initialization_chain/N "
            "or /preparation_actions/N. reachability_refs support the complete initialization "
            "path and invocation guards; leave them empty when a required edge is unproved, "
            "and report an applicability gap at context_anchor. Known local behavior claims "
            "remain valid under their explicit conditions. Preserve numeric API arguments with their original "
            "base; any decimal/octal conversion must be exact, not a conventional permission "
            "or flag value. State the actual return-value guard admitting each preparation "
            "and distinguish an attempted effect from success when its return is unchecked. "
            "Describe established arguments, cwd/env "
            "and static preparation, conditional applicability and unknown values "
            "without choosing a recipe or assuming that launching a daemon succeeds."
        )
    )

    @model_validator(mode="after")
    def validate_finding(self):
        self.finding.validate_references(
            self.model_dump(mode="json"),
            allowed_roots=INIT_LAUNCH_EVIDENCE_ROOTS,
        )
        return self


class LaunchRecipeAgentOutput(StrictModel):
    """The only structured data authored by LaunchRecipeAgent."""

    revision_explanation: str | None = Field(
        default=None,
        description="When correcting a rejected response, explain any changed or withdrawn behavioral claims and the source basis or precise resulting gap. Locator-only corrections need no semantic revision explanation.",
    )

    launch_recipes: List[LaunchRecipeAnalysis] = Field(
        default_factory=list,
        description=(
            "All concrete invocations intended to start the selected service. "
            "Validation, status, stop and reload commands are excluded."
        ),
    )
    analysis_gaps: List[AnalysisGap] = Field(
        default_factory=list,
        description=(
            "Missing applicability, semantics or instance values for known recipes, "
            "and plausible launch references that could not be made concrete. "
            "Routine status, signal, log and comment hits are omitted."
        ),
    )


class LaunchCorrection(StrictModel):
    attempt: int = Field(ge=1)
    rejection_reason: str
    rejected_response: dict[str, Any] | None
    revision_explanation: str | None = None


class InitLaunchAnalysisResult(StrictModel):
    """Single source of truth persisted by InitLaunchAnalyzer."""

    execution: AnalysisExecution = Field(description="Execution outcome, independent of launch applicability and semantic gaps.")
    correction_history: list[LaunchCorrection] = Field(default_factory=list, description="Rejected structured responses and the explanation for each subsequent semantic revision; not accepted findings.")

    schema_version: Literal[7] = Field(description="InitLaunch result version; older formats are rejected.")
    phase: Literal["static", "full"] = Field(description="static collects initialization entries without Agent calls; full includes semantic launch analysis.")
    target_identity: TargetIdentity = Field(description="Selected target and its verified guest-path aliases.")
    finding_target: FindingTarget = Field(description="Controller-verified target bytes and guest path used by finding identity.")
    initialization_roots: List[str] = Field(description="Deterministically discovered firmware initialization entry paths.")
    planning_findings: PlanningFindings = Field(description="Environment semantic findings from the same launch analysis.")
    launch_recipes: Dict[str, LaunchRecipe] = Field(default_factory=dict, description="Controller-validated launch invocations keyed by stable recipe identity.")
    analysis_gaps: List[AnalysisGap] = Field(default_factory=list, description="Explicit missing launch or initialization evidence.")

    @model_validator(mode="after")
    def _validate_complete_result(self):
        self.execution.validate_phase(self.phase)
        if any(gap.source is not None and gap.source.text.startswith("@source:") for gap in self.analysis_gaps):
            raise ValueError("Persisted gap evidence must materialize source identifiers")
        if self.finding_target.path != self.target_identity.selected_rootfs_path:
            raise ValueError("finding target disagrees with selected target identity")
        if self.phase == "static" and (self.launch_recipes or self.planning_findings):
            raise ValueError("static InitLaunch only collects initialization entries and gaps")
        mismatched = [
            key
            for key, recipe in self.launch_recipes.items()
            if key != recipe.recipe_id
        ]
        if mismatched:
            raise ValueError(
                f"launch recipe keys do not match recipe_id: {mismatched}"
            )
        expected = {self.finding_target.ref("init_launch", key): key for key in self.launch_recipes}
        if set(self.planning_findings) != set(expected):
            raise ValueError("planning_findings must exactly cover launch_recipes")
        for ref, finding in self.planning_findings.items():
            key = expected[ref]
            recipe = self.launch_recipes[key]
            record = pointer("launch_recipes", key)
            if finding.domain != InitLaunchFindingDomain(
                kind="init_launch", recipe_id=key,
                preparation_refs=[pointer("launch_recipes", key, "preparation_actions", i)
                                  for i in range(len(recipe.preparation_actions))],
            ):
                raise ValueError("launch finding domain disagrees with its source recipe")
            if finding.boundary.kind != "environment" or finding.boundary.anchors != [
                FindingAnchor(kind="environment", ref=record + "/launch_site"),
                FindingAnchor(kind="environment", ref=record + "/context_anchor"),
            ]:
                raise ValueError("launch finding must anchor its source launch_site")
            validate_bound_finding(
                finding, record_ref=record, document=recipe.model_dump(mode="json"),
                allowed_roots=INIT_LAUNCH_EVIDENCE_ROOTS,
            )
        validate_finding_references(self.planning_findings, self.model_dump(mode="json"))
        return self
