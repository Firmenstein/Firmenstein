"""Explicit synthetic contracts for offline Planner/Generator boundary tests."""
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import InterventionContract
from types import SimpleNamespace
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import BehaviorScope


def scopes_for_test(refs):
    return [BehaviorScope(finding_ref=ref, claim_indices=[0], applicability="The fixture's documented invocation context") for ref in refs]


def finding_resolver_for_test():
    return SimpleNamespace(finding_evidence=lambda ref: {"finding": {"claims": [{"statement": "Synthetic caller behavior."}]}})


def contract_for_test(operations):
    return InterventionContract(
        applicability=["Only the exact fixture anchor and its documented inputs"],
        owned_resources=["The source object in the fixture anchor"],
        operations=operations,
        state=["Per-invocation state unless an operation explicitly shares it"],
        native_fallback=["Preserve native behavior outside the fixture scope"],
        verification=["Verify each operation against the fixture caller"],
        allowed_refinement_scope=["Implementation within these fixture conditions"],
    )

from pathlib import Path
from fmst_analyzer.analysis.init_launch.analyzer_schema import LaunchRecipe, SourceSnippet
from fmst_analyzer.analysis.base.finding_binding import pointer
from fmst_analyzer.synthesizer.intervention_plan_analyzer.catalog import (
    PlanningTargetIdentity, FindingIndexEntry, SourceKind, SourceArtifact, PlanningEvidenceCatalog,
)
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    ResolvedCallsiteAnchor, LaunchChoice, InterventionUnitDraft, ResourceAnchor,
)

class _View:
    functions = {
        ("libnvram.so", 0x1000): "nvram_get",
        ("httpd", 0x2000): "start",
    }

    def get_decompiled_name(self, binary_name, function_ea):
        try:
            return self.functions[(Path(binary_name).name, function_ea)]
        except KeyError as error:
            raise ValueError("not found") from error

class _Resolver:
    def finding_evidence(self, finding_ref):
        return finding_resolver_for_test().finding_evidence(finding_ref)

    def evidence_identities(self, allowed_finding_refs):
        return {"resource-1", "ioctl-cs", "exit-cs"}

    def resolve_callsite(self, callsite_id, allowed_finding_refs):
        if callsite_id not in {"ioctl-cs", "exit-cs"}:
            raise ValueError("unknown callsite")
        return ResolvedCallsiteAnchor(
            callsite_id=callsite_id,
            binary_name="httpd",
            function_name="start",
            function_ea=0x2000,
            snapshot_hash="s" * 64,
            ctree_index=7,
            source_ea=0x2010,
            line_number=3,
            column_number=2,
            api_name="ioctl" if callsite_id == "ioctl-cs" else "exit",
        )

def _target():
    return PlanningTargetIdentity(
        target_basename="httpd",
        selected_rootfs_path="usr/sbin/httpd",
        executable_sha256="a" * 64,
        argv0="httpd",
        firmware_sha256="b" * 64,
    )

def _recipe():
    site = SourceSnippet(
        path="etc/init.d/S50httpd",
        location="line 12",
        text="/usr/sbin/httpd -C /etc/httpd.conf",
    )
    return LaunchRecipe(
        recipe_id="launch-test",
        launch_site=site,
        context_anchor=site,
        applicability="The initialization entry directly invokes the selected target.",
        executable_path="/usr/sbin/httpd",
        command_template=["/usr/sbin/httpd", "-C", "/etc/httpd.conf"],
        initialization_chain=[site],
    )

def _choice():
    return LaunchChoice(recipe_id="launch-test", reason="only candidate")

def _catalog(*finding_refs: str):
    refs = finding_refs or ("file:F1",)
    findings = {
        ref: FindingIndexEntry(
                 source_kind=SourceKind.FILE,
                 source_id="resource-1" if index == 0 else f"resource-{index + 1}",
                 summary="Resource behavior is required",
                 finding_ref=ref,
                 boundary_kind="resource",
                 anchor_keys=[],
                 evidence_refs=[],
                 source_locator=pointer("planning_findings", ref),
             )
        for index, ref in enumerate(refs)
    }
    artifacts = {
        kind: SourceArtifact(
                  source_kind=kind,
                  relative_path=f"{kind.value}.json",
                  schema_version=1,
                  phase="full",
                  content_sha256="0" * 64, provenance_sha256="0" * 64,
              )
        for kind in SourceKind
    }
    return PlanningEvidenceCatalog(
        target_identity=_target(),
        source_artifacts=artifacts,
        finding_index=findings,
        launch_candidates={"launch-test": _recipe()},
    )

def _pseudo_file_unit(*, contracts=None):
    return InterventionUnitDraft(
        behavior_scopes=scopes_for_test(["file:F1"]),
        strategy="pseudo_file",
        anchors=[ResourceAnchor(
            resource_kind="path",
            value="/dev/null",
            source_ref="file:F1",
        )],
        contract=contract_for_test(contracts or [
            "open allocates a valid descriptor at runtime",
            "write returns the supplied byte count",
            "read returns EOF",
            "close releases the descriptor lifecycle",
        ]),
        summary="Provide /dev/null file API behavior",
    )
