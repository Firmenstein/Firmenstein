"""Resolve normalized InterventionUnit anchors into IIB manifest entries."""

from __future__ import annotations

from fmst_analyzer.analysis.base.code_analyzer.analysis_view import AnalysisView
from fmst_analyzer.synthesizer.intervention_plan_analyzer.schema import (
    InterventionUnit,
    ResolvedCallsiteAnchor,
    ResolvedFunctionAnchor,
    ResourceAnchor,
)

from .shell import (
    ResolvedManifest,
    ResolvedManifestEntry,
    callsite_short_slug,
    slugify,
)


class AnchorResolutionError(RuntimeError):
    """Raised when a normalized plan Unit cannot be generated safely."""


def _callsite_resume_offset(
    view: AnalysisView,
    binary_name: str,
    function_ea: int,
    source_ea: int,
) -> int:
    """Resolve the instruction after an intercepted call from the IDA listing.

    MIPS calls have one architectural delay-slot instruction, so execution
    resumes at the second instruction after the call. ARM and x86 resume at
    the immediately following instruction. Reading instruction addresses from
    the persisted listing avoids assuming a fixed x86/Thumb instruction size.
    """
    try:
        resume_ea = view.get_callsite_resume_ea(
            binary_name,
            function_ea,
            source_ea,
        )
    except Exception as error:
        raise AnchorResolutionError(
            f"cannot resolve callsite resume for {binary_name}@0x{source_ea:x}"
        ) from error
    return _module_offset(view, binary_name, resume_ea)


def _module_offset(
    view: AnalysisView,
    binary_name: str,
    effective_address: int,
) -> int:
    try:
        image_base = view.get_binary_image_base(binary_name)
    except Exception as error:
        raise AnchorResolutionError(
            f"cannot resolve image base for {binary_name}"
        ) from error
    offset = effective_address - image_base
    if offset < 0:
        raise AnchorResolutionError(
            f"address 0x{effective_address:x} precedes {binary_name} image "
            f"base 0x{image_base:x}"
        )
    return offset


def resolve_units(
    units: list[InterventionUnit],
    view: AnalysisView,
) -> ResolvedManifest:
    entries: list[ResolvedManifestEntry] = []
    for unit in units:
        entries.extend(resolve_unit(unit, view).entries)
    return ResolvedManifest(entries=entries)


def resolve_unit(
    unit: InterventionUnit,
    view: AnalysisView,
) -> ResolvedManifest:
    entries: list[ResolvedManifestEntry] = []
    if unit.strategy == "function_stub":
        for anchor in unit.anchors:
            if not isinstance(anchor, ResolvedFunctionAnchor):
                raise AnchorResolutionError(
                    f"{unit.unit_id}: function_stub has a non-function anchor"
                )
            try:
                resolved_name = view.get_decompiled_name(
                    anchor.binary_name,
                    anchor.function_ea,
                )
            except Exception as error:
                raise AnchorResolutionError(
                    f"{unit.unit_id}: unknown function "
                    f"{anchor.binary_name}@0x{anchor.function_ea:x}"
                ) from error
            if not resolved_name:
                raise AnchorResolutionError(
                    f"{unit.unit_id}: unknown function "
                    f"{anchor.binary_name}@0x{anchor.function_ea:x}"
                )
            entries.append(ResolvedManifestEntry(
                unit_id=unit.unit_id,
                strategy="function_stub",
                binary=anchor.binary_name,
                offset=_module_offset(
                    view, anchor.binary_name, anchor.function_ea
                ),
                symbol_hint=anchor.function_name,
                entry_slug=slugify(anchor.function_name),
            ))
    elif unit.strategy == "callsite_hook":
        for anchor in unit.anchors:
            if not isinstance(anchor, ResolvedCallsiteAnchor):
                raise AnchorResolutionError(
                    f"{unit.unit_id}: callsite_hook has a non-callsite anchor"
                )
            if anchor.source_ea is None:
                raise AnchorResolutionError(
                    f"{unit.unit_id}: missing source_ea for {anchor.callsite_id}"
                )
            try:
                caller_name = view.get_decompiled_name(
                    anchor.binary_name,
                    anchor.function_ea,
                )
            except Exception as error:
                raise AnchorResolutionError(
                    f"{unit.unit_id}: unknown callsite binary/function "
                    f"{anchor.binary_name}@0x{anchor.function_ea:x}"
                ) from error
            if not caller_name:
                raise AnchorResolutionError(
                    f"{unit.unit_id}: unknown callsite binary/function "
                    f"{anchor.binary_name}@0x{anchor.function_ea:x}"
                )
            entries.append(ResolvedManifestEntry(
                unit_id=unit.unit_id,
                strategy="callsite_hook",
                binary=anchor.binary_name,
                offset=_module_offset(
                    view, anchor.binary_name, anchor.source_ea
                ),
                symbol_hint=(
                    f"{anchor.function_name}:ctree[{anchor.ctree_index}]:"
                    f"{anchor.api_name}"
                ),
                entry_slug=callsite_short_slug(anchor.callsite_id),
                callsite_id=anchor.callsite_id,
                resume_offset=_callsite_resume_offset(
                    view,
                    anchor.binary_name,
                    anchor.function_ea,
                    anchor.source_ea,
                ),
            ))
    elif unit.strategy == "pseudo_file":
        paths: list[str] = []
        for anchor in unit.anchors:
            if not isinstance(anchor, ResourceAnchor):
                raise AnchorResolutionError(
                    f"{unit.unit_id}: pseudo_file has a non-resource anchor"
                )
            if anchor.resource_kind == "path_pattern":
                raise AnchorResolutionError(
                    f"{unit.unit_id}: unsupported_path_pattern"
                )
            if anchor.resource_kind != "path":
                raise AnchorResolutionError(
                    f"{unit.unit_id}: pseudo_file requires exact path anchors"
                )
            paths.append(anchor.value)
        entries.append(ResolvedManifestEntry(
            unit_id=unit.unit_id,
            strategy="pseudo_file",
            pseudo_file_paths=list(dict.fromkeys(paths)),
        ))
    else:
        raise AnchorResolutionError(
            f"{unit.unit_id}: {unit.strategy} is not an execution strategy"
        )
    return ResolvedManifest(entries=entries)


__all__ = ["AnchorResolutionError", "resolve_unit", "resolve_units"]
