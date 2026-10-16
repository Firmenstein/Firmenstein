"""Source-backed baseline for design planning, separate from runtime evidence."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from fmst_analyzer.framework import guestweave_skill, runtime_workspace as default_workspace
from fmst_analyzer.synthesizer.intervention_skill import REHOSTING_PLANNING_SKILL


class BaselineSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    relative_path: str
    file_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symbol: str | None
    text: str


class PlanningContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_level: Literal["implementation"]
    implementation_sources: dict[str, BaselineSource]
    runtime_observations: list[str]
    limitations: list[str]


def build_planning_context(runtime_workspace: Path | None = None) -> PlanningContext:
    """Read the actual launch/staging code, public IIB API and capabilities.

    No binary is executed. These sources explain the intended baseline; they
    neither establish target-specific topology nor certify runtime conformance.
    """
    src = Path(__file__).resolve().parents[3]
    framework = Path(runtime_workspace).resolve(strict=True) if runtime_workspace else default_workspace()
    sources = {}
    relative = "fmst_analyzer/runner/docker_sandbox.py"
    path = src / relative
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    module = ast.parse(text)
    symbols = {node.name: node for node in module.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
    cls = symbols["DockerRootfsSandbox"]
    for node in cls.body:
        if isinstance(node, ast.FunctionDef):
            symbols[f"DockerRootfsSandbox.{node.name}"] = node
    for name in ("_harness_arguments", "_container_runtime_mounts",
                 "DockerRootfsSandbox.update_rootfs_actions", "DockerRootfsSandbox.run_attempt"):
        sources[name] = BaselineSource(relative_path=relative,
            file_sha256=hashlib.sha256(raw).hexdigest(), symbol=name,
            text=ast.get_source_segment(text, symbols[name]))
    for key, relative in {
        "runtime_capability_declarations": "fmst_iib_runtime/fmst-iib-runtime/src/capabilities.rs",
        "iib_capability_identifiers": "fmst_iib_runtime/fmst-iib-api/src/capability.rs",
        "iib_context_api": "fmst_iib_runtime/fmst-iib-api/src/context.rs",
        "iib_pseudo_file_api": "fmst_iib_runtime/fmst-iib-api/src/pseudo_file.rs",
        "iib_native_call_implementation": "fmst_iib_runtime/fmst-iib-runtime/src/native_call.rs",
    }.items():
        raw = (framework / Path(relative).relative_to("fmst_iib_runtime")).read_bytes()
        sources[key] = BaselineSource(relative_path=relative,
            file_sha256=hashlib.sha256(raw).hexdigest(), symbol=None, text=raw.decode("utf-8"))
    for namespace, skill in (("planning", REHOSTING_PLANNING_SKILL),
                            ("guestweave", guestweave_skill(framework))):
        for path in skill.source_files:
            if path.suffix != ".md":
                continue
            relative = ("fmst_iib_runtime/" + path.relative_to(framework).as_posix()
                        if namespace == "guestweave" else path.relative_to(src).as_posix())
            raw = path.read_bytes()
            sources[f"{namespace}:{relative}"] = BaselineSource(relative_path=relative,
                file_sha256=hashlib.sha256(raw).hexdigest(), symbol=None, text=raw.decode("utf-8"))
    return PlanningContext(
        evidence_level="implementation", implementation_sources=sources, runtime_observations=[],
        limitations=[
            "These are implementation sources, not a runtime conformance result for this target.",
            "No firmware device state, LAN/WAN topology, active peers, or launch guard values have been observed.",
            "Runtime capability declarations identify intended support; target-specific ABI and behavior still require verification.",
        ],
    )


def validate_planning_context(context: PlanningContext, runtime_workspace: Path | None = None) -> None:
    if context != build_planning_context(runtime_workspace):
        raise ValueError("Plan baseline/capability source content changed; rerun intervention-plan")
