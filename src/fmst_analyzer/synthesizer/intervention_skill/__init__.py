"""Firmenstein planning policy and stage-specific application contracts."""

from pathlib import Path
import hashlib
import json

from fmst_basic.agent import AgentSkillSpec


_BUNDLE_ROOT = Path(__file__).parent / "bundle"
APPLICATION_REFERENCES = Path(__file__).parent / "references"
CANDIDATE_ENGINEERING = APPLICATION_REFERENCES / "candidate-engineering.md"

REHOSTING_PLANNING_SKILL = AgentSkillSpec(
    name="rehosting-planning",
    plugin_root=_BUNDLE_ROOT,
    skill_dir=_BUNDLE_ROOT / "skills" / "rehosting-planning",
)
APPLICATION_CONTRACT = REHOSTING_PLANNING_SKILL.skill_dir / "references/application-contract.md"
APPLICATION_READ_ROOTS = (APPLICATION_REFERENCES, APPLICATION_CONTRACT.parent)


def application_guidance(stage: str) -> str:
    files = [APPLICATION_CONTRACT]
    if stage in {"generation", "runtime-refinement"}:
        files.append(CANDIDATE_ENGINEERING)
    if stage in {"generation", "environment-generation", "runtime-refinement"}:
        files.append(APPLICATION_REFERENCES / f"{stage}.md")
    return "Read the supplied Firmenstein application contracts for this stage:\n" + json.dumps([
        {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in files
    ], indent=2)


__all__ = ["REHOSTING_PLANNING_SKILL", "APPLICATION_REFERENCES", "APPLICATION_CONTRACT", "CANDIDATE_ENGINEERING",
           "APPLICATION_READ_ROOTS", "application_guidance"]
