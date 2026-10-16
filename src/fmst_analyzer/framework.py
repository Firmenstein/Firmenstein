"""Select one GuestWeave checkout for planning, authorship and execution."""

from pathlib import Path
import os

from fmst_basic.agent import AgentSkillSpec


def runtime_workspace(config=None) -> Path:
    selected = getattr(config, "runtime_workspace", None) or os.getenv("FMST_GUESTWEAVE_WORKSPACE")
    return Path(selected or Path(__file__).resolve().parents[1] / "fmst_iib_runtime").expanduser().resolve(strict=True)


def guestweave_skill(framework: Path) -> AgentSkillSpec:
    framework = Path(framework).resolve(strict=True)
    reference_paths = (
        "docs", "examples", "fmst-iib-api/src", "fmst-iib-runtime/src",
        "harness-arm", "harness-mips", "harness-x86", "dependencies", "patches", "docker",
        "tools", "THIRD_PARTY.md",
    )
    return AgentSkillSpec(name="guestweave-intervention-engineering",
        skill_dir=framework / "skills/intervention-engineering",
        reference_roots=tuple(framework / relative for relative in reference_paths
            if (framework / relative).exists()))


def framework_references(framework: Path) -> dict[str, str]:
    """Give task readers explicit locations from the selected checkout."""
    framework = Path(framework).resolve(strict=True)
    return {name: str(framework / path) for name, path in {
        "interventions": "docs/interventions.md", "abi": "docs/abi.md",
        "runtime": "docs/api.md", "build": "docs/build.md",
    }.items() if (framework / path).is_file()}
