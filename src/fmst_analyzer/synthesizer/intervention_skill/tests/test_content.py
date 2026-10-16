"""Structural checks for the shared intervention-engineering skill bundle.

The skill is prose consumed by an Agent, not a machine-readable policy
schema.  These tests therefore protect packaging and navigation only; they do
not freeze wording, word counts, or a list of keywords.
"""

from fmst_analyzer.synthesizer.intervention_skill import (
    REHOSTING_PLANNING_SKILL,
)


def test_skill_bundle_is_valid_and_documents_are_nonempty():
    skill = REHOSTING_PLANNING_SKILL
    # Use the same frontmatter/link checks as provider dispatch. Reference
    # filenames and prose headings are not a separate test-owned contract.
    skill.validate_current()
    for path in skill.skill_dir.rglob("*.md"):
        assert path.read_text(encoding="utf-8").strip(), path
