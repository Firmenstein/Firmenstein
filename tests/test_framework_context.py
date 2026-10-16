from pathlib import Path
from types import SimpleNamespace
import hashlib
import shutil

import pytest

from fmst_analyzer.framework import guestweave_skill, runtime_workspace
from fmst_analyzer.synthesizer.intervention_plan_analyzer.planning_context import (
    build_planning_context, validate_planning_context,
)


@pytest.fixture
def external_framework(tmp_path):
    source = runtime_workspace()
    destination = tmp_path / "renamed-source-package"
    shutil.copytree(source, destination,
        ignore=shutil.ignore_patterns("tmp", "target", ".git", "__pycache__"))
    return destination


def test_selected_framework_controls_api_and_knowledge_identity(external_framework):
    selected = runtime_workspace(SimpleNamespace(runtime_workspace=external_framework))
    api = selected / "fmst-iib-api/src/context.rs"
    api.write_text(api.read_text() + "\n// selected external API snapshot\n")
    context = build_planning_context(selected)
    assert context.implementation_sources["iib_context_api"].file_sha256 == hashlib.sha256(api.read_bytes()).hexdigest()
    validate_planning_context(context, selected)
    (selected / "docs/abi.md").write_text((selected / "docs/abi.md").read_text() + "\nChanged contract.\n")
    with pytest.raises(ValueError, match="source content changed"):
        validate_planning_context(context, selected)


def test_relocating_identical_framework_keeps_content_identity(external_framework):
    source = runtime_workspace()
    original = guestweave_skill(source)
    copied = guestweave_skill(external_framework)
    assert copied.content_sha256 == original.content_sha256
    assert copied.skill_file != original.skill_file
    api = external_framework / "fmst-iib-api/src/context.rs"
    api.write_text(api.read_text() + "\n// contract source changed\n")
    with pytest.raises(ValueError, match="content changed"):
        copied.validate_current()


def test_missing_selected_framework_does_not_fall_back(tmp_path):
    with pytest.raises(FileNotFoundError):
        runtime_workspace(SimpleNamespace(runtime_workspace=tmp_path / "absent"))
