import hashlib
from types import SimpleNamespace

import pytest

from fmst_analyzer.runner.launch import admit_launch_proposal
from fmst_analyzer.runner.schema import RunnerDecision, RuntimeLaunchProposal, LaunchEvidence


@pytest.fixture
def proposal_input(tmp_path):
    root = tmp_path / "rootfs"
    root.mkdir()
    binary = root / "guest"
    binary.write_bytes(b"\x7fELFcontrolled-fixture")
    source = root / "rc"
    source.write_text("/guest --serve\n")
    identity = SimpleNamespace(selected_rootfs_path="guest", executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    proposal = RuntimeLaunchProposal(executable_path="/guest", args=["--serve"], working_directory="/", environment={},
        evidence=[LaunchEvidence(path=str(source), sha256=hashlib.sha256(source.read_bytes()).hexdigest(), excerpt="/guest --serve")],
        rationale="fixture invocation", limitations=["Runtime success unproved"])
    decision = RunnerDecision(action="run", browser_origin="http://guest/", guest_args=["--serve"], launch_proposal=proposal, summary="fixture")
    return decision, dict(target_identity=identity, rootfs=root, readable_roots=[root], check_budget=lambda: None), source


def test_launch_admission_preserves_sources_and_binds_execution(proposal_input):
    decision, args, source = proposal_input
    before = source.read_bytes()
    record = admit_launch_proposal(decision, **args)
    assert record.recipe_id.startswith("runtime-launch:")
    assert record.original_recipe_id is None
    assert record.proposal.args == decision.guest_args
    assert source.read_bytes() == before
    assert record.model_validate_json(record.model_dump_json()) == record


@pytest.mark.parametrize("fault", ["missing", "target", "digest", "excerpt", "argv", "outside", "elf"])
def test_launch_admission_rejects_unbound_or_substituted_inputs(proposal_input, fault, tmp_path):
    decision, args, source = proposal_input
    if fault == "missing": decision.launch_proposal = None
    elif fault == "target": decision.launch_proposal.executable_path = "/other"
    elif fault == "digest": decision.launch_proposal.evidence[0].sha256 = "0" * 64
    elif fault == "excerpt": decision.launch_proposal.evidence[0].excerpt = "invented evidence"
    elif fault == "argv": decision.guest_args = ["different"]
    elif fault == "outside":
        other = tmp_path / "other"; other.write_bytes(source.read_bytes())
        decision.launch_proposal.evidence[0].path = str(other)
    elif fault == "elf": (args['rootfs'] / 'guest').write_bytes(b'changed ELF')
    with pytest.raises(RuntimeError): admit_launch_proposal(decision, **args)
