"""Peer source feedback separates invalid identity from unavailable evidence tools."""
from hashlib import sha256
from types import SimpleNamespace

import pytest

from fmst_analyzer.analysis.base.output_validation import OutputValidationError
from fmst_analyzer.analysis.ipc_analyzer.agent_schema import PeerVerificationOutput
from fmst_analyzer.analysis.ipc_analyzer.peer_verification import (
    PeerVerificationAgent, _make_assembly_reader, _validate_published_source,
)


@pytest.fixture
def peer_source(tmp_path):
    rootfs = tmp_path / "rootfs"
    source = rootfs / "usr/bin/peer"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"\x7fELFsource-fixture")
    assembly = tmp_path / "assembly"
    path = assembly / "peer/entry.s"
    path.parent.mkdir(parents=True)
    path.write_text(
        f"; source_sha256: {sha256(source.read_bytes()).hexdigest()}\n"
        "; function: entry\n; symbol: entry\n; entry_ea: 0x1000\nNOP\n"
    )
    return rootfs, source, assembly, path


def reference(name="entry", ea=0x1000):
    return SimpleNamespace(binary_path="usr/bin/peer", function_name=name,
                           function_ea=ea, line_number=None)


@pytest.mark.parametrize("name", ["unknown", "invented_function"])
def test_unknown_peer_function_receives_correctable_location_feedback(peer_source, name):
    rootfs, _, assembly, _ = peer_source
    with pytest.raises(OutputValidationError, match="/peer_findings/7/evidence/0") as error:
        _validate_published_source(rootfs, assembly, reference(name, None),
                                   "/peer_findings/7/evidence/0",
                                   source_function_lookup=lambda path, symbol: None)
    assert name in str(error.value)


@pytest.mark.parametrize("name,ea", [("source_alias", 0x1000), ("real_import_without_listing", 0x2000)])
def test_native_source_identity_accepts_alias_or_function_without_own_listing(peer_source, name, ea):
    rootfs, _, assembly, _ = peer_source
    _validate_published_source(rootfs, assembly, reference(name, ea), "/evidence/0",
                               source_function_lookup=lambda path, symbol: SimpleNamespace(ea=ea))


def test_missing_listing_and_unavailable_index_is_not_model_error(peer_source):
    rootfs, _, assembly, _ = peer_source
    with pytest.raises(FileNotFoundError):
        _validate_published_source(rootfs, assembly, reference("unpublished"), "/evidence/0")


def test_peer_index_tool_failure_propagates(peer_source):
    rootfs, _, assembly, _ = peer_source
    def unavailable(path, symbol):
        raise OSError("source index cannot be read")
    with pytest.raises(OSError, match="source index cannot be read"):
        _validate_published_source(rootfs, assembly, reference("additional"), "/evidence/0",
                                   source_function_lookup=unavailable)


def test_wrong_function_entry_is_rejected_without_judging_claim(peer_source):
    rootfs, _, assembly, _ = peer_source
    with pytest.raises(OutputValidationError, match="function_ea=0x1004"):
        _validate_published_source(rootfs, assembly, reference(ea=0x1004), "/evidence/0")


def test_peer_feedback_keeps_all_invalid_source_locations(peer_source):
    rootfs, source, assembly, _ = peer_source
    result = PeerVerificationOutput.model_validate({"peer_findings": [{
        "executable_path": "usr/bin/peer", "argv0": None, "verdict": "rejected", "role": "unknown",
        "endpoint_locations": [{"binary_path": "usr/bin/peer", "function_name": "missing_a", "primitive": "bind"}],
        "summary": "Original observation remains unchanged.",
        "evidence": [{"claim": "Observed behavior", "binary_path": "usr/bin/peer", "function_name": name}
                     for name in ["missing_b", "missing_c"]],
        "missing_evidence": [],
    }]})
    before = result.model_dump_json()
    with pytest.raises(OutputValidationError) as error:
        PeerVerificationAgent._validate_output(
            result, channel=SimpleNamespace(endpoints=[]),
            firmware_index=SimpleNamespace(elf_kind={source: "exec"}), rootfs=rootfs,
            candidate_paths={"usr/bin/peer"},
            assembly_root=assembly, source_function_lookup=lambda path, symbol: None,
        )
    for field in ["endpoint_locations/0", "evidence/0", "evidence/1"]:
        assert f"/peer_findings/0/{field}" in str(error.value)
    assert result.model_dump_json() == before


def test_peer_reader_accepts_absolute_published_path_and_rejects_escape(peer_source):
    _, source, assembly, path = peer_source
    reader = _make_assembly_reader(assembly, {"peer/entry.s"})
    assert "entry_ea: 0x1000" in reader.invoke({"path": str(path)})
    assert "escapes" in reader.invoke({"path": str(source)})
