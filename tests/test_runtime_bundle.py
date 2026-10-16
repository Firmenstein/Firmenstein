from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from fmst_analyzer.framework import runtime_workspace


def _load_bundle_module():
    path = runtime_workspace() / "tools" / "build_runtime_bundle.py"
    spec = importlib.util.spec_from_file_location("guestweave_bundle_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_framework_bundle_has_no_implicit_application_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_bundle_module()
    harness = tmp_path / "harness"
    harness.write_bytes(b"harness")
    bundle = tmp_path / "bundle"
    loader = tmp_path / "ld.so"
    loader.write_bytes(b"loader")
    copied: list[tuple[Path, Path]] = []

    monkeypatch.setattr(module, "_loader", lambda _binary: loader)
    monkeypatch.setattr(module, "_interpreter_path", lambda _binary: "/lib/ld.so")
    monkeypatch.setattr(module, "_dependencies", lambda _binary, _loader: {})
    monkeypatch.setattr(module.shutil, "copy2", lambda source, target: copied.append((source, target)))

    module.build_bundle(harness, bundle)

    assert (harness, bundle / "harness") in copied
    assert (loader, bundle / "ld.so") in copied
    assert {destination.name for _, destination in copied} == {"harness", "ld.so"}
    assert not (bundle / "harness-cli.version").exists()



def test_framework_bundle_accepts_only_explicit_extra_binaries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_bundle_module()
    harness = tmp_path / "harness"
    helper = tmp_path / "helper"
    harness.write_bytes(b"harness")
    helper.write_bytes(b"helper")
    bundle = tmp_path / "bundle"
    loader = tmp_path / "ld.so"
    loader.write_bytes(b"loader")
    copied: list[tuple[Path, Path]] = []

    monkeypatch.setattr(module, "_loader", lambda _binary: loader)
    monkeypatch.setattr(module, "_interpreter_path", lambda _binary: "/lib/ld.so")
    monkeypatch.setattr(module, "_dependencies", lambda _binary, _loader: {})
    monkeypatch.setattr(module.shutil, "copy2", lambda source, target: copied.append((source, target)))

    module.build_bundle(harness, bundle, binaries={"wait": helper})

    assert (helper, bundle / "wait") in copied
    assert "sh" not in {destination.name for _, destination in copied}


@pytest.mark.parametrize("value", ["/tmp/helper=/bin/sh", "helper", "= /bin/sh", "helper=relative"])
def test_binary_declaration_rejects_nonportable_destination(value: str) -> None:
    module = _load_bundle_module()
    with pytest.raises(module.argparse.ArgumentTypeError):
        module._parse_binary(value)
