"""Offline coverage for the IDA argument-name-hint pin.

These tests exercise the configuration resolver only; no IDA installation or
native backend is required.  See ``ida_env`` for why the pin exists.
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from fmst_analyzer.nodes.decompiler.ida import ida_env


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Isolate the scoped directory, the IDA environment and the ordering flag.

    ``$IDAUSR`` starts out already listing the scope, which is how the
    repository ``.env`` deploys it.  ``_pin_applied_late`` is process-wide, so
    it is reset here as well; a session that already imported ``idapro`` would
    otherwise leak its ordering verdict into every resolver test.
    """
    userdir = tmp_path / "userdir"
    userdir.mkdir()
    idadir = tmp_path / "idadir"
    (idadir / "cfg").mkdir(parents=True)
    scope = tmp_path / "ida-no-arg-hints"

    monkeypatch.setattr(ida_env, "scope_dir", lambda: scope)
    monkeypatch.setattr(ida_env, "_pin_applied_late", False)
    monkeypatch.setenv("IDAUSR", f"{userdir}{os.pathsep}{scope}")
    monkeypatch.setenv("IDADIR", str(idadir))
    return SimpleNamespace(userdir=userdir, idadir=idadir, scope=scope)


def test_prepare_writes_the_override_and_pins_the_mode(env):
    assert ida_env.argument_hints_mode() is None

    value = ida_env.prepare_ida_environment()

    override = env.scope / "cfg" / "hexrays.cfg"
    assert override.is_file()
    assert ida_env.DISABLED_MODE in override.read_text(encoding="utf-8")
    assert value.split(os.pathsep) == [str(env.userdir), str(env.scope)]
    assert ida_env.argument_hints_mode() == ida_env.DISABLED_MODE


def test_prepare_keeps_the_real_user_directory_first_and_is_idempotent(env):
    first = ida_env.prepare_ida_environment()
    second = ida_env.prepare_ida_environment()

    assert first == second
    assert first.split(os.pathsep)[0] == str(env.userdir)
    assert first.count(ida_env.SCOPE_DIR_NAME) == 1


def test_prepare_appends_the_scope_when_it_is_absent(env, monkeypatch):
    monkeypatch.setenv("IDAUSR", str(env.userdir))

    value = ida_env.prepare_ida_environment()

    assert value.split(os.pathsep) == [str(env.userdir), str(env.scope)]


def test_the_scope_outranks_the_installation_default(env):
    (env.idadir / "cfg" / "hexrays.cfg").write_text(
        "ARG_HINTS_MODE = HAHM_INLAY\n", encoding="utf-8"
    )

    ida_env.prepare_ida_environment()

    assert ida_env.argument_hints_mode() == ida_env.DISABLED_MODE
    ida_env.require_argument_hints_disabled()


def test_guard_accepts_a_pre_9_4_configuration(env):
    """IDA before 9.4 has no such setting, so there is nothing to pin."""
    ida_env.require_argument_hints_disabled()


def test_pre_9_4_scope_omits_the_unsupported_keyword(env):
    ida_env.prepare_ida_environment()
    assert "ARG_HINTS_MODE" in (env.scope / "cfg" / "hexrays.cfg").read_text()
    (env.idadir / "cfg" / "hexrays.cfg").write_text("// Pre-9.4 decompiler settings.\n")

    ida_env.prepare_ida_environment()

    override = env.scope / "cfg" / "hexrays.cfg"
    assert "ARG_HINTS_MODE" not in override.read_text()
    assert ida_env.argument_hints_mode() is None
    ida_env.require_argument_hints_disabled()


def test_scope_restores_the_pin_when_switching_to_argument_hint_support(env):
    install_config = env.idadir / "cfg" / "hexrays.cfg"
    install_config.write_text("// Pre-9.4 decompiler settings.\n")
    ida_env.prepare_ida_environment()

    install_config.write_text("ARG_HINTS_MODE = HAHM_INLAY\n")
    ida_env.prepare_ida_environment()

    assert ida_env.argument_hints_mode() == ida_env.DISABLED_MODE
    assert "ARG_HINTS_MODE" in (env.scope / "cfg" / "hexrays.cfg").read_text()
    ida_env.require_argument_hints_disabled()


def test_guard_rejects_a_user_level_override(env):
    (env.userdir / "hexrays.cfg").write_text(
        "ARG_HINTS_MODE = HAHM_INLAY\n", encoding="utf-8"
    )
    ida_env.prepare_ida_environment()

    assert ida_env.argument_hints_mode() == "HAHM_INLAY"
    with pytest.raises(RuntimeError, match="ARG_HINTS_MODE = HAHM_INLAY"):
        ida_env.require_argument_hints_disabled()


def test_commented_settings_do_not_shadow_the_scope(env):
    (env.userdir / "hexrays.cfg").write_text(
        "// ARG_HINTS_MODE = HAHM_INLAY\n/* ARG_HINTS_MODE = HAHM_INLAY */\n",
        encoding="utf-8",
    )

    ida_env.prepare_ida_environment()

    assert ida_env.argument_hints_mode() == ida_env.DISABLED_MODE


def test_guard_reports_a_pin_applied_after_ida_was_imported(env, monkeypatch):
    """The files can look right while the running IDA is already latched."""
    monkeypatch.setenv("IDAUSR", str(env.userdir))
    monkeypatch.setitem(sys.modules, "idapro", object())

    ida_env.prepare_ida_environment()

    assert ida_env._pin_applied_late is True
    assert ida_env.argument_hints_mode() == ida_env.DISABLED_MODE
    with pytest.raises(RuntimeError, match="after `import idapro`"):
        ida_env.require_argument_hints_disabled()


def test_an_already_listed_scope_is_not_reported_as_late(env, monkeypatch):
    """The repository .env path: the scope is on $IDAUSR before IDA loads."""
    monkeypatch.setitem(sys.modules, "idapro", object())

    ida_env.prepare_ida_environment()

    assert ida_env._pin_applied_late is False
    ida_env.require_argument_hints_disabled()


def test_repository_root_is_a_checkout():
    assert (ida_env.repository_root() / "src" / "pyproject.toml").is_file()
