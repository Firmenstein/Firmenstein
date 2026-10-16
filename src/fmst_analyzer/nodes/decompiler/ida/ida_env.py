"""Pin IDA's pseudocode rendering for Firmenstein, and prove that it is pinned.

IDA 9.4 introduced ``ARG_HINTS_MODE`` in ``cfg/hexrays.cfg``, defaulting to
``HAHM_INLAY``.  With it, Hex-Rays renders argument names at the callsite::

    return leaf(value: value + 1);          # 9.4 default
    return leaf(value + 1);                 # 9.2 and earlier

Firmenstein locates a call expression inside the pseudocode text with a
verbatim substring match and derives the published ``column_number`` from the
position of that match.  The injected ``"value: "`` both defeats the match and
shifts every column after it, and because long calls wrap onto extra lines it
also shifts ``line_number`` for every function that follows.  The same text
feeds ``raw_pseudocode_hash``/``rendered_code_hash``, so the snapshot identity
becomes renderer-dependent.

The setting is unreachable from IDA's Python API and lives in a machine-wide
file that also drives the GUI, so it cannot be toggled per call.  Instead this
module redirects IDA's resource lookup **for this process** through
``$IDAUSR``: the real user directory stays first, so ``ida.reg``/licence and
personal settings keep working, and a Firmenstein-owned directory carrying
``cfg/hexrays.cfg`` follows it.  Users opening IDA normally are unaffected and
keep the vendor default.

When the selected installation's ``hexrays.cfg`` has no argument-hint setting,
the scoped file contains only a comment.  Older Hex-Rays versions reject the
9.4-only keyword even though they do not need the rendering override.

IDA snapshots ``$IDAUSR`` while ``idapro`` initialises its native bindings, so
:func:`prepare_ida_environment` must run *before* ``import idapro`` -- the
``ida`` package ``__init__`` does that.  :func:`require_argument_hints_disabled`
turns a later configuration drift into a loud failure instead of silently
emitting hint-polluted snapshots.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import List, Optional

__all__ = [
    "argument_hints_mode",
    "ensure_scope",
    "prepare_ida_environment",
    "repository_root",
    "require_argument_hints_disabled",
    "scope_dir",
]

SCOPE_ENV_VAR = "IDAUSR"
SCOPE_DIR_NAME = "ida-no-arg-hints"
_OVERRIDE_RELATIVE = Path("cfg") / "hexrays.cfg"
DISABLED_MODE = "HAHM_DISABLED"

_OVERRIDE_CONTENT = """\
/* Firmenstein-scoped IDA configuration.
 *
 * IDA 9.4 defaults to argument name hints in calls (ARG_HINTS_MODE =
 * HAHM_INLAY), which injects "name: " into pseudocode text and breaks
 * Firmenstein's expression_text / column_number / line_number.  This file is
 * reached through $IDAUSR only, so a normal IDA session keeps the default.
 * See fmst_analyzer.nodes.decompiler.ida.ida_env for the full rationale.
 */
ARG_HINTS_MODE = HAHM_DISABLED
"""

_PRE_HINTS_CONTENT = """\
/* The selected Hex-Rays installation has no argument-name-hint setting.
 * Keep this scoped file free of keywords unsupported by that installation.
 * Switching to an installation with argument hints restores the override.
 */
"""

_SETTING_RE = re.compile(r"^\s*ARG_HINTS_MODE\s*=\s*([A-Za-z_][A-Za-z_0-9]*)")

#: Set when the scope had to be added after ``idapro`` was already imported,
#: i.e. after IDA had resolved ``$IDAUSR``.  The files then look correct while
#: the running IDA is not, so the guard has to distrust them.
_pin_applied_late = False


def repository_root() -> Path:
    """Locate the checkout root that owns this package.

    Identified by ``src/pyproject.toml`` so the scope directory lands inside
    the checkout (and therefore inside its git ignore rules) rather than in a
    site-packages tree.
    """
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "src" / "pyproject.toml").is_file():
            return parent
    return here.parents[5]


def scope_dir() -> Path:
    """The Firmenstein-owned IDA user directory holding the override."""
    return repository_root() / ".fmst" / SCOPE_DIR_NAME


def ensure_scope() -> Path:
    """Create or refresh the scoped override; returns the scope directory."""
    root = scope_dir()
    target = root / _OVERRIDE_RELATIVE
    content = _PRE_HINTS_CONTENT if _installation_has_argument_hints() is False else _OVERRIDE_CONTENT
    if not target.is_file() or target.read_text(encoding="utf-8") != content:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return root


def _user_directories() -> List[Path]:
    """IDA user directories, mirroring ``ida_diskio.get_user_idadir``."""
    raw = os.environ.get(SCOPE_ENV_VAR, "")
    directories = [Path(part).expanduser() for part in raw.split(os.pathsep) if part.strip()]
    return directories or [Path.home() / ".idapro"]


def prepare_ida_environment() -> str:
    """Make this process read the scoped override; returns the new ``$IDAUSR``.

    Idempotent, and must run before ``import idapro``.  If IDA has already
    imported by the time the scope is first added, the pin cannot have taken
    effect for this process; that is remembered so
    :func:`require_argument_hints_disabled` can say so instead of trusting the
    configuration files.
    """
    global _pin_applied_late
    scope = ensure_scope().resolve()
    directories = _user_directories()
    if not any(scope == directory.resolve() for directory in directories):
        if "idapro" in sys.modules:
            _pin_applied_late = True
        directories.append(scope)
    value = os.pathsep.join(str(directory) for directory in directories)
    os.environ[SCOPE_ENV_VAR] = value
    return value


def _configuration_files() -> List[Path]:
    """Candidate ``hexrays.cfg`` files, in IDA's own search order."""
    files: List[Path] = []
    for directory in _user_directories():
        files.append(directory / "hexrays.cfg")
        files.append(directory / "cfg" / "hexrays.cfg")
    indir = os.environ.get("IDADIR")
    if indir:
        files.append(Path(indir).expanduser() / "cfg" / "hexrays.cfg")
    return files


def _defined_mode(path: Path) -> Optional[str]:
    """The ``ARG_HINTS_MODE`` a single file defines, ignoring comments."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    in_block_comment = False
    for line in text.splitlines():
        if in_block_comment:
            if "*/" in line:
                in_block_comment = False
            continue
        stripped = line.strip()
        if stripped.startswith("/*"):
            in_block_comment = "*/" not in stripped
            continue
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        match = _SETTING_RE.match(line)
        if match:
            return match.group(1)
    return None


def _installation_has_argument_hints() -> Optional[bool]:
    """Read support before native imports; unknown installations keep the pin."""
    indir = os.environ.get("IDADIR")
    if not indir:
        return None
    path = Path(indir).expanduser() / "cfg" / "hexrays.cfg"
    try:
        path.read_text(encoding="utf-8")
    except OSError:
        return None
    return _defined_mode(path) is not None


def argument_hints_mode() -> Optional[str]:
    """The ``ARG_HINTS_MODE`` IDA will apply, or ``None`` before IDA 9.4.

    IDA takes the first value it finds while walking the user directories and
    then ``$IDADIR/cfg``; a file that exists without defining the setting does
    not shadow a later definition.
    """
    if _installation_has_argument_hints() is False:
        return None
    for path in _configuration_files():
        mode = _defined_mode(path)
        if mode is not None:
            return mode
    return None


def require_argument_hints_disabled() -> None:
    """Fail loudly when IDA would render argument-name hints into our text."""
    if _installation_has_argument_hints() is False:
        return
    if _pin_applied_late:
        raise RuntimeError(
            "The argument-name-hint pin was applied after `import idapro`, and "
            "IDA resolves $IDAUSR only while loading its native bindings, so "
            f"the running IDA is not reading {scope_dir()}.  Load the repository "
            ".env or import fmst_analyzer's IDA package before `import idapro`."
        )
    mode = argument_hints_mode()
    if mode is None or mode == DISABLED_MODE:
        return
    raise RuntimeError(
        f"IDA would render argument-name hints (ARG_HINTS_MODE = {mode}), which "
        "corrupts Firmenstein's expression_text, column_number and line_number. "
        f"Firmenstein pins {DISABLED_MODE} through the scoped IDA user directory "
        f"{scope_dir()} listed in ${SCOPE_ENV_VAR}.  Load the repository .env "
        "(which sets it) or call prepare_ida_environment() before `import idapro`."
    )
