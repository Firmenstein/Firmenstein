"""Expose the running Python installation to the Planner's read-only shell."""
from pathlib import Path
import sys
import sysconfig


def evidence_python_runtime() -> tuple[dict, list[Path]]:
    """Use a canonical executable plus explicit packages, avoiding venv link hops."""
    roots = {Path(prefix).resolve() for prefix in
             (sys.prefix, sys.exec_prefix, sys.base_prefix, sys.base_exec_prefix)}
    executable = Path(sys.executable).resolve()
    packages = sorted({str(Path(sysconfig.get_path(key)).resolve()) for key in ("purelib", "platlib")})
    roots.update(Path(path) for path in packages)
    roots.add(executable.parent)
    # Resolving the executable bypasses the venv. Restore its package lookup
    # explicitly under isolated Python, without reading shell startup files.
    bootstrap = f"import sys; sys.path[:0] = {packages!r}; exec(sys.argv[1])"
    return {
        "command_prefix": [str(executable), "-I", "-B", "-c", bootstrap],
        "usage": "Append one quoted Python program as the next argument to this argv prefix. "
                 "Standard-library modules and installed lief are available for read-only byte, string and ELF inspection. "
                 "Do not depend on host strings, readelf or awk variants. "
                 "Map guest addresses through the ELF before reading file bytes. "
                 "This does not execute firmware; writes and network remain disabled.",
    }, sorted(roots)
