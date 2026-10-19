"""Process-local descriptor capacity for native SDK subprocesses."""
from __future__ import annotations

import resource

NATIVE_FD_SOFT_LIMIT = 65536


def prepare_native_fd_limit() -> dict[str, int]:
    """Raise only this worker's soft NOFILE within its existing hard limit.

    Called at native SDK startup, never at import or by static analysis.
    This fixes a low inherited limit; it neither proves capacity nor hides leaks.
    """
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    requested = NATIVE_FD_SOFT_LIMIT if hard == resource.RLIM_INFINITY else min(NATIVE_FD_SOFT_LIMIT, hard)
    if soft != resource.RLIM_INFINITY and requested > soft:
        resource.setrlimit(resource.RLIMIT_NOFILE, (requested, hard))
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    return {"soft": soft, "hard": hard}
