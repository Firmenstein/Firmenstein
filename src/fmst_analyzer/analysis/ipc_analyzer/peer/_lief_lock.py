"""Process-wide lock serialising `lief.ELF.parse()` calls.

lief's parse() is not thread-safe; concurrent invocation from multiple
threads deadlocks inside the C++ core with ~40-60% probability (measured
on the R6700v3 rootfs, 1056 ELFs, 2-3 threads). Every call into
`lief.ELF.parse` from IPC peer-retrieval paths that may run concurrently (tool
dispatch via `asyncio.gather`, index builder) must acquire this lock.

Single-threaded parse over 1056 ELFs takes ~0.17s, so serialising
across 3 parallel agent tool calls (~0.5s total) is a negligible cost.
"""
import threading

LIEF_PARSE_LOCK = threading.Lock()
