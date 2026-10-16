"""Load the native backend only when requested; text rendering stays portable.

Importing this package also pins the IDA user-directory override that keeps
pseudocode free of argument-name hints (see :mod:`~.ida_env`).  That has to
happen before any submodule runs ``import idapro``, because IDA resolves
``$IDAUSR`` once, while the native bindings load.  Setting it does not import
the native backend, so the lazy-loading contract above is preserved.
"""

from importlib import import_module

from .ida_env import prepare_ida_environment

prepare_ida_environment()


def __getattr__(name):
    modules = {
        "IDABinary": "ida_binary",
        "IDAFunction": "ida_function",
        "IDBManager": "idb_manager",
    }
    if name not in modules:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{modules[name]}"), name)
