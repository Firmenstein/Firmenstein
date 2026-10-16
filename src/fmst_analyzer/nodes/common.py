from functools import wraps
from loguru import logger
from enum import Flag, auto

class FunctionAttr(Flag):
    """Function's inherent base attributes — symbol-table facts that depend
    only on the owning binary, not on any cross-binary analysis view.

    Impl-resolution status (NO_IMPL / DEFAULT_LIB / RESOLVED_IN_SCOPE) is
    NOT a function attribute — it's a per-ADG view fact. Query it via
    ``ApiDepGraph.get_impl_status(func)`` instead.
    """
    EXTERNAL = auto()
    TEXT = auto()
    THUNK = auto()
    EXPORTED = auto()
    LOCAL = auto()
    PLT = auto()
    UNKNOWN = auto()

    def __str__(self):
        if not self:
            return "NONE"
        flags = []
        for flag in FunctionAttr:
            if self & flag:
                flags.append(flag.name)
        return " | ".join(flags)

    def __repr__(self):
        return f"FA.{str(self)}"