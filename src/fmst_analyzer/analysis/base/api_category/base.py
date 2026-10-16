from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import List, Optional, Set


class APICategory(Enum):
    """API resource categories."""
    FILE = auto()
    NETWORK = auto()
    IPC = auto()
    PROCESS = auto()
    RUNTIME = auto()
    THREAD = auto()
    APPLICATION = auto()


class BaseResourceOps(ABC):
    """
    Base class for resource operations.

    Provides predefined API lists for each resource category.
    Each subclass defines create_predefined and info_predefined lists
    for its domain.
    """

    @property
    @abstractmethod
    def create_predefined(self) -> List[str]:
        """Predefined APIs that create new resource instances (return a handle)."""

    @property
    @abstractmethod
    def info_predefined(self) -> List[str]:
        """Predefined APIs that carry key info or query resource state."""

    def get_all_predefined_apis(self) -> List[str]:
        """Get combined list of all predefined APIs."""
        return self.create_predefined + self.info_predefined


_ALL_RESOURCE_PREDEFINED: Optional[Set[str]] = None


def get_all_predefined_resource_apis() -> Set[str]:
    """
    Returns a cached set of ALL predefined resource API names
    across all categories (FILE, IPC, NETWORK, PROCESS, RUNTIME, THREAD, APPLICATION).

    Used by the initial passes to filter known resource APIs out of LLM candidates.
    """
    global _ALL_RESOURCE_PREDEFINED
    if _ALL_RESOURCE_PREDEFINED is None:
        from .file import FileResourceOps
        from .ipc import IPCResourceOps
        from .network import NetworkResourceOps
        from .process import ProcessResourceOps
        from .runtime import RuntimeResourceOps
        from .thread import ThreadResourceOps
        from .application import ApplicationResourceOps

        _ALL_RESOURCE_PREDEFINED = set()
        for ops_class in [
            FileResourceOps, IPCResourceOps, NetworkResourceOps,
            ProcessResourceOps, RuntimeResourceOps, ThreadResourceOps,
            ApplicationResourceOps,
        ]:
            ops = ops_class()
            _ALL_RESOURCE_PREDEFINED.update(ops.get_all_predefined_apis())

    return _ALL_RESOURCE_PREDEFINED
