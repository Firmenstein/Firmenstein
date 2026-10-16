"""Versioned Linux interaction API registry for IPCAnalyzer.

The registry encodes ABI-level participation points only.  It contains no
vendor paths, daemon names, or firmware-specific classification rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .schema import IPCMechanism


INTERACTION_REGISTRY_VERSION = 2


class InteractionRole(str, Enum):
    """Whether an API can identify a resource or only operates on one."""

    RESOURCE_ANCHOR = "resource_anchor"
    FALLBACK_ACCESSOR = "fallback_accessor"
    AUXILIARY = "auxiliary"


@dataclass(frozen=True)
class InteractionAPI:
    family: str
    mechanism_hint: IPCMechanism
    purpose: str
    role: InteractionRole


def _entries(
    family: str,
    mechanism: IPCMechanism,
    purpose: str,
    role: InteractionRole,
    *names: str,
) -> dict[str, InteractionAPI]:
    return {
        name: InteractionAPI(
            family=family,
            mechanism_hint=mechanism,
            purpose=purpose,
            role=role,
        )
        for name in names
    }


_REGISTRY: dict[str, InteractionAPI] = {}
_REGISTRY.update(_entries(
    "sysv_shm", IPCMechanism.SYSV_SHM,
    "Create or obtain a System V shared-memory segment by key.",
    InteractionRole.RESOURCE_ANCHOR, "shmget",
))
_REGISTRY.update(_entries(
    "sysv_shm", IPCMechanism.SYSV_SHM,
    "Attach a segment when no getter anchor is visible.",
    InteractionRole.FALLBACK_ACCESSOR, "shmat",
))
_REGISTRY.update(_entries(
    "sysv_shm", IPCMechanism.SYSV_SHM,
    "Operate on an already identified shared-memory segment.",
    InteractionRole.AUXILIARY, "shmdt", "shmctl",
))
_REGISTRY.update(_entries(
    "sysv_message_queue", IPCMechanism.SYSV_MSG,
    "Create or obtain a System V message queue by key.",
    InteractionRole.RESOURCE_ANCHOR, "msgget",
))
_REGISTRY.update(_entries(
    "sysv_message_queue", IPCMechanism.SYSV_MSG,
    "Access a queue when no getter anchor is visible.",
    InteractionRole.FALLBACK_ACCESSOR, "msgsnd", "msgrcv",
))
_REGISTRY.update(_entries(
    "sysv_message_queue", IPCMechanism.SYSV_MSG,
    "Control an already identified message queue.",
    InteractionRole.AUXILIARY, "msgctl",
))
_REGISTRY.update(_entries(
    "sysv_semaphore", IPCMechanism.SYSV_SEM,
    "Create or obtain a System V semaphore set by key.",
    InteractionRole.RESOURCE_ANCHOR, "semget",
))
_REGISTRY.update(_entries(
    "sysv_semaphore", IPCMechanism.SYSV_SEM,
    "Access a semaphore set when no getter anchor is visible.",
    InteractionRole.FALLBACK_ACCESSOR, "semop", "semtimedop",
))
_REGISTRY.update(_entries(
    "sysv_semaphore", IPCMechanism.SYSV_SEM,
    "Control an already identified semaphore set.",
    InteractionRole.AUXILIARY, "semctl",
))
_REGISTRY.update(_entries(
    "sysv_key", IPCMechanism.UNKNOWN,
    "Construct a symbolic System V IPC key from a path and project id.",
    InteractionRole.AUXILIARY, "ftok",
))
_REGISTRY.update(_entries(
    "posix_shm", IPCMechanism.POSIX_SHM,
    "Open POSIX named shared memory by name.",
    InteractionRole.RESOURCE_ANCHOR, "shm_open",
))
_REGISTRY.update(_entries(
    "posix_shm", IPCMechanism.POSIX_SHM,
    "Remove an already identified POSIX shared-memory name.",
    InteractionRole.AUXILIARY, "shm_unlink",
))
_REGISTRY.update(_entries(
    "posix_message_queue", IPCMechanism.POSIX_MQ,
    "Open a POSIX message queue by name.",
    InteractionRole.RESOURCE_ANCHOR, "mq_open",
))
_REGISTRY.update(_entries(
    "posix_message_queue", IPCMechanism.POSIX_MQ,
    "Access a queue when no open anchor is visible.",
    InteractionRole.FALLBACK_ACCESSOR,
    "mq_send", "mq_receive", "mq_timedsend", "mq_timedreceive",
))
_REGISTRY.update(_entries(
    "posix_message_queue", IPCMechanism.POSIX_MQ,
    "Control an already identified POSIX message queue.",
    InteractionRole.AUXILIARY, "mq_close", "mq_unlink", "mq_notify",
))
_REGISTRY.update(_entries(
    "posix_semaphore", IPCMechanism.POSIX_SEM,
    "Open a POSIX named semaphore by name.",
    InteractionRole.RESOURCE_ANCHOR, "sem_open",
))
_REGISTRY.update(_entries(
    "posix_semaphore", IPCMechanism.POSIX_SEM,
    "Access a semaphore when no open anchor is visible.",
    InteractionRole.FALLBACK_ACCESSOR,
    "sem_wait", "sem_trywait", "sem_timedwait", "sem_post",
))
_REGISTRY.update(_entries(
    "posix_semaphore", IPCMechanism.POSIX_SEM,
    "Control an already identified POSIX semaphore.",
    InteractionRole.AUXILIARY, "sem_close", "sem_unlink",
))
_REGISTRY.update(_entries(
    "socket_endpoint", IPCMechanism.UNKNOWN,
    "Name or select a socket resource through an endpoint address.",
    InteractionRole.RESOURCE_ANCHOR, "bind", "connect", "sendto", "sendmsg",
))
_REGISTRY.update(_entries(
    "socket_endpoint", IPCMechanism.UNKNOWN,
    "Construct or operate on a socket whose resource identity is established elsewhere.",
    InteractionRole.AUXILIARY,
    "socket", "listen", "accept", "accept4", "send", "recv", "recvfrom",
    "recvmsg", "shutdown",
))
_REGISTRY.update(_entries(
    "fifo", IPCMechanism.FIFO,
    "Create a named FIFO by path.",
    InteractionRole.RESOURCE_ANCHOR, "mkfifo", "mkfifoat",
))


INTERACTION_APIS = MappingProxyType(_REGISTRY)


__all__ = [
    "INTERACTION_APIS",
    "INTERACTION_REGISTRY_VERSION",
    "InteractionAPI",
    "InteractionRole",
]
