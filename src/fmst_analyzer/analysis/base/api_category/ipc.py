"""
IPC (Inter-Process Communication) resource operations classification.

This module is the authoritative source for all IPC-related APIs.
It consolidates socket APIs, SysV IPC, POSIX IPC, pipes, event file
descriptors, and signal file descriptors.

Classification (2-category system):
- create: APIs that return a NEW IPC handle (socket fd, shmid, mqd_t, sem_t*, pipefd, etc.)
- info: APIs carrying key configuration/topology info (bind address, connect target, etc.)
         or querying/managing IPC namespace (ftok, *_unlink)
"""

from typing import List
from .base import BaseResourceOps


class IPCResourceOps(BaseResourceOps):
    """
    IPC resource operations classifier.

    Covers all inter-process communication mechanisms:
    - Network sockets (TCP, UDP, Unix domain, raw sockets, etc.)
    - System V IPC: shared memory (shmget), message queues (msgget), semaphores (semget)
    - POSIX IPC: shared memory (shm_open), message queues (mq_open), semaphores (sem_open/sem_init)
    - Anonymous/named pipes (pipe, pipe2, mkfifo)
    - Event file descriptors (eventfd)
    - Signal file descriptors (signalfd)
    """

    @property
    def create_predefined(self) -> List[str]:
        return [
            # === Socket Creation ===
            "socket",         # socket(domain, type, protocol) -> fd
            "socketpair",     # socketpair(domain, type, protocol, sv[2]) -> 2 fds

            # === System V IPC Creation (return numeric IPC IDs) ===
            "shmget",         # shmget(key, size, shmflg) -> shmid
            "msgget",         # msgget(key, msgflg) -> msqid
            "semget",         # semget(key, nsems, semflg) -> semid

            # === POSIX Shared Memory ===
            "shm_open",       # shm_open(name, oflag, mode) -> fd

            # === POSIX Message Queues ===
            "mq_open",        # mq_open(name, oflag, mode, attr) -> mqd_t

            # === POSIX Named Semaphores ===
            "sem_open",       # sem_open(name, oflag, mode, value) -> sem_t*

            # === POSIX Unnamed Semaphores (in shared memory) ===
            "sem_init",       # sem_init(sem, pshared, value) -> 0 (sem_t* pre-allocated)

            # === Anonymous Pipes ===
            "pipe",           # pipe(pipefd[2]) -> fills pipefd[0]/[1]
            "pipe2",          # pipe2(pipefd[2], flags) -> fills pipefd[0]/[1]

            # === Named Pipes (FIFO) ===
            "mkfifo",         # mkfifo(pathname, mode) -> creates FIFO file

            # === Event File Descriptors ===
            "eventfd",        # eventfd(initval, flags) -> fd
            "eventfd2",       # eventfd2(initval, flags) -> fd (Linux kernel internal variant)
        ]

    @property
    def info_predefined(self) -> List[str]:
        return [
            # === Socket Configuration (key topology/addressing info) ===
            "bind",           # bind(sockfd, addr, addrlen) - assigns address to socket
            "connect",        # connect(sockfd, addr, addrlen) - connects to remote address
            "listen",         # listen(sockfd, backlog) - marks socket as passive
            "accept",         # accept(sockfd, addr, addrlen) -> new_fd - accepts connection
            "accept4",        # accept4(sockfd, addr, addrlen, flags) -> new_fd
            "shutdown",       # shutdown(sockfd, how) - shuts down part of connection

            # Socket option configuration
            "setsockopt",     # setsockopt(sockfd, level, optname, optval, optlen)

            # Socket address queries (key for understanding IPC topology)
            "getsockname",    # getsockname(sockfd, addr, addrlen) - local address
            "getpeername",    # getpeername(sockfd, addr, addrlen) - remote address

            # === IPC Namespace Management ===
            # SysV IPC key generation (from path string)
            "ftok",           # ftok(pathname, proj_id) -> key_t - generates IPC key

            # POSIX IPC unlink (by string name)
            "mq_unlink",      # mq_unlink(name) - delete POSIX message queue by name
            "shm_unlink",     # shm_unlink(name) - delete POSIX shared memory by name
            "sem_unlink",     # sem_unlink(name) - delete POSIX named semaphore by name
        ]
