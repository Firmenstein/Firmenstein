"""
Process resource operations classification.

This module covers process lifecycle and management APIs.
IPC mechanism APIs (pipes, shared memory, message queues, semaphores, sockets,
eventfd, signalfd) are in ipc.py.

Classification (2-category system):
- create: APIs that spawn a new process (fork -> PID, popen -> FILE*)
- info: APIs carrying key info (exec* with program path/args, wait/kill for process interaction)
"""

from typing import List
from .base import BaseResourceOps


class ProcessResourceOps(BaseResourceOps):
    """
    Process resource operations classifier.

    Covers process creation and key process management operations.
    IPC mechanisms (pipes, shared memory, message queues, semaphores) are in IPCResourceOps.
    """

    @property
    def create_predefined(self) -> List[str]:
        return [
            # Process creation (return PID or FILE* as handle)
            "fork",          # pid_t fork(void)
            "vfork",         # pid_t vfork(void)
            "clone",         # long clone(unsigned long flags, void *stack, ...)
            "clone3",        # long clone3(struct clone_args *cl_args, size_t size)
            "system",        # int system(const char *command)
            "popen",         # FILE *popen(const char *command, const char *type)
            "posix_spawn",   # int posix_spawn(pid_t *pid, ...)
            "posix_spawnp",  # int posix_spawnp(pid_t *pid, ...)
            "forkpty",       # pid_t forkpty(int *amaster, char *name, ...)
        ]

    @property
    def info_predefined(self) -> List[str]:
        return [
            # Program execution — carries program path and arguments (key info for harness synthesis)
            "execve",        # int execve(const char *pathname, char *const argv[], char *const envp[])
            "execv",         # int execv(const char *pathname, char *const argv[])
            "execvp",        # int execvp(const char *file, char *const argv[])
            "execvpe",       # int execvpe(const char *file, char *const argv[], char *const envp[])
            "execl",         # int execl(const char *pathname, const char *arg, ...)
            "execlp",        # int execlp(const char *file, const char *arg, ...)
            "execle",        # int execle(const char *pathname, const char *arg, ..., char *const envp[])
            "fexecve",       # int fexecve(int fd, char *const argv[], char *const envp[])

            # Process synchronization (understanding process interaction patterns)
            "wait",          # pid_t wait(int *wstatus)
            "waitpid",       # pid_t waitpid(pid_t pid, int *wstatus, int options)
            "waitid",        # int waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options)

            # Process signaling (key for understanding process control)
            "kill",          # int kill(pid_t pid, int sig)
            "killpg",        # int killpg(int pgrp, int sig)
        ]
