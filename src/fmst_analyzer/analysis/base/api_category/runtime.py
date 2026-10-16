"""
Runtime resource operations classification.

This module defines all runtime-related APIs. It covers the current process's
internal state, the OS environment, and system-wide state queries.

Previously, system-wide APIs were in a separate global_.py module. They are now
unified under RUNTIME as they all relate to OS/runtime environment.

Classification (2-category system):
- create: APIs that create runtime resources returning a handle (dlopen, timer_create, mount, etc.)
- info: APIs carrying key config or querying runtime/system state (getenv, uname, time, etc.)
"""

from typing import List
from .base import BaseResourceOps


class RuntimeResourceOps(BaseResourceOps):
    """
    Runtime resource operations classifier.

    Handles APIs that operate on the current process's runtime environment
    and system-wide state, including:
    - Environment variables
    - Dynamic linking and loading
    - Signal handling
    - Process credentials and capabilities
    - Resource limits
    - Working directory
    - System information and time
    - Kernel modules and mounts
    - Process control and configuration
    """
    @property
    def create_predefined(self) -> List[str]:
        return [
            # Dynamic library loading (returns handle)
            "dlopen",         # void *dlopen(const char *filename, int flags) - returns dl handle

            # Timers (create timer instances, returns timer_t)
            "timer_create",   # int timer_create(clockid_t clockid, ..., timer_t *timerid)

            # Mount points (from old GLOBAL category)
            "mount",          # int mount(const char *source, const char *target, ...)

            # Kernel module loading (from old GLOBAL category)
            "init_module",    # int init_module(void *module_image, unsigned long len, ...)
            "finit_module",   # int finit_module(int fd, const char *param_values, int flags)

            # Swap areas (from old GLOBAL category)
            "swapon",         # int swapon(const char *path, int swapflags)
        ]

    @property
    def info_predefined(self) -> List[str]:
        return [
            # === Environment Variables (by name) ===
            "getenv",         # char *getenv(const char *name)
            "secure_getenv",  # char *secure_getenv(const char *name)
            "setenv",         # int setenv(const char *name, const char *value, int overwrite)
            "putenv",         # int putenv(char *string)
            "unsetenv",       # int unsetenv(const char *name)

            # === Locale ===
            "setlocale",      # char *setlocale(int category, const char *locale)

            # === Process Identity ===
            "getpid",         # pid_t getpid(void)
            "getppid",        # pid_t getppid(void)

            # === Process Credentials ===
            "getuid",         # uid_t getuid(void)
            "geteuid",        # uid_t geteuid(void)
            "getgid",         # gid_t getgid(void)
            "getegid",        # gid_t getegid(void)
            "getgroups",      # int getgroups(int size, gid_t list[])
            "setuid",         # int setuid(uid_t uid)
            "seteuid",        # int seteuid(uid_t euid)
            "setgid",         # int setgid(gid_t gid)
            "setegid",        # int setegid(gid_t egid)

            # === Working Directory ===
            "getcwd",         # char *getcwd(char *buf, size_t size)
            "get_current_dir_name", # char *get_current_dir_name(void)
            "chdir",          # int chdir(const char *path)
            "chroot",         # int chroot(const char *path)

            # === Signal Handling ===
            "signal",         # sighandler_t signal(int signum, sighandler_t handler)
            "sigaction",      # int sigaction(int signum, const struct sigaction *act, ...)

            # === Resource Limits ===
            "getrlimit",      # int getrlimit(int resource, struct rlimit *rlim)
            "setrlimit",      # int setrlimit(int resource, const struct rlimit *rlim)
            "prlimit",        # int prlimit(pid_t pid, int resource, ...)

            # === Process Control ===
            "prctl",          # int prctl(int option, ...)
            "daemon",         # int daemon(int nochdir, int noclose)
            "umask",          # mode_t umask(mode_t mask)
            "nice",           # int nice(int inc)
            "getpriority",    # int getpriority(int which, id_t who)
            "setpriority",    # int setpriority(int which, id_t who, int prio)

            # === Namespace ===
            "unshare",        # int unshare(int flags)

            # === Capabilities ===
            "capget",         # int capget(cap_user_header_t hdrp, cap_user_data_t datap)
            "capset",         # int capset(cap_user_header_t hdrp, ...)

            # === System Information (from old GLOBAL category) ===
            "uname",          # int uname(struct utsname *buf)
            "sysinfo",        # int sysinfo(struct sysinfo *info)
            "sysconf",        # long sysconf(int name)
            "confstr",        # size_t confstr(int name, char *buf, size_t len)

            # === System Time (from old GLOBAL category) ===
            "time",           # time_t time(time_t *tloc)
            "gettimeofday",   # int gettimeofday(struct timeval *tv, struct timezone *tz)
            "clock_gettime",  # int clock_gettime(clockid_t clk_id, struct timespec *tp)
            "clock_getres",   # int clock_getres(clockid_t clk_id, struct timespec *res)
            "settimeofday",   # int settimeofday(const struct timeval *tv, ...)
            "clock_settime",  # int clock_settime(clockid_t clk_id, ...)

            # === Timers and Sleep ===
            "alarm",          # unsigned int alarm(unsigned int seconds)
            "getitimer",      # int getitimer(int which, struct itimerval *curr_value)
            "setitimer",      # int setitimer(int which, ...)
            "sleep",          # unsigned int sleep(unsigned int seconds)
            "nanosleep",      # int nanosleep(const struct timespec *req, ...)

            # === Module/Mount Management (from old GLOBAL category) ===
            "delete_module",  # int delete_module(const char *name, int flags)
            "umount",         # int umount(const char *target)
            "umount2",        # int umount2(const char *target, int flags)
            "swapoff",        # int swapoff(const char *path)

            # === Hostname (from old NETWORK, system-level operations) ===
            "sethostname",    # int sethostname(const char *name, size_t len)
            "setdomainname",  # int setdomainname(const char *name, size_t len)
        ]
