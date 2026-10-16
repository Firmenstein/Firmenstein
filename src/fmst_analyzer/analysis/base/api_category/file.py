"""
File Resource operations classification.

This module defines all file-related APIs including device files (/dev/*),
pseudo-filesystems (/proc, /sys), and regular filesystem operations.

Previously, device APIs were in a separate device.py module. They are now
unified under FILE since /dev, /proc, /sys are all accessed via filesystem APIs.
Specific subclassification (regular file vs device vs pseudo-fs) is handled
by the downstream FileResolver module.

Classification (2-category system):
- create: APIs that return a NEW handle (fd, FILE*, DIR*)
- info: APIs that carry key info via path/name (stat, chmod, mkdir, etc.)
"""

from typing import List
from .base import BaseResourceOps

class FileResourceOps(BaseResourceOps):
    """
    File resource operations classifier.

    Handles APIs that operate on file system resources including:
    - Regular files and directories
    - Device files (/dev/*)
    - Pseudo-filesystems (/proc, /sys)
    - Symbolic links
    - File descriptors
    - Directory streams
    - Buffered I/O streams (FILE*)
    - I/O multiplexing (epoll)
    - File monitoring (inotify, fanotify)
    - Pseudo-terminals (PTY)
    """
    @property
    def create_predefined(self) -> List[str]:
        """
        APIs that create new file resources and return a handle.
        """
        return [
            # File creation (returns fd)
            "open",           # open(path, O_CREAT, ...)
            "open64",         # open64(path, flags, ...)
            "creat",          # creat(path, mode)
            "creat64",        # creat64(path, mode)
            "openat",         # openat(dirfd, path, O_CREAT, ...)
            "openat64",       # openat64(dirfd, path, ...)
            "openat2",        # openat2() - newer variant

            # Directory stream (returns DIR*)
            "opendir",        # opendir(path) - returns DIR*

            # Temporary files (returns fd or FILE*)
            "mkstemp",        # mkstemp(template) - secure temp file, returns fd
            "mkostemp",       # mkostemp(template, flags)
            "mkstemps",       # mkstemps(template, suffixlen)
            "tmpfile",        # tmpfile() - returns FILE*
            "tmpfile64",      # tmpfile64() - 64-bit variant

            # Buffered I/O stream creation (returns FILE*)
            "fopen",          # fopen(path, mode)
            "fopen64",        # fopen64() - large file support
            "freopen",        # reopen an existing FILE* on a new path
            "freopen64",      # freopen64() - large file support

            # Memory streams (returns FILE*)
            "fmemopen",       # fmemopen(buf, size, mode)
            "open_memstream", # open_memstream(&ptr, &size)

            # File monitoring instances (returns fd)
            "inotify_init",   # inotify_init() - create inotify instance
            "inotify_init1",  # inotify_init1(flags)
            "fanotify_init",  # fanotify_init(flags, event_f_flags)

            # I/O multiplexing instances (returns fd)
            "epoll_create",   # epoll_create(size) - create epoll instance
            "epoll_create1",  # epoll_create1(flags)

            # Pseudo-terminal creation (from old DEVICE category)
            "posix_openpt",   # int posix_openpt(int flags)
            "openpty",        # int openpty(int *amaster, int *aslave, ...)
        ]

    @property
    def info_predefined(self) -> List[str]:
        """
        APIs carrying key filesystem info via path/name or querying metadata.
        """
        return [
            # File status/metadata by path
            "stat",           # stat(path, statbuf)
            "lstat",          # lstat(path, statbuf) - don't follow symlinks
            "stat64",         # stat64() - large file support
            "lstat64",        # lstat64()

            # File access check (by path)
            "access",         # access(path, mode)

            # File system information (by path)
            "statfs",         # statfs(path, buf)
            "statfs64",       # statfs64()
            "statvfs",        # statvfs(path, buf)
            "statvfs64",      # statvfs64()

            # Path resolution
            "realpath",       # realpath(path, resolved_path)
            "readlink",       # readlink(path, buf, bufsiz)
            "canonicalize_file_name", # canonicalize_file_name(path)

            # Pattern matching (by path pattern)
            "glob",           # glob(pattern, flags, errfunc, pglob)
            "glob64",         # glob64() - 64-bit variant

            # Extended attributes (by path)
            "getxattr",       # getxattr(path, name, value, size)
            "lgetxattr",      # lgetxattr() - don't follow symlinks
            "setxattr",       # setxattr(path, name, value, size, flags)
            "lsetxattr",      # lsetxattr() - don't follow symlinks

            # File permissions (by path)
            "chmod",          # chmod(path, mode)

            # File ownership (by path)
            "chown",          # chown(path, owner, group)
            "lchown",         # lchown(path, owner, group) - don't follow symlinks

            # File timestamps (by path)
            "utime",          # utime(path, times)
            "utimes",         # utimes(path, times)

            # Directory creation (by path)
            "mkdir",          # mkdir(path, mode)
            "mkdtemp",        # mkdtemp(template)

            # Link creation (by path)
            "link",           # link(oldpath, newpath)
            "symlink",        # symlink(target, linkpath)

            # File/directory deletion (by path)
            "unlink",         # unlink(path)
            "remove",         # remove(path)
            "rmdir",          # rmdir(path)

            # Rename (by path)
            "rename",         # rename(oldpath, newpath)

            # Truncate (by path)
            "truncate",       # truncate(path, length)

            # Device node creation (by path) — from old DEVICE category
            "mknod",          # mknod(pathname, mode, dev)
            "mknodat",        # mknodat(dirfd, pathname, mode, dev)

            # TTY access via implicit scope — from old DEVICE category
            "ctermid",        # ctermid(s) - get controlling terminal name
        ]
