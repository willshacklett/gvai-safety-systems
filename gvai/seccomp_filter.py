from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import tempfile
from dataclasses import dataclass


SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000


def errno_action(value: int) -> int:
    return SCMP_ACT_ERRNO | (value & 0xFFFF)


@dataclass
class SeccompFilter:
    """
    Owns a file containing classic BPF exported by libseccomp.
    Keep this object alive while its fd is passed to bubblewrap.
    """

    file: object
    fd: int

    def close(self) -> None:
        try:
            self.file.close()
        except Exception:
            pass


class SeccompUnavailable(RuntimeError):
    pass


def _load_libseccomp():
    name = ctypes.util.find_library("seccomp")

    if not name:
        raise SeccompUnavailable(
            "libseccomp could not be found."
        )

    lib = ctypes.CDLL(name)

    lib.seccomp_init.argtypes = [
        ctypes.c_uint32,
    ]
    lib.seccomp_init.restype = ctypes.c_void_p

    lib.seccomp_release.argtypes = [
        ctypes.c_void_p,
    ]
    lib.seccomp_release.restype = None

    lib.seccomp_syscall_resolve_name.argtypes = [
        ctypes.c_char_p,
    ]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int

    lib.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    lib.seccomp_rule_add.restype = ctypes.c_int

    lib.seccomp_export_bpf.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    lib.seccomp_export_bpf.restype = ctypes.c_int

    return lib


def libseccomp_available() -> bool:
    try:
        _load_libseccomp()
        return True
    except Exception:
        return False


def build_no_spawn_filter() -> SeccompFilter:
    """
    Default allow, but return EPERM for process-creation syscalls.

    Blocking clone/fork/vfork/clone3 prevents the sandboxed worker
    from creating child processes while still allowing bubblewrap
    to exec the initial worker.
    """

    lib = _load_libseccomp()

    ctx = lib.seccomp_init(
        SCMP_ACT_ALLOW
    )

    if not ctx:
        raise SeccompUnavailable(
            "seccomp_init failed."
        )

    tmp = tempfile.TemporaryFile()

    try:
        denied = (
            b"fork",
            b"vfork",
            b"clone",
            b"clone3",
        )

        for syscall_name in denied:
            syscall_number = (
                lib.seccomp_syscall_resolve_name(
                    syscall_name
                )
            )

            # A syscall absent on this architecture is harmless.
            if syscall_number < 0:
                continue

            rc = lib.seccomp_rule_add(
                ctx,
                errno_action(errno.EPERM),
                syscall_number,
                0,
            )

            if rc != 0:
                raise SeccompUnavailable(
                    "Failed to add seccomp rule for "
                    f"{syscall_name.decode()} "
                    f"(rc={rc})."
                )

        rc = lib.seccomp_export_bpf(
            ctx,
            tmp.fileno(),
        )

        if rc != 0:
            raise SeccompUnavailable(
                f"seccomp_export_bpf failed (rc={rc})."
            )

        tmp.flush()
        tmp.seek(0)

        return SeccompFilter(
            file=tmp,
            fd=tmp.fileno(),
        )

    except Exception:
        tmp.close()
        raise

    finally:
        lib.seccomp_release(ctx)
