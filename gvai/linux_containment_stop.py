"""Dormant stop-only Linux adapter; descriptor provisioning is a trusted-parent duty."""

from dataclasses import dataclass
import os
import threading


def _close_descriptors_once(descriptors):
    first_error = None
    for fd in descriptors:
        try:
            os.close(fd)
        except BaseException as error:
            if first_error is None:
                first_error = error
    return first_error


@dataclass(frozen=True)
class CleanupEvidence:
    status: str
    kill_requested: bool = False
    empty: bool = False
    reaped: bool = False


class OwnedContainment:
    """Retain duplicates of parent-provisioned cgroup and direct-child pidfds.

    No paths or numeric PIDs are accepted. Descriptor provenance, common cgroup
    membership and completeness of the trusted reaper set are NOT inferred here.
    """

    def __init__(self, *, kill_fd: int, events_fd: int, child_pidfds: tuple[int, ...]):
        if (
            type(child_pidfds) is not tuple or not child_pidfds
            or any(type(fd) is not int or fd < 0 for fd in (kill_fd, events_fd, *child_pidfds))
            or len(set((kill_fd, events_fd, *child_pidfds))) != 2 + len(child_pidfds)
        ):
            raise ValueError("Distinct parent-owned descriptors are required.")
        self._lock = threading.Lock()
        self._fds = []
        self._reaped = set()
        self._closed = False
        try:
            for fd in (kill_fd, events_fd, *child_pidfds):
                retained = os.dup(fd)
                self._fds.append(retained)
                os.set_inheritable(retained, False)
        except BaseException as error:
            descriptors, self._fds = self._fds, []
            cleanup_error = _close_descriptors_once(descriptors)
            if cleanup_error is not None:
                raise error from cleanup_error
            raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                descriptors, self._fds = self._fds, []
                error = _close_descriptors_once(descriptors)
                if error is not None:
                    raise error

    def stop(self) -> CleanupEvidence:
        """Request whole-cgroup kill and collect nonblocking kernel observations.

        No polling deadline or promise of bounded process termination is supplied.
        A trusted namespace init/host reaper must account for all descendants.
        """
        with self._lock:
            if self._closed:
                return CleanupEvidence("uncertain")
            kill_requested = empty = False
            failed = False
            try:
                kill_requested = os.write(self._fds[0], b"1") == 1
                if not kill_requested:
                    failed = True
            except Exception:
                failed = True
            try:
                os.lseek(self._fds[1], 0, os.SEEK_SET)
                raw = os.read(self._fds[1], 4097)
                if len(raw) > 4096:
                    raise ValueError("Oversized cgroup event data.")
                fields = {}
                for line in raw.decode("ascii").splitlines():
                    key, value = line.split()
                    if key in fields or value not in ("0", "1"):
                        raise ValueError("Malformed cgroup event data.")
                    fields[key] = value
                if "populated" not in fields:
                    raise ValueError("Missing cgroup population evidence.")
                empty = fields["populated"] == "0"
            except Exception:
                failed = True
            for fd in self._fds[2:]:
                if fd in self._reaped:
                    continue
                try:
                    result = os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG)
                    if (
                        result is not None and result.si_pid > 0
                        and result.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
                    ):
                        self._reaped.add(fd)
                except Exception:
                    # ECHILD is not accepted as proof: another reaper may own it.
                    failed = True
            reaped = len(self._reaped) == len(self._fds) - 2
            status = "uncertain" if failed else "terminated" if empty and reaped else "pending"
            return CleanupEvidence(status, kill_requested, empty, reaped)
