"""Test-only contracts. Resources remain hard-HOLD pending an external boundary."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "tests/ask-gv/customer-zero-commercial-smoke-driver.mjs"
L = "3c117260901cb15877512161cb24fa8e5587aa73"
N = "c3fd88a236f32aa9b84e6baaa212cb4db79d02ca"
PRESERVED_HEAD = "da20805adf79dac35f79ab99b303960ab66e4a96"
FILES = (
    "ask-gv/decision-client.mjs", "tests/ask-gv/decision-client.test.mjs",
    "tests/ask-gv/customer-zero-commercial-smoke-driver.mjs",
    "tests/integration/test_customer_zero_commercial_smoke.py",
    "docs/customer_zero_advisory_smoke_v1.md",
)
ZERO = dict(token_delta=0, tool_calls_delta=0, error_delta=0,
            repeated_action_delta=0, recursion_depth=0, latency_ms=None)
ID = re.compile(r"askgv-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
SCOPE = "one-disposable-advisory-smoke"
LIMIT = 16384
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
CODES = frozenset(("prerequisite", "protocol_error", "deadline", "output_overflow",
    "spawn_failure", "process_exit", "cancelled", "ownership_unverified",
    "cleanup_failure", "source_integrity", "git_identity", "libpq_environment",
    "destination_invalid", "external_boundary_required"))
START = b"SMOKE-CHILD-START\n"


class Hold(RuntimeError):
    """Only fixed classifications and booleans; never retain private exceptions."""
    def __init__(self, code="prerequisite", *, child_started=False, cleanup_verified=False, exit_status=None):
        self.code = code if code in CODES else "prerequisite"
        self.child_started = child_started is True
        self.cleanup_verified = cleanup_verified is True
        self.exit_status = exit_status if type(exit_status) is int and -255 <= exit_status <= 255 else None
        super().__init__("HOLD: " + self.code)


def need(condition, code="protocol_error"):
    if not condition:
        raise Hold(code)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result)
        result[key] = value
    return result


def strict_json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: need(False))
    except Exception:
        raise Hold("protocol_error") from None


def bounded_source(path, *, root=ROOT, maximum=262144):
    """Inert byte/identity check, not an execution freeze or self-authentication."""
    path, root = Path(path), Path(root)
    need(root.resolve() == root and path.is_relative_to(root), "source_integrity")
    for item in [path, *path.parents]:
        if item == root.parent:
            break
        need(not item.is_symlink(), "source_integrity")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             "source_integrity")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(8192, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        named = path.lstat()
        need((named.st_dev, named.st_ino, named.st_size, named.st_mtime_ns, named.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "source_integrity")
        need(len(data) <= maximum and (before.st_dev, before.st_ino, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns) == (after.st_dev, after.st_ino,
             after.st_size, after.st_mtime_ns, after.st_ctime_ns), "source_integrity")
        return bytes(data)
    except Hold:
        raise
    except Exception:
        raise Hold("source_integrity") from None
    finally:
        if fd is not None:
            os.close(fd)


def candidate_digest(*, root=ROOT, reader=None):
    reader = reader or (lambda rel: bounded_source(Path(root) / rel, root=root))
    manifest = "".join(path + "\0" + hashlib.sha256(reader(path)).hexdigest() + "\n"
                       for path in sorted(FILES))
    return hashlib.sha256(manifest.encode()).hexdigest()


def require_approved_candidate(expected, *, digest=None):
    need(type(expected) is str and DIGEST.fullmatch(expected), "source_integrity")
    need((digest or candidate_digest)() == expected, "source_integrity")
    return expected  # Never substitute a newly calculated, unapproved digest.


def refuse_libpq_environment(environment):
    # Inspect keys only; do not obtain/format/print any ambient values.
    need(not any(type(key) is str and key.upper().startswith("PG") for key in environment),
         "libpq_environment")


def validate_destination(dsn, database, role, port, *, environment):
    """Deliberately narrow canonical synthetic DSN grammar; no libpq import/connect.

    Exactly six unquoted ASCII keyword values, no URI/escapes/aliases/duplicates.
    The restricted synthetic password alphabet is intentional, not a general DSN API.
    """
    refuse_libpq_environment(environment)
    need(type(dsn) is str and len(dsn) <= 4096 and type(port) is int and 1 <= port <= 65535,
         "destination_invalid")
    need(type(database) is str and re.fullmatch(r"gvai_advisory_test_customer_zero_[a-z0-9_]{1,40}", database), "destination_invalid")
    need(type(role) is str and re.fullmatch(r"customer_zero_[a-z0-9_]{1,40}", role), "destination_invalid")
    need(all(32 <= ord(c) <= 126 and c not in "'\"\\" for c in dsn), "destination_invalid")
    fields = {}
    for token in dsn.split(" "):
        need(token.count("=") == 1, "destination_invalid")
        key, value = token.split("=")
        need(key not in fields and bool(value), "destination_invalid")
        fields[key] = value
    need(set(fields) == {"host", "hostaddr", "port", "dbname", "user", "password"}, "destination_invalid")
    need(fields["host"] == fields["hostaddr"] == "127.0.0.1", "destination_invalid")
    need(fields["port"] == str(port) and re.fullmatch(r"[1-9][0-9]{0,4}", fields["port"]), "destination_invalid")
    need(fields["dbname"] == database and fields["user"] == role, "destination_invalid")
    need(re.fullmatch(r"[A-Za-z0-9_-]{16,256}", fields["password"]), "destination_invalid")
    return " ".join(name + "=" + fields[name] for name in ("host", "hostaddr", "port", "dbname", "user", "password"))


def require_external_execution_boundary():
    # Intentionally no flag, record field, digest or caller callback can enable this.
    # A separately reviewed frozen source/runtime/supervisor integration is absent.
    raise Hold("external_boundary_required")


_NODE_BINDING = None

def node_path():
    """Bind one resolved executable/stat identity, not a trusted runtime attestation."""
    global _NODE_BINDING
    try:
        if _NODE_BINDING is None:
            found = shutil.which("node")
            need(found is not None, "spawn_failure")
            path = Path(found).resolve(strict=True)
            st = path.stat()
            need(stat.S_ISREG(st.st_mode) and os.access(path, os.X_OK), "spawn_failure")
            _NODE_BINDING = (path, st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        path, *identity = _NODE_BINDING
        st = path.stat()
        need(identity == [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns], "source_integrity")
        return str(path)
    except Hold:
        raise
    except Exception:
        raise Hold("spawn_failure") from None


class LinuxOwnership:
    """Kernel child anchor stays UNREAPED until group cleanup; never call poll().

    Requires an exclusive trusted waiter and default SIGCHLD disposition. A hostile
    same-process waiter/reaper or SIGKILL requires the independent external owner.
    """
    @staticmethod
    def identity(pid):
        with open("/proc/" + str(pid) + "/stat", "rb", buffering=0) as stream:
            data = stream.read(8193)
        need(len(data) <= 8192, "ownership_unverified")
        fields = data.rsplit(b")", 1)[1].split()
        return (int(fields[1]), int(fields[2]), int(fields[3]), int(fields[19]))

    def anchor(self, proc):
        need(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal") and
             hasattr(os, "WNOWAIT"), "ownership_unverified")
        proc._smoke_pidfd = os.pidfd_open(proc.pid, 0)
        identity = self.identity(proc.pid)
        need(identity[:3] == (os.getpid(), proc.pid, proc.pid), "ownership_unverified")
        need(identity == self.identity(proc.pid), "ownership_unverified")
        return identity

    @staticmethod
    def peek(proc):
        # WNOWAIT preserves the PID/session anchor even after the leader exits.
        result = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if result is None:
            return None
        need(result.si_pid == proc.pid, "ownership_unverified")
        return result.si_status if result.si_code == os.CLD_EXITED else -result.si_status

    def signal_group(self, proc, anchor):
        # No numeric group signal unless this exact, still-unreaped child owns it.
        self.peek(proc)
        need(anchor == self.identity(proc.pid) and anchor[:3] == (os.getpid(), proc.pid, proc.pid),
             "ownership_unverified")
        os.killpg(proc.pid, signal.SIGKILL)

    def descendants_gone(self, proc):
        # Read-only bounded membership check while the unreaped leader pins PGID.
        count = 0
        with os.scandir("/proc") as entries:
            for entry in entries:
                if not entry.name.isdecimal() or int(entry.name) == proc.pid:
                    continue
                count += 1
                need(count <= 8192, "cleanup_failure")
                try:
                    identity = self.identity(int(entry.name))
                except (FileNotFoundError, ProcessLookupError):
                    continue
                if identity[2] == proc.pid:
                    return False
        return True

    @staticmethod
    def signal_leader_handle(proc):
        # A pidfd addresses the original leader even if numeric identity is lost.
        handle = getattr(proc, "_smoke_pidfd", None)
        if handle is not None:
            try:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
            except ProcessLookupError:
                pass

    @staticmethod
    def close_handle(proc):
        handle = getattr(proc, "_smoke_pidfd", None)
        if handle is not None:
            os.close(handle)
            proc._smoke_pidfd = None


class OwnedProcess:
    def __init__(self, *, popen=None, ownership=None):
        self.popen = popen or subprocess.Popen
        self.ownership = ownership or LinuxOwnership()
        self.proc = None
        self.anchor = None
        self.cancelled = False
        self.cleanup_verified = False
        self.previous = {}

    def __enter__(self):
        need(threading.current_thread() is threading.main_thread() and
             signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "ownership_unverified")
        if isinstance(self.ownership, LinuxOwnership):
            need(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal") and hasattr(os, "WNOWAIT"), "ownership_unverified")
        try:
            for number in (signal.SIGTERM, signal.SIGINT):
                self.previous[number] = signal.getsignal(number)
                signal.signal(number, self.note_cancelled)
            return self
        except BaseException:
            self.restore_handlers()
            raise

    def note_cancelled(self, *_):
        self.cancelled = True

    def check_cancelled(self):
        need(not self.cancelled, "cancelled")

    def spawn(self, argv, cwd, environment):
        self.check_cancelled()
        try:
            self.proc = self.popen(argv, cwd=cwd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment,
                                   start_new_session=True, bufsize=0)
        except Exception:
            raise Hold("spawn_failure") from None
        # Everything after successful Popen is already inside the context's finally.
        try:
            self.anchor = self.ownership.anchor(self.proc)
        except Exception:
            raise Hold("ownership_unverified") from None
        self.check_cancelled()
        return self.proc

    def restore_handlers(self):
        for number, handler in self.previous.items():
            signal.signal(number, handler)
        self.previous.clear()

    def __exit__(self, *_):
        problem = False
        try:
            if self.proc is None:
                self.cleanup_verified = True
                return
            try:
                if self.anchor is None:
                    # Never guess a PGID on partial identity failure.
                    try:
                        self.ownership.signal_leader_handle(self.proc)
                    except Exception:
                        pass
                    problem = True
                else:
                    self.ownership.signal_group(self.proc, self.anchor)
                    deadline = time.monotonic() + 2
                    while not self.ownership.descendants_gone(self.proc):
                        if time.monotonic() >= deadline:
                            problem = True
                            break
                        time.sleep(0.01)
            except Exception:
                try:
                    self.ownership.signal_leader_handle(self.proc)
                except Exception:
                    pass
                problem = True
            try:
                # The first and only reaping point; no later numeric group signals.
                self.proc.wait(timeout=2)
            except Exception:
                problem = True
            finally:
                for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                    if pipe is not None:
                        try:
                            pipe.close()
                        except Exception:
                            problem = True
                try:
                    self.ownership.close_handle(self.proc)
                except Exception:
                    problem = True
            self.cleanup_verified = not problem
            if problem:
                raise Hold("cleanup_failure")
        finally:
            self.restore_handlers()


def bounded_capture(argv, *, cwd=ROOT, environment=None, first=None, reply=None,
                    timeout=8, limit=LIMIT, start_marker=None, popen=None,
                    ownership=None, selector_factory=None, raw_input=None):
    """Finite live I/O and owned lifecycle, with fixed redacted failure evidence."""
    need(0 < timeout <= 15 and 0 < limit <= 131072, "prerequisite")
    need(not (first is not None and raw_input is not None), "protocol_error")
    initial = raw_input if raw_input is not None else (b"" if first is None else json.dumps(first, allow_nan=False).encode() + b"\n")
    need(type(initial) is bytes and len(initial) <= LIMIT, "protocol_error")
    pending = bytearray(initial)
    streams = None
    owner = OwnedProcess(popen=popen, ownership=ownership)
    received = {"stdout": bytearray(), "stderr": bytearray()}
    stdout_pending, frames, wire_requests = bytearray(), [], []
    started = False
    exit_status = None
    failure = None
    result = None
    try:
        with owner:
            try:
                proc = owner.spawn(argv, cwd, environment or {"PATH": os.defpath, "TZ": "UTC"})
                deadline = time.monotonic() + timeout
                streams = (selector_factory or selectors.DefaultSelector)()
                for pipe, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
                    os.set_blocking(pipe.fileno(), False)
                    streams.register(pipe, selectors.EVENT_READ, name)
                os.set_blocking(proc.stdin.fileno(), False)
                if pending:
                    streams.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                while any(key.data != "stdin" for key in streams.get_map().values()):
                    owner.check_cancelled()
                    remaining = deadline - time.monotonic()
                    need(remaining > 0, "deadline")
                    for selected, _ in streams.select(min(remaining, 0.1)):
                        pipe, name = selected.fileobj, selected.data
                        if name == "stdin":
                            try:
                                sent = os.write(pipe.fileno(), pending)
                            except BlockingIOError:
                                continue
                            del pending[:sent]
                            if not pending:
                                streams.unregister(pipe)
                            continue
                        try:
                            chunk = os.read(pipe.fileno(), 4096)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            streams.unregister(pipe)
                            continue
                        previous_size = len(received[name])
                        received[name].extend(chunk)
                        if name == "stdout" and start_marker is not None:
                            if len(received[name]) >= len(start_marker) and not started:
                                need(received[name].startswith(start_marker), "protocol_error")
                                started = True
                        need(len(received[name]) <= limit, "output_overflow")
                        if name == "stdout" and first is not None:
                            # Strip only the explicitly requested start acknowledgement.
                            start_at = max(previous_size, len(start_marker or b""))
                            stdout_pending.extend(received[name][start_at:])
                            while b"\n" in stdout_pending:
                                line, _, rest = stdout_pending.partition(b"\n")
                                stdout_pending = bytearray(rest)
                                frame = strict_json(line.decode("utf-8", errors="strict"))
                                need(type(frame) is dict and len(frames) < 2)
                                frames.append(frame)
                                if frame.get("type") == "request":
                                    need(not wire_requests and reply is not None and not pending)
                                    body = frame.get("body")
                                    validate_body(body, first["config"]["project"])
                                    wire_requests.append(body)
                                    response = reply(body)
                                    encoded = json.dumps(response, allow_nan=False).encode() + b"\n"
                                    need(len(encoded) <= LIMIT)
                                    pending.extend(encoded)
                                    streams.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
                while (exit_status := owner.ownership.peek(proc)) is None:
                    owner.check_cancelled()
                    need(time.monotonic() < deadline, "deadline")
                    time.sleep(0.01)
                need(exit_status == 0, "process_exit")
                need(not received["stderr"] and not stdout_pending and not pending, "protocol_error")
                need(start_marker is None or started, "protocol_error")
                if first is None:
                    result = bytes(received["stdout"])[len(start_marker or b""):]
                else:
                    expected_types = ["request", "result"] if first["mode"] == "contract" else ["result"]
                    need([frame.get("type") for frame in frames] == expected_types)
                    result = frames[-1].get("result")
                    validate_result(result)
                    if wire_requests:
                        need(result["request_id"] == wire_requests[0]["request_id"])
                    result = result, wire_requests
            finally:
                if streams is not None:
                    streams.close()
    except Hold as error:
        failure = error.code
    except (KeyboardInterrupt, SystemExit):
        failure = "cancelled"
    except Exception:
        failure = "protocol_error"
    if failure is not None:
        raise Hold(failure, child_started=started, cleanup_verified=owner.cleanup_verified,
                   exit_status=exit_status) from None
    need(owner.cleanup_verified, "cleanup_failure")
    return result


def bounded_node(args, first=None, reply=None, *, timeout=8, limit=LIMIT,
                 resource_admission=None, approved_candidate=None, start_marker=None):
    environment = {"PATH": os.defpath, "TZ": "UTC"}
    if first is not None and first.get("mode") == "disposable":
        # Validate equality, never promote an unchecked second digest. Still hard-HOLD.
        require_approved_candidate(approved_candidate)
        need(first["authorization"]["candidate_sha256"] == approved_candidate, "source_integrity")
        require_external_execution_boundary()
    else:
        need(resource_admission is None and approved_candidate is None)
    return bounded_capture([node_path(), *args], first=first, reply=reply,
                           environment=environment, timeout=timeout, limit=limit,
                           start_marker=start_marker)


def bounded_git(arguments):
    # All callers supply fixed, read-only Git subcommands and bounded output.
    path = shutil.which("git")
    need(path is not None, "git_identity")
    return bounded_capture([str(Path(path).resolve()), "-C", str(ROOT), *arguments],
        environment={"PATH": os.defpath, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
        timeout=5, limit=131072)


def verify_execution_sources(expected_candidate, expected_head, *, capture=None,
                             reader=None, modules=None, root=ROOT):
    """Inert drift detection only. Does NOT authenticate this mutable verifier."""
    require_approved_candidate(expected_candidate, digest=lambda: candidate_digest(root=root, reader=reader))
    need(type(expected_head) is str and re.fullmatch(r"[0-9a-f]{40}", expected_head), "git_identity")
    capture = capture or bounded_git
    reader = reader or (lambda rel: bounded_source(Path(root) / rel, root=root))
    need(capture(["rev-parse", "--show-toplevel"]).decode().strip() == str(root), "git_identity")
    need(capture(["rev-parse", "HEAD"]).decode().strip() == expected_head, "git_identity")
    need(capture(["branch", "--show-current"]).decode().strip() == "feature/customer-zero-advisory-smoke-v1", "git_identity")
    need(not capture(["status", "--porcelain=v1", "--untracked-files=all"]), "source_integrity")
    need(not capture(["ls-files", "--others", "--ignored", "--exclude-standard", "-z"]), "source_integrity")
    need(all(row.startswith(b"H ") for row in capture(["ls-files", "-v"]).splitlines()), "source_integrity")
    # Bound actual backend/context bytes to the reviewed Git identity, not five additions.
    raw = capture(["ls-tree", "-r", "-z", expected_head, "--", "gvai", "migrations/postgresql",
                   "pyproject.toml", "requirements.txt", "requirements-dev.txt",
                   "requirements-private-staging.txt", "requirements-postgresql-test.txt"])
    need(raw == capture(["ls-tree", "-r", "-z", L, "--", "gvai", "migrations/postgresql",
                   "pyproject.toml", "requirements.txt", "requirements-dev.txt",
                   "requirements-private-staging.txt", "requirements-postgresql-test.txt"]), "source_integrity")
    entries = raw.rstrip(b"\0").split(b"\0")
    need(1 <= len(entries) <= 512, "source_integrity")
    paths, total = set(), 0
    for entry in entries:
        meta, rel_bytes = entry.split(b"\t", 1)
        mode, kind, oid = meta.split()
        rel = rel_bytes.decode("utf-8", errors="strict")
        need(mode in (b"100644", b"100755") and kind == b"blob" and rel not in paths and
             not Path(rel).is_absolute() and ".." not in Path(rel).parts, "source_integrity")
        paths.add(rel)
        data = reader(rel)
        total += len(data)
        need(len(data) <= 262144 and total <= 4194304, "source_integrity")
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest().encode()
        need(actual == oid, "source_integrity")
    need({"gvai/private_staging.py", "gvai/commercial_http.py", "gvai/commercial_service.py",
          "gvai/postgresql_advisory.py", "gvai/postgresql_reservation_authority.py"} <= paths, "source_integrity")
    for name, module in (sys.modules if modules is None else modules).items():
        if name == "gvai" or name.startswith("gvai."):
            origin = getattr(module, "__file__", None)
            need(type(origin) is str and Path(origin).resolve().is_relative_to(Path(root) / "gvai"), "source_integrity")
            need(str(Path(origin).resolve().relative_to(root)) in paths, "source_integrity")
    require_approved_candidate(expected_candidate, digest=lambda: candidate_digest(root=root, reader=reader))
    return expected_candidate

def validate_body(body, project):
    need(type(body) is dict and set(body) == {"version", "request_id", "resource_id", "telemetry", "reported_effects"})
    need(body["version"] == "v1" and type(body["request_id"]) is str and ID.fullmatch(body["request_id"]))
    need(body["resource_id"] == project and body["telemetry"] == ZERO and body["reported_effects"] == [])
    need(all(type(body["telemetry"][name]) is int for name in ZERO if name != "latency_ms"))


def validate_result(result):
    need(type(result) is dict and set(result) == {"version", "evidence", "requests", "request_id", "http_status", "accepted_advisory_only", "enforcement_applied", "observations"})
    need(result["version"] == "customer-zero-advisory-smoke-v1" and result["requests"] == 1)
    need(result["evidence"] in ("mocked-contract", "disposable-connectivity-only"))
    need(ID.fullmatch(result["request_id"]) and result["enforcement_applied"] is False)
    pre, provider = result["observations"]
    for record in (pre, provider):
        need(record["request_id"] == result["request_id"] and record["mode"] == "advisory" and record["enforcement_applied"] is False)
    need(pre["phase"] == "pre_dispatch" and provider["phase"] == "provider" and provider["provider_outcome"] == "not_attempted")
    need(pre["status"] in ("evaluated", "unavailable", "timeout", "cancelled"))
    need(result["accepted_advisory_only"] is (True if pre["status"] == "evaluated" else None))
    serialized = json.dumps(result)
    need(len(serialized.encode()) <= 4096 and not any(word in serialized for word in ("Bearer", "explanation", "telemetry", "credential", "key")))


def memory_service():
    # Real L auth/service/evaluator/serialization, synthetic in-memory custody only.
    from gvai.commercial_api_keys import CustomerApiKeys, InMemoryApiKeyStore
    from gvai.commercial_identity import (CommercialAuthorizer, CommercialCapability,
                                          CommercialResourceKind, CommercialResourceOwnership)
    from gvai.commercial_service import CommercialEvaluationService
    from gvai.commercial_usage import CommercialUsage, InMemoryUsageStore

    class Ownership:
        def lookup(self, resource):
            if resource == "customer-zero-contract":
                return CommercialResourceOwnership(resource, "synthetic-tenant", CommercialResourceKind.EVALUATION)
            return None

    now = lambda: 1790812800  # Fixed 2026-10-01; not wall-clock eligibility.
    keys = CustomerApiKeys(InMemoryApiKeyStore(), verifier_secret=b"synthetic-contract-only-secret-32bytes", clock=now)
    issued = keys.issue(principal_id="synthetic-principal", tenant_id="synthetic-tenant",
                        capabilities=frozenset({CommercialCapability.EVALUATE}), expires_at=now() + 3600)
    key = issued.take_secret()
    usage = CommercialUsage(CommercialAuthorizer(keys, Ownership(), clock=now),
                            InMemoryUsageStore({"synthetic-tenant": 3}, clock=now))
    return CommercialEvaluationService(usage), key


# PURE CONTRACT SECTION: no socket/DB dependencies and no ambient opt-in required.
class PureContracts(unittest.TestCase):
    def config(self, key="FAKE-contract-only-key"):
        return dict(endpoint="http://127.0.0.1:8080/v1/evaluations", project="customer-zero-contract", key=key)

    def test_import_safe_and_no_implicit_native_transport(self):
        script = """
          import assert from 'node:assert/strict';
          import net from 'node:net';
          net.Server.prototype.listen=()=>{throw Error('listener forbidden');};
          net.Socket.prototype.connect=()=>{throw Error('network forbidden');};
          globalThis.fetch=()=>{throw Error('native fetch forbidden');};
          const before=process.stdin.listenerCount('data');
          const m=await import('./tests/ask-gv/customer-zero-commercial-smoke-driver.mjs');
          assert.equal(process.stdin.listenerCount('data'),before);
          await assert.rejects(m.runSmoke({endpoint:'http://127.0.0.1:8080/v1/evaluations',project:'customer-zero-contract',key:'FAKE-contract-only-key'}));
          assert.throws(()=>m.validateDisposableInput({mode:'disposable'}));
          process.stdout.write('import-safe');
        """
        self.assertEqual(bounded_node(["--input-type=module", "-e", script], timeout=4), b"import-safe")

    def test_real_python_service_round_trip_is_connectivity_only(self):
        service, key = memory_service()
        calls = []

        def reply(body):
            calls.append(body)
            response = service.evaluate(key, body["resource_id"], body["request_id"], body["telemetry"], body["reported_effects"])
            envelope = response.to_dict()
            self.assertIs(envelope["evaluation"]["advisory_only"], True)
            self.assertIs(envelope["evaluation"]["enforcement_applied"], False)
            return {"status": 200, "body": envelope}

        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result, bodies = bounded_node([str(DRIVER)], {"mode": "contract", "config": self.config(key)}, reply)
        self.assertEqual(len(calls), 1)
        self.assertEqual(bodies, calls)
        self.assertEqual(result["evidence"], "mocked-contract")
        self.assertEqual(result["observations"][0]["status"], "evaluated")
        self.assertEqual([result["observations"][0][k] for k in ("decision", "risk_band", "risk_score")], ["ALLOW", "green", 0.0])
        self.assertNotIn(key, json.dumps(result))
        # Same synthetic request replay is service denial; no HTTP status claim here.
        body = bodies[0]
        replay = service.evaluate(key, body["resource_id"], body["request_id"], body["telemetry"], [])
        self.assertEqual(replay.reason.value, "replay")

    def test_mocked_error_and_identity_mismatch_are_not_decisions(self):
        from gvai.evaluation import evaluate_request
        from gvai.commercial_service import CommercialServiceResponse, ServiceOutcome, ServiceReason
        for case in (401, 403, 409, 429, 500, 503, "wrong-id", "wrong-flags", "extra-field"):
            with self.subTest(case=case):
                def reply(body):
                    request = {k: v for k, v in body.items() if k != "resource_id"}
                    envelope = CommercialServiceResponse(ServiceOutcome.EVALUATED, ServiceReason.EVALUATED, evaluate_request(request)).to_dict()
                    if case == "wrong-id":
                        envelope["evaluation"]["request_id"] = "wrong"
                    if case == "wrong-flags":
                        envelope["evaluation"]["enforcement_applied"] = True
                    if case == "extra-field":
                        envelope["private"] = "DO-NOT-EMIT"
                    return dict(status=case if type(case) is int else 200, body=envelope)
                result, bodies = bounded_node([str(DRIVER)], {"mode": "contract", "config": self.config()}, reply)
                self.assertEqual(result["observations"][0]["status"], "unavailable")
                self.assertIsNone(result["accepted_advisory_only"])
                self.assertEqual(len(bodies), 1)
                self.assertNotIn("DO-NOT-EMIT", json.dumps(result))

    def test_driver_transport_failure_deadline_and_cancel_no_retry(self):
        script = """
          import assert from 'node:assert/strict';
          import {runSmoke} from './tests/ask-gv/customer-zero-commercial-smoke-driver.mjs';
          globalThis.fetch=()=>{throw Error('native forbidden');};
          const config={endpoint:'http://127.0.0.1:8080/v1/evaluations',project:'customer-zero-contract',key:'FAKE-contract-only-key'};
          let calls=0;
          const failed=await runSmoke(config,{fetchImpl:async()=>{calls++;throw Error('PRIVATE-error');}});
          assert.equal(calls,1);assert.equal(failed.observations[0].status,'unavailable');
          const started=performance.now();let seen;
          const timed=await runSmoke(config,{fetchImpl:async(_u,o)=>{seen=o.signal;return new Promise(()=>{});}});
          assert.equal(timed.requests,1);assert.equal(timed.observations[0].status,'timeout');assert.equal(seen.aborted,true);
          assert.ok(performance.now()-started>=400 && performance.now()-started<2000);
          const controller=new AbortController();controller.abort();
          const cancel=await runSmoke(config,{signal:controller.signal,fetchImpl:()=>{throw Error('must not call');}});
          assert.equal(cancel.requests,0);assert.equal(cancel.observations[0].status,'cancelled');
          assert.equal(cancel.observations[1].provider_outcome,'not_attempted');
          assert.ok(!JSON.stringify(failed).includes('PRIVATE'));process.stdout.write('bounded-failures');
        """
        self.assertEqual(bounded_node(["--input-type=module", "-e", script], timeout=4), b"bounded-failures")

    def test_live_output_and_subprocess_deadline_limits(self):
        cases = [("process.stdout.write('SMOKE-CHILD-START\\n');process.stdout.write('x'.repeat(32768));", 2, "output_overflow"),
                 ("process.stdout.write('SMOKE-CHILD-START\\n');setInterval(()=>{},100);", 0.25, "deadline")]
        for script, timeout, expected in cases:
            with self.subTest(expected=expected), self.assertRaises(Hold) as caught:
                bounded_node(["-e", script], timeout=timeout, limit=8192, start_marker=START)
            self.assertEqual(caught.exception.code, expected)
            self.assertTrue(caught.exception.child_started)
            self.assertTrue(caught.exception.cleanup_verified)
        first = {"mode": "contract", "config": self.config()}
        script = "process.stdout.write('SMOKE-CHILD-START\\nnot-json\\n');"
        with self.assertRaises(Hold) as caught:
            bounded_capture([node_path(), "-e", script], first=first, timeout=2, start_marker=START)
        self.assertEqual(caught.exception.code, "protocol_error")
        self.assertTrue(caught.exception.child_started)
        self.assertTrue(caught.exception.cleanup_verified)

    def test_disposable_missing_or_inconsistent_authorization_holds(self):
        for environment in ({}, {"GVAI_CUSTOMER_ZERO_DISPOSABLE": "1"},
                            {"GVAI_CUSTOMER_ZERO_DISPOSABLE": "1", "GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED": SCOPE}):
            with self.assertRaises(Hold):
                load_resource_gate(environment)
        fixture = {"fixture_id": "customer-zero-test"}
        approval = dict(scope=SCOPE, fixture_id="customer-zero-other", fixture_sha256="a"*64,
                        candidate_sha256="b"*64, authorized=True, review_id="independent-review", expires_unix=200, source_head=PRESERVED_HEAD)
        with self.assertRaises(Hold):
            validate_approval(approval, fixture, "a"*64, "b"*64, now=100)
        approval["fixture_id"] = fixture["fixture_id"]
        validate_approval(approval, fixture, "a"*64, "b"*64, now=100)
        for patch_value in ({"authorized": False}, {"candidate_sha256": "c"*64}, {"expires_unix": 50}):
            with self.assertRaises(Hold):
                validate_approval({**approval, **patch_value}, fixture, "a"*64, "b"*64, now=100)


# OPT-IN DISPOSABLE SECTION. No fixture setup, DDL, Docker or role lifecycle.
def private_record(path, expected):
    need(type(path) is str and Path(path).is_absolute() and re.fullmatch(r"[0-9a-f]{64}", expected or ""))
    parent = Path(path).parent.lstat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and stat.S_IMODE(parent.st_mode) == 0o700)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and stat.S_IMODE(info.st_mode) in (0o400, 0o600) and info.st_size <= LIMIT)
        raw = os.read(fd, LIMIT + 1)
    finally:
        os.close(fd)
    need(len(raw) <= LIMIT and hashlib.sha256(raw).hexdigest() == expected)
    return strict_json(raw)


def validate_approval(approval, fixture, fixture_sha, candidate_sha, *, now):
    need(type(approval) is dict and set(approval) == {"scope", "fixture_id", "fixture_sha256", "candidate_sha256", "authorized", "review_id", "expires_unix", "source_head"})
    need(type(approval["source_head"]) is str and re.fullmatch(r"[0-9a-f]{40}", approval["source_head"]), "git_identity")
    need(approval["scope"] == SCOPE and approval["authorized"] is True)
    need(approval["fixture_id"] == fixture["fixture_id"] and approval["fixture_sha256"] == fixture_sha
         and approval["candidate_sha256"] == candidate_sha)
    need(type(approval["review_id"]) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", approval["review_id"]))
    need(type(approval["expires_unix"]) is int and now < approval["expires_unix"] <= now + 86400)


def load_resource_gate(environment=None):
    environment = os.environ if environment is None else environment
    need(environment.get("GVAI_CUSTOMER_ZERO_DISPOSABLE") == "1")
    need(environment.get("GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED") == SCOPE)
    refuse_libpq_environment(environment)
    require_external_execution_boundary()  # Permanent HOLD until a separately reviewed external integration.
    fixture_sha = environment.get("GVAI_CUSTOMER_ZERO_FIXTURE_SHA256", "")
    approval_sha = environment.get("GVAI_CUSTOMER_ZERO_APPROVAL_SHA256", "")
    fixture = private_record(environment.get("GVAI_CUSTOMER_ZERO_FIXTURE_FILE"), fixture_sha)
    approval = private_record(environment.get("GVAI_CUSTOMER_ZERO_APPROVAL_FILE"), approval_sha)
    approved_candidate = approval["candidate_sha256"]
    require_approved_candidate(approved_candidate)
    validate_approval(approval, fixture, fixture_sha, approved_candidate, now=int(time.time()))
    verify_execution_sources(approved_candidate, approval["source_head"])
    need(type(fixture) is dict and set(fixture) == {"fixture_id", "synthetic_only", "project", "evaluation_key", "usage_key", "runtime_config", "expected_database", "expected_runtime_role", "expected_server_version", "expected_database_port"})
    need(fixture["synthetic_only"] is True and re.fullmatch(r"customer-zero-[a-z0-9-]{1,64}", fixture["fixture_id"]))
    need(re.fullmatch(r"customer-zero-[a-z0-9-]{1,64}", fixture["project"]))
    need(re.fullmatch(r"gvai_advisory_test_customer_zero_[a-z0-9_]{1,40}", fixture["expected_database"]))
    need(re.fullmatch(r"customer_zero_[a-z0-9_]{1,40}", fixture["expected_runtime_role"]))
    need(re.fullmatch(r"[0-9]{6}", fixture["expected_server_version"]))
    need(fixture["evaluation_key"] != fixture["usage_key"])
    for name in ("evaluation_key", "usage_key"):
        need(re.fullmatch(r"gvai_customer_v1_[0-9a-f]{32}_[0-9a-f]{64}", fixture[name]))
    config = fixture["runtime_config"]
    need(type(config) is dict and set(config) == {"mode", "database_dsn", "verifier_secret_hex", "authority", "port", "max_connections"})
    need(config["mode"] == "private-staging" and type(config["port"]) is int and config["port"] == 0)
    need(type(config["max_connections"]) is int and config["max_connections"] == 2)
    need(config["authority"] == {"authority_id": "customer-zero-disposable", "epoch": 1, "trust_domain": "customer-zero-disposable"})
    need(type(config["verifier_secret_hex"]) is str and re.fullmatch(r"[0-9a-f]{64}", config["verifier_secret_hex"]))
    config["database_dsn"] = validate_destination(config["database_dsn"], fixture["expected_database"],
        fixture["expected_runtime_role"], fixture["expected_database_port"], environment=environment)
    need(bounded_node(["--version"], timeout=3).strip() == b"v24.22.2")
    return fixture, approval_sha, approved_candidate




class SourceAdmissionContracts(unittest.TestCase):
    def synthetic(self):
        database, role, port = "gvai_advisory_test_customer_zero_unit", "customer_zero_unit", 15432
        dsn = ("host=127.0.0.1 hostaddr=127.0.0.1 port=15432 dbname=" + database +
               " user=" + role + " password=FAKE_SYNTHETIC_1234")
        return dsn, database, role, port

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(Hold) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_destination_is_explicit_unambiguous_and_inert(self):
        dsn, database, role, port = self.synthetic()
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            self.assertEqual(validate_destination(dsn, database, role, port, environment={}), dsn)
            for bad in (dsn.replace("hostaddr=127.0.0.1 ", ""), dsn.replace("port=15432 ", ""),
                        dsn + " host=127.0.0.1", dsn + " service=forbidden", dsn + " options=forbidden",
                        dsn.replace("hostaddr=127.0.0.1", "hostaddr=192.0.2.1"),
                        dsn.replace("port=15432", "port=15432,15433"), dsn.replace("port=15432", "port=015432"),
                        dsn.replace("port=15432", "port=15433"), dsn.replace(" ", "\t", 1),
                        dsn.replace("host=127.0.0.1", "host='127.0.0.1'"), dsn + "\\", "postgresql://invalid"):
                self.assert_code("destination_invalid", validate_destination, bad, database, role, port, environment={})
            for invalid in (0, 65536, True, "15432", 1.5):
                self.assert_code("destination_invalid", validate_destination, dsn, database, role, invalid, environment={})
            for edge in (1, 65535):
                validate_destination(dsn.replace("port=15432", "port=" + str(edge)), database, role, edge, environment={})

    def test_ambient_libpq_values_are_never_read_or_disclosed(self):
        class KeysOnly(dict):
            def __getitem__(self, _):
                raise AssertionError("environment value must not be read")
        args = self.synthetic()
        for name in ("PGHOSTADDR", "PGPORT", "PGSERVICE", "PGSERVICEFILE", "PGSSLKEY", "PGANYTHING"):
            error = self.assert_code("libpq_environment", validate_destination, *args,
                                     environment=KeysOnly({name: object()}))
            self.assertEqual(str(error), "HOLD: libpq_environment")
            self.assertNotIn(name, str(error))

    def test_expected_digest_is_retained_or_holds_before_spawn(self):
        expected = "a" * 64
        self.assertEqual(require_approved_candidate(expected, digest=lambda: expected), expected)
        self.assert_code("source_integrity", require_approved_candidate, expected, digest=lambda: "b"*64)
        with patch.dict(globals(), candidate_digest=lambda: expected), patch("subprocess.Popen") as spawn:
            first = {"mode": "disposable", "authorization": {"candidate_sha256": "b"*64}}
            self.assert_code("source_integrity", bounded_node, [str(DRIVER)], first,
                             resource_admission="c"*64, approved_candidate=expected)
            first["authorization"]["candidate_sha256"] = expected
            self.assert_code("external_boundary_required", bounded_node, [str(DRIVER)], first,
                             resource_admission="c"*64, approved_candidate=expected)
            spawn.assert_not_called()

    def test_inert_git_backend_and_import_context_checks(self):
        from types import SimpleNamespace
        names = ["gvai/private_staging.py", "gvai/commercial_http.py", "gvai/commercial_service.py",
                 "gvai/postgresql_advisory.py", "gvai/postgresql_reservation_authority.py"]
        blobs = {rel: ("synthetic-only:" + rel).encode() for rel in [*FILES, *names]}
        def read(rel):
            return blobs[rel]
        expected = candidate_digest(reader=read)
        entries = b"".join(b"100644 blob " + hashlib.sha1(b"blob " + str(len(blobs[p])).encode() + b"\0" + blobs[p]).hexdigest().encode() + b"\t" + p.encode() + b"\0" for p in names)
        def capture(args):
            if args == ["rev-parse", "--show-toplevel"]:
                return str(ROOT).encode() + b"\n"
            if args == ["rev-parse", "HEAD"]:
                return PRESERVED_HEAD.encode() + b"\n"
            if args == ["branch", "--show-current"]:
                return b"feature/customer-zero-advisory-smoke-v1\n"
            if args[0] == "ls-tree":
                return entries
            return b""
        self.assertEqual(verify_execution_sources(expected, PRESERVED_HEAD, capture=capture, reader=read, modules={}), expected)
        def dirty(args):
            return b" M gvai/private_staging.py\n" if args[0] == "status" else capture(args)
        self.assert_code("source_integrity", verify_execution_sources, expected, PRESERVED_HEAD,
                         capture=dirty, reader=read, modules={})
        def wrong_head(args):
            return b"f"*40+b"\n" if args == ["rev-parse", "HEAD"] else capture(args)
        self.assert_code("git_identity", verify_execution_sources, expected, PRESERVED_HEAD,
                         capture=wrong_head, reader=read, modules={})
        blobs[names[0]] = b"changed backend outside five-file digest"
        self.assertEqual(candidate_digest(reader=read), expected)
        self.assert_code("source_integrity", verify_execution_sources, expected, PRESERVED_HEAD,
                         capture=capture, reader=read, modules={})
        blobs[names[0]] = ("synthetic-only:" + names[0]).encode()
        self.assert_code("source_integrity", verify_execution_sources, expected, PRESERVED_HEAD,
                         capture=capture, reader=read,
                         modules={"gvai.fake": SimpleNamespace(__file__="/tmp/unapproved.py")})

    def test_resource_gate_cannot_be_enabled_by_caller_assertions(self):
        environment = {"GVAI_CUSTOMER_ZERO_DISPOSABLE": "1", "GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED": SCOPE,
                       "GVAI_CUSTOMER_ZERO_APPROVAL_SHA256": "a"*64,
                       "GVAI_CUSTOMER_ZERO_FIXTURE_SHA256": "b"*64}
        with patch.dict(globals(), private_record=lambda *_: (_ for _ in ()).throw(AssertionError("must not read fixture"))):
            self.assert_code("external_boundary_required", load_resource_gate, environment)
            self.assert_code("libpq_environment", load_resource_gate, {**environment, "PGHOSTADDR": "DO-NOT-DISCLOSE"})

    def test_disposable_result_exit_policy_with_mocked_observations(self):
        script = """
          import assert from 'node:assert/strict';
          import {runSmoke,completionFrame} from './tests/ask-gv/customer-zero-commercial-smoke-driver.mjs';
          globalThis.fetch=()=>{throw Error('native forbidden');};
          const config={endpoint:'http://127.0.0.1:8080/v1/evaluations',project:'customer-zero-contract',key:'FAKE-contract-only-key'};
          const unavailable=await runSmoke(config,{fetchImpl:async()=>new Response('{}',{status:503})});
          for(const status of ['unavailable','timeout','cancelled']){
            const r=structuredClone(unavailable);r.evidence='disposable-connectivity-only';r.observations[0].status=status;
            const f=completionFrame(r,'disposable');assert.equal(f.exitCode,2);assert.equal(f.frame.type,'hold');
            assert.equal(completionFrame(r,'contract').exitCode,0);
          }
          const success=await runSmoke(config,{evidence:'mocked-contract',fetchImpl:async(_u,o)=>Response.json({outcome:'evaluated',reason:'evaluated',evaluation:{version:'gvai-evaluation-v1',request_id:JSON.parse(o.body).request_id,decision:'ALLOW',risk_score:0,risk_band:'green',explanation:'synthetic',evaluation_status:'ok',advisory_only:true,enforcement_applied:false}})});
          assert.equal(completionFrame(success,'disposable').exitCode,2); // mock is never native evidence
          success.evidence='disposable-connectivity-only';assert.equal(completionFrame(success,'disposable').exitCode,0);
          for(const change of [{requests:2},{accepted_advisory_only:false},{enforcement_applied:true},{http_status:503}])assert.equal(completionFrame({...success,...change},'disposable').exitCode,2);
          assert.ok(!JSON.stringify(completionFrame({...success,private:'PRIVATE'},'disposable')).includes('PRIVATE'));
          process.stdout.write('mocked-exit-policy');
        """
        self.assertEqual(bounded_node(["--input-type=module", "-e", script], timeout=4), b"mocked-exit-policy")

    def test_source_path_replacement_is_rejected_with_inert_file_mocks(self):
        from types import SimpleNamespace
        opened = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=3,
            st_dev=1, st_ino=8, st_mtime_ns=1, st_ctime_ns=1)
        replaced = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=3,
            st_dev=1, st_ino=9, st_mtime_ns=1, st_ctime_ns=1)
        with patch("os.open", return_value=91), patch("os.fstat", return_value=opened), \
             patch("os.read", side_effect=[b"abc", b""]), patch("os.close") as close, \
             patch.object(Path, "lstat", return_value=replaced):
            self.assert_code("source_integrity", bounded_source, ROOT / "synthetic-file")
            close.assert_called_once_with(91)

    def test_mocked_native_cli_admission_never_reaches_fetch(self):
        script = """
          import net from 'node:net';
          import {fileURLToPath} from 'node:url';
          net.Server.prototype.listen=()=>{throw Error('listener forbidden');};
          net.Socket.prototype.connect=()=>{throw Error('network forbidden');};
          let calls=0;globalThis.fetch=()=>{calls++;throw Error('native forbidden');};
          process.env.GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED='one-disposable-advisory-smoke';
          process.env.GVAI_CUSTOMER_ZERO_APPROVAL_SHA256='a'.repeat(64);
          process.stdout.write('SMOKE-CHILD-START\\n');
          const module=new URL('./tests/ask-gv/customer-zero-commercial-smoke-driver.mjs',import.meta.url);
          process.argv[1]=fileURLToPath(module);
          process.on('beforeExit',()=>{if(calls)process.exitCode=99;});
          await import(module);
        """
        private_input = dict(mode="disposable", config=self_config_for_cli(),
            authorization=dict(fixture_id="customer-zero-test", approval_sha256="a"*64,
                               candidate_sha256="b"*64, scope=SCOPE))
        with self.assertRaises(Hold) as caught:
            bounded_capture([node_path(), "--input-type=module", "-e", script],
                raw_input=json.dumps(private_input).encode()+b"\n", timeout=4, start_marker=START)
        self.assertEqual(caught.exception.code, "process_exit")
        self.assertEqual(caught.exception.exit_status, 2)
        self.assertTrue(caught.exception.child_started)
        self.assertTrue(caught.exception.cleanup_verified)


def self_config_for_cli():
    return dict(endpoint="http://127.0.0.1:15432/v1/evaluations", project="customer-zero-test", key="FAKE-synthetic-cli-key")


class LifecycleFaultContracts(unittest.TestCase):
    class Pipe:
        def close(self):
            pass
    class Process:
        pid = 32123
        def __init__(self, events, wait_failure=False):
            self.events, self.wait_failure, self.reaped = events, wait_failure, False
            self.stdin = LifecycleFaultContracts.Pipe()
            self.stdout = LifecycleFaultContracts.Pipe()
            self.stderr = LifecycleFaultContracts.Pipe()
        def poll(self):
            raise AssertionError("poll would prematurely reap the ownership anchor")
        def wait(self, timeout):
            self.events.append(("reap", timeout))
            self.reaped = True
            if self.wait_failure:
                raise subprocess.TimeoutExpired("synthetic", timeout)
            return 0
    class Ownership:
        def __init__(self, events, *, changed=False, fail_anchor=False):
            self.events, self.changed, self.fail_anchor = events, changed, fail_anchor
        def anchor(self, proc):
            self.events.append("anchor")
            if self.fail_anchor:
                raise OSError("PRIVATE anchor detail")
            return (123, proc.pid, proc.pid, 111)
        def peek(self, proc):
            self.events.append("peek-unreaped")
            return 0  # exited leader, still retained until group cleanup
        def signal_group(self, proc, anchor):
            self.events.append("verify-group")
            if self.changed:
                raise Hold("ownership_unverified")
            assert not proc.reaped and anchor[1] == proc.pid
            self.events.append("kill-owned-group")
        def descendants_gone(self, proc):
            self.events.append("descendants-absent")
            return True
        def signal_leader_handle(self, proc):
            self.events.append("pidfd-only")
        def close_handle(self, proc):
            self.events.append("close-pidfd")

    def test_exited_leader_retains_anchor_through_group_cleanup(self):
        events = []
        proc = self.Process(events)
        owner = OwnedProcess(popen=lambda *a, **k: proc, ownership=self.Ownership(events))
        with owner:
            owner.spawn(["synthetic"], ROOT, {})
            self.assertEqual(owner.ownership.peek(proc), 0)
        self.assertTrue(owner.cleanup_verified)
        self.assertLess(events.index("kill-owned-group"), events.index(("reap", 2)))
        self.assertIn("descendants-absent", events)

    def test_partial_selector_setup_failure_is_owned_and_reaped(self):
        events = []
        proc = self.Process(events)
        def broken_selector():
            raise OSError("PRIVATE selector failure")
        with self.assertRaises(Hold) as caught:
            bounded_capture(["synthetic"], popen=lambda *a, **k: proc,
                            ownership=self.Ownership(events), selector_factory=broken_selector)
        self.assertEqual(caught.exception.code, "protocol_error")
        self.assertTrue(caught.exception.cleanup_verified)
        self.assertIn("kill-owned-group", events)
        self.assertTrue(proc.reaped)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_identity_change_and_partial_anchor_never_guess_numeric_group(self):
        for options in ({"changed": True}, {"fail_anchor": True}):
            events = []
            owner = OwnedProcess(popen=lambda *a, **k: self.Process(events), ownership=self.Ownership(events, **options))
            with self.assertRaises(Hold) as caught:
                with owner:
                    owner.spawn(["synthetic"], ROOT, {})
            self.assertEqual(caught.exception.code, "cleanup_failure")
            self.assertFalse(owner.cleanup_verified)
            self.assertNotIn("kill-owned-group", events)
            self.assertIn("pidfd-only", events)
            self.assertIn(("reap", 2), events)

    def test_cooperative_cancellation_restores_handlers_after_cleanup(self):
        handlers = {n: signal.getsignal(n) for n in (signal.SIGTERM, signal.SIGINT)}
        events = []
        owner = OwnedProcess(popen=lambda *a, **k: self.Process(events), ownership=self.Ownership(events))
        with self.assertRaises(Hold) as caught:
            with owner:
                owner.spawn(["synthetic"], ROOT, {})
                owner.note_cancelled()
                owner.check_cancelled()
        self.assertEqual(caught.exception.code, "cancelled")
        self.assertTrue(owner.cleanup_verified)
        self.assertIn("kill-owned-group", events)
        self.assertEqual({n: signal.getsignal(n) for n in handlers}, handlers)

    def test_spawn_failure_is_distinct_and_creates_no_process(self):
        def failed(*a, **k):
            raise OSError("PRIVATE spawn failure")
        with self.assertRaises(Hold) as caught:
            bounded_capture(["synthetic"], popen=failed)
        self.assertEqual(caught.exception.code, "spawn_failure")
        self.assertFalse(caught.exception.child_started)
        self.assertTrue(caught.exception.cleanup_verified)
        self.assertNotIn("PRIVATE", str(caught.exception))

    def test_reap_failure_is_bounded_and_never_reported_clean(self):
        events = []
        owner = OwnedProcess(popen=lambda *a, **k: self.Process(events, wait_failure=True), ownership=self.Ownership(events))
        with self.assertRaises(Hold) as caught:
            with owner:
                owner.spawn(["synthetic"], ROOT, {})
        self.assertEqual(caught.exception.code, "cleanup_failure")
        self.assertFalse(owner.cleanup_verified)
        self.assertEqual(events.count(("reap", 2)), 1)

    def test_group_escape_inside_owned_session_is_not_reported_gone(self):
        from types import SimpleNamespace
        class Entries(list):
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
        ownership = LinuxOwnership()
        with patch("os.scandir", return_value=Entries([SimpleNamespace(name="32124")])), \
             patch.object(ownership, "identity", return_value=(999, 70000, 32123, 123)):
            self.assertFalse(ownership.descendants_gone(SimpleNamespace(pid=32123)))


class DisposableSmoke(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GVAI_CUSTOMER_ZERO_DISPOSABLE") == "1",
                         "NOT RUN: separately authorized reviewed disposable fixture required")
    def test_disposable_http_postgresql_smoke(self):
        # Missing admission information is a failure/HOLD, never a skip or a PASS.
        app = None
        try:
            fixture, approval_sha, approved_candidate = load_resource_gate()
            from gvai.commercial_reservation_authority import AuthorityIdentity
            from gvai.private_staging import PrivateStagingApplication, StagingConfig
            cfg = fixture["runtime_config"]
            require_approved_candidate(approved_candidate)
            refuse_libpq_environment(os.environ)
            app = PrivateStagingApplication(StagingConfig(cfg["database_dsn"], bytes.fromhex(cfg["verifier_secret_hex"]),
                AuthorityIdentity(**cfg["authority"]), port=0, max_connections=2))
            with app.connections() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT current_database(),current_user,current_setting('server_version_num')")
                need(cursor.fetchone() == (fixture["expected_database"], fixture["expected_runtime_role"], fixture["expected_server_version"]))
            # Independent usage key; Node receives only the evaluate-only customer key.
            need(app.usage.summary(fixture["evaluation_key"], fixture["project"]) is None)
            before = app.usage.summary(fixture["usage_key"], fixture["project"])
            need(before is not None and (before.allowance, before.consumed, before.reserved, before.completed, before.failed) == (3, 0, 0, 0, 0))
            app.start()
            endpoint = "http://127.0.0.1:" + str(app.server.server_port) + "/v1/evaluations"
            private_input = dict(mode="disposable", config=dict(endpoint=endpoint, project=fixture["project"], key=fixture["evaluation_key"]),
                authorization=dict(fixture_id=fixture["fixture_id"], approval_sha256=approval_sha,
                                   candidate_sha256=require_approved_candidate(approved_candidate), scope=SCOPE))
            result, bodies = bounded_node([str(DRIVER)], private_input, resource_admission=approval_sha, approved_candidate=approved_candidate)
            need(not bodies and result["evidence"] == "disposable-connectivity-only" and result["http_status"] == 200)
            need(result["observations"][0]["status"] == "evaluated")
            need(tuple(result["observations"][0][field] for field in ("decision", "risk_band", "risk_score")) == ("ALLOW", "green", 0))
            after = app.usage.summary(fixture["usage_key"], fixture["project"])
            need(after is not None and (after.allowance, after.consumed, after.reserved, after.completed, after.failed, after.remaining) == (3, 1, 0, 1, 0, 2))
            # Only one generated request. Replay, restart and fault matrices are later slices.
        except Exception:
            raise Hold("prerequisite") from None
        finally:
            if app is not None:
                try:
                    app.stop()
                except Exception:
                    raise Hold("cleanup_failure") from None


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    unittest.main(verbosity=2)
