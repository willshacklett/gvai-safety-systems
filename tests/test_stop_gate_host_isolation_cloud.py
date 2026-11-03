"""OS-level UID/DAC isolation harness for the external STOP gate (Cloud sandbox).

Creates three throwaway system users, launches the REAL gate/backend
entrypoints (gvai.external_gate_service) as separate users with socket
activation emulated the way systemd does it, then runs the host acceptance
module as root. Skipped unless root with useradd/setpriv/runuser available.

What a pass here shows: UID/DAC separation between API, gate and backend, and
that the acceptance checks detect weakened permissions. What it does NOT
show: systemd sandboxing, AppArmor, cgroups, network confinement, or anything
about Lab-01.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import pytest

pytest.importorskip("cryptography")
import cffi
import cryptography
import pycparser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import host_isolation_acceptance as hia
from test_experimental_external_gate import pub, signed

PY = "/usr/bin/python3"
USERS = {"api": "gvsim-api", "gate": "gvsim-gate", "backend": "gvsim-backend"}
needs_root = pytest.mark.skipif(
    os.geteuid() != 0 or not all(shutil.which(c) for c in ("useradd", "userdel", "setpriv", "runuser")),
    reason="requires root plus useradd/setpriv/runuser (disposable sandbox only)",
)


def sh(*argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def _listen(path, owner_uid, mode=0o600):
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    os.chown(path, owner_uid, -1)
    os.chmod(path, mode)
    s.listen(64)
    return s.detach()


class Sim:
    def __init__(self):
        self.created_users = []
        self.dir = tempfile.mkdtemp(prefix="gvsim-")
        os.chmod(self.dir, 0o755)
        self.procs = []
        self.stop_key, self.arm_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        for role, name in USERS.items():
            if sh("id", name).returncode == 0:
                raise RuntimeError(f"user {name} already exists; refusing to touch it")
            assert sh("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name).returncode == 0
            self.created_users.append(name)
        import pwd

        self.uid = {r: pwd.getpwnam(n).pw_uid for r, n in USERS.items()}
        self.gid = {r: pwd.getpwnam(n).pw_gid for r, n in USERS.items()}
        self._layout_dirs()

    def _p(self, *parts):
        return os.path.join(self.dir, *parts)

    def _mk(self, path, uid, gid, mode):
        os.makedirs(path)
        os.chown(path, uid, gid)
        os.chmod(path, mode)

    def _layout_dirs(self):
        site = self._p("site")
        os.makedirs(site)
        for mod in (cryptography, cffi, pycparser):
            shutil.copytree(os.path.dirname(mod.__file__), os.path.join(site, os.path.basename(os.path.dirname(mod.__file__))))
        import glob
        import _cffi_backend

        shutil.copy(_cffi_backend.__file__, site)
        shutil.copytree(os.path.join(os.path.dirname(__file__), "..", "gvai"), self._p("src", "gvai"))
        subprocess.run(["chmod", "-R", "a+rX", self.dir])
        self._mk(self._p("gate-state"), self.uid["gate"], self.gid["gate"], 0o700)
        self._mk(self._p("etc-gate"), 0, self.gid["gate"], 0o750)
        self._mk(self._p("etc-backend"), 0, self.gid["backend"], 0o750)
        self._mk(self._p("cred"), self.uid["backend"], self.gid["backend"], 0o700)
        os.makedirs(self._p("run"))
        os.chmod(self._p("run"), 0o755)
        self.credential = os.urandom(32)
        cred = self._p("cred", "downstream")
        with open(cred, "wb") as fh:
            fh.write(self.credential)
        os.chown(cred, self.uid["backend"], self.gid["backend"])
        os.chmod(cred, 0o600)
        self.sock = {
            "gate_service": self._p("run", "gate.sock"),
            "gate_control": self._p("run", "gate-control.sock"),
            "backend_service": self._p("run", "backend.sock"),
            "backend_notice": self._p("run", "backend-notice.sock"),
        }
        gate_cfg = {
            "state_dir": self._p("gate-state"), "latch_id": "latch-1",
            "stop_keys": {"stop-k1": pub(self.stop_key).hex()},
            "arm_keys": {"arm-k1": pub(self.arm_key).hex()},
            "operations": ["downstream_sign"], "token_ttl": 5.0,
            "backend_notice_socket": self.sock["backend_notice"], "heartbeat_interval": 0.1,
        }
        self.gate_cfg_path = self._p("etc-gate", "gate.json")
        self._write(self.gate_cfg_path, gate_cfg, self.gid["gate"], 0o640)

    def _write(self, path, obj, gid, mode):
        with open(path, "w") as fh:
            json.dump(obj, fh)
        os.chown(path, 0, gid)
        os.chmod(path, mode)

    def _launch(self, role, module_role, cfg_path, listeners, extra_env=None):
        fds = {name: _listen(path, uid) for name, (path, uid) in listeners.items()}
        order = list(fds)
        env = {
            "LISTEN_FDS": str(len(order)), "LISTEN_FDNAMES": ":".join(order),
            "PATH": "/usr/bin:/bin", **(extra_env or {}),
        }
        code = (
            "import os,sys;os.environ['LISTEN_PID']=str(os.getpid());"
            f"sys.path[:0]=[{self._p('site')!r},{self._p('src')!r}];"
            "from gvai.external_gate_service import main;"
            f"sys.exit(main([{module_role!r},'--config',{cfg_path!r}]))"
        )

        def preexec():
            import fcntl

            high = [fcntl.fcntl(fds[n], fcntl.F_DUPFD, 100) for n in order]
            for i, fd in enumerate(high):
                os.dup2(fd, 3 + i)  # dup2 clears CLOEXEC on the target

        argv = [
            "setpriv", f"--reuid={self.uid[role]}", f"--regid={self.gid[role]}", "--clear-groups",
            "--no-new-privs", "--bounding-set=-all", "--inh-caps=-all",
            PY, "-c", code,
        ]
        proc = subprocess.Popen(
            argv, env=env, close_fds=False, preexec_fn=preexec,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        for fd in fds.values():
            os.close(fd)
        self.procs.append(proc)
        return proc

    def start(self):
        pk = sh(
            "setpriv", f"--reuid={self.uid['gate']}", f"--regid={self.gid['gate']}", "--clear-groups",
            PY, "-c",
            f"import sys;sys.path[:0]=[{self._p('site')!r},{self._p('src')!r}];"
            "from gvai.external_gate_service import main;"
            f"sys.exit(main(['gate-pubkey','--config',{self.gate_cfg_path!r}]))",
        )
        assert pk.returncode == 0, pk.stderr
        backend_cfg = {
            "gate_public_key": pk.stdout.strip(), "latch_id": "latch-1",
            "notice_max_age": 3.0, "interrupt_deadline": 1.0,
        }
        self.backend_cfg_path = self._p("etc-backend", "backend.json")
        self._write(self.backend_cfg_path, backend_cfg, self.gid["backend"], 0o640)
        self.backend = self._launch(
            "backend", "backend", self.backend_cfg_path,
            {"service": (self.sock["backend_service"], self.uid["api"]),
             "notice": (self.sock["backend_notice"], self.uid["gate"])},
            {"CREDENTIALS_DIRECTORY": self._p("cred")},
        )
        self.gate = self._launch(
            "gate", "gate", self.gate_cfg_path,
            {"service": (self.sock["gate_service"], self.uid["api"]),
             "control": (self.sock["gate_control"], 0)},
        )
        from gvai import experimental_external_gate as eg

        for _ in range(100):
            if eg.GateClient(self.sock["gate_service"]).status().get("ok"):
                return
            time.sleep(0.1)
        raise RuntimeError("gate did not come up: " + self.gate.stderr.read().decode()[-500:])

    def layout(self):
        return {
            "users": USERS,
            "files": {
                "gate_seed": self._p("gate-state", "gate_key.seed"),
                "anchor": self._p("gate-state", "anchor.json"),
                "store": self._p("gate-state", "store.json"),
                "backend_credential": self._p("cred", "downstream"),
            },
            "dirs": {"gate_state": self._p("gate-state"), "backend_credential": self._p("cred")},
            "sockets": self.sock,
            "pids": {"gate": self.gate.pid, "backend": self.backend.pid},
            "scan_roots": [self.dir],
        }

    def control(self):
        from gvai import experimental_external_gate as eg

        return eg.GateClient(self.sock["gate_control"])

    def arm(self, seq):
        r = self.control().submit_command(signed(self.arm_key, "arm-k1", seq, "arm"))
        assert r["ok"], r
        time.sleep(0.1)

    def stop(self, seq):
        r = self.control().submit_command(signed(self.stop_key, "stop-k1", seq, "stop"))
        assert r["ok"], r

    def close(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait(5)
        for name in self.created_users:
            sh("userdel", name)
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture(scope="module")
def sim():
    s = Sim()
    try:
        s.start()
        s.arm(1)
        # Make the protected files exist before probing.
        deadline = time.time() + 5
        while time.time() < deadline and not os.path.exists(s.layout()["files"]["anchor"]):
            time.sleep(0.1)
        yield s
    finally:
        s.close()


def result_map(report):
    return {r["id"]: r for r in report["results"]}


@needs_root
def test_acceptance_passes_with_least_privilege_layout(sim):
    report = hia.run_acceptance(sim.layout())
    failed = [r for r in report["results"] if not r["ok"]]
    assert failed == [], failed
    assert report["all_passed"] and report["failed"] == 0
    ids = result_map(report)
    for required in (
        "read_gate_seed", "append_anchor", "rename_anchor", "create_in_gate_state_dir",
        "read_backend_credential", "signal0_gate", "signal0_backend", "read_mem_gate",
        "connect_gate_control_socket", "connect_backend_notice_socket",
        "positive_gate_service_reachable", "gate_service_refuses_command",
        "backend_service_refuses_notice", "no_protected_secret_readable_by_api_user",
        "gate_no_new_privs", "backend_effective_caps_empty", "control_owner_can_read_gate_seed",
    ):
        assert ids[required]["ok"], required
    print("ACCEPTANCE_COUNTS", report["passed"], report["failed"])


@needs_root
def test_acceptance_detects_weakened_permissions(sim):
    seed = sim.layout()["files"]["gate_seed"]
    anchor = sim.layout()["files"]["anchor"]
    state_dir = sim.layout()["dirs"]["gate_state"]
    os.chmod(state_dir, 0o755)
    os.chmod(seed, 0o644)
    os.chmod(anchor, 0o666)
    try:
        report = hia.run_acceptance(sim.layout())
    finally:
        os.chmod(state_dir, 0o700)
        os.chmod(seed, 0o600)
        os.chmod(anchor, 0o600)
    assert not report["all_passed"]
    assert {"read_gate_seed", "read_anchor", "append_anchor",
            "no_protected_secret_readable_by_api_user"} <= set(report["failed_ids"])


@needs_root
def test_acceptance_detects_open_control_socket_and_group_membership(sim):
    os.chmod(sim.sock["gate_control"], 0o666)
    try:
        report = hia.run_acceptance(sim.layout())
    finally:
        os.chmod(sim.sock["gate_control"], 0o600)
    assert "connect_gate_control_socket" in report["failed_ids"]


@needs_root
def test_api_user_cannot_clear_backend_startup_inhibition(sim):
    script = (
        "import sys,json;sys.path[:0]=[%r,%r];"
        "from gvai import experimental_external_gate as eg;"
        "svc=eg.GatedService(eg.GateClient(%r),eg.BackendClient(%r));"
        "print(json.dumps(svc.call('downstream_sign',{'x':1})))"
    ) % (sim._p("site"), sim._p("src"), sim.sock["gate_service"], sim.sock["backend_service"])
    r = sh("runuser", "-u", USERS["api"], "--", PY, "-c", script)
    out = json.loads(r.stdout)
    assert out == {"ok": False, "reason": "recovery_inhibited"}
    assert sim.credential.hex() not in r.stdout and sim.credential not in r.stdout.encode()
    sim.stop(2)
    r = sh("runuser", "-u", USERS["api"], "--", PY, "-c", script)
    assert json.loads(r.stdout)["ok"] is False
    sim.arm(3)
    r = sh("runuser", "-u", USERS["api"], "--", PY, "-c", script)
    assert json.loads(r.stdout) == {"ok": False, "reason": "recovery_inhibited"}


@needs_root
def test_api_user_cannot_arm_even_with_valid_command_bytes(sim):
    # The ARM bytes are valid, but the API user can neither reach the control socket
    # nor use the service socket for commands.
    cmd = json.dumps(signed(sim.arm_key, "arm-k1", 99, "arm"))
    script = (
        "import sys,json;sys.path[:0]=[%r,%r];"
        "from gvai import experimental_external_gate as eg;"
        "print(json.dumps([eg.GateClient(%r).submit_command(%s)['reason'],"
        "eg.GateClient(%r).submit_command(%s)['reason']]))"
    ) % (sim._p("site"), sim._p("src"), sim.sock["gate_control"], cmd, sim.sock["gate_service"], cmd)
    r = sh("runuser", "-u", USERS["api"], "--", PY, "-c", script)
    assert json.loads(r.stdout) == ["communication_failure", "request_not_permitted"]


def test_process_hardening_evaluator_pure():
    ok = {"Uid": "999\t999\t999\t999", "NoNewPrivs": "1", "CapEff": "0000000000000000",
          "CapBnd": "0000000000000000", "Groups": ""}
    assert all(c["ok"] for c in hia.evaluate_process_hardening(ok, 999))
    bad = dict(ok, NoNewPrivs="0", CapEff="0000000000000001", Groups="27", Uid="0\t0\t0\t0")
    failed = {c["id"] for c in hia.evaluate_process_hardening(bad, 0) if not c["ok"]}
    assert failed == {"uid_all_equal_expected", "no_new_privs", "effective_caps_empty",
                      "no_supplementary_groups"}
    aa = hia.evaluate_process_hardening(ok, 999, apparmor="unconfined", expected_apparmor="gvai-stop-gate")
    assert [c["ok"] for c in aa][-1] is False
    aa = hia.evaluate_process_hardening(ok, 999, apparmor="gvai-stop-gate (enforce)", expected_apparmor="gvai-stop-gate")
    assert aa[-1]["ok"]
    assert hia.parse_proc_status("Name:\tx\nNoNewPrivs:\t1\nCapEff:\t0\n") == {"NoNewPrivs": "1", "CapEff": "0"}
