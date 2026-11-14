"""Resource-free contracts by default; one separately admitted disposable case.

No test-module imports, listeners, DB connections or network operations at import.
Run this file directly for stdlib unittest (no blanket discovery is necessary).
"""
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
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
DRIVER = ROOT / "tests/ask-gv/customer-zero-commercial-smoke-driver.mjs"
L = "3c117260901cb15877512161cb24fa8e5587aa73"
N = "c3fd88a236f32aa9b84e6baaa212cb4db79d02ca"
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


class Hold(RuntimeError):
    """Fixed redacted failure; never attach raw subprocess or database output."""


def need(condition):
    if not condition:
        raise Hold("HOLD: smoke prerequisite or contract failed")


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
        raise Hold("HOLD: invalid private frame") from None


def candidate_digest():
    manifest = "".join(path + "\0" + hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                       + "\n" for path in sorted(FILES))
    return hashlib.sha256(manifest.encode()).hexdigest()


def node_path():
    node = shutil.which("node")
    need(node is not None)
    return node


def bounded_node(args, first=None, reply=None, *, timeout=8, limit=LIMIT, resource_admission=None):
    """Private JSON-lines protocol; bounded live reads, writes and whole process.

    No communicate(capture everything) and no unbounded check_output. Exact owned
    process group is killed/reaped on failure, deadline, oversized output or exit.
    args are trusted static options only; keys/config travel over private stdin.
    """
    need(0 < timeout <= 15 and 0 < limit <= 32768)
    pending = bytearray(b"" if first is None else json.dumps(first, allow_nan=False).encode() + b"\n")
    need(len(pending) <= LIMIT)
    child_environment = {"PATH": os.defpath, "TZ": "UTC"}
    if first is not None and first.get("mode") == "disposable":
        need(resource_admission is not None and resource_admission == first["authorization"]["approval_sha256"])
        child_environment.update(GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED=SCOPE,
                                 GVAI_CUSTOMER_ZERO_APPROVAL_SHA256=resource_admission)
    else:
        need(resource_admission is None)
    proc = subprocess.Popen([node_path(), *args], cwd=ROOT, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=child_environment,
                            start_new_session=True, bufsize=0)
    deadline = time.monotonic() + timeout
    streams = selectors.DefaultSelector()
    received = {"stdout": bytearray(), "stderr": bytearray()}
    frames, wire_requests = [], []
    stdout_pending = bytearray()
    try:
        for pipe, name in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            os.set_blocking(pipe.fileno(), False)
            streams.register(pipe, selectors.EVENT_READ, name)
        os.set_blocking(proc.stdin.fileno(), False)
        if pending:
            streams.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
        while any(key.data != "stdin" for key in streams.get_map().values()):
            remaining = deadline - time.monotonic()
            need(remaining > 0)
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
                chunk = os.read(pipe.fileno(), 4096)
                if not chunk:
                    streams.unregister(pipe)
                    continue
                received[name].extend(chunk)
                need(len(received[name]) <= limit)
                if name == "stdout" and first is not None:
                    stdout_pending.extend(chunk)
                    while b"\n" in stdout_pending:
                        line, _, rest = stdout_pending.partition(b"\n")
                        stdout_pending = bytearray(rest)
                        frame = strict_json(line.decode("utf-8", errors="strict"))
                        need(isinstance(frame, dict) and len(frames) < 2)
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
        need(proc.wait(timeout=max(0.01, deadline - time.monotonic())) == 0)
        need(not received["stderr"] and not stdout_pending and not pending)
        if first is None:
            return bytes(received["stdout"])
        expected_types = ["request", "result"] if first["mode"] == "contract" else ["result"]
        need([frame.get("type") for frame in frames] == expected_types)
        result = frames[-1].get("result")
        validate_result(result)
        if wire_requests:
            need(result["request_id"] == wire_requests[0]["request_id"])
        return result, wire_requests
    except BaseException as error:
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise Hold("HOLD: Node failed, timed out or exceeded protocol bounds") from None
    finally:
        streams.close()
        # No subprocess descendants are expected. All cleanup is confined to this owned group.
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        proc.wait(timeout=2)
        for pipe in (proc.stdin, proc.stdout, proc.stderr):
            pipe.close()


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
        for script, timeout in (("process.stdout.write('x'.repeat(32768));", 2),
                                ("setInterval(()=>{},100);", 0.2)):
            with self.assertRaises(Hold):
                bounded_node(["-e", script], timeout=timeout, limit=8192)

    def test_disposable_missing_or_inconsistent_authorization_holds(self):
        for environment in ({}, {"GVAI_CUSTOMER_ZERO_DISPOSABLE": "1"},
                            {"GVAI_CUSTOMER_ZERO_DISPOSABLE": "1", "GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED": SCOPE}):
            with self.assertRaises(Hold):
                load_resource_gate(environment)
        fixture = {"fixture_id": "customer-zero-test"}
        approval = dict(scope=SCOPE, fixture_id="customer-zero-other", fixture_sha256="a"*64,
                        candidate_sha256="b"*64, authorized=True, review_id="independent-review", expires_unix=200)
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
    need(type(approval) is dict and set(approval) == {"scope", "fixture_id", "fixture_sha256", "candidate_sha256", "authorized", "review_id", "expires_unix"})
    need(approval["scope"] == SCOPE and approval["authorized"] is True)
    need(approval["fixture_id"] == fixture["fixture_id"] and approval["fixture_sha256"] == fixture_sha
         and approval["candidate_sha256"] == candidate_sha)
    need(type(approval["review_id"]) is str and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", approval["review_id"]))
    need(type(approval["expires_unix"]) is int and now < approval["expires_unix"] <= now + 86400)


def load_resource_gate(environment=None):
    environment = os.environ if environment is None else environment
    need(environment.get("GVAI_CUSTOMER_ZERO_DISPOSABLE") == "1")
    need(environment.get("GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED") == SCOPE)
    fixture_sha = environment.get("GVAI_CUSTOMER_ZERO_FIXTURE_SHA256", "")
    approval_sha = environment.get("GVAI_CUSTOMER_ZERO_APPROVAL_SHA256", "")
    fixture = private_record(environment.get("GVAI_CUSTOMER_ZERO_FIXTURE_FILE"), fixture_sha)
    approval = private_record(environment.get("GVAI_CUSTOMER_ZERO_APPROVAL_FILE"), approval_sha)
    validate_approval(approval, fixture, fixture_sha, candidate_digest(), now=int(time.time()))
    need(type(fixture) is dict and set(fixture) == {"fixture_id", "synthetic_only", "project", "evaluation_key", "usage_key", "runtime_config", "expected_database", "expected_runtime_role", "expected_server_version"})
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
    # Importing conninfo does not connect. Only after all external admission checks.
    from psycopg.conninfo import conninfo_to_dict
    parameters = conninfo_to_dict(config["database_dsn"])
    need(parameters.get("host") == "127.0.0.1" and parameters.get("hostaddr", "127.0.0.1") == "127.0.0.1")
    need(parameters.get("dbname") == fixture["expected_database"] and parameters.get("user") == fixture["expected_runtime_role"])
    need(set(parameters) <= {"host", "hostaddr", "port", "dbname", "user", "password"} and bool(parameters.get("password")))
    need(bounded_node(["--version"], timeout=3).strip() == b"v24.22.2")
    return fixture, approval_sha


class DisposableSmoke(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("GVAI_CUSTOMER_ZERO_DISPOSABLE") == "1",
                         "NOT RUN: separately authorized reviewed disposable fixture required")
    def test_disposable_http_postgresql_smoke(self):
        # Missing admission information is a failure/HOLD, never a skip or a PASS.
        app = None
        try:
            fixture, approval_sha = load_resource_gate()
            from gvai.commercial_reservation_authority import AuthorityIdentity
            from gvai.private_staging import PrivateStagingApplication, StagingConfig
            cfg = fixture["runtime_config"]
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
                                   candidate_sha256=candidate_digest(), scope=SCOPE))
            result, bodies = bounded_node([str(DRIVER)], private_input, resource_admission=approval_sha)
            need(not bodies and result["evidence"] == "disposable-connectivity-only" and result["http_status"] == 200)
            need(result["observations"][0]["status"] == "evaluated")
            need(tuple(result["observations"][0][field] for field in ("decision", "risk_band", "risk_score")) == ("ALLOW", "green", 0))
            after = app.usage.summary(fixture["usage_key"], fixture["project"])
            need(after is not None and (after.allowance, after.consumed, after.reserved, after.completed, after.failed, after.remaining) == (3, 1, 0, 1, 0, 2))
            # Only one generated request. Replay, restart and fault matrices are later slices.
        except Exception:
            raise Hold("HOLD: disposable smoke incomplete; reconcile durable state before any retry") from None
        finally:
            if app is not None:
                try:
                    app.stop()
                except Exception:
                    raise Hold("HOLD: disposable HTTP/DB lease shutdown unverified") from None


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    unittest.main(verbosity=2)
