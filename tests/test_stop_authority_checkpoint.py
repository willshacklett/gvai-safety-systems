"""Authenticated fake remote exchanges; no actual off-host authority."""

import json
import threading
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import stop_authority_checkpoint as cp
from gvai import stop_authority_filesystem as fs
from gvai import stop_generation_authority as sa
from gvai.experimental_stop_latch import StopLatchKeyring, signing_bytes


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


def assert_rejected(rig, raw):
    response = cp._verify(
        cp._decode(rig.server.exchange(raw)), cp.RESPONSE_DOMAIN,
        rig.server_key.public_key(),
    )
    assert response["verdict"] == "UNKNOWN"
    assert response["reason"] == "checkpoint_request_rejected"
    assert response["checkpoint"] is None


class Transport:
    def __init__(self, server):
        self.server = server
        self.mode = "ok"
        self.requests, self.replies = [], []

    def exchange(self, raw):
        self.requests.append(raw)
        if self.mode == "unavailable":
            raise OSError("private remote detail")
        if self.mode == "lost_before":
            raise TimeoutError("request not delivered")
        if self.mode == "replay_reply":
            return self.replies[-1]
        reply = self.server.exchange(raw)
        self.replies.append(reply)
        if self.mode == "lost_after":
            raise TimeoutError("reply lost")
        if self.mode == "tampered":
            return reply.replace(b"checkpoint_matches", b"checkpoint_advanced")
        return reply


class Rig:
    def __init__(self, tmp_path):
        self.stop, arm, self.client_key, self.server_key, self.other_key = [
            Ed25519PrivateKey.generate() for _ in range(5)
        ]
        self.keys = StopLatchKeyring({"stop": public(self.stop)}, {"arm": public(arm)})
        self.path = tmp_path / "authority"
        self.path.mkdir(mode=0o700)
        self.genesis = sa.AuthoritySnapshot("authority", "latch")
        fs.FilesystemAuthorityAdapter.provision(str(self.path), self.genesis, self.keys)
        self.local = fs.FilesystemAuthorityAdapter(str(self.path), "authority", "latch", self.keys)
        self.authority = sa.StopGenerationAuthority("authority", "latch", self.keys, self.local)
        self.initial = cp.checkpoint_for(self.genesis, "checkpoint", "offhost")
        self.server = cp.SimulatedCheckpointServer(
            initial=self.initial, server_id="server",
            clients={"client": ("writer", public(self.client_key)),
                     "other": ("other", public(self.other_key))},
            signer=self.server_key.sign, stop_keys=self.keys,
        )
        self.transport = Transport(self.server)
        self.client = self.make_client()

    def make_client(self, **changes):
        options = dict(
            authority_id="authority", latch_id="latch", checkpoint_id="checkpoint",
            trust_domain="offhost", client_id="client", writer_id="writer",
            server_id="server", server_public_key=public(self.server_key),
            signer=self.client_key.sign, transport=self.transport, stop_keys=self.keys,
        )
        options.update(changes)
        return cp.CheckpointClient(**options)

    def fence(self, writer="writer", previous=0):
        assert self.authority.fence_writer(writer, previous).reason == "writer_fenced"
        return self.local.load()

    def stop_once(self, sequence=1, writer="writer", fence=1):
        envelope = {
            "version": 1, "latch_id": "latch", "sequence": sequence,
            "command_type": "stop", "key_id": "stop",
            "signature": self.stop.sign(signing_bytes("latch", sequence, "stop", "stop")).hex(),
        }
        result = self.authority.request_stop(envelope, writer_id=writer, writer_fence=fence)
        assert result.recorded and result.durable
        return self.local.load()


@pytest.fixture
def rig(tmp_path):
    rig = Rig(tmp_path)
    try:
        yield rig
    finally:
        rig.local.close()


def test_genesis_verify_local_first_then_remote(rig):
    assert rig.client.verify(rig.genesis).verdict == "VERIFIED"
    fence = rig.fence()
    assert rig.client.verify(fence).verdict == "CONFLICT"
    result = rig.client.advance(fence, expected=rig.initial)
    assert result.verdict == "VERIFIED"
    stopped = rig.stop_once()
    assert rig.client.verify(stopped).verdict == "CONFLICT"
    advanced = rig.client.advance(stopped, expected=result.checkpoint)
    assert advanced.verdict == "VERIFIED" and advanced.checkpoint.stop_epoch == 1
    assert rig.client.verify(stopped).verdict == "VERIFIED"
    assert rig.client.verify(fence).verdict == "CONFLICT"


def test_coherent_local_rollback_rejected_by_retained_fake_remote(rig):
    rig.fence()
    old = (rig.path / fs.STATE).read_bytes()
    stopped = rig.stop_once()
    assert rig.client.advance(stopped, expected=rig.initial).verdict == "VERIFIED"
    rig.local.close()
    (rig.path / fs.STATE).write_bytes(old)
    rig.local = fs.FilesystemAuthorityAdapter(str(rig.path), "authority", "latch", rig.keys)
    old_snapshot = rig.local.load()
    assert rig.local.locally_durable(old_snapshot)
    assert rig.client.verify(old_snapshot).verdict == "CONFLICT"
    assert rig.client.advance(old_snapshot, expected=rig.initial).verdict == "CONFLICT"


@pytest.mark.parametrize("mode,verdict", [
    ("unavailable", "UNAVAILABLE"), ("lost_before", "UNKNOWN"), ("lost_after", "UNKNOWN"),
])
def test_failures_and_fresh_retry_idempotence(rig, mode, verdict):
    snapshot = rig.fence()
    rig.transport.mode = mode
    assert rig.client.advance(snapshot, expected=rig.initial).verdict == verdict
    rig.transport.mode = "ok"
    retry = rig.client.advance(snapshot, expected=rig.initial)
    assert retry.verdict == "VERIFIED"
    head = rig.server._head
    assert rig.client.advance(snapshot, expected=rig.initial).verdict == "VERIFIED"
    assert rig.server._head == head


def test_replayed_request_cannot_advance_twice(rig):
    snapshot = rig.fence()
    rig.client.advance(snapshot, expected=rig.initial)
    head = rig.server._head
    response = json.loads(rig.server.exchange(rig.transport.requests[-1]))
    assert response["verdict"] == "CONFLICT" and response["reason"] == "request_replayed"
    assert rig.server._head == head


def test_replayed_response_and_wrong_signer_deny(rig):
    assert rig.client.verify(rig.genesis).verdict == "VERIFIED"
    rig.transport.mode = "replay_reply"
    assert rig.client.verify(rig.genesis).verdict == "UNKNOWN"
    rig.transport.mode = "ok"
    wrong = rig.make_client(server_public_key=public(rig.other_key))
    assert wrong.verify(rig.genesis).verdict == "UNKNOWN"
    wrong = rig.make_client(signer=rig.stop.sign)
    assert wrong.verify(rig.genesis).verdict == "UNKNOWN"


@pytest.mark.parametrize("field,value", [
    ("authority_id", "other"), ("latch_id", "other"), ("checkpoint_id", "other"),
    ("trust_domain", "other"), ("writer_id", "other"), ("server_id", "other"),
])
def test_identity_binding(rig, field, value):
    client = rig.make_client(**{field: value})
    if field in ("authority_id", "latch_id"):
        with pytest.raises(ValueError):
            client.verify(rig.genesis)
    else:
        assert client.verify(rig.genesis).verdict == "UNKNOWN"


def test_stale_fence_and_conflicting_writer(rig):
    first = rig.fence()
    old_head = rig.client.advance(first, expected=rig.initial).checkpoint
    second = rig.fence("other", 1)
    other = rig.make_client(
        client_id="other", writer_id="other", signer=rig.other_key.sign,
    )
    assert other.advance(second, expected=old_head).verdict == "VERIFIED"
    assert rig.client.advance(first, expected=rig.initial).verdict == "CONFLICT"
    assert rig.client.advance(second, expected=old_head).verdict == "CONFLICT"


def test_conflicting_digest_and_stale_expected_head(rig):
    first = rig.fence()
    verified = rig.client.advance(first, expected=rig.initial)
    stopped = rig.stop_once()
    bad = replace(verified.checkpoint, head_digest="f" * 64)
    assert rig.client.advance(stopped, expected=bad).verdict == "CONFLICT"
    assert rig.client.advance(stopped, expected=rig.initial).verdict == "CONFLICT"
    assert rig.server._head == verified.checkpoint


def test_concurrent_conflicting_updates_one_winner(rig):
    local_a = sa.InMemoryAuthorityAdapter(rig.genesis)
    local_b = sa.InMemoryAuthorityAdapter(rig.genesis)
    a = sa.StopGenerationAuthority("authority", "latch", rig.keys, local_a)
    b = sa.StopGenerationAuthority("authority", "latch", rig.keys, local_b)
    a.fence_writer("writer", 0)
    b.fence_writer("other", 0)
    barrier = threading.Barrier(2)
    class Concurrent:
        def exchange(self, raw):
            barrier.wait(5)
            return rig.server.exchange(raw)
    clients = [
        rig.make_client(transport=Concurrent()),
        rig.make_client(transport=Concurrent(), client_id="other",
                        writer_id="other", signer=rig.other_key.sign),
    ]
    snapshots = [local_a.load(), local_b.load()]
    results, errors = [], []
    def run(client, snapshot):
        try:
            results.append(client.advance(snapshot, expected=rig.initial))
        except BaseException as exc:
            errors.append(exc)
    threads = [threading.Thread(target=run, args=pair, daemon=True)
               for pair in zip(clients, snapshots)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(6)
        assert not thread.is_alive()
    assert not errors
    assert sorted(result.verdict for result in results) == ["CONFLICT", "VERIFIED"]
    assert rig.server._head.revision == 1


@pytest.mark.parametrize("missing", [True, False])
def test_missing_or_inconsistent_remote_never_verified(rig, missing):
    if missing:
        rig.server._head = None
    else:
        head = replace(rig.initial)
        object.__setattr__(head, "stop_epoch", True)
        rig.server._head = head
    assert rig.client.verify(rig.genesis).verdict == ("UNAVAILABLE" if missing else "UNKNOWN")


def test_response_tampering_and_false_verified_head(rig):
    rig.client.verify(rig.genesis)
    rig.transport.mode = "tampered"
    assert rig.client.verify(rig.genesis).verdict == "UNKNOWN"
    class Liar:
        def exchange(self, raw):
            response = json.loads(rig.server.exchange(raw))
            response.pop("signature")
            response["checkpoint"]["head_digest"] = "f" * 64
            return cp._signed(response, cp.RESPONSE_DOMAIN, rig.server_key.sign)
    assert rig.make_client(transport=Liar()).verify(rig.genesis).verdict == "UNKNOWN"


@pytest.mark.parametrize("raw", [
    b"", b"{}", b"\xff", b"[]", b'{"x":NaN}', b'{"x":1,"x":1}',
    b" " * (cp.MAX_WIRE_BYTES + 1),
])
def test_malformed_unsigned_requests_never_change_remote(rig, raw):
    assert_rejected(rig, raw)
    assert rig.server._head == rig.initial


@pytest.mark.parametrize("field,value", [
    ("stop_epoch", True), ("stop_epoch", -1), ("revision", 2**53 + 1),
    ("writer_fence", 1), ("head_digest", "F" * 64),
])
def test_checkpoint_model_validation(rig, field, value):
    with pytest.raises(ValueError):
        replace(rig.initial, **{field: value})


def test_no_implicit_provisioning_and_replay_bound(rig, monkeypatch):
    with pytest.raises(ValueError, match="explicit_genesis_required"):
        cp.SimulatedCheckpointServer(
            initial=None, server_id="server", clients={},
            signer=rig.server_key.sign, stop_keys=rig.keys,
        )
    monkeypatch.setattr(cp, "MAX_REQUESTS", 1)
    assert rig.client.verify(rig.genesis).verdict == "VERIFIED"
    assert rig.client.verify(rig.genesis).verdict == "UNAVAILABLE"


def test_local_crash_gap_catchup_and_fake_remote_loss_limitation(rig):
    stopped = rig.fence()
    stopped = rig.stop_once()
    rig.local.close()
    rig.local = fs.FilesystemAuthorityAdapter(str(rig.path), "authority", "latch", rig.keys)
    assert rig.client.verify(rig.local.load()).verdict == "CONFLICT"
    assert rig.client.advance(stopped, expected=rig.initial).verdict == "VERIFIED"
    # Fake server history loss is not independently rollback resistant.
    rig.server._head = rig.initial
    assert rig.client.verify(rig.genesis).verdict == "VERIFIED"


@pytest.mark.parametrize("field,value", [
    ("trust_domain", "other"), ("checkpoint_id", "other"),
    ("writer_fence", 2), ("action", "advance"), ("nonce", "f" * 64),
])
def test_request_field_tampering_rejected_before_state_change(rig, field, value):
    rig.client.verify(rig.genesis)
    request = json.loads(rig.transport.requests[-1])
    request[field] = value
    raw = cp._canonical(request)
    assert_rejected(rig, raw)
    assert rig.server._head == rig.initial


@pytest.mark.parametrize("field,value", [
    ("writer_fence", True), ("writer_fence", 2), ("writer_id", "other"),
    ("checkpoint_id", "other"), ("trust_domain", "other"),
])
def test_authenticated_invalid_request_binding_rejected(rig, field, value):
    rig.client.verify(rig.genesis)
    request = json.loads(rig.transport.requests[-1])
    request.pop("signature")
    request[field] = value
    raw = cp._signed(request, cp.REQUEST_DOMAIN, rig.client_key.sign)
    assert_rejected(rig, raw)
    assert rig.server._head == rig.initial


def test_corrupted_signed_history_and_checkpoint_scopes_deny(rig):
    rig.fence()
    snapshot = rig.local.load()
    corrupt = replace(snapshot.events[-1], event_digest="f" * 64)
    with pytest.raises(ValueError):
        rig.client.verify(replace(snapshot, events=(corrupt,)))
    with pytest.raises(ValueError, match="expected_checkpoint_scope_mismatch"):
        rig.client.advance(snapshot, expected=replace(rig.initial, trust_domain="other"))
    assert rig.server._head == rig.initial


def test_reused_client_key_configuration_rejected(rig):
    with pytest.raises(ValueError, match="invalid_or_reused_client_key"):
        cp.SimulatedCheckpointServer(
            initial=rig.initial, server_id="server",
            clients={"a": ("writer", public(rig.client_key)),
                     "b": ("other", public(rig.client_key))},
            signer=rig.server_key.sign, stop_keys=rig.keys,
        )


def test_concurrent_identical_advances_are_idempotent(rig):
    snapshot = rig.fence()
    barrier = threading.Barrier(2)
    class Concurrent:
        def exchange(self, raw):
            barrier.wait(5)
            return rig.server.exchange(raw)
    clients = [rig.make_client(transport=Concurrent()) for _ in range(2)]
    results = []
    def run(client):
        results.append(client.advance(snapshot, expected=rig.initial))
    threads = [threading.Thread(target=run, args=(client,), daemon=True) for client in clients]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(6)
        assert not thread.is_alive()
    assert len(results) == 2 and all(result.verdict == "VERIFIED" for result in results)
    assert rig.server._head.revision == 1


@pytest.mark.parametrize("value", [[], {}, None, 1, True, [["nested"]]])
def test_malformed_client_lookup_denies_without_exception(rig, value):
    rig.client.verify(rig.genesis)
    request = json.loads(rig.transport.requests[-1])
    request["client_id"] = value
    assert_rejected(rig, cp._canonical(request))
    assert rig.server._head == rig.initial and len(rig.server._nonces) == 1


@pytest.mark.parametrize("field", ["action", "writer_id", "nonce"])
@pytest.mark.parametrize("value", [[], {}, None])
def test_authenticated_malformed_dispatch_fields(rig, field, value):
    rig.client.verify(rig.genesis)
    request = json.loads(rig.transport.requests[-1])
    request.pop("signature")
    request[field] = value
    assert_rejected(rig, cp._signed(request, cp.REQUEST_DOMAIN, rig.client_key.sign))
    assert rig.server._head == rig.initial


@pytest.mark.parametrize("depth", [30, 1500])
def test_nested_lookup_values_within_wire_limit(rig, depth):
    raw = b'{"client_id":' + b"[" * depth + b"null" + b"]" * depth + b"}"
    assert len(raw) < cp.MAX_WIRE_BYTES
    assert_rejected(rig, raw)
    assert rig.server._head == rig.initial


def test_request_response_domain_reuse_rejected(rig):
    rig.client.verify(rig.genesis)
    body = json.loads(rig.transport.requests[-1])
    body.pop("signature")
    # Correct client key, incorrect signing domain.
    assert_rejected(rig, cp._signed(body, cp.RESPONSE_DOMAIN, rig.client_key.sign))
    class WrongDomain:
        def exchange(self, raw):
            response = json.loads(rig.server.exchange(raw))
            response.pop("signature")
            return cp._signed(response, cp.REQUEST_DOMAIN, rig.server_key.sign)
    result = rig.make_client(transport=WrongDomain()).verify(rig.genesis)
    assert result.verdict == "UNKNOWN" and result.reason == "checkpoint_response_unverifiable"
    assert rig.server._head == rig.initial


@pytest.mark.parametrize("mutation", ["missing", "bool_epoch", "bad_digest", "forged_stop", "extra"])
def test_direct_authenticated_malformed_snapshot_denies(rig, mutation):
    rig.fence()
    snapshot = rig.stop_once()
    rig.client.verify(snapshot)
    body = json.loads(rig.transport.requests[-1])
    body.pop("signature")
    if mutation == "missing":
        del body["snapshot"]["events"]
    elif mutation == "extra":
        body["snapshot"]["extra"] = 1
    else:
        event = body["snapshot"]["events"][-1]
        if mutation == "bool_epoch":
            event["stop_epoch"] = True
        elif mutation == "bad_digest":
            event["event_digest"] = "f" * 64
        else:
            event["command"]["signature"] = "0" * 128
    assert_rejected(rig, cp._signed(body, cp.REQUEST_DOMAIN, rig.client_key.sign))
    assert rig.server._head == rig.initial


def test_signing_failure_after_advance_reconciles_exact_retry(rig):
    snapshot = rig.fence()
    original = rig.server._signer
    def unavailable(payload):
        raise OSError("private signing failure")
    rig.server._signer = unavailable
    result = rig.client.advance(snapshot, expected=rig.initial)
    assert result.verdict == "UNKNOWN"
    assert rig.server._head == cp.checkpoint_for(snapshot, "checkpoint", "offhost")
    rig.server._signer = original
    head = rig.server._head
    retry = rig.client.advance(snapshot, expected=rig.initial)
    assert retry.verdict == "VERIFIED" and retry.reason == "checkpoint_already_advanced"
    assert rig.server._head == head


def test_delayed_valid_response_is_historical_after_newer_stop(rig):
    snapshot = rig.fence()
    first = rig.client.advance(snapshot, expected=rig.initial)
    stopped = rig.stop_once()
    entered, release = threading.Event(), threading.Event()
    class Delayed:
        def exchange(self, raw):
            response = rig.server.exchange(raw)
            entered.set()
            assert release.wait(5)
            return response
    results, errors = [], []
    client = rig.make_client(transport=Delayed())
    def run():
        try:
            results.append(client.verify(snapshot))
        except BaseException as exc:
            errors.append(exc)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert entered.wait(5)
        newer = rig.client.advance(stopped, expected=first.checkpoint)
        assert newer.verdict == "VERIFIED" and newer.checkpoint.stop_epoch == 1
    finally:
        release.set()
        thread.join(6)
    assert not thread.is_alive() and not errors
    assert len(results) == 1 and results[0].verdict == "VERIFIED"
    assert results[0].checkpoint.stop_epoch == 0
    assert rig.client.verify(snapshot).verdict == "CONFLICT"
    assert rig.client.verify(stopped).verdict == "VERIFIED"
