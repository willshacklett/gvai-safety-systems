import ast
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import gvai.experimental_stop_latch as latch
from gvai.commercial_reservation_authority import AuthorityIdentity
from gvai.commercial_service import (
    CommercialEvaluationService,
    ServiceOutcome,
    ServiceReason,
)
from gvai.commercial_usage import UsageReason, UsageResult
from gvai.experimental_stop_latch import (
    GENESIS_HASH,
    FileStopLatchSource,
    LatchAnchor,
    LatchEnforcedEvaluationService,
    LatchEnforcedUsage,
    LatchReason,
    LatchState,
    StopLatchGate,
    StopLatchRecord,
    StopLatchVerifier,
    build_latch_enforced_service,
    decode_record,
)

AUTHORITY = AuthorityIdentity("stop-authority", 1, "stop-domain")
NOW = 1_800_000_000
KEY_ID = "stop-key-1"


def raw_public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class Supervisor:
    """Test-only holder of the STOP signing key; never given to service objects."""

    def __init__(self, key=None, key_id=KEY_ID, authority=AUTHORITY):
        self.key = key or Ed25519PrivateKey.generate()
        self.key_id = key_id
        self.authority = authority
        self.public = raw_public(self.key)

    def sign(self, sequence, previous_hash, state=LatchState.RUN, issued_at=NOW,
             lifetime=60, key_id=None, authority=None):
        unsigned = StopLatchRecord(
            authority or self.authority, sequence, previous_hash, state,
            issued_at, issued_at + lifetime, key_id or self.key_id, b"\x00" * 64,
        )
        signature = self.key.sign(unsigned.canonical_bytes())
        return replace(unsigned, signature=signature)

    def chain(self, count, **kwargs):
        records, previous = [], GENESIS_HASH
        for sequence in range(1, count + 1):
            record = self.sign(sequence, previous, **kwargs)
            records.append(record)
            previous = record.record_hash()
        return records


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def make_verifier(supervisor, clock=None, anchor=None, **overrides):
    config = dict(
        authority=AUTHORITY,
        trusted_public_keys={supervisor.key_id: supervisor.public},
        other_purpose_key_ids=frozenset(),
        other_purpose_public_keys=frozenset(),
        anchor=anchor or LatchAnchor(),
        clock=clock or Clock(),
    )
    config.update(overrides)
    return StopLatchVerifier(**config)


@pytest.fixture
def supervisor():
    return Supervisor()


def reason(verifier, record):
    return verifier.check(record).reason


# --- Baseline allow path and deny-by-default ---------------------------------

def test_only_a_fresh_authentic_chained_run_lease_allows(supervisor):
    verifier = make_verifier(supervisor)
    first, second = supervisor.chain(2)
    decision = verifier.check(first)
    assert decision.allowed and bool(decision)
    assert decision.reason is LatchReason.RUN_LEASE_VALID
    assert verifier.check(first).allowed  # idempotent lease reuse
    assert verifier.check(second).allowed
    assert not verifier.stopped


@pytest.mark.parametrize("candidate", [None, object(), b"x", {}, "run", 1, True])
def test_missing_or_wrong_type_denies(supervisor, candidate):
    result = make_verifier(supervisor).check(candidate)
    assert not result and not result.allowed
    assert result.reason in {LatchReason.MISSING, LatchReason.CORRUPT}


def test_decision_is_falsy_for_every_reason_but_one():
    for item in LatchReason:
        assert bool(latch.LatchDecision(item)) is (item is LatchReason.RUN_LEASE_VALID)


# --- Tampering / corruption ---------------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("sequence", 2), ("previous_hash", "1" * 64), ("issued_at", NOW + 1),
    ("expires_at", NOW + 61), ("signing_key_id", "stop-key-1"),
])
def test_any_signed_field_change_denies(supervisor, field, value):
    record = supervisor.chain(1)[0]
    if field == "signing_key_id":
        other = Supervisor(key_id="other-key")
        verifier = make_verifier(supervisor, trusted_public_keys={
            KEY_ID: supervisor.public, "other-key": other.public})
        tampered = replace(record, signing_key_id="other-key")
    else:
        verifier = make_verifier(supervisor)
        tampered = replace(record, **{field: value})
    assert reason(verifier, tampered) in {
        LatchReason.INVALID_SIGNATURE, LatchReason.SEQUENCE_GAP, LatchReason.CHAIN_BREAK,
    }
    assert not verifier.check(tampered)


def test_state_flip_from_stopped_to_run_denies(supervisor):
    stopped = supervisor.sign(1, GENESIS_HASH, LatchState.STOPPED)
    forged = replace(stopped, state=LatchState.RUN)
    assert reason(make_verifier(supervisor), forged) is LatchReason.INVALID_SIGNATURE


def test_post_construction_mutation_of_frozen_record_denies(supervisor):
    record = supervisor.chain(1)[0]
    verifier = make_verifier(supervisor)
    object.__setattr__(record, "sequence", 0)
    assert reason(verifier, record) is LatchReason.CORRUPT
    record = supervisor.chain(1)[0]
    object.__setattr__(record, "state", "run")
    assert reason(verifier, record) is LatchReason.CORRUPT
    record = supervisor.chain(1)[0]
    object.__setattr__(record, "sequence", 1 + 2**64)
    assert reason(verifier, record) is LatchReason.CORRUPT


def test_mutated_authority_object_is_rejected(supervisor):
    record = supervisor.chain(1)[0]
    object.__setattr__(record.authority, "epoch", 99)
    assert not make_verifier(supervisor).check(record)


@pytest.mark.parametrize("kwargs", [
    dict(sequence=0), dict(sequence=True), dict(previous_hash="G" * 64),
    dict(previous_hash="A" * 64), dict(signature=b"\x00" * 63),
    dict(version=2), dict(purpose="other"), dict(signature_algorithm="HMAC"),
    dict(issued_at=NOW, expires_at=NOW), dict(expires_at=NOW + 10_000),
])
def test_malformed_records_cannot_be_constructed(supervisor, kwargs):
    base = dict(
        authority=AUTHORITY, sequence=1, previous_hash=GENESIS_HASH,
        state=LatchState.RUN, issued_at=NOW, expires_at=NOW + 60,
        signing_key_id=KEY_ID, signature=b"\x00" * 64,
    )
    base.update(kwargs)
    with pytest.raises(ValueError):
        StopLatchRecord(**base)


# --- Unsigned / untrusted / forged / key reuse --------------------------------

def test_unsigned_and_zero_signature_denies(supervisor):
    record = replace(supervisor.chain(1)[0], signature=b"\x00" * 64)
    assert reason(make_verifier(supervisor), record) is LatchReason.INVALID_SIGNATURE


def test_attacker_key_with_trusted_key_id_is_forgery(supervisor):
    attacker = Supervisor()  # same key id, different key
    record = attacker.chain(1)[0]
    assert reason(make_verifier(supervisor), record) is LatchReason.INVALID_SIGNATURE


def test_unknown_key_id_is_untrusted(supervisor):
    attacker = Supervisor(key_id="attacker-key")
    assert reason(make_verifier(supervisor), attacker.chain(1)[0]) is LatchReason.UNTRUSTED_KEY


def test_revoked_key_is_untrusted(supervisor):
    verifier = make_verifier(
        supervisor,
        trusted_public_keys={KEY_ID: supervisor.public, "stop-key-2": Supervisor().public},
        revoked_key_ids=frozenset({KEY_ID}),
    )
    assert reason(verifier, supervisor.chain(1)[0]) is LatchReason.UNTRUSTED_KEY


@pytest.mark.parametrize("authority", [
    AuthorityIdentity("other-authority", 1, "stop-domain"),
    AuthorityIdentity("stop-authority", 2, "stop-domain"),
    AuthorityIdentity("stop-authority", 1, "other-domain"),
])
def test_wrong_authority_epoch_or_domain_denies(supervisor, authority):
    record = supervisor.sign(1, GENESIS_HASH, authority=authority)
    assert reason(make_verifier(supervisor), record) is LatchReason.UNTRUSTED_AUTHORITY


def test_signature_from_other_domain_is_not_a_latch_signature(supervisor):
    record = supervisor.chain(1)[0]
    bare = supervisor.key.sign(record.canonical_bytes()[len(latch.LATCH_DOMAIN):])
    assert reason(make_verifier(supervisor), replace(record, signature=bare)) is (
        LatchReason.INVALID_SIGNATURE
    )


def test_key_reuse_from_other_purposes_is_rejected_at_construction(supervisor):
    for overrides in (
        dict(other_purpose_key_ids=frozenset({KEY_ID})),
        dict(other_purpose_public_keys=frozenset({supervisor.public})),  # renamed key
    ):
        with pytest.raises(ValueError):
            make_verifier(supervisor, **overrides)
    with pytest.raises(ValueError):
        make_verifier(supervisor, trusted_public_keys={
            "a": supervisor.public, "b": supervisor.public})


def test_receipt_or_checkpoint_key_signed_latch_is_not_accepted(supervisor):
    foreign = Supervisor()  # stands for a receipt/checkpoint key
    verifier = make_verifier(
        supervisor, other_purpose_public_keys=frozenset({foreign.public})
    )
    forged = foreign.sign(1, GENESIS_HASH)
    assert not verifier.check(forged)


def test_verifier_and_service_layer_cannot_sign():
    source = Path(latch.__file__).read_text()
    tree = ast.parse(source)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "Ed25519PrivateKey" not in names | attrs
    assert not {"sign", "generate", "private_bytes", "from_private_bytes"} & attrs
    public = [n for n in dir(latch) if not n.startswith("_")]
    assert not [n for n in public if "sign" in n.lower() and n != "signature"]
    assert not hasattr(StopLatchVerifier, "reset")
    assert not hasattr(StopLatchVerifier, "clear")
    assert not hasattr(StopLatchVerifier, "unstop")
    verifier = make_verifier(Supervisor())
    assert not [a for a in dir(verifier) if "private" in a.lower()]


def test_private_key_material_is_rejected_as_a_public_key(supervisor):
    for bad in (supervisor.key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()) + b"x", bytearray(supervisor.public), "00" * 32):
        with pytest.raises(ValueError):
            make_verifier(supervisor, trusted_public_keys={KEY_ID: bad})


def test_verifier_state_is_not_externally_assignable(supervisor):
    verifier = make_verifier(supervisor)
    for name in ("_stopped", "_high_sequence", "anything"):
        with pytest.raises(AttributeError):
            setattr(verifier, name, 1)
    with pytest.raises(AttributeError):
        del verifier._keys


# --- Rollback, replay, STOP stickiness ----------------------------------------

def test_older_run_record_after_newer_is_rolled_back(supervisor):
    verifier = make_verifier(supervisor)
    first, second, third = supervisor.chain(3)
    assert verifier.check(first) and verifier.check(second) and verifier.check(third)
    assert reason(verifier, first) is LatchReason.ROLLED_BACK
    assert reason(verifier, second) is LatchReason.ROLLED_BACK


def test_equal_sequence_conflicting_record_denies(supervisor):
    verifier = make_verifier(supervisor)
    first = supervisor.chain(1)[0]
    alternative = supervisor.sign(1, GENESIS_HASH, issued_at=NOW + 1)
    assert verifier.check(first)
    assert reason(verifier, alternative) is LatchReason.CONFLICT


def test_forked_chain_and_gap_deny_without_advancing(supervisor):
    verifier = make_verifier(supervisor)
    first, second = supervisor.chain(2)
    assert verifier.check(first)
    fork = supervisor.sign(2, "f" * 64)
    assert reason(verifier, fork) is LatchReason.CHAIN_BREAK
    gap = supervisor.sign(4, second.record_hash())
    assert reason(verifier, gap) is LatchReason.SEQUENCE_GAP
    assert verifier.check(second)  # failed attempts did not poison or advance


def test_stop_is_sticky_and_old_run_replay_cannot_reopen(supervisor):
    verifier = make_verifier(supervisor)
    first = supervisor.chain(1)[0]
    stop = supervisor.sign(2, first.record_hash(), LatchState.STOPPED)
    assert verifier.check(first)
    assert reason(verifier, stop) is LatchReason.STOPPED and verifier.stopped
    later_run = supervisor.sign(3, stop.record_hash(), LatchState.RUN)
    for candidate in (first, later_run, None, "junk", stop):
        assert reason(verifier, candidate) is LatchReason.STOPPED


def test_captured_stop_replayed_anywhere_still_stops(supervisor):
    old_stop = supervisor.sign(1, GENESIS_HASH, LatchState.STOPPED, issued_at=NOW - 10_000)
    verifier = make_verifier(supervisor)
    assert reason(verifier, old_stop) is LatchReason.STOPPED
    assert not verifier.check(supervisor.chain(2)[1])


def test_stop_with_gap_or_bad_chain_still_latches(supervisor):
    stop = supervisor.sign(99, "e" * 64, LatchState.STOPPED)
    verifier = make_verifier(supervisor)
    assert reason(verifier, stop) is LatchReason.STOPPED and verifier.stopped


def test_forged_stop_does_not_latch(supervisor):
    attacker = Supervisor()
    verifier = make_verifier(supervisor)
    assert reason(verifier, attacker.sign(1, GENESIS_HASH, LatchState.STOPPED)) is (
        LatchReason.INVALID_SIGNATURE
    )
    assert not verifier.stopped
    assert verifier.check(supervisor.chain(1)[0])


def test_expired_and_future_leases_deny_and_replay_after_expiry_fails(supervisor):
    clock = Clock()
    verifier = make_verifier(supervisor, clock=clock)
    record = supervisor.chain(1)[0]
    assert verifier.check(record)
    clock.now = NOW + 60
    assert reason(verifier, record) is LatchReason.EXPIRED
    future = supervisor.sign(2, record.record_hash(), issued_at=NOW + 100)
    clock.now = NOW + 61
    assert reason(verifier, future) is LatchReason.NOT_YET_VALID


def test_clock_rollback_and_bad_clock_values_deny(supervisor):
    clock = Clock()
    verifier = make_verifier(supervisor, clock=clock)
    record = supervisor.chain(1)[0]
    assert verifier.check(record)
    clock.now = NOW - 1
    assert reason(verifier, record) is LatchReason.CLOCK_ERROR
    for bad in (float("nan"), float("inf"), "now", None, True, -1):
        clock.now = bad
        assert reason(verifier, record) is LatchReason.CLOCK_ERROR
    clock.now = NOW
    assert verifier.check(record)


def test_clock_exception_fails_closed(supervisor):
    def broken():
        raise RuntimeError("clock down")

    assert reason(make_verifier(supervisor, clock=broken), supervisor.chain(1)[0]) is (
        LatchReason.INTERNAL_ERROR
    )


def test_restart_cannot_go_below_the_provisioned_anchor(supervisor):
    records = supervisor.chain(5)
    anchor = LatchAnchor(4, records[3].record_hash())
    restarted = make_verifier(supervisor, anchor=anchor)
    assert reason(restarted, records[0]) is LatchReason.ROLLED_BACK
    assert reason(restarted, records[2]) is LatchReason.ROLLED_BACK
    assert restarted.check(records[4])


def test_anchor_validation():
    for args in ((0, "1" * 64), (1, GENESIS_HASH), (-1, GENESIS_HASH), (1, "xyz")):
        with pytest.raises(ValueError):
            LatchAnchor(*args)


# --- Wire format, file source: deletion / corruption ---------------------------

def write(path, data, mode=0o600):
    path.write_bytes(data)
    os.chmod(path, mode)


def test_wire_roundtrip_and_strict_decoding(supervisor, tmp_path):
    record = supervisor.chain(1)[0]
    assert decode_record(record.to_wire()) == record
    wire = record.to_wire()
    bad = [
        wire[:-1], wire + b" ", b"", b"[]", b"null", wire.replace(b"{", b"{ ", 1),
        wire.replace(b'"sequence":1', b'"sequence":1,"sequence":2'),
        wire.replace(b'"sequence":1', b'"sequence":1.0'),
        wire.replace(b'"sequence":1', b'"sequence":true'),
        wire[:-1] + b',"extra":1}', wire.replace(b'"state":"run"', b'"state":"RUN"'),
        wire.replace(b'"issued_at":%d' % NOW, b'"issued_at":NaN'),
        b"\xff" + wire, b"{" * 5000, wire * 100,
    ]
    for item in bad:
        with pytest.raises((ValueError, UnicodeDecodeError)):
            decode_record(item)
    for non_bytes in (None, wire.decode(), bytearray(wire)):
        with pytest.raises(ValueError):
            decode_record(non_bytes)


def test_file_source_deletion_corruption_and_unsafe_files_deny(supervisor, tmp_path):
    path = tmp_path / "latch.json"
    gate = StopLatchGate(make_verifier(supervisor), FileStopLatchSource(str(path)))
    assert gate.require_run("reserve").reason is LatchReason.MISSING
    record = supervisor.chain(1)[0]
    write(path, record.to_wire())
    assert gate.require_run("reserve").allowed
    path.unlink()
    assert gate.require_run("reserve").reason is LatchReason.MISSING
    for payload in (b"", b"garbage", record.to_wire()[:50], b"\x00" * 100):
        write(path, payload)
        assert gate.require_run("evaluate").reason is LatchReason.SOURCE_UNAVAILABLE
    write(path, record.to_wire(), mode=0o666)
    assert gate.require_run("evaluate").reason is LatchReason.SOURCE_UNAVAILABLE
    write(path, record.to_wire())
    link = tmp_path / "link.json"
    link.symlink_to(path)
    symlink_gate = StopLatchGate(make_verifier(supervisor), FileStopLatchSource(str(link)))
    assert not symlink_gate.require_run("evaluate")
    hard = tmp_path / "hard.json"
    os.link(path, hard)
    assert not gate.require_run("evaluate")
    hard.unlink()
    path.unlink()
    path.mkdir()
    assert not gate.require_run("evaluate")


def test_deleting_or_corrupting_file_after_stop_cannot_reopen(supervisor, tmp_path):
    path = tmp_path / "latch.json"
    gate = StopLatchGate(make_verifier(supervisor), FileStopLatchSource(str(path)))
    first = supervisor.chain(1)[0]
    write(path, first.to_wire())
    assert gate.require_run("reserve")
    write(path, supervisor.sign(2, first.record_hash(), LatchState.STOPPED).to_wire())
    assert gate.require_run("reserve").reason is LatchReason.STOPPED
    path.unlink()
    assert gate.require_run("reserve").reason is LatchReason.STOPPED
    write(path, first.to_wire())  # rollback to an old valid RUN file
    assert gate.require_run("evaluate").reason is LatchReason.STOPPED
    write(path, b"corrupt")
    assert gate.require_run("evaluate").reason is LatchReason.STOPPED


def test_file_rollback_before_stop_is_detected(supervisor, tmp_path):
    path = tmp_path / "latch.json"
    gate = StopLatchGate(make_verifier(supervisor), FileStopLatchSource(str(path)))
    first, second = supervisor.chain(2)
    write(path, second.to_wire())
    assert gate.require_run("reserve")
    write(path, first.to_wire())
    assert gate.require_run("reserve").reason is LatchReason.ROLLED_BACK


def test_source_exception_and_invalid_operation_deny(supervisor):
    class Broken:
        def read_latest(self):
            raise OSError("down")

    gate = StopLatchGate(make_verifier(supervisor), Broken())
    assert gate.require_run("reserve").reason is LatchReason.SOURCE_UNAVAILABLE
    for op in ("execute", "", None, 1, "Evaluate"):
        assert gate.require_run(op).reason is LatchReason.INVALID_OPERATION
    with pytest.raises(ValueError):
        StopLatchGate(object(), Broken())
    with pytest.raises(ValueError):
        StopLatchGate(make_verifier(supervisor), object())


# --- Enforcement wrappers and unchanged advisory behavior ----------------------

class FakeUsage:
    def __init__(self):
        self.reserved, self.completed = 0, 0

    def reserve_evaluation(self, credential, resource_id, request_id, payload):
        self.reserved += 1
        return UsageResult(UsageReason.RESERVED)

    def complete(self, credential, resource_id, request_id, *, succeeded):
        self.completed += 1
        return UsageResult(UsageReason.COMPLETED if succeeded else UsageReason.FAILED)


class Holder:
    def __init__(self, record=None):
        self.record = record

    def read_latest(self):
        return self.record


TELEMETRY = {
    "token_delta": 100, "tool_calls_delta": 1, "error_delta": 0,
    "repeated_action_delta": 0, "recursion_depth": 0, "latency_ms": None,
}


def build(supervisor, record=None, **kwargs):
    holder = Holder(record)
    usage = FakeUsage()
    gate = StopLatchGate(make_verifier(supervisor, **kwargs), holder)
    return build_latch_enforced_service(usage, gate), usage, holder, gate


def call(service, request_id="request-1"):
    return service.evaluate("credential", "project-a", request_id, TELEMETRY, [])


def test_enforced_service_denies_before_any_usage_or_evaluator_work(supervisor):
    for record in (None, "junk", Supervisor().chain(1)[0]):
        service, usage, _, _ = build(supervisor, record)
        response = call(service)
        assert response.outcome is ServiceOutcome.DENIED
        assert response.reason is ServiceReason.AUTHORIZATION_DENIED
        assert response.evaluation is None
        assert usage.reserved == 0


def test_valid_run_lease_preserves_advisory_behavior(supervisor):
    service, usage, _, _ = build(supervisor, supervisor.chain(1)[0])
    baseline = CommercialEvaluationService(FakeUsage()).evaluate(
        "credential", "project-a", "request-1", TELEMETRY, []
    )
    response = call(service)
    assert response.outcome is ServiceOutcome.EVALUATED
    assert response.to_dict() == baseline.to_dict()
    assert usage.reserved == 1 and usage.completed == 1


def test_reserve_is_independently_enforced_if_service_check_is_skipped(supervisor):
    usage = FakeUsage()
    holder = Holder(None)
    gate = StopLatchGate(make_verifier(supervisor), holder)
    inner = CommercialEvaluationService(LatchEnforcedUsage(usage, gate))
    response = call(inner)
    assert response.reason is ServiceReason.AUTHORIZATION_DENIED and usage.reserved == 0
    assert LatchEnforcedUsage(usage, gate).reserve_evaluation(
        "c", "r", "q", b"{}").reason is UsageReason.UNAUTHORIZED


def test_stop_midstream_blocks_next_evaluate_and_reserve(supervisor):
    first = supervisor.chain(1)[0]
    service, usage, holder, gate = build(supervisor, first)
    assert call(service).outcome is ServiceOutcome.EVALUATED
    holder.record = supervisor.sign(2, first.record_hash(), LatchState.STOPPED)
    assert call(service, "request-2").outcome is ServiceOutcome.DENIED
    holder.record = first
    assert call(service, "request-3").outcome is ServiceOutcome.DENIED
    assert usage.reserved == 1


def test_wrappers_require_a_real_gate(supervisor):
    for gate in (None, object(), lambda op: True, type("G", (), {"require_run": lambda s, o: True})()):
        with pytest.raises(ValueError):
            LatchEnforcedUsage(FakeUsage(), gate)
        with pytest.raises(ValueError):
            LatchEnforcedEvaluationService(CommercialEvaluationService(FakeUsage()), gate)
    gate = StopLatchGate(make_verifier(supervisor), Holder())
    with pytest.raises(ValueError):
        LatchEnforcedEvaluationService(object(), gate)


def test_production_modules_do_not_import_the_latch():
    root = Path(latch.__file__).parent
    importers = [
        p.name for p in root.glob("*.py")
        if "experimental_stop_latch" in p.read_text() and p.name != "experimental_stop_latch.py"
    ]
    assert importers == []


# --- Concurrency ---------------------------------------------------------------

def test_concurrent_checks_of_one_lease_are_consistent(supervisor):
    verifier = make_verifier(supervisor)
    record = supervisor.chain(1)[0]
    with ThreadPoolExecutor(32) as pool:
        results = list(pool.map(lambda _: verifier.check(record).allowed, range(500)))
    assert all(results)


def test_concurrent_stop_never_allows_after_observation(supervisor):
    first = supervisor.chain(1)[0]
    stop = supervisor.sign(2, first.record_hash(), LatchState.STOPPED)
    verifier = make_verifier(supervisor)
    holder = Holder(first)
    gate = StopLatchGate(verifier, holder)
    stopped_at = threading.Event()
    violations, barrier = [], threading.Barrier(17)

    def reader():
        barrier.wait()
        for _ in range(2000):
            was_stopped = stopped_at.is_set()
            decision = gate.require_run("reserve")
            if was_stopped and decision.allowed:
                violations.append(decision)

    def stopper():
        barrier.wait()
        time.sleep(0.01)
        holder.record = stop
        gate.require_run("reserve")
        stopped_at.set()

    threads = [threading.Thread(target=reader) for _ in range(16)]
    threads.append(threading.Thread(target=stopper))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert violations == [] and verifier.stopped
    assert not gate.require_run("evaluate")


def test_concurrent_conflicting_records_cannot_both_win(supervisor):
    left = supervisor.sign(1, GENESIS_HASH, issued_at=NOW)
    right = supervisor.sign(1, GENESIS_HASH, issued_at=NOW + 1)
    verifier = make_verifier(supervisor)
    barrier = threading.Barrier(2)
    outcomes = []

    def run(record):
        barrier.wait()
        outcomes.append(verifier.check(record).allowed)

    threads = [threading.Thread(target=run, args=(r,)) for r in (left, right)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == [False, True]


def test_concurrent_rollback_and_advance_race_is_monotonic(supervisor):
    import random

    records = supervisor.chain(40)
    verifier = make_verifier(supervisor)
    shuffled = records * 3
    random.Random(7).shuffle(shuffled)
    with ThreadPoolExecutor(16) as pool:
        list(pool.map(verifier.check, shuffled))
    high = verifier._high_sequence
    assert 1 <= high <= 40
    for record in records:
        decision = verifier.check(record).reason
        if record.sequence < high:
            assert decision is LatchReason.ROLLED_BACK
        elif record.sequence == high:
            assert decision is LatchReason.RUN_LEASE_VALID
        else:
            assert decision is LatchReason.SEQUENCE_GAP
