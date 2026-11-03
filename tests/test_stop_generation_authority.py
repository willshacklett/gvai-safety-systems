"""Disconnected C1 contract: fault injection, no durable/enforcement claims."""

import threading
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_stop_latch as sl
from gvai import stop_generation_authority as sa


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


class FaultAdapter(sa.InMemoryAuthorityAdapter):
    mode = "ok"

    def load(self):
        if self.mode == "read_failure":
            raise OSError("private storage detail")
        return super().load()

    def compare_and_swap(self, expected, proposed):
        if self.mode == "before_commit":
            raise OSError("before commit")
        if self.mode == "partial":
            with self._lock:
                self._snapshot = replace(
                    proposed, events=proposed.events[:-1] + (
                        replace(proposed.events[-1], event_digest="f" * 64),
                    ),
                )
            return "UNKNOWN"
        result = super().compare_and_swap(expected, proposed)
        if self.mode == "lost_reply":
            raise OSError("ack lost after commit")
        return result


class Rig:
    def __init__(self):
        self.stop_key = Ed25519PrivateKey.generate()
        self.arm_key = Ed25519PrivateKey.generate()
        self.keys = sl.StopLatchKeyring(
            {"stop": public(self.stop_key)}, {"arm": public(self.arm_key)},
        )
        self.adapter = FaultAdapter(sa.AuthoritySnapshot("authority", "latch"))
        self.authority = self.restart()
        result = self.authority.fence_writer("writer", 0)
        assert result.reason == "writer_fenced" and result.writer_fence == 1

    def restart(self, checkpoint=None):
        return sa.StopGenerationAuthority(
            "authority", "latch", self.keys, self.adapter, checkpoint,
        )

    def command(self, sequence=1, kind="stop", key=None, latch="latch"):
        key = key if key is not None else self.stop_key
        return {
            "version": 1, "latch_id": latch, "sequence": sequence,
            "command_type": kind, "key_id": "stop",
            "signature": key.sign(sl.signing_bytes(latch, sequence, kind, "stop")).hex(),
        }

    def stop(self, command=None, authority=None, writer="writer", fence=1):
        return (authority or self.authority).request_stop(
            command if command is not None else self.command(),
            writer_id=writer, writer_fence=fence,
        )


@pytest.fixture
def rig():
    return Rig()


def test_genesis_epoch_and_fence_never_reopens(rig):
    state = rig.adapter.load()
    assert (state.stop_epoch, state.revision, state.writer_fence, state.terminal) == (0, 1, 1, False)
    assert rig.stop().reason == "stop_recorded"
    assert rig.authority.fence_writer("other", 1).reason == "writer_fenced"
    state = rig.adapter.load()
    assert (state.stop_epoch, state.revision, state.terminal) == (1, 3, True)
    assert rig.stop(rig.command(2), writer="other", fence=2).stop_epoch == 2


def test_exact_retry_and_old_retry_after_later_stop(rig):
    first = rig.stop()
    assert first.requested and first.recorded
    assert not first.durable and not first.backend_notified and not first.workload_terminated
    assert first.deny_execution
    assert rig.stop().reason == "already_recorded"
    assert rig.stop(rig.command(2)).stop_epoch == 2
    retry = rig.stop(authority=rig.restart())
    assert retry.reason == "already_recorded" and retry.stop_epoch == 2
    assert rig.adapter.load().revision == 3


def test_same_signed_identity_conflicting_content(rig):
    rig.stop()
    original = sl.parse_command(rig.command())
    other_key = Ed25519PrivateKey.generate()
    # A changed signature which fails authentication is rejected before identity lookup.
    assert rig.stop(rig.command(key=other_key)).reason == "authentication_failed"
    # Test the conflict branch with an explicit authentication test double;
    # ordinary Ed25519 signing is deterministic for this exact V1 identity.
    alternative = replace(original, signature=b"x" * 64)
    class AcceptBoth(sl.StopLatchKeyring):
        def verify(self, command):
            return command in (original, alternative)
    ring = AcceptBoth({"stop": public(rig.stop_key)}, {"arm": public(rig.arm_key)})
    authority = sa.StopGenerationAuthority("authority", "latch", ring, rig.adapter)
    result = rig.stop(sl.command_envelope(alternative), authority)
    assert result.reason == "command_identity_conflict" and not result.recorded


@pytest.mark.parametrize("case", ["forged", "arm", "wrong_latch", "malformed"])
def test_unauthenticated_stop_never_advances(rig, case):
    commands = {
        "forged": rig.command(key=Ed25519PrivateKey.generate()),
        "arm": rig.command(kind="arm"),
        "wrong_latch": rig.command(latch="other"),
        "malformed": {},
    }
    result = rig.stop(commands[case])
    assert not result.requested and not result.recorded
    assert rig.adapter.load().stop_epoch == 0


@pytest.mark.parametrize("writer,fence,reason", [
    ("other", 1, "conflicting_writer"), ("writer", 0, "stale_writer_fence"),
    ("writer", 2, "stale_writer_fence"), ("", 1, "invalid_writer"),
    ("writer", True, "invalid_writer"),
])
def test_writer_fencing(rig, writer, fence, reason):
    assert rig.stop(writer=writer, fence=fence).reason == reason
    assert rig.adapter.load().stop_epoch == 0


def test_rotated_writer_old_session_cannot_retry_or_write(rig):
    rig.stop()
    rig.authority.fence_writer("writer", 1)
    assert rig.stop().reason == "stale_writer_fence"
    assert rig.stop(rig.command(2)).reason == "stale_writer_fence"
    assert rig.stop(fence=2).reason == "already_recorded"
    assert rig.authority.fence_writer("other", 1).reason == "stale_writer_fence"


@pytest.mark.parametrize("mode,recorded", [
    ("before_commit", False), ("lost_reply", True), ("partial", False),
])
def test_uncertain_commit_and_recovery(rig, mode, recorded):
    rig.adapter.mode = mode
    result = rig.stop()
    assert result.reason == "commit_uncertain" and result.requested and not result.recorded
    rig.adapter.mode = "ok"
    assert rig.stop().reason == "commit_uncertain"  # Sticky; no implicit recovery.
    restarted = rig.restart()
    retry = rig.stop(authority=restarted)
    if mode == "partial":
        assert retry.reason == "authority_state_invalid" and not retry.recorded
    else:
        assert retry.reason == ("already_recorded" if recorded else "stop_recorded")
        assert retry.recorded and not retry.durable


def test_unavailable_authority_no_detail_leak_and_sticky(rig):
    rig.adapter.mode = "read_failure"
    result = rig.stop()
    assert result.reason == "authority_unavailable"
    assert result.requested and not result.recorded
    rig.adapter.mode = "ok"
    assert rig.authority.inspect().reason == "authority_unavailable"
    assert rig.restart().inspect().reason == "state_verified"


def test_rollback_and_fork_against_seen_history(rig):
    old = rig.adapter.load()
    rig.stop()
    rig.adapter._snapshot = old
    assert rig.authority.inspect().reason == "authority_state_invalid"
    # A fresh instance cannot detect complete rollback without an independent checkpoint.
    assert rig.restart().inspect().reason == "state_verified"


def test_missing_and_wrong_identity_recovery_denies(rig):
    for snapshot in (None, sa.AuthoritySnapshot("other", "latch")):
        rig.adapter._snapshot = snapshot
        assert rig.restart().inspect().reason == "authority_state_invalid"


def test_stale_read_cannot_overwrite_current_state(rig):
    old = rig.adapter.load()
    rig.stop()
    current = rig.adapter.load()
    rig.adapter.load = lambda: old  # Deliberately violate linearizable-read contract.
    result = rig.stop(rig.command(2), authority=rig.restart())
    assert result.reason == "conditional_conflict" and not result.recorded
    assert rig.adapter._snapshot == current


def test_unsupported_commit_reply_is_uncertain(rig):
    rig.adapter.compare_and_swap = lambda expected, proposed: True
    assert rig.stop().reason == "commit_uncertain"
    assert rig.adapter.load().stop_epoch == 0


def test_independent_checkpoint_simulator_rejects_stale_restart(rig):
    old = rig.adapter.load()
    rig.stop()
    trusted = rig.adapter.load()
    class Checkpoint:
        def verify(self, snapshot):
            return (
                snapshot.revision >= trusted.revision
                and snapshot.events[:trusted.revision] == trusted.events
            )
    assert rig.restart(Checkpoint()).inspect().reason == "state_verified"
    rig.adapter._snapshot = old
    assert rig.restart(Checkpoint()).inspect().reason == "authority_state_invalid"


@pytest.mark.parametrize("result", [False, None, 1])
def test_checkpoint_failure_denies(rig, result):
    class Checkpoint:
        def verify(self, snapshot):
            return result
    assert rig.stop(authority=rig.restart(Checkpoint())).reason == "authority_state_invalid"


def test_throwing_checkpoint_denies(rig):
    class Checkpoint:
        def verify(self, snapshot):
            raise OSError("unavailable")
    assert rig.restart(Checkpoint()).inspect().reason == "authority_unavailable"


@pytest.mark.parametrize("field,value", [
    ("stop_epoch", 0), ("revision", 9), ("writer_fence", 2),
    ("writer_id", "other"), ("terminal", False), ("previous_digest", "f" * 64),
    ("event_digest", "f" * 64), ("authority_id", "other"),
])
def test_corrupt_or_inconsistent_history(rig, field, value):
    rig.stop()
    state = rig.adapter.load()
    event = replace(state.events[-1], **{field: value})
    if field != "event_digest":
        event = replace(event, event_digest=sa._event_digest(event))
    rig.adapter._snapshot = replace(state, events=state.events[:-1] + (event,))
    assert rig.restart().inspect().reason == "authority_state_invalid"


@pytest.mark.parametrize("value", [True, -1, 2**53 + 1, float("nan"), "1"])
def test_malformed_records(value):
    with pytest.raises(ValueError):
        sa.AuthorityEvent(
            "authority", "latch", 1, value, False, "writer", 1,
            "fence", None, None, sa.GENESIS_DIGEST, sa.GENESIS_DIGEST,
        )


@pytest.mark.parametrize("kind", ["stop", "fence"])
def test_concurrent_conditional_updates(rig, kind):
    barrier = threading.Barrier(2)
    original = rig.adapter.compare_and_swap
    def synchronized(expected, proposed):
        barrier.wait(5)
        return original(expected, proposed)
    rig.adapter.compare_and_swap = synchronized
    authorities = [rig.restart(), rig.restart()]
    results, errors = [], []
    def run(authority):
        try:
            result = (
                rig.stop(authority=authority) if kind == "stop"
                else authority.fence_writer("writer", 1)
            )
            results.append(result)
        except BaseException as exc:
            errors.append(exc)
    threads = [threading.Thread(target=run, args=(authority,), daemon=True)
               for authority in authorities]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(6)
        assert not thread.is_alive()
    assert not errors and len(results) == 2
    assert sum(result.reason == "conditional_conflict" for result in results) == 1
    assert rig.adapter.load().revision == 2
    rig.adapter.compare_and_swap = original
    if kind == "stop":
        assert rig.stop(authority=rig.restart()).reason == "already_recorded"
        assert rig.adapter.load().stop_epoch == 1


def test_adapter_rejects_non_append_and_stale_snapshot(rig):
    expected = rig.adapter.load()
    rig.stop()
    assert rig.adapter.compare_and_swap(expected, expected) == "CONFLICT"
    current = rig.adapter.load()
    with pytest.raises(ValueError, match="invalid_conditional_update"):
        rig.adapter.compare_and_swap(current, current)


def test_epoch_and_history_exhaustion(rig, monkeypatch):
    # Lower the contract limits to exercise the real saturation paths.
    monkeypatch.setattr(sa, "MAX_STOP_EPOCH", 1)
    assert rig.stop().reason == "stop_recorded"
    assert rig.stop(rig.command(2)).reason == "epoch_or_fence_exhausted"
    monkeypatch.setattr(sa, "MAX_WRITER_FENCE", 1)
    assert rig.authority.fence_writer("writer", 1).reason == "epoch_or_fence_exhausted"
    monkeypatch.setattr(sa, "MAX_STOP_EPOCH", 2**53)
    monkeypatch.setattr(sa, "MAX_EVENTS", 2)
    assert rig.stop(rig.command(2)).reason == "history_exhausted"
    assert rig.adapter.load().terminal


def test_stop_has_no_clock_or_activation_dependency(rig):
    import inspect
    assert "clock" not in inspect.signature(sa.StopGenerationAuthority).parameters
    command = rig.command()
    baseline = sl.parse_command(command)
    assert rig.stop(command).recorded
    assert sl.command_envelope(baseline) == command
    assert rig.adapter.load().events[-1].command.digest() == baseline.digest()
