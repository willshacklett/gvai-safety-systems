"""Local persistence contracts, not physical power-loss/independence evidence."""

import json
import os
import pathlib
import subprocess
import sys
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_stop_latch as sl
from gvai import stop_authority_filesystem as fs
from gvai import stop_generation_authority as sa


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


class Crash(BaseException):
    pass


class Rig:
    def __init__(self, tmp_path):
        self.path = tmp_path / "authority"
        self.path.mkdir(mode=0o700)
        self.stop_key = Ed25519PrivateKey.generate()
        self.arm_key = Ed25519PrivateKey.generate()
        self.keys = sl.StopLatchKeyring(
            {"stop": public(self.stop_key)}, {"arm": public(self.arm_key)},
        )
        fs.FilesystemAuthorityAdapter.provision(
            str(self.path), sa.AuthoritySnapshot("authority", "latch"), self.keys,
        )
        self.adapter = self.open()
        self.authority = self.wrap(self.adapter)
        assert self.authority.fence_writer("writer", 0).reason == "writer_fenced"

    def open(self):
        return fs.FilesystemAuthorityAdapter(str(self.path), "authority", "latch", self.keys)

    def wrap(self, adapter):
        return sa.StopGenerationAuthority("authority", "latch", self.keys, adapter)

    def command(self, sequence=1):
        return {
            "version": 1, "latch_id": "latch", "sequence": sequence,
            "command_type": "stop", "key_id": "stop",
            "signature": self.stop_key.sign(
                sl.signing_bytes("latch", sequence, "stop", "stop"),
            ).hex(),
        }

    def stop(self, sequence=1):
        return self.authority.request_stop(
            self.command(sequence), writer_id="writer", writer_fence=1,
        )

    def restart(self):
        self.adapter.close()
        self.adapter = self.open()
        self.authority = self.wrap(self.adapter)


@pytest.fixture
def rig(tmp_path):
    rig = Rig(tmp_path)
    try:
        yield rig
    finally:
        rig.adapter.close()


def test_durable_stop_exact_restart_retry_and_evidence(rig):
    snapshot = rig.adapter.load()
    assert fs.decode_snapshot(fs.encode_snapshot(snapshot)) == snapshot
    result = rig.stop()
    assert result.reason == "stop_recorded" and result.recorded and result.durable
    assert result.stop_epoch == 1
    assert result.deny_execution and not result.backend_notified and not result.workload_terminated
    assert not rig.adapter.locally_durable(snapshot)
    rig.restart()
    retry = rig.stop()
    assert retry.reason == "already_recorded" and retry.durable and retry.stop_epoch == 1
    assert rig.stop(2).stop_epoch == 2
    rig.restart()
    assert rig.stop().stop_epoch == 2
    assert not (rig.path / fs.INTENT).exists()
    assert not (rig.path / fs.PENDING).exists()


def test_exclusive_session_and_release(rig):
    with pytest.raises(BlockingIOError):
        rig.open()
    rig.restart()
    assert rig.authority.inspect().reason == "state_verified"


def test_conditional_conflicts_and_invalid_append(rig):
    old = rig.adapter.load()
    rig.stop()
    current = rig.adapter.load()
    assert rig.adapter.compare_and_swap(old, old) == "CONFLICT"
    with pytest.raises(ValueError, match="invalid_conditional_update"):
        rig.adapter.compare_and_swap(current, current)
    with pytest.raises(ValueError, match="authority_adapter_fault"):
        rig.adapter.load()


@pytest.mark.parametrize("writer,fence,reason", [
    ("other", 1, "conflicting_writer"), ("writer", 0, "stale_writer_fence"),
    ("writer", 2, "stale_writer_fence"),
])
def test_persistent_writer_fencing(rig, writer, fence, reason):
    rig.restart()
    result = rig.authority.request_stop(rig.command(), writer_id=writer, writer_fence=fence)
    assert result.reason == reason and not result.durable
    assert rig.adapter.load().stop_epoch == 0


@pytest.mark.parametrize("phase,recoverable,recorded", [
    ("before_intent", True, False),
    ("before_intent_sync", False, False),
    ("intent_durable", False, False),
    ("before_pending_write", False, False),
    ("before_pending_sync", False, False),
    ("pending_synced", False, False),
    ("after_replace", False, True),
    ("replacement_synced", False, True),
    ("before_intent_remove", False, True),
    ("before_cleanup_sync", True, True),
    ("cleanup_synced", True, True),
    ("before_ack", True, True),
])
def test_crash_boundaries(rig, phase, recoverable, recorded):
    def crash(name):
        if name == phase:
            raise Crash(name)

    rig.adapter._phase = crash
    with pytest.raises(Crash):
        rig.stop()
    with pytest.raises(ValueError):
        rig.adapter.load()
    rig.adapter.close()
    on_disk = fs.decode_snapshot((rig.path / fs.STATE).read_bytes())
    assert on_disk.stop_epoch == int(recorded)
    if not recoverable:
        with pytest.raises(ValueError, match="incomplete_authority_commit"):
            rig.open()
    else:
        rig.adapter = rig.open()
        rig.authority = rig.wrap(rig.adapter)
        result = rig.stop()
        assert result.reason == ("already_recorded" if recorded else "stop_recorded")
        assert result.durable and result.stop_epoch == 1


def test_lost_ack_is_uncertain_not_durable(rig):
    def lose(name):
        if name == "before_ack":
            raise OSError("reply lost")
    rig.adapter._phase = lose
    result = rig.stop()
    assert result.reason == "commit_uncertain" and not result.recorded and not result.durable
    assert rig.stop().reason == "commit_uncertain"
    rig.restart()
    assert rig.stop().reason == "already_recorded"
    assert rig.stop().durable


@pytest.mark.parametrize("operation", ["write", "fsync", "replace", "readback"])
def test_syscall_failures_poison_and_deny(rig, monkeypatch, operation):
    original_fsync = os.fsync
    state = {"armed": False}
    def arm(name):
        if name == "before_pending_write":
            state["armed"] = True
    rig.adapter._phase = arm
    if operation == "write":
        original = rig.adapter._write_all
        def write(fd, raw):
            if state["armed"]:
                os.write(fd, raw[:10])
                raise OSError("partial write")
            original(fd, raw)
        monkeypatch.setattr(rig.adapter, "_write_all", write)
    elif operation == "fsync":
        def sync(fd):
            if state["armed"]:
                raise OSError("sync failed")
            original_fsync(fd)
        monkeypatch.setattr(fs.os, "fsync", sync)
    elif operation == "replace":
        def failed(*args, **kwargs):
            raise OSError("rename failed")
        monkeypatch.setattr(fs.os, "replace", failed)
    else:
        original = rig.adapter._read
        count = {"calls": 0}
        def read(fd):
            count["calls"] += 1
            raw = original(fd)
            return raw + b" " if state["armed"] else raw
        monkeypatch.setattr(rig.adapter, "_read", read)
    result = rig.stop()
    assert result.reason == "commit_uncertain" and not result.durable
    assert rig.authority.inspect().reason == "commit_uncertain"
    rig.adapter.close()
    with pytest.raises(ValueError, match="incomplete_authority_commit"):
        rig.open()


@pytest.mark.parametrize("phase", ["before_intent_sync", "before_cleanup_sync"])
def test_sync_failure_before_and_after_replacement(rig, monkeypatch, phase):
    original = os.fsync
    state = {"fail": False}
    rig.adapter._phase = lambda name: state.update(fail=True) if name == phase else None
    def sync(fd):
        if state["fail"]:
            raise OSError("sync failed")
        original(fd)
    monkeypatch.setattr(fs.os, "fsync", sync)
    result = rig.stop()
    assert result.reason == "commit_uncertain" and not result.durable


@pytest.mark.parametrize("raw", [
    b"", b"{", b"\xff", b"[]", b'{"version":1,"version":1}',
    b'{"value":NaN}', b" " * (fs.MAX_FILE_BYTES + 1),
])
def test_corrupt_startup(rig, raw):
    rig.adapter.close()
    (rig.path / fs.STATE).write_bytes(raw)
    with pytest.raises(ValueError):
        rig.open()


def test_missing_state_not_genesis(rig):
    rig.adapter.close()
    (rig.path / fs.STATE).unlink()
    with pytest.raises(FileNotFoundError):
        rig.open()
    with pytest.raises(ValueError, match="authority_directory_not_empty"):
        fs.FilesystemAuthorityAdapter.provision(
            str(rig.path), sa.AuthoritySnapshot("authority", "latch"), rig.keys,
        )


@pytest.mark.parametrize("field,value", [
    ("stop_epoch", 0), ("revision", 3), ("writer_id", "other"),
    ("writer_fence", 2), ("terminal", False), ("event_digest", "f" * 64),
])
def test_full_history_validation_on_startup(rig, field, value):
    rig.stop()
    snapshot = rig.adapter.load()
    event = replace(snapshot.events[-1], **{field: value})
    if field != "event_digest":
        event = replace(event, event_digest=sa._event_digest(event))
    rig.adapter.close()
    (rig.path / fs.STATE).write_bytes(fs.encode_snapshot(
        replace(snapshot, events=snapshot.events[:-1] + (event,)),
    ))
    with pytest.raises(ValueError):
        rig.open()


def test_live_history_rewind_rejected_but_coherent_restart_rollback_not_detected(rig):
    old = (rig.path / fs.STATE).read_bytes()
    rig.stop()
    (rig.path / fs.STATE).write_bytes(old)
    assert rig.authority.inspect().reason == "authority_state_invalid"
    rig.restart()
    assert rig.adapter.load().stop_epoch == 0
    assert rig.stop().durable  # Explicit local-only rollback limitation.


@pytest.mark.parametrize("name", [fs.STATE, fs.LOCK])
def test_symlink_and_unsafe_mode_rejected(rig, name):
    rig.adapter.close()
    file = rig.path / name
    file.chmod(0o644)
    with pytest.raises(ValueError, match="unsafe_authority_file"):
        rig.open()
    file.chmod(0o600)
    file.rename(rig.path / "target")
    file.symlink_to("target")
    with pytest.raises(OSError):
        rig.open()


def test_hardlink_fifo_and_directory_permissions(rig):
    rig.adapter.close()
    state = rig.path / fs.STATE
    os.link(state, rig.path / "linked")
    with pytest.raises(ValueError, match="unsafe_authority_file"):
        rig.open()
    (rig.path / "linked").unlink()
    state.unlink()
    os.mkfifo(state, 0o600)
    with pytest.raises(ValueError, match="unsafe_authority_file"):
        rig.open()
    rig.path.chmod(0o755)
    with pytest.raises(ValueError, match="unsafe_authority_directory"):
        rig.open()


def test_startup_sync_and_readback_failure(rig, monkeypatch):
    rig.adapter.close()
    def failed(fd):
        raise OSError("startup sync failed")
    monkeypatch.setattr(fs.os, "fsync", failed)
    with pytest.raises(OSError):
        rig.open()


def test_zero_write_fails_instead_of_looping(monkeypatch):
    monkeypatch.setattr(fs.os, "write", lambda fd, raw: 0)
    with pytest.raises(OSError, match="short_authority_write"):
        fs.FilesystemAuthorityAdapter._write_all(1, b"x")


def test_invalid_durability_evidence_cannot_ack(rig):
    rig.adapter.locally_durable = lambda snapshot: 1
    result = rig.stop()
    assert result.reason == "authority_state_invalid" and not result.durable


def test_throwing_durability_evidence_cannot_ack(rig):
    def unavailable(snapshot):
        raise OSError("unavailable")
    rig.adapter.locally_durable = unavailable
    result = rig.stop()
    assert result.reason == "authority_unavailable" and not result.durable


def test_startup_readback_change_denies(rig):
    rig.adapter.close()
    def change(name):
        if name == "before_readback":
            with (rig.path / fs.STATE).open("ab") as out:
                out.write(b" ")
    with pytest.raises(ValueError, match="authority_readback_mismatch"):
        fs.FilesystemAuthorityAdapter(
            str(rig.path), "authority", "latch", rig.keys, phase=change,
        )


def test_live_read_failure_is_sticky(rig, monkeypatch):
    def down(fd):
        raise OSError("private read error")
    monkeypatch.setattr(rig.adapter, "_read", down)
    result = rig.stop()
    assert result.reason == "authority_unavailable" and not result.durable
    assert rig.authority.inspect().reason == "authority_unavailable"


def test_lock_substitution_denies(rig):
    (rig.path / fs.LOCK).rename(rig.path / "old.lock")
    lock = rig.path / fs.LOCK
    lock.write_bytes(b"")
    lock.chmod(0o600)
    assert rig.authority.inspect().reason == "authority_state_invalid"


@pytest.mark.parametrize("phase,recoverable,recorded", [
    ("before_intent", True, False),
    ("before_pending_sync", False, False),
    ("after_replace", False, True),
    ("replacement_synced", False, True),
    ("before_cleanup_sync", True, True),
    ("cleanup_synced", True, True),
])
def test_hard_process_exit_at_persistence_barriers(rig, phase, recoverable, recorded):
    rig.adapter.close()
    payload = {
        "directory": str(rig.path), "phase": phase,
        "stop": public(rig.stop_key).hex(), "arm": public(rig.arm_key).hex(),
        "command": rig.command(),
    }
    script = """
import json, os, sys
from gvai.experimental_stop_latch import StopLatchKeyring
from gvai.stop_generation_authority import StopGenerationAuthority
from gvai.stop_authority_filesystem import FilesystemAuthorityAdapter
p = json.loads(sys.argv[1])
keys = StopLatchKeyring({'stop': bytes.fromhex(p['stop'])}, {'arm': bytes.fromhex(p['arm'])})
def crash(name):
    if name == p['phase']:
        os._exit(71)
with FilesystemAuthorityAdapter(p['directory'], 'authority', 'latch', keys, phase=crash) as adapter:
    authority = StopGenerationAuthority('authority', 'latch', keys, adapter)
    authority.request_stop(p['command'], writer_id='writer', writer_fence=1)
raise RuntimeError('crash point not reached')
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, json.dumps(payload)],
        cwd=pathlib.Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=10,
    )
    assert completed.returncode == 71, completed.stderr
    snapshot = fs.decode_snapshot((rig.path / fs.STATE).read_bytes())
    assert snapshot.stop_epoch == int(recorded)
    if recoverable:
        rig.adapter = rig.open()
        rig.authority = rig.wrap(rig.adapter)
        result = rig.stop()
        assert result.reason == ("already_recorded" if recorded else "stop_recorded")
        assert result.durable and result.stop_epoch == 1
    else:
        with pytest.raises(ValueError, match="incomplete_authority_commit"):
            rig.open()


def test_subprocess_restart_retry_uses_only_public_keys(rig):
    assert rig.stop().durable
    rig.adapter.close()
    payload = {
        "directory": str(rig.path),
        "stop": public(rig.stop_key).hex(), "arm": public(rig.arm_key).hex(),
        "command": rig.command(),
    }
    script = """
import json, sys
from gvai.experimental_stop_latch import StopLatchKeyring
from gvai.stop_generation_authority import StopGenerationAuthority
from gvai.stop_authority_filesystem import FilesystemAuthorityAdapter
p = json.loads(sys.argv[1])
keys = StopLatchKeyring({'stop': bytes.fromhex(p['stop'])}, {'arm': bytes.fromhex(p['arm'])})
with FilesystemAuthorityAdapter(p['directory'], 'authority', 'latch', keys) as adapter:
    authority = StopGenerationAuthority('authority', 'latch', keys, adapter)
    result = authority.request_stop(p['command'], writer_id='writer', writer_fence=1)
    print(json.dumps({'reason': result.reason, 'durable': result.durable, 'epoch': result.stop_epoch}))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, json.dumps(payload)],
        cwd=pathlib.Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=10, check=True,
    )
    assert json.loads(completed.stdout) == {
        "reason": "already_recorded", "durable": True, "epoch": 1,
    }


@pytest.mark.parametrize("phase", ["before_state_sync", "before_readback"])
def test_identical_bytes_different_inode_deny_load(rig, phase):
    old = (rig.path / fs.STATE).read_bytes()
    def substitute(name):
        if name == phase:
            replacement = rig.path / "replacement"
            replacement.write_bytes(old)
            replacement.chmod(0o600)
            os.replace(replacement, rig.path / fs.STATE)
    rig.adapter._phase = substitute
    result = rig.authority.inspect()
    assert result.reason == "authority_state_invalid"
    assert not result.durable
    with pytest.raises(ValueError, match="authority_adapter_fault"):
        rig.adapter.locally_durable(sa.AuthoritySnapshot("authority", "latch"))


@pytest.mark.parametrize("phase,name", [
    ("pending_synced", fs.PENDING), ("after_replace", fs.STATE),
    ("replacement_synced", fs.STATE), ("before_intent_remove", fs.STATE),
])
@pytest.mark.parametrize("substitution", ["regular", "symlink", "fifo"])
def test_retained_pending_descriptor_detects_path_substitution(rig, phase, name, substitution):
    def substitute(at):
        if at != phase:
            return
        target = rig.path / name
        raw = target.read_bytes()
        target.rename(rig.path / "displaced")
        if substitution == "regular":
            target.write_bytes(raw)
            target.chmod(0o600)
        elif substitution == "symlink":
            target.symlink_to("displaced")
        else:
            os.mkfifo(target, 0o600)
    rig.adapter._phase = substitute
    result = rig.stop()
    assert result.reason == "commit_uncertain"
    assert not result.recorded and not result.durable
    rig.adapter.close()
    with pytest.raises(ValueError, match="incomplete_authority_commit"):
        rig.open()


def test_same_descriptor_is_validated_synced_and_read_back(rig, monkeypatch):
    reads, synced = [], []
    original_read, original_sync = rig.adapter._read, os.fsync
    def read(fd):
        reads.append(fd)
        return original_read(fd)
    def sync(fd):
        synced.append(fd)
        original_sync(fd)
    monkeypatch.setattr(rig.adapter, "_read", read)
    monkeypatch.setattr(fs.os, "fsync", sync)
    snapshot = rig.adapter.load()
    assert len(reads) == 2 and reads[0] == reads[1]
    assert reads[0] in synced
    assert rig.adapter.locally_durable(snapshot)


def test_cached_evidence_is_historical_not_live_storage_proof(rig):
    assert rig.stop().durable
    snapshot = rig.adapter.load()
    assert rig.adapter.locally_durable(snapshot)
    (rig.path / fs.STATE).write_bytes(b"corrupt")
    # No disk read: evidence describes the previous completed synchronization.
    assert rig.adapter.locally_durable(snapshot)
    assert not rig.adapter.locally_durable(replace(snapshot, events=()))
    assert not rig.adapter.locally_durable(None)
    assert rig.authority.inspect().reason == "authority_state_invalid"
    with pytest.raises(ValueError):
        rig.adapter.locally_durable(snapshot)
    rig.adapter.close()
    with pytest.raises(ValueError):
        rig.open()


def test_latest_head_only_and_close_invalidates_evidence(rig):
    first = rig.adapter.load()
    rig.stop()
    second = rig.adapter.load()
    assert not rig.adapter.locally_durable(first)
    assert rig.adapter.locally_durable(second)
    rig.adapter.close()
    with pytest.raises(ValueError):
        rig.adapter.locally_durable(second)


def test_failed_identity_verification_never_acknowledges(rig, monkeypatch):
    original = rig.adapter._verify_identity
    def verify(name, fd, identity=None):
        if name == fs.PENDING:
            raise OSError("identity verification unavailable")
        original(name, fd, identity)
    monkeypatch.setattr(rig.adapter, "_verify_identity", verify)
    result = rig.stop()
    assert result.reason == "commit_uncertain" and not result.durable
    rig.adapter.close()
    with pytest.raises(ValueError, match="incomplete_authority_commit"):
        rig.open()


def test_descriptor_rebinding_to_replacement_inode_denies(rig, monkeypatch):
    held = {}
    original = rig.adapter._read
    def read(fd):
        held["fd"] = fd
        return original(fd)
    monkeypatch.setattr(rig.adapter, "_read", read)
    def substitute(name):
        if name != "before_state_sync":
            return
        target = rig.path / fs.STATE
        replacement = rig.path / "replacement"
        replacement.write_bytes(target.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, target)
        other = os.open(target, os.O_RDONLY)
        try:
            os.dup2(other, held["fd"])
        finally:
            os.close(other)
    rig.adapter._phase = substitute
    assert rig.authority.inspect().reason == "authority_state_invalid"
    with pytest.raises(ValueError):
        rig.adapter.locally_durable(sa.AuthoritySnapshot("authority", "latch"))
