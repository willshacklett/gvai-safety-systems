"""Adversarial tests for the experimental restart-persistent STOP journal.

Offline and Cloud-only: temporary directories, no network, no live host. The
private keys below exist only in tests to stand in for offline provisioning.
"""

from __future__ import annotations

import ast
import json
import multiprocessing
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import stop_generation_journal as sgj
from gvai.stop_generation_journal import (
    JournalAnchor,
    JournalRecord,
    StopGenerationJournal,
    decode_journal,
    encode_journal,
)

MODULE_PATH = pathlib.Path(sgj.__file__)
ROOT = MODULE_PATH.parent.parent
AUTHORITY = "offline-authority"
DOMAIN = "stop-generation"
KEY_ID = "provision-key-1"


def _pub(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _open(key, generation, index, previous, key_id=KEY_ID, authority=AUTHORITY, domain=DOMAIN):
    unsigned = JournalRecord(
        "open", generation, index, previous,
        authority_id=authority, trust_domain=domain, key_id=key_id, signature=b"\0" * 64,
    )
    signature = key.sign(unsigned.signing_input())
    return JournalRecord(
        "open", generation, index, previous,
        authority_id=authority, trust_domain=domain, key_id=key_id, signature=signature,
    )


def _stop(prev: JournalRecord, index, reason="manual"):
    return JournalRecord("stop", prev.generation, index, prev.record_hash(), reason=reason)


def _chain_open_stop_open(key):
    first = _open(key, 1, 0, sgj.GENESIS_HASH)
    stop = _stop(first, 1)
    second = _open(key, 2, 2, stop.record_hash())
    return first, stop, second


class Base(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.tmp = tempfile.mkdtemp(prefix="sgj-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dir = os.path.join(self.tmp, "j")
        os.mkdir(self.dir, 0o700)
        self.opened = []

    def provision(self, records=None, directory=None):
        directory = directory or self.dir
        records = records or (_open(self.key, 1, 0, sgj.GENESIS_HASH),)
        pathlib.Path(directory, sgj.LOCK_NAME).touch(mode=0o600)
        os.chmod(os.path.join(directory, sgj.LOCK_NAME), 0o600)
        self.write(records, directory)
        return records

    def write(self, records, directory=None):
        path = os.path.join(directory or self.dir, sgj.JOURNAL_NAME)
        self.raw_write(encode_journal(tuple(records)), path)

    @staticmethod
    def raw_write(raw, path):
        if os.path.lexists(path):
            os.unlink(path)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, raw)
        os.close(fd)

    def journal(self, directory=None, **overrides):
        kwargs = dict(
            authority_id=AUTHORITY,
            trust_domain=DOMAIN,
            trusted_public_keys={KEY_ID: _pub(self.key)},
        )
        kwargs.update(overrides)
        instance = StopGenerationJournal(directory or self.dir, **kwargs)
        self.addCleanup(instance.close)
        return instance

    def jpath(self, name=sgj.JOURNAL_NAME):
        return os.path.join(self.dir, name)


class PersistenceTests(Base):
    def test_unprovisioned_is_stopped(self):
        j = self.journal()
        self.assertTrue(j.state.stopped)
        self.assertTrue(j.state.fault)

    def test_missing_journal_file_is_stopped_unprovisioned(self):
        pathlib.Path(self.jpath(sgj.LOCK_NAME)).touch(mode=0o600)
        os.chmod(self.jpath(sgj.LOCK_NAME), 0o600)
        state = self.journal().state
        self.assertTrue(state.stopped)
        self.assertEqual(state.reason, "unprovisioned")

    def test_provisioned_generation_reports_not_stopped_informationally(self):
        self.provision()
        state = self.journal().state
        self.assertFalse(state.stopped)
        self.assertEqual(state.generation, 1)
        self.assertEqual(state.rollback_detection, "none")

    def test_stop_is_durable_and_survives_restart(self):
        self.provision()
        outcome = self.journal().latch_stop("operator")
        self.assertTrue(outcome.durable)
        self.assertTrue(outcome.stopped)
        fresh = self.journal()
        self.assertTrue(fresh.state.stopped)
        self.assertTrue(fresh.state.terminal)
        self.assertEqual(fresh.state.generation, 1)
        self.assertFalse(os.path.exists(self.jpath(sgj.INTENT_NAME)))
        self.assertFalse(os.path.exists(self.jpath(sgj.PENDING_NAME)))

    def test_stop_survives_real_process_restart(self):
        self.provision()
        self.journal().latch_stop()
        code = (
            "import sys;sys.path.insert(0,%r);"
            "from gvai.stop_generation_journal import StopGenerationJournal as J;"
            "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey;"
            "j=J(%r,authority_id=%r,trust_domain=%r,trusted_public_keys={%r:bytes.fromhex(%r)});"
            "s=j.state;sys.exit(0 if s.stopped and s.terminal else 3)"
        ) % (str(ROOT), self.dir, AUTHORITY, DOMAIN, KEY_ID, _pub(self.key).hex())
        result = subprocess.run([sys.executable, "-c", code], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stop_is_idempotent_and_adds_one_record(self):
        self.provision()
        j = self.journal()
        j.latch_stop("a")
        j.latch_stop("b")
        self.assertEqual(self.journal().state.record_count, 2)

    def test_new_generation_requires_offline_signed_open_after_stop(self):
        first, stop, second = _chain_open_stop_open(self.key)
        self.provision((first, stop, second))
        state = self.journal().state
        self.assertFalse(state.stopped)
        self.assertEqual(state.generation, 2)

    def test_stop_in_generation_two_is_terminal_for_generation_two(self):
        first, stop, second = _chain_open_stop_open(self.key)
        self.provision((first, stop, second))
        self.journal().latch_stop()
        state = self.journal().state
        self.assertTrue(state.terminal)
        self.assertEqual(state.generation, 2)

    def test_stopped_instance_never_reverses_even_if_file_is_replaced(self):
        self.provision()
        j = self.journal()
        j.latch_stop()
        self.write((_open(self.key, 1, 0, sgj.GENESIS_HASH),))
        self.assertTrue(j.state.stopped)

    def test_stop_reason_is_sanitised(self):
        self.provision()
        outcome = self.journal().latch_stop("bad reason\n{")
        self.assertTrue(outcome.durable)
        self.assertIn(b'"reason":"stop"', pathlib.Path(self.jpath()).read_bytes())


class GenerationAuthorityTests(Base):
    def assertFaults(self, records, code, **overrides):
        self.provision(records)
        state = self.journal(**overrides).state
        self.assertTrue(state.stopped)
        self.assertEqual(state.reason, code)

    def test_forged_open_signature(self):
        other = Ed25519PrivateKey.generate()
        self.assertFaults((_open(other, 1, 0, sgj.GENESIS_HASH),), "invalid_signature")

    def test_unknown_key_id(self):
        self.assertFaults((_open(self.key, 1, 0, sgj.GENESIS_HASH, key_id="other"),), "untrusted_key")

    def test_wrong_authority_or_domain(self):
        self.assertFaults((_open(self.key, 1, 0, sgj.GENESIS_HASH, authority="evil"),), "untrusted_authority")
        shutil.rmtree(self.dir)
        os.mkdir(self.dir, 0o700)
        self.assertFaults((_open(self.key, 1, 0, sgj.GENESIS_HASH, domain="evil"),), "untrusted_authority")

    def test_revoked_key(self):
        self.assertFaults(
            (_open(self.key, 1, 0, sgj.GENESIS_HASH),), "untrusted_key",
            revoked_key_ids=frozenset({KEY_ID}),
        )

    def test_unexpected_first_generation(self):
        self.assertFaults((_open(self.key, 5, 0, sgj.GENESIS_HASH),), "unexpected_first_generation")

    def test_open_without_stop_cannot_start_new_generation(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        second = _open(self.key, 2, 1, first.record_hash())
        self.assertFaults((first, second), "generation_not_authorised")

    def test_skipped_generation(self):
        first, stop, _ = _chain_open_stop_open(self.key)
        skipped = _open(self.key, 3, 2, stop.record_hash())
        self.assertFaults((first, stop, skipped), "generation_not_authorised")

    def test_unsigned_modification_of_signed_open_fields(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        raw = encode_journal((first,)).replace(b'"generation":1', b'"generation":1', 1)
        data = json.loads(raw)
        data["records"][0]["trust_domain"] = "other"
        self.provision()
        os.unlink(self.jpath())
        self.raw_write(sgj._canon(data), self.jpath())
        self.assertTrue(self.journal().state.fault)

    def test_replayed_open_from_other_history(self):
        first, stop, second = _chain_open_stop_open(self.key)
        other_first = _open(self.key, 1, 0, sgj.GENESIS_HASH, key_id=KEY_ID)
        other_stop = JournalRecord("stop", 1, 1, other_first.record_hash(), reason="different")
        self.assertFaults((other_first, other_stop, second), "chain_break")

    def test_stop_record_for_wrong_generation(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        bad = JournalRecord("stop", 2, 1, first.record_hash(), reason="x")
        self.assertFaults((first, bad), "chain_break")

    def test_double_stop_is_chain_break(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        stop = _stop(first, 1)
        stop2 = JournalRecord("stop", 1, 2, stop.record_hash(), reason="y")
        self.assertFaults((first, stop, stop2), "chain_break")

    def test_key_reuse_rejected(self):
        pub = _pub(self.key)
        base = dict(authority_id=AUTHORITY, trust_domain=DOMAIN)
        with self.assertRaises(ValueError):
            StopGenerationJournal(self.dir, trusted_public_keys={KEY_ID: pub},
                                  other_purpose_key_ids=frozenset({KEY_ID}), **base)
        with self.assertRaises(ValueError):
            StopGenerationJournal(self.dir, trusted_public_keys={KEY_ID: pub},
                                  other_purpose_public_keys=frozenset({pub}), **base)
        with self.assertRaises(ValueError):
            StopGenerationJournal(self.dir, trusted_public_keys={KEY_ID: pub, "k2": pub}, **base)

    def test_invalid_constructor_inputs(self):
        for bad in ({}, {KEY_ID: b"short"}, {"bad id": b"\0" * 32}):
            with self.assertRaises(ValueError):
                StopGenerationJournal(self.dir, authority_id=AUTHORITY, trust_domain=DOMAIN,
                                      trusted_public_keys=bad)


class CorruptionTests(Base):
    def stopped_with(self, code=None):
        state = self.journal().state
        self.assertTrue(state.stopped)
        self.assertTrue(state.fault)
        if code:
            self.assertEqual(state.reason, code)

    def test_corrupt_bytes(self):
        self.provision()
        pathlib.Path(self.jpath()).write_bytes(b"\xff\xfe garbage")
        self.stopped_with("journal_corrupt")

    def test_truncated(self):
        self.provision()
        raw = pathlib.Path(self.jpath()).read_bytes()
        pathlib.Path(self.jpath()).write_bytes(raw[: len(raw) // 2])
        self.stopped_with("journal_corrupt")

    def test_empty(self):
        self.provision()
        pathlib.Path(self.jpath()).write_bytes(b"")
        self.stopped_with("journal_corrupt")

    def test_oversized(self):
        self.provision()
        pathlib.Path(self.jpath()).write_bytes(b"x" * (sgj.MAX_FILE_BYTES + 1))
        self.stopped_with("unsafe_journal_file")

    def test_noncanonical_whitespace(self):
        self.provision()
        raw = pathlib.Path(self.jpath()).read_bytes()
        pathlib.Path(self.jpath()).write_bytes(raw.replace(b",", b", ", 1))
        self.stopped_with("journal_corrupt")

    def test_duplicate_fields_and_unknown_fields(self):
        self.provision()
        raw = pathlib.Path(self.jpath()).read_bytes()
        pathlib.Path(self.jpath()).write_bytes(raw.replace(b'"version":1', b'"version":1,"version":1'))
        self.stopped_with("journal_corrupt")
        os.unlink(self.jpath())
        data = json.loads(raw)
        data["extra"] = 1
        self.raw_write(sgj._canon(data), self.jpath())
        self.stopped_with("journal_corrupt")

    def test_type_coercion_rejected(self):
        self.provision()
        data = json.loads(pathlib.Path(self.jpath()).read_bytes())
        for value in (True, 1.0, "1"):
            data["records"][0]["generation"] = value
            os.unlink(self.jpath())
            self.raw_write(sgj._canon(data), self.jpath())
            self.stopped_with("journal_corrupt")

    def test_tampered_stop_reason_breaks_following_chain(self):
        first, stop, second = _chain_open_stop_open(self.key)
        forged = JournalRecord("stop", 1, 1, first.record_hash(), reason="edited")
        self.provision((first, forged, second))
        self.stopped_with("chain_break")

    def test_deleted_stop_record_cannot_silently_reopen_generation(self):
        first, stop, second = _chain_open_stop_open(self.key)
        self.provision((first, second))
        self.stopped_with("chain_break")

    def test_non_ascii_rejected(self):
        self.provision()
        pathlib.Path(self.jpath()).write_bytes("é".encode())
        self.stopped_with("journal_corrupt")

    def test_record_count_limit(self):
        self.provision()
        data = json.loads(pathlib.Path(self.jpath()).read_bytes())
        data["records"] = data["records"] * (sgj.MAX_RECORDS + 1)
        os.unlink(self.jpath())
        self.raw_write(sgj._canon(data), self.jpath())
        self.stopped_with("journal_corrupt")

    def test_decoder_rejects_non_bytes(self):
        with self.assertRaises(ValueError):
            decode_journal("text")


class CrashTests(Base):
    def setUp(self):
        super().setUp()
        self.provision()

    def assert_never_reopens(self, j):
        self.assertTrue(j.state.stopped)
        fresh = self.journal()
        self.assertTrue(fresh.state.stopped)
        return fresh

    def test_fsync_failure_reports_not_durable_but_stays_stopped(self):
        j = self.journal()
        with mock.patch("os.fsync", side_effect=OSError("disk")):
            outcome = j.latch_stop()
        self.assertTrue(outcome.stopped)
        self.assertFalse(outcome.durable)
        fresh = self.assert_never_reopens(j)
        self.assertEqual(fresh.state.reason, "incomplete_commit")

    def test_each_syscall_failure_leaves_stop_and_preserved_intent(self):
        for name in ("write", "rename", "fsync"):
            with self.subTest(name=name):
                shutil.rmtree(self.dir)
                os.mkdir(self.dir, 0o700)
                self.provision()
                j = self.journal()
                calls = {"n": 0}
                real = getattr(os, name)

                def flaky(*a, _real=real, _calls=calls, **k):
                    _calls["n"] += 1
                    if _calls["n"] >= (1 if name == "rename" else 2):
                        raise OSError("injected")
                    return _real(*a, **k)

                with mock.patch("os." + name, side_effect=flaky):
                    outcome = j.latch_stop()
                self.assertFalse(outcome.durable)
                self.assertTrue(j.state.stopped)
                self.assertTrue(os.path.exists(self.jpath(sgj.INTENT_NAME)))
                self.assertTrue(self.journal().state.stopped)

    def test_simulated_crash_after_intent_before_rename(self):
        j = self.journal()
        with mock.patch("os.rename", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                j.latch_stop()
        self.assertTrue(j.state.stopped)
        self.assertTrue(os.path.exists(self.jpath(sgj.INTENT_NAME)))
        self.assertTrue(os.path.exists(self.jpath(sgj.PENDING_NAME)))
        self.assertEqual(self.journal().state.reason, "incomplete_commit")

    def test_crash_after_rename_before_intent_cleanup_is_conservative(self):
        j = self.journal()
        with mock.patch("os.unlink", side_effect=OSError("injected")):
            outcome = j.latch_stop()
        self.assertTrue(outcome.stopped)
        self.assertTrue(j.state.stopped)
        fresh = self.journal()
        self.assertEqual(fresh.state.reason, "incomplete_commit")

    def test_leftover_pending_alone_is_fault(self):
        pathlib.Path(self.jpath(sgj.PENDING_NAME)).write_bytes(b"x")
        self.assertEqual(self.journal().state.reason, "incomplete_commit")

    def test_stop_request_in_memory_precedes_io(self):
        j = self.journal()
        with mock.patch.object(j, "_latch_stop_locked", side_effect=RuntimeError):
            outcome = j.latch_stop()
        self.assertTrue(outcome.stopped)
        self.assertFalse(outcome.durable)
        self.assertTrue(j.state.stopped)

    def test_failed_instance_never_retries_to_success(self):
        j = self.journal()
        with mock.patch("os.fsync", side_effect=OSError):
            j.latch_stop()
        self.assertFalse(j.latch_stop().durable)

    def test_unsynced_crash_window_is_documented_limitation(self):
        # A crash before the intent file exists leaves no trace; restart reads not-stopped.
        self.assertFalse(self.journal().state.stopped)


class FilesystemAttackTests(Base):
    def test_symlinked_journal_file(self):
        self.provision()
        target = os.path.join(self.tmp, "elsewhere")
        shutil.move(self.jpath(), target)
        os.symlink(target, self.jpath())
        self.assertEqual(self.journal().state.reason, "unsafe_journal_file")

    def test_symlinked_lock_file(self):
        self.provision()
        target = os.path.join(self.tmp, "lock")
        pathlib.Path(target).touch(mode=0o600)
        os.unlink(self.jpath(sgj.LOCK_NAME))
        os.symlink(target, self.jpath(sgj.LOCK_NAME))
        self.assertEqual(self.journal().state.reason, "journal_unavailable")

    def test_symlinked_directory(self):
        self.provision()
        link = os.path.join(self.tmp, "link")
        os.symlink(self.dir, link)
        state = self.journal(link).state
        self.assertTrue(state.stopped and state.fault)

    def test_hardlinked_journal_file(self):
        self.provision()
        os.link(self.jpath(), os.path.join(self.tmp, "alias"))
        self.assertEqual(self.journal().state.reason, "unsafe_journal_file")

    def test_hardlinked_lock_file(self):
        self.provision()
        os.link(self.jpath(sgj.LOCK_NAME), os.path.join(self.tmp, "alias"))
        self.assertEqual(self.journal().state.reason, "unsafe_lock_file")

    def test_group_or_world_accessible_files(self):
        for mode in (0o640, 0o604, 0o660):
            with self.subTest(mode=oct(mode)):
                shutil.rmtree(self.dir)
                os.mkdir(self.dir, 0o700)
                self.provision()
                os.chmod(self.jpath(), mode)
                self.assertEqual(self.journal().state.reason, "unsafe_journal_file")

    def test_group_or_world_writable_directory(self):
        self.provision()
        os.chmod(self.dir, 0o770)
        self.assertEqual(self.journal().state.reason, "unsafe_directory")

    def test_fifo_in_place_of_journal(self):
        self.provision()
        os.unlink(self.jpath())
        os.mkfifo(self.jpath(), 0o600)
        self.assertEqual(self.journal().state.reason, "unsafe_journal_file")

    def test_directory_in_place_of_journal(self):
        self.provision()
        os.unlink(self.jpath())
        os.mkdir(self.jpath(), 0o700)
        self.assertEqual(self.journal().state.reason, "unsafe_journal_file")

    def test_lock_file_substitution_after_open(self):
        self.provision()
        j = self.journal()
        self.assertFalse(j.state.stopped)
        j2 = self.journal()
        os.unlink(self.jpath(sgj.LOCK_NAME))
        pathlib.Path(self.jpath(sgj.LOCK_NAME)).touch(mode=0o600)
        os.chmod(self.jpath(sgj.LOCK_NAME), 0o600)
        self.assertEqual(j2.state.reason, "lock_substituted")

    def test_directory_swap_after_construction_does_not_redirect(self):
        self.provision()
        j = self.journal()
        moved = os.path.join(self.tmp, "moved")
        os.rename(self.dir, moved)
        evil = os.path.join(self.tmp, "j")
        os.mkdir(evil, 0o700)
        self.provision(directory=evil)
        outcome = j.latch_stop()
        self.assertTrue(outcome.durable)
        self.assertTrue(decode_journal(pathlib.Path(moved, sgj.JOURNAL_NAME).read_bytes())[-1].kind == "stop")
        self.assertEqual(len(decode_journal(pathlib.Path(evil, sgj.JOURNAL_NAME).read_bytes())), 1)

    def test_prestaged_symlink_intent_not_followed(self):
        self.provision()
        victim = os.path.join(self.tmp, "victim")
        os.symlink(victim, self.jpath(sgj.INTENT_NAME))
        outcome = self.journal().latch_stop()
        self.assertFalse(outcome.durable)
        self.assertFalse(os.path.exists(victim))

    def test_missing_directory(self):
        state = self.journal(os.path.join(self.tmp, "absent")).state
        self.assertEqual(state.reason, "journal_unavailable")

    @unittest.skipUnless(os.geteuid() == 0, "requires root to create foreign-owned files")
    def test_foreign_owned_files_rejected(self):
        self.provision()
        os.chown(self.jpath(), 65534, 65534)
        self.assertEqual(self.journal().state.reason, "unsafe_journal_file")
        os.chown(self.dir, 65534, 65534)
        self.assertEqual(self.journal().state.reason, "unsafe_directory")

    def test_closed_instance_is_stopped(self):
        self.provision()
        j = self.journal()
        j.close()
        self.assertTrue(j.state.stopped)
        self.assertFalse(j.latch_stop().durable)


class RollbackTests(Base):
    def test_in_process_rollback_detected_by_long_lived_instance(self):
        first, stop, second = _chain_open_stop_open(self.key)
        self.provision((first, stop, second))
        j = self.journal()
        self.assertFalse(j.state.stopped)
        self.write((first,))
        state = j.state
        self.assertEqual(state.reason, "rollback_detected")
        self.write((first, stop, second))
        self.assertTrue(j.state.stopped)  # sticky

    def test_in_process_fork_detected(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        self.provision((first, _stop(first, 1, "one")))
        j = self.journal()
        self.assertTrue(j.state.terminal)
        self.write((first, _stop(first, 1, "two")))
        self.assertTrue(j.state.stopped)  # sticky once STOP was seen
        self.assertTrue(self.journal().state.stopped)

    def test_fork_detected_by_instance_that_saw_other_branch(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        s1 = _stop(first, 1, "one")
        s2 = _stop(first, 1, "two")
        self.provision((first,))
        j = self.journal()
        self.assertFalse(j.state.stopped)
        # A different valid extension replaces the seen prefix chain of equal length.
        j._seen = (first.record_hash(), s1.record_hash())
        self.write((first, s2))
        self.assertEqual(j.state.reason, "fork_detected")

    def test_anchor_detects_rollback_after_restart(self):
        first, stop, second = _chain_open_stop_open(self.key)
        self.provision((first, stop, second))
        anchor = JournalAnchor(2, stop.record_hash())
        self.write((first,))
        state = self.journal(anchor=anchor).state
        self.assertEqual(state.reason, "rollback_detected")
        self.assertEqual(state.rollback_detection, "independent_anchor")

    def test_anchor_detects_fork(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        self.provision((first, _stop(first, 1, "two")))
        anchor = JournalAnchor(2, _stop(first, 1, "one").record_hash())
        self.assertEqual(self.journal(anchor=anchor).state.reason, "fork_detected")

    def test_anchor_detects_deletion(self):
        self.provision()
        os.unlink(self.jpath())
        anchor = JournalAnchor(1, "a" * 64)
        self.assertEqual(self.journal(anchor=anchor).state.reason, "journal_deleted")

    def test_anchor_at_stop_keeps_stop_after_valid_replay_of_stop_state(self):
        first = _open(self.key, 1, 0, sgj.GENESIS_HASH)
        stop = _stop(first, 1)
        self.provision((first, stop))
        anchor = JournalAnchor(2, stop.record_hash())
        self.assertTrue(self.journal(anchor=anchor).state.terminal)

    def test_deletion_after_observation_detected_without_anchor(self):
        self.provision()
        j = self.journal()
        self.assertFalse(j.state.stopped)
        os.unlink(self.jpath())
        self.assertEqual(j.state.reason, "journal_deleted")

    def test_COHERENT_ROLLBACK_IS_UNDETECTABLE_WITHOUT_AN_ANCHOR(self):
        """Documented limitation: a full, coherent restore of old state reopens a new instance."""

        self.provision()
        backup = os.path.join(self.tmp, "backup")
        shutil.copytree(self.dir, backup)
        self.journal().latch_stop()
        self.assertTrue(self.journal().state.terminal)
        shutil.rmtree(self.dir)
        shutil.copytree(backup, self.dir)
        restored = self.journal()
        self.assertFalse(restored.state.stopped)
        self.assertEqual(restored.state.rollback_detection, "none")

    def test_coherent_rollback_detected_only_with_independent_anchor(self):
        self.provision()
        backup = os.path.join(self.tmp, "backup")
        shutil.copytree(self.dir, backup)
        j = self.journal()
        j.latch_stop()
        head = j.state
        anchor = JournalAnchor(head.record_count, head.head_hash)
        shutil.rmtree(self.dir)
        shutil.copytree(backup, self.dir)
        self.assertEqual(self.journal(anchor=anchor).state.reason, "rollback_detected")

    def test_anchor_validation(self):
        for args in ((0, "a" * 64), (1, "short"), (True, "a" * 64), (65, "a" * 64)):
            with self.assertRaises(ValueError):
                JournalAnchor(*args)


class ConcurrencyTests(Base):
    def test_threads_racing_stop_and_readers(self):
        self.provision()
        instances = [self.journal() for _ in range(6)]
        barrier = threading.Barrier(len(instances) * 2)
        results, observed = [], []

        def writer(j):
            barrier.wait()
            results.append(j.latch_stop())

        def reader(j):
            barrier.wait()
            for _ in range(20):
                s = j.state
                observed.append(s)
                if s.stopped:
                    self.assertTrue(j.state.stopped)

        threads = [threading.Thread(target=f, args=(j,)) for j in instances for f in (writer, reader)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertTrue(all(r.stopped for r in results))
        self.assertEqual(sum(1 for r in results if r.durable), len(results))
        records = decode_journal(pathlib.Path(self.jpath()).read_bytes())
        self.assertEqual([r.kind for r in records], ["open", "stop"])
        self.assertFalse(any(not s.stopped and s.terminal for s in observed))

    def test_reader_never_sees_partial_state_during_commit(self):
        self.provision()
        j = self.journal()
        done = threading.Event()
        bad = []

        def read():
            while not done.is_set():
                fresh = self.journal()
                s = fresh.state
                if s.reason not in ("not_stopped", "stopped", "lock_unavailable"):
                    bad.append(s)
                fresh.close()

        t = threading.Thread(target=read)
        t.start()
        j.latch_stop()
        done.set()
        t.join()
        self.assertEqual(bad, [])

    def test_lock_contention_fails_closed_without_sticking(self):
        self.provision()
        j = self.journal()
        holder = os.open(self.jpath(sgj.LOCK_NAME), os.O_RDONLY)
        import fcntl
        fcntl.flock(holder, fcntl.LOCK_EX)
        try:
            with mock.patch.object(sgj, "LOCK_TIMEOUT_SECONDS", 0.05):
                self.assertEqual(j.state.reason, "lock_unavailable")
                self.assertTrue(j.state.stopped)
        finally:
            fcntl.flock(holder, fcntl.LOCK_UN)
            os.close(holder)
        self.assertFalse(j.state.stopped)

    def test_writer_under_contention_fails_closed(self):
        self.provision()
        j = self.journal()
        holder = os.open(self.jpath(sgj.LOCK_NAME), os.O_RDONLY)
        import fcntl
        fcntl.flock(holder, fcntl.LOCK_EX)
        try:
            with mock.patch.object(sgj, "LOCK_TIMEOUT_SECONDS", 0.05):
                outcome = j.latch_stop()
        finally:
            fcntl.flock(holder, fcntl.LOCK_UN)
            os.close(holder)
        self.assertTrue(outcome.stopped)
        self.assertFalse(outcome.durable)
        self.assertTrue(j.state.stopped)

    def test_multiprocess_writers_and_readers(self):
        self.provision()
        ctx = multiprocessing.get_context("fork")
        queue = ctx.Queue()
        pub = _pub(self.key)

        def work(role):
            j = StopGenerationJournal(
                self.dir, authority_id=AUTHORITY, trust_domain=DOMAIN,
                trusted_public_keys={KEY_ID: pub},
            )
            if role == "w":
                queue.put(("w", j.latch_stop().stopped))
            else:
                queue.put(("r", j.state.stopped or j.state.generation == 1))
            j.close()

        procs = [ctx.Process(target=work, args=(r,)) for r in "wrwrwr"]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
        self.assertTrue(all(p.exitcode == 0 for p in procs))
        self.assertTrue(all(queue.get(timeout=5)[1] for _ in procs))
        records = decode_journal(pathlib.Path(self.jpath()).read_bytes())
        self.assertEqual([r.kind for r in records], ["open", "stop"])


class StaticSurfaceTests(unittest.TestCase):
    source = MODULE_PATH.read_text()
    tree = ast.parse(source)

    def test_no_reopening_api_names(self):
        banned = {"arm", "reset", "clear", "unstop", "reopen", "resume", "reactivate", "rearm", "disarm"}
        names = set()
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                names.add(node.name)
        for public in (n for n in dir(sgj) if not n.startswith("_")):
            names.add(public)
        for cls in (sgj.StopGenerationJournal, sgj.JournalState, sgj.StopOutcome):
            names.update(n for n in dir(cls) if not n.startswith("__"))
        for name in names:
            tokens = set(re.split(r"_+", name.lower().lstrip("_")))
            self.assertFalse(tokens & banned, name)

    def test_public_methods_are_exactly_reviewed_set(self):
        public = {n for n in dir(sgj.StopGenerationJournal) if not n.startswith("_")}
        self.assertEqual(public, {"close", "latch_stop", "state"})

    def test_no_signing_authority(self):
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ImportFrom):
                imported.update(f"{node.module}.{a.name}" for a in node.names)
            elif isinstance(node, ast.Import):
                imported.update(a.name for a in node.names)
        crypto = {i for i in imported if i.startswith("cryptography")}
        self.assertEqual(crypto, {
            "cryptography.exceptions.InvalidSignature",
            "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey",
        })
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Attribute):
                self.assertNotIn(node.attr, {"sign", "private_bytes", "generate", "from_private_bytes"})
                self.assertNotIn("private_key", node.attr.lower())
            if isinstance(node, ast.Name):
                self.assertNotIn("PrivateKey", node.id)

    def test_no_network_subprocess_or_wiring_imports(self):
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", None) or ""
                names = [module] + [a.name for a in node.names]
                for n in names:
                    for banned in ("socket", "subprocess", "gvai", "requests", "http", "urllib", "systemd"):
                        self.assertFalse(n == banned or n.startswith(banned + "."), n)

    def test_no_other_module_imports_journal(self):
        for path in ROOT.glob("gvai/**/*.py"):
            if path == MODULE_PATH:
                continue
            self.assertNotIn("stop_generation_journal", path.read_text(), str(path))

    def test_state_objects_are_frozen(self):
        state = sgj.JournalState(True, None, "x")
        with self.assertRaises(Exception):
            state.stopped = False

    def test_journal_files_are_private_when_written(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        key = Ed25519PrivateKey.generate()
        os.chmod(tmp, 0o700)
        pathlib.Path(tmp, sgj.LOCK_NAME).touch(mode=0o600)
        os.chmod(pathlib.Path(tmp, sgj.LOCK_NAME), 0o600)
        pathlib.Path(tmp, sgj.JOURNAL_NAME).write_bytes(encode_journal((_open(key, 1, 0, sgj.GENESIS_HASH),)))
        os.chmod(pathlib.Path(tmp, sgj.JOURNAL_NAME), 0o600)
        j = StopGenerationJournal(tmp, authority_id=AUTHORITY, trust_domain=DOMAIN,
                                  trusted_public_keys={KEY_ID: _pub(key)})
        j.latch_stop()
        j.close()
        mode = stat.S_IMODE(os.stat(os.path.join(tmp, sgj.JOURNAL_NAME)).st_mode)
        self.assertEqual(mode, 0o600)


if __name__ == "__main__":
    unittest.main()
