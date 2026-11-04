import copy
import hashlib
import threading
import unittest
from datetime import date
from concurrent.futures import ThreadPoolExecutor

from gvai.commercial_api_keys import (
    API_KEY_PREFIX,
    CustomerApiKeys,
    InMemoryApiKeyStore,
    api_key_credential_material,
)
from gvai.commercial_identity import CommercialCapability
from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    CommitState,
    EvidenceClass,
    GENESIS_HASH,
    ReservationEvent,
    ReservationStatus,
    CanonicalReservationRequest,
)
from gvai.postgresql_reservation_authority import PostgreSQLReservationAuthority


_AUTHORITY = AuthorityIdentity("authority-test", 1, "test-domain")
_VERIFIER_SECRET = b"isolated-test-verifier-secret-32-bytes"
_CREDENTIAL = API_KEY_PREFIX + "a" * 32 + "_" + "b" * 64


class _FakeDatabase:
    def __init__(self):
        key_id, verifier = api_key_credential_material(_CREDENTIAL, _VERIFIER_SECRET)
        self.lock = threading.RLock()
        self.fail_statement = None
        self.unknown_commit_once = False
        self.rollback_ack_lost_once = False
        self.queries = []
        self.query_parameters = []
        self.state = {
            "credentials": {
                key_id: {
                    "tenant_ref": 1,
                    "membership_ref": 1,
                    "principal_id": "principal-a",
                    "verifier": verifier,
                    "status": "active",
                    "revoked_at": None,
                    "created_before_now": True,
                    "not_expired": True,
                    "can_evaluate": True,
                }
            },
            "schema_version": (1, "001_reservation_authority_v1"),
            "tenants": {1: ("tenant-a", "active")},
            "memberships": {1: ("principal-a", "active")},
            "resources": {
                "resource-a": (1, 1, "evaluation", "active"),
                "resource-b": (2, 1, "evaluation", "active"),
            },
            "policy": ("policy-7", 2),
            "authority": (
                _AUTHORITY.authority_id,
                _AUTHORITY.epoch,
                _AUTHORITY.trust_domain,
                0,
                GENESIS_HASH,
            ),
            "buckets": {},
            "events": {},
            "idempotency": {},
        }

    def connect(self):
        return _FakeConnection(self)

    def reserve_v1(self, parameters):
        (
            key_id,
            candidate_verifier,
            expected_authority_id,
            expected_epoch,
            expected_trust_domain,
            request_id,
            resource_id,
            payload_digest,
        ) = parameters
        state = self.state
        credential = state["credentials"].get(key_id)
        if (
            credential is None
            or candidate_verifier != credential["verifier"]
            or credential["status"] != "active"
            or credential["revoked_at"] is not None
            or credential["created_before_now"] is not True
            or credential["not_expired"] is not True
            or credential["can_evaluate"] is not True
        ):
            return self._decision(ReservationStatus.UNAUTHORIZED)

        tenant_ref = credential["tenant_ref"]
        membership_ref = credential["membership_ref"]
        tenant = state["tenants"].get(tenant_ref)
        membership = state["memberships"].get(membership_ref)
        if tenant is None or tenant[1] != "active" or membership is None or membership[1] != "active":
            return self._decision(ReservationStatus.UNAUTHORIZED)

        ownership = state["resources"].get(resource_id)
        if (
            ownership is None
            or ownership[1] != tenant_ref
            or ownership[2] != "evaluation"
            or ownership[3] != "active"
        ):
            return self._decision(ReservationStatus.UNAUTHORIZED)

        head = state["authority"]
        if head[:3] != (
            expected_authority_id,
            expected_epoch,
            expected_trust_domain,
        ):
            return self._decision(ReservationStatus.UNAUTHORIZED)

        request = CanonicalReservationRequest(request_id, resource_id, payload_digest)
        request_id_digest = self._digest(request_id)
        resource_digest = self._digest(resource_id)
        idempotency_key = (head[0], tenant_ref, request_id_digest)
        existing = state["idempotency"].get(idempotency_key)
        if existing is not None:
            if existing[:2] != (request.request_digest, resource_digest):
                return self._decision(ReservationStatus.CONFLICT)
            row = state["events"].get(existing[2])
            if row is None or self._event(row).event_hash != row[6]:
                raise RuntimeError("Stored event hash mismatch")
            return (ReservationStatus.REPLAY.value,) + row

        policy_version, allowance = state["policy"]
        period_start = date(2026, 10, 1)
        bucket_key = (tenant_ref, period_start)
        bucket = state["buckets"].setdefault(
            bucket_key, (policy_version, allowance, 0)
        )
        if bucket[:2] != (policy_version, allowance):
            return self._decision(ReservationStatus.AUTHORITY_UNAVAILABLE)
        if bucket[2] >= allowance:
            return self._decision(ReservationStatus.QUOTA_EXCEEDED)

        sequence = head[3] + 1
        event = ReservationEvent(
            authority=_AUTHORITY,
            sequence=sequence,
            event_id="test-event-%08d" % sequence,
            previous_event_hash=head[4],
            tenant_digest=self._digest(tenant[0]),
            principal_digest=self._digest(membership[0]),
            resource_digest=resource_digest,
            request_id_digest=request_id_digest,
            request_digest=request.request_digest,
            period="2026-10",
            policy_version=policy_version,
        )
        row = self._event_row(event, period_start)
        state["buckets"][bucket_key] = (bucket[0], bucket[1], bucket[2] + 1)
        state["events"][event.event_id] = row
        if self.fail_statement == "after_event_insert":
            raise OSError("simulated routine failure after event trigger")
        state["idempotency"][idempotency_key] = (
            event.request_digest, event.resource_digest, event.event_id
        )
        state["authority"] = (
            head[0], head[1], head[2], event.sequence, event.event_hash
        )
        return (ReservationStatus.RESERVED.value,) + row

    @staticmethod
    def _digest(value):
        return hashlib.sha256(value.encode("ascii")).hexdigest()

    @staticmethod
    def _event_row(event, period_start):
        return (
            event.authority.authority_id,
            event.authority.epoch,
            event.authority.trust_domain,
            event.sequence,
            event.event_id,
            event.previous_event_hash,
            event.event_hash,
            event.tenant_digest,
            event.principal_digest,
            event.resource_digest,
            event.request_id_digest,
            event.request_digest,
            period_start,
            event.policy_version,
            event.units,
            event.version,
        )

    @staticmethod
    def _event(row):
        (
            authority_id, epoch, trust_domain, sequence, event_id,
            previous_event_hash, event_hash, tenant_digest, principal_digest,
            resource_digest, request_id_digest, request_digest, period_start,
            policy_version, units, version,
        ) = row
        return ReservationEvent(
            authority=AuthorityIdentity(authority_id, epoch, trust_domain),
            sequence=sequence,
            event_id=event_id,
            previous_event_hash=previous_event_hash,
            tenant_digest=tenant_digest,
            principal_digest=principal_digest,
            resource_digest=resource_digest,
            request_id_digest=request_id_digest,
            request_digest=request_digest,
            period=period_start.strftime("%Y-%m"),
            policy_version=policy_version,
            units=units,
            version=version,
        )

    @staticmethod
    def _decision(status):
        return (status.value,) + (None,) * 16


class _FakeConnection:
    def __init__(self, database):
        self.database = database
        self.autocommit = True
        self.transaction_snapshot = None
        self.closed = False

    def cursor(self):
        return _FakeCursor(self)

    def _begin(self):
        if self.transaction_snapshot is None:
            self.database.lock.acquire()
            self.transaction_snapshot = copy.deepcopy(self.database.state)

    def commit(self):
        if self.transaction_snapshot is None:
            raise AssertionError("commit without a transaction")
        self.transaction_snapshot = None
        self.database.lock.release()
        if self.database.unknown_commit_once:
            self.database.unknown_commit_once = False
            raise OSError("simulated lost commit acknowledgement")

    def rollback(self):
        if self.transaction_snapshot is not None:
            self.database.state = self.transaction_snapshot
            self.transaction_snapshot = None
            self.database.lock.release()
            if self.database.rollback_ack_lost_once:
                self.database.rollback_ack_lost_once = False
                raise OSError("simulated lost rollback acknowledgement")

    def close(self):
        self.rollback()
        self.closed = True


class _FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.row = None
        self.rowcount = -1

    def execute(self, query, parameters=None):
        self.connection._begin()
        sql = " ".join(query.lower().split())
        parameters = parameters or ()
        self.connection.database.queries.append(sql)
        self.connection.database.query_parameters.append(parameters)
        self.rowcount = -1
        if not sql.startswith("select * from gvai_authority.reserve_v1("):
            raise PermissionError("restricted runtime may only execute reserve_v1")
        self.row = self.connection.database.reserve_v1(parameters)

    def fetchone(self):
        return self.row

    def close(self):
        pass


class PostgreSQLReservationAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.database = _FakeDatabase()
        self.authority = PostgreSQLReservationAuthority(
            self.database.connect,
            authority=_AUTHORITY,
            credential_verifier_secret=_VERIFIER_SECRET,
        )

    @staticmethod
    def request(request_id="request-1", resource_id="resource-a", payload=b"bounded input"):
        return CanonicalReservationRequest.from_bounded_input(
            request_id, resource_id, payload
        )

    def test_shared_verifier_matches_existing_customer_api_key_records(self):
        store = InMemoryApiKeyStore()
        key_manager = CustomerApiKeys(
            store, verifier_secret=_VERIFIER_SECRET, clock=lambda: 1000
        )
        issued = key_manager.issue(
            principal_id="principal-a",
            tenant_id="tenant-a",
            capabilities=frozenset({CommercialCapability.EVALUATE}),
            expires_at=2000,
        )
        credential = issued.take_secret()
        material = api_key_credential_material(credential, _VERIFIER_SECRET)
        self.assertEqual(material[0], issued.key_id)
        self.assertEqual(material[1], store.lookup(issued.key_id).verifier)

    def test_fresh_reservation_commits_before_returning_unauthenticated_receipt(self):
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.RESERVED)
        self.assertEqual(result.commit_state, CommitState.COMMITTED)
        self.assertEqual(result.receipt.evidence_class, EvidenceClass.UNAUTHENTICATED)
        self.assertIsNone(result.receipt.signature)
        self.assertEqual(len(self.database.state["events"]), 1)
        self.assertEqual(self.database.state["authority"][3], 1)
        canonical_event = result.receipt.event.canonical_bytes()
        self.assertNotIn(_CREDENTIAL.encode("ascii"), canonical_event)
        self.assertNotIn(b"bounded input", canonical_event)

    def test_authority_identity_mismatch_fails_closed(self):
        self.database.state["authority"] = (
            "other-authority", 2, "other-domain", 0, GENESIS_HASH
        )
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.UNAUTHORIZED)
        self.assertEqual(result.commit_state, CommitState.NOT_COMMITTED)
        self.assertEqual(self.database.state["events"], {})

    def test_runtime_cannot_write_protected_tables_directly(self):
        connection = self.database.connect()
        cursor = connection.cursor()
        with self.assertRaises(PermissionError):
            cursor.execute(
                "INSERT INTO gvai_authority.reservation_events (event_id) VALUES (%s)",
                ("forbidden",),
            )
        connection.rollback()
        self.assertEqual(self.database.state["events"], {})

    def test_adapter_uses_only_the_restricted_routine(self):
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.RESERVED)
        self.assertEqual(len(self.database.queries), 1)
        self.assertIn("gvai_authority.reserve_v1", self.database.queries[0])
        self.assertNotIn("insert into", self.database.queries[0])
        self.assertNotIn("update gvai_authority", self.database.queries[0])
        parameters = self.database.query_parameters[0]
        self.assertNotIn(_CREDENTIAL, parameters)
        self.assertNotIn(b"bounded input", parameters)
        self.assertEqual(parameters[-1], self.request().payload_digest)

    def test_exact_replay_returns_existing_event_without_another_unit(self):
        first = self.authority.reserve(self.request(), _CREDENTIAL)
        replay = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(first.status, ReservationStatus.RESERVED)
        self.assertEqual(replay.status, ReservationStatus.REPLAY)
        self.assertEqual(first.receipt.event.event_id, replay.receipt.event.event_id)
        self.assertEqual(self.database.state["authority"][3], 1)
        self.assertEqual(next(iter(self.database.state["buckets"].values()))[2], 1)

    def test_changed_request_under_same_id_conflicts(self):
        self.authority.reserve(self.request(), _CREDENTIAL)
        for request in (
            self.request(payload=b"different bounded input"),
            self.request(resource_id="resource-b"),
        ):
            with self.subTest(request=request):
                result = self.authority.reserve(request, _CREDENTIAL)
                self.assertEqual(result.status, ReservationStatus.CONFLICT)
        self.assertEqual(self.database.state["authority"][3], 1)

    def test_revoked_and_expired_credentials_are_denied(self):
        record = next(iter(self.database.state["credentials"].values()))
        for update in (
            {"status": "revoked", "revoked_at": date(2026, 10, 1)},
            {"not_expired": False},
        ):
            with self.subTest(update=update):
                original = record.copy()
                record.update(update)
                result = self.authority.reserve(self.request(), _CREDENTIAL)
                self.assertEqual(result.status, ReservationStatus.UNAUTHORIZED)
                record.clear()
                record.update(original)

    def test_disabled_tenant_and_foreign_resource_are_denied(self):
        self.database.state["tenants"][1] = ("tenant-a", "disabled")
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.UNAUTHORIZED)
        self.database.state["tenants"][1] = ("tenant-a", "active")
        self.database.state["resources"]["resource-a"] = (
            1, 2, "evaluation", "active"
        )
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.UNAUTHORIZED)

    def test_quota_exhaustion_denies_without_advancing_head(self):
        self.database.state["policy"] = ("policy-zero", 0)
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.QUOTA_EXCEEDED)
        self.assertEqual(self.database.state["authority"][3], 0)
        self.assertEqual(self.database.state["events"], {})

    def test_concurrent_requests_cannot_overspend_last_quota_unit(self):
        self.database.state["policy"] = ("policy-one", 1)
        requests = [self.request("request-a"), self.request("request-b")]
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda request: self.authority.reserve(request, _CREDENTIAL), requests
            ))
        statuses = sorted(result.status.value for result in results)
        self.assertEqual(statuses, ["quota_exceeded", "reserved"])
        self.assertEqual(self.database.state["authority"][3], 1)

    def test_insert_failure_rolls_back_event_quota_idempotency_and_head(self):
        self.database.fail_statement = "after_event_insert"
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.AUTHORITY_UNAVAILABLE)
        self.assertEqual(result.commit_state, CommitState.NOT_COMMITTED)
        self.assertEqual(self.database.state["events"], {})
        self.assertEqual(self.database.state["idempotency"], {})
        self.assertEqual(self.database.state["buckets"], {})
        self.assertEqual(self.database.state["authority"][3], 0)

    def test_lost_commit_ack_is_unknown_and_same_key_retry_is_replay(self):
        self.database.unknown_commit_once = True
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.AUTHORITY_UNAVAILABLE)
        self.assertEqual(result.commit_state, CommitState.UNKNOWN)
        retry = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(retry.status, ReservationStatus.REPLAY)
        self.assertEqual(self.database.state["authority"][3], 1)

    def test_lost_rollback_ack_is_unknown_and_same_key_retry_is_safe(self):
        self.database.fail_statement = "after_event_insert"
        self.database.rollback_ack_lost_once = True
        result = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(result.status, ReservationStatus.AUTHORITY_UNAVAILABLE)
        self.assertEqual(result.commit_state, CommitState.UNKNOWN)
        self.assertEqual(self.database.state["events"], {})
        self.database.fail_statement = None
        retry = self.authority.reserve(self.request(), _CREDENTIAL)
        self.assertEqual(retry.status, ReservationStatus.RESERVED)
        self.assertEqual(self.database.state["authority"][3], 1)

    def test_canonical_event_hash_and_authority_head_chain_are_continuous(self):
        first = self.authority.reserve(self.request("request-a"), _CREDENTIAL)
        second = self.authority.reserve(self.request("request-b"), _CREDENTIAL)
        events = sorted(
            (result.receipt.event for result in (first, second)),
            key=lambda event: event.sequence,
        )
        self.assertEqual([event.sequence for event in events], [1, 2])
        self.assertEqual(events[0].previous_event_hash, GENESIS_HASH)
        self.assertEqual(events[1].previous_event_hash, events[0].event_hash)
        for event in events:
            self.assertEqual(
                event.event_hash,
                self.database.state["events"][event.event_id][6],
            )
        self.assertEqual(self.database.state["authority"][4], events[1].event_hash)


if __name__ == "__main__":
    unittest.main()
