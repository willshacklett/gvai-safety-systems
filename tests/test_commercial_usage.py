import math
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch

from gvai.commercial_api_keys import CustomerApiKeys, InMemoryApiKeyStore
from gvai.commercial_identity import (
    CommercialAuthorizer,
    CommercialCapability as Capability,
    CommercialResourceKind as Kind,
    CommercialResourceOwnership as Ownership,
    VerifiedCustomerIdentity,
)
from gvai.commercial_usage import (
    CommercialUsage,
    InMemoryUsageStore,
    MAX_EVALUATION_UNITS,
    ReservationState,
    UsageReason as Reason,
    UsageResult,
)


def timestamp(year, month, day=1):
    return datetime(year, month, day, tzinfo=timezone.utc).timestamp()


class UsageTests(unittest.TestCase):
    def setUp(self):
        self.now = timestamp(2026, 10)
        self.identities = {
            tenant: VerifiedCustomerIdentity(
                "customer-" + tenant, tenant, frozenset(Capability),
                int(timestamp(2030, 1)),
            )
            for tenant in ("tenant-a", "tenant-b")
        }
        self.resources = {
            tenant + suffix: Ownership(tenant + suffix, tenant, kind)
            for tenant in self.identities
            for suffix, kind in (("-project", Kind.EVALUATION), ("-other", Kind.EVALUATION), ("-usage", Kind.USAGE))
        }
        self.verifier = type("Verifier", (), {})()
        self.verifier.verify = self.identities.get
        self.ownership = type("OwnershipStore", (), {})()
        self.ownership.lookup = self.resources.get
        self.authorizer = CommercialAuthorizer(self.verifier, self.ownership, clock=lambda: self.now)
        self.store = InMemoryUsageStore({"tenant-a": 2, "tenant-b": 1}, clock=lambda: self.now)
        self.usage = CommercialUsage(self.authorizer, self.store)

    def reserve(self, key="request-1", tenant="tenant-a"):
        return self.usage.reserve(tenant, tenant + "-project", key)

    def summary(self, tenant="tenant-a"):
        return self.usage.summary(tenant, tenant + "-usage")

    def complete(self, succeeded=True, key="request-1"):
        return self.usage.complete("tenant-a", "tenant-a-project", key, succeeded=succeeded)

    def test_exact_quota_boundary_and_no_refunds(self):
        self.assertEqual(self.reserve().reason, Reason.RESERVED)
        self.assertEqual(self.complete(False).reason, Reason.FAILED)
        self.assertEqual(self.reserve("request-2").reason, Reason.RESERVED)
        self.assertEqual(self.complete(True, "request-2").reason, Reason.COMPLETED)
        self.assertEqual(self.reserve("request-3").reason, Reason.QUOTA_EXHAUSTED)
        summary = self.summary().summary
        self.assertEqual((summary.consumed, summary.remaining, summary.failed, summary.completed), (2, 0, 1, 1))

    def test_simultaneous_distinct_reservations_share_one_atomic_allowance(self):
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda number: self.reserve("request-" + str(number)), range(100)))
        self.assertEqual(sum(result.may_evaluate for result in results), 2)
        self.assertEqual(sum(result.reason is Reason.QUOTA_EXHAUSTED for result in results), 98)
        self.assertEqual(self.summary().summary.consumed, 2)

    def test_simultaneous_duplicates_grant_exactly_one_execution(self):
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: self.reserve(), range(100)))
        self.assertEqual(sum(result.may_evaluate for result in results), 1)
        self.assertEqual(sum(result.reason is Reason.REPLAY for result in results), 99)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_multiple_facades_share_the_same_quota_and_retry_scope(self):
        usages = [CommercialUsage(self.authorizer, self.store) for _ in range(10)]
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(lambda usage: usage.reserve("tenant-a", "tenant-a-project", "same"), usages))
        self.assertEqual(sum(result.may_evaluate for result in results), 1)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_racing_completions_are_monotonic_and_never_refund(self):
        self.reserve()
        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(self.complete, [True, False] * 25))
        terminal = [result for result in results if result.reason in (Reason.COMPLETED, Reason.FAILED)]
        self.assertEqual(len(terminal), 1)
        self.assertEqual(self.summary().summary.consumed, 1)
        self.assertEqual(self.summary().summary.reserved, 0)

    def test_retry_completion_and_conflicting_terminal_states(self):
        self.assertEqual(self.complete().reason, Reason.NOT_FOUND)
        self.reserve()
        self.assertEqual(self.reserve().reason, Reason.REPLAY)
        self.assertEqual(self.complete().reason, Reason.COMPLETED)
        self.assertEqual(self.complete().reason, Reason.REPLAY)
        self.assertEqual(self.complete(False).reason, Reason.CONFLICT)
        self.assertEqual(self.reserve().reservation.state, ReservationState.COMPLETED)
        self.assertFalse(self.reserve().may_evaluate)

    def test_failed_reservation_is_not_a_free_retry(self):
        self.reserve()
        self.complete(False)
        self.assertEqual(self.complete(False).reason, Reason.REPLAY)
        self.assertEqual(self.complete(True).reason, Reason.CONFLICT)
        replay = self.reserve()
        self.assertEqual(replay.reservation.state, ReservationState.FAILED)
        self.assertFalse(replay.may_evaluate)

    def test_tenant_wide_key_conflict_cannot_bypass_via_other_resource(self):
        self.reserve()
        conflict = self.usage.reserve("tenant-a", "tenant-a-other", "request-1")
        self.assertEqual(conflict.reason, Reason.CONFLICT)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_same_id_is_independent_across_tenants(self):
        self.assertTrue(self.reserve().may_evaluate)
        self.assertTrue(self.reserve(tenant="tenant-b").may_evaluate)
        self.assertEqual(self.summary("tenant-b").summary.consumed, 1)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_cross_tenant_access_denies_without_accounting(self):
        with patch.object(self.store, "_apply", side_effect=AssertionError("must not access")) as apply:
            results = [
                self.usage.reserve("tenant-a", "tenant-b-project", "request-1"),
                self.usage.complete("tenant-a", "tenant-b-project", "request-1", succeeded=True),
                self.usage.summary("tenant-a", "tenant-b-usage"),
            ]
        self.assertTrue(all(result.reason is Reason.UNAUTHORIZED for result in results))
        apply.assert_not_called()

    def test_forged_claims_and_wrong_resource_kinds(self):
        for credential in (None, {}, {"tenant_id": "tenant-a", "quota": 9999, "paid": True}, self.identities["tenant-a"]):
            with self.subTest(credential=credential):
                self.assertEqual(self.usage.reserve(credential, "tenant-a-project", "req").reason, Reason.UNAUTHORIZED)
        self.assertEqual(self.usage.summary("tenant-a", "tenant-a-project").reason, Reason.UNAUTHORIZED)
        self.assertEqual(self.usage.reserve("tenant-a", "tenant-a-usage", "req").reason, Reason.UNAUTHORIZED)
        with self.assertRaises(TypeError):
            self.usage.reserve("tenant-a", "tenant-a-project", "req", tenant_id="tenant-b", quota=999)
        self.assertEqual(self.summary().summary.consumed, 0)

    def test_missing_capability_revocation_and_ownership_changes_are_rechecked(self):
        self.reserve()
        identity = self.identities["tenant-a"]
        self.identities["tenant-a"] = replace(identity, capabilities=frozenset({Capability.EVALUATE}))
        self.assertEqual(self.summary().reason, Reason.UNAUTHORIZED)
        self.identities["tenant-a"] = replace(identity, revoked=True)
        self.assertEqual(self.reserve().reason, Reason.UNAUTHORIZED)
        self.assertEqual(self.complete().reason, Reason.UNAUTHORIZED)
        self.identities["tenant-a"] = identity
        self.resources["tenant-a-project"] = Ownership("tenant-a-project", "tenant-b", Kind.EVALUATION)
        self.assertEqual(self.reserve().reason, Reason.UNAUTHORIZED)

    def test_missing_and_zero_policy_default_deny(self):
        for policies, reason in (({}, Reason.POLICY_MISSING), ({"tenant-a": 0}, Reason.QUOTA_EXHAUSTED)):
            usage = CommercialUsage(self.authorizer, InMemoryUsageStore(policies, clock=lambda: self.now))
            self.assertEqual(usage.reserve("tenant-a", "tenant-a-project", "req").reason, reason)

    def test_policy_is_copied_and_never_derived_from_price(self):
        policies = {"tenant-a": 1}
        store = InMemoryUsageStore(policies, clock=lambda: self.now)
        policies["tenant-a"] = 999
        usage = CommercialUsage(self.authorizer, store)
        self.assertTrue(usage.reserve("tenant-a", "tenant-a-project", "one").may_evaluate)
        self.assertEqual(usage.reserve("tenant-a", "tenant-a-project", "two").reason, Reason.QUOTA_EXHAUSTED)

    def test_monthly_utc_boundary_and_lifetime_replay(self):
        self.now = timestamp(2026, 11) - 0.001
        self.assertEqual(self.reserve().reservation.period, "2026-10")
        self.now = timestamp(2026, 11)
        self.assertEqual(self.summary().summary.consumed, 0)
        replay = self.reserve()
        self.assertEqual(replay.reason, Reason.REPLAY)
        self.assertEqual(replay.reservation.period, "2026-10")
        self.assertEqual(self.complete().reason, Reason.COMPLETED)
        self.assertEqual(self.summary().summary.consumed, 0)
        self.assertEqual(self.reserve("new").reservation.period, "2026-11")

    def test_adjacent_floats_select_exact_utc_month(self):
        for boundary, previous, following in (
            (timestamp(2026, 11), "2026-10", "2026-11"),
            (timestamp(2027, 1), "2026-12", "2027-01"),
            (timestamp(2028, 3), "2028-02", "2028-03"),
        ):
            for now, expected in (
                (math.nextafter(boundary, -math.inf), previous),
                (boundary, following),
                (math.nextafter(boundary, math.inf), following),
            ):
                with self.subTest(boundary=boundary, now=now):
                    self.now = now
                    store = InMemoryUsageStore({"tenant-a": 2}, clock=lambda: self.now)
                    usage = CommercialUsage(self.authorizer, store)
                    result = usage.reserve("tenant-a", "tenant-a-project", "request")
                    self.assertTrue(result.may_evaluate)
                    self.assertEqual(result.reservation.period, expected)
                    summary = usage.summary("tenant-a", "tenant-a-usage").summary
                    self.assertEqual(summary.period, expected)
                    self.assertEqual(summary.consumed, 1)

    def test_exhausted_quota_opens_only_at_exact_boundary_and_replays_stay_closed(self):
        boundary = timestamp(2026, 11)
        self.now = math.nextafter(boundary, -math.inf)
        self.assertTrue(self.reserve().may_evaluate)
        self.assertTrue(self.reserve("old-second").may_evaluate)
        denied = self.reserve("fresh")
        self.assertEqual(denied.reason, Reason.QUOTA_EXHAUSTED)
        self.assertFalse(denied.may_evaluate)
        self.assertFalse(bool(denied))
        self.assertEqual(self.summary().summary.period, "2026-10")
        self.assertEqual(self.summary().summary.remaining, 0)

        self.now = boundary
        self.assertEqual(self.summary().summary.consumed, 0)
        replay = self.reserve()
        self.assertEqual(replay.reason, Reason.REPLAY)
        self.assertEqual(replay.reservation.period, "2026-10")
        self.assertFalse(replay.may_evaluate)
        self.assertFalse(bool(replay))
        fresh = self.reserve("fresh")
        self.assertTrue(fresh.may_evaluate)
        self.assertEqual(fresh.reservation.period, "2026-11")

        self.now = math.nextafter(boundary, math.inf)
        self.assertTrue(self.reserve("after").may_evaluate)
        replay = self.reserve("fresh")
        self.assertEqual(replay.reason, Reason.REPLAY)
        self.assertFalse(replay.may_evaluate)
        self.assertFalse(bool(replay))
        self.assertEqual(self.summary().summary.consumed, 2)
        denied = self.reserve("exhausted-again")
        self.assertEqual(denied.reason, Reason.QUOTA_EXHAUSTED)
        self.assertFalse(denied.may_evaluate)
        self.assertFalse(bool(denied))

    def test_adjacent_float_rollback_across_boundary_never_reopens_quota(self):
        boundary = timestamp(2026, 11)
        before = math.nextafter(boundary, -math.inf)
        after = math.nextafter(boundary, math.inf)
        self.now = before
        self.reserve()
        self.now = boundary
        self.assertTrue(self.reserve("new-month").may_evaluate)
        self.now = after
        self.summary()

        for now in (before, boundary):
            self.now = now
            for operation in (self.reserve, self.summary, self.complete):
                with self.subTest(now=now, operation=operation.__name__):
                    result = operation()
                    self.assertEqual(result.reason, Reason.CLOCK_ROLLBACK)
                    self.assertFalse(result.may_evaluate)
                    self.assertFalse(bool(result))

        self.now = after
        replay = self.reserve()
        self.assertEqual(replay.reason, Reason.REPLAY)
        self.assertEqual(replay.reservation.period, "2026-10")
        self.assertFalse(replay.may_evaluate)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_december_rollover_and_leap_day(self):
        for before, after in ((timestamp(2026, 12, 31), timestamp(2027, 1)), (timestamp(2028, 2, 29), timestamp(2028, 3))):
            self.now = before
            key = str(int(before))
            old_period = self.reserve(key).reservation.period
            self.now = after
            summary = self.summary().summary
            self.assertNotEqual(summary.period, old_period)
            self.assertEqual(summary.consumed, 0)

    def test_clock_rollback_in_same_month_and_across_rollover_denies(self):
        self.reserve()
        for operation in (self.reserve, self.summary, self.complete):
            self.now -= 1
            self.assertEqual(operation().reason, Reason.CLOCK_ROLLBACK)
            self.now += 1
        self.now = timestamp(2026, 11)
        self.summary()
        self.now -= 0.001
        self.assertEqual(self.reserve("new").reason, Reason.CLOCK_ROLLBACK)
        self.now = timestamp(2026, 11)
        self.assertEqual(self.reserve().reason, Reason.REPLAY)

    def test_denial_also_advances_clock_high_water(self):
        self.reserve()
        self.reserve("two")
        self.now += 10
        self.assertEqual(self.reserve("three").reason, Reason.QUOTA_EXHAUSTED)
        self.now -= 1
        self.assertEqual(self.summary().reason, Reason.CLOCK_ROLLBACK)

    def test_bad_store_clocks_fail_closed_without_records(self):
        for now in (True, None, "1000", -1, float("nan"), float("inf"), 10**100, timestamp(9999, 1)):
            with self.subTest(now=now):
                with patch.object(self.store, "_clock", return_value=now):
                    self.assertEqual(self.reserve().reason, Reason.ACCOUNTING_ERROR)
        self.assertEqual(self.summary().summary.consumed, 0)

    def test_malformed_policy_is_rejected(self):
        for value in (True, -1, 1.5, "99", None, MAX_EVALUATION_UNITS + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                InMemoryUsageStore({"tenant-a": value})
        for tenant in ("", "gvai-internal", None):
            with self.subTest(tenant=tenant), self.assertRaises(ValueError):
                InMemoryUsageStore({tenant: 1})

    def test_malformed_requests_do_not_consume(self):
        for key in (None, "", {}, True, "x" * 129, "../bad", "non-ascii-\u00e9"):
            with self.subTest(key=key):
                self.assertEqual(self.reserve(key).reason, Reason.INVALID_INPUT)
        self.assertEqual(self.complete(1).reason, Reason.INVALID_INPUT)
        self.assertEqual(self.summary().summary.consumed, 0)

    def test_signed_64_bit_boundary_and_corrupt_counts_fail_closed(self):
        self.store = InMemoryUsageStore({"tenant-a": MAX_EVALUATION_UNITS}, clock=lambda: self.now)
        self.usage = CommercialUsage(self.authorizer, self.store)
        self.reserve()
        ledger = self.store._ledgers["tenant-a"]
        for count in (-1, True, MAX_EVALUATION_UNITS + 1):
            self.store._ledgers["tenant-a"] = replace(ledger, counts={"2026-10": count})
            self.assertEqual(self.reserve("new").reason, Reason.ACCOUNTING_ERROR)
        self.store._ledgers["tenant-a"] = replace(ledger, counts={"2026-10": MAX_EVALUATION_UNITS - 1})
        self.assertTrue(self.reserve("last").may_evaluate)
        self.assertEqual(self.store._ledgers["tenant-a"].counts["2026-10"], MAX_EVALUATION_UNITS)
        self.assertEqual(self.reserve("overflow").reason, Reason.QUOTA_EXHAUSTED)

    def test_store_failure_before_write_allows_safe_retry(self):
        with patch.object(self.store, "_apply", side_effect=RuntimeError("customer-secret")):
            for result in (self.reserve(), self.summary(), self.complete()):
                self.assertEqual(result.reason, Reason.ACCOUNTING_ERROR)
                self.assertFalse(result.may_evaluate)
                self.assertNotIn("customer-secret", repr(result))
        self.assertTrue(self.reserve().may_evaluate)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_publication_failure_has_no_partial_charge_or_idempotency_record(self):
        class FailingPublication(dict):
            def __setitem__(self, key, value):
                raise MemoryError("test-only")

        with patch.object(self.store, "_ledgers", FailingPublication()):
            self.assertEqual(self.reserve().reason, Reason.ACCOUNTING_ERROR)
            self.assertEqual(len(self.store._ledgers), 0)
        self.assertTrue(self.reserve().may_evaluate)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_ambiguous_write_failure_never_reissues_permission(self):
        original = self.store._apply

        def fail_after_write(*args):
            original(*args)
            raise RuntimeError("customer-secret")

        with patch.object(self.store, "_apply", side_effect=fail_after_write):
            self.assertEqual(self.reserve().reason, Reason.ACCOUNTING_ERROR)
        self.assertEqual(self.reserve().reason, Reason.REPLAY)
        self.assertFalse(self.reserve().may_evaluate)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_completion_failure_keeps_charge_and_is_retryable(self):
        self.reserve()
        with patch.object(self.store, "_apply", side_effect=RuntimeError):
            self.assertEqual(self.complete().reason, Reason.ACCOUNTING_ERROR)
        self.assertEqual(self.complete().reason, Reason.COMPLETED)
        self.assertEqual(self.summary().summary.consumed, 1)

    def test_verifier_and_ownership_outages_never_reach_store(self):
        for dependency, attribute in ((self.verifier, "verify"), (self.ownership, "lookup")):
            with patch.object(dependency, attribute, side_effect=RuntimeError("secret")):
                with patch.object(self.store, "_apply") as apply:
                    self.assertEqual(self.reserve().reason, Reason.UNAUTHORIZED)
                    self.assertEqual(self.summary().reason, Reason.UNAUTHORIZED)
                    apply.assert_not_called()

    def test_records_contain_only_accounting_metadata(self):
        self.reserve("opaque-request-id")
        records = repr(self.store._ledgers)
        self.assertNotIn("opaque-request-id", records)
        self.assertNotIn("tenant-a-project", records)
        self.assertNotIn("telemetry", records)
        self.assertNotIn("customer-tenant-a", records)

    def test_authorizer_resolves_tenant_only_on_success_and_does_not_cache(self):
        decision = self.authorizer.authorize("tenant-a", Capability.EVALUATE, "tenant-a-project")
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.tenant_id, "tenant-a")
        self.assertNotIn("tenant-a", repr(decision))
        self.identities["tenant-a"] = replace(self.identities["tenant-a"], revoked=True)
        denied = self.authorizer.authorize("tenant-a", Capability.EVALUATE, "tenant-a-project")
        self.assertFalse(denied.allowed)
        self.assertIsNone(denied.tenant_id)
        for credential, resource in ((None, "tenant-a-project"), ({}, "tenant-a-project"), ("tenant-b", "tenant-a-project"), ("tenant-b", "unknown")):
            with self.subTest(credential=credential, resource=resource):
                self.assertIsNone(self.authorizer.authorize(credential, Capability.EVALUATE, resource).tenant_id)
        with patch.object(self.verifier, "verify", side_effect=RuntimeError):
            self.assertIsNone(self.authorizer.authorize("tenant-b", Capability.EVALUATE, "tenant-b-project").tenant_id)

    def test_results_are_explicit_and_boolean_never_grants_replays(self):
        for reason in Reason:
            result = UsageResult(reason)
            self.assertEqual(bool(result), reason is Reason.RESERVED)
            self.assertEqual(result.may_evaluate, bool(result))
        self.assertEqual(UsageResult(Reason.ACCOUNTING_ERROR).outcome, "error")
        self.assertEqual(UsageResult(Reason.QUOTA_EXHAUSTED).outcome, "denied")
        self.assertEqual(UsageResult(Reason.REPLAY).outcome, "success")

    def test_real_api_key_adapter_preserves_revocation_behavior(self):
        keys = CustomerApiKeys(InMemoryApiKeyStore(), verifier_secret=b"test-only-independent-secret-0000", clock=lambda: self.now)
        issued = keys.issue(principal_id="customer", tenant_id="tenant-a", capabilities=frozenset(Capability), expires_at=int(timestamp(2027, 1)))
        credential = issued.take_secret()
        usage = CommercialUsage(CommercialAuthorizer(keys, self.ownership, clock=lambda: self.now), self.store)
        self.assertTrue(usage.reserve(credential, "tenant-a-project", "req").may_evaluate)
        self.assertEqual(usage.summary(credential, "tenant-a-usage").summary.consumed, 1)
        keys.revoke(issued.key_id)
        self.assertEqual(usage.reserve(credential, "tenant-a-project", "req").reason, Reason.UNAUTHORIZED)
        self.assertEqual(usage.summary(credential, "tenant-a-usage").reason, Reason.UNAUTHORIZED)
        self.assertNotIn(credential, repr(self.store._ledgers))

    def test_supervisor_controls_and_evaluator_are_never_called(self):
        from gvai.effect_gate import GVEffectGate
        from gvai.effects import make_action
        from gvai.external_control import GVExternalControlPlane
        from gvai.runtime_policy import GVRuntimePolicy

        with patch("gvai.evaluation.evaluate_request", side_effect=AssertionError("no evaluation")) as evaluate:
            with patch.object(GVExternalControlPlane, "evaluate_internal_shutdown", side_effect=AssertionError("no STOP")) as stop:
                with patch.object(GVRuntimePolicy, "evaluate_command", side_effect=AssertionError("no commands")) as command:
                    self.reserve()
                    self.complete()
                    self.summary()
                    self.assertEqual(self.usage.reserve({"command_type": "shutdown"}, "tenant-a-project", "req").reason, Reason.UNAUTHORIZED)
            evaluate.assert_not_called()
            stop.assert_not_called()
            command.assert_not_called()
        action = make_action("test-only", {"low_impact"})
        self.assertTrue(GVExternalControlPlane().evaluate_internal_shutdown(action).halted)
        self.assertTrue(GVRuntimePolicy(GVEffectGate([])).evaluate_internal_shutdown(action, sentinel_status="stable").halted)
        with patch.object(self.store, "_apply", side_effect=RuntimeError("accounting unavailable")):
            self.assertEqual(self.reserve().reason, Reason.ACCOUNTING_ERROR)
            self.assertTrue(GVExternalControlPlane().evaluate_internal_shutdown(action).halted)
            self.assertTrue(GVRuntimePolicy(GVEffectGate([])).evaluate_internal_shutdown(action, sentinel_status="stable").halted)


if __name__ == "__main__":
    unittest.main()
