"""Bounded Stripe TEST-mode reconciler running as the dedicated least-privilege database role.

Authority: the reconciler can only call the audited ``reconcile_*`` functions. It never reads
or writes billing tables directly, never receives an owner credential, and only ever sends
GET requests to Stripe. Stripe is read with no database transaction or row lock held.
"""

from __future__ import annotations

from dataclasses import dataclass
import heapq
import json
import logging
import os
import threading
import time
from typing import Any, Callable

from gvai.postgresql_billing import Claim, PostgreSQLReconcilerStore
from gvai.stripe_billing import FRESH_SECONDS, BillingUnavailable, StripeAPI, SubscriptionAuthority, fail


LOG = logging.getLogger(__name__)
ACTIVE_INTERVAL_SECONDS = 20
JITTER_SECONDS = 2
CALLS_PER_FETCH = 6
LAG_WARN_SECONDS = 10.0
LAG_CRITICAL_SECONDS = 25.0
MIN_LEASE_MARGIN_SECONDS = 5.0


class BoundedStripe:
    """GET-only Stripe client with a shared request rate and a per-fetch deadline."""

    def __init__(
        self, api: StripeAPI, *, rate_per_second: float = 10.0, burst: int = 10,
        deadline_seconds: float = 25.0, clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not 0 < rate_per_second <= 25 or not 1 <= burst <= 50 or not 1 <= deadline_seconds <= 25:
            raise ValueError("Stripe test-mode request bounds are 25 requests/second and a 25s fetch deadline.")
        self.api, self.rate, self.burst = api, rate_per_second, float(burst)
        self.deadline, self.clock, self.sleep = deadline_seconds, clock, sleep
        self._tokens, self._stamp = float(burst), clock()
        self._lock = threading.Lock()
        self._local = threading.local()

    def begin_fetch(self) -> None:
        self._local.started = self.clock()

    def _take(self) -> float:
        with self._lock:
            now = self.clock()
            self._tokens = min(self.burst, self._tokens + (now - self._stamp) * self.rate)
            self._stamp = now
            if self._tokens >= 1:
                self._tokens -= 1
                return 0.0
            return (1 - self._tokens) / self.rate

    def request(
        self, method: str, path: str, parameters: dict[str, str] | None = None,
        *, idempotency_key: str | None = None,
    ) -> Any:
        if method != "GET" or idempotency_key is not None:
            raise fail("reconciler_read_only")
        started = getattr(self._local, "started", None)
        if started is None:
            started = self._local.started = self.clock()
        while True:
            if self.clock() - started >= self.deadline:
                raise fail("fetch_deadline_exceeded", transient=True)
            wait = self._take()
            if wait <= 0:
                break
            self.sleep(max(0.001, min(wait, 0.25)))
        value = self.api.request(method, path, parameters)
        if self.clock() - started > self.deadline:
            raise fail("fetch_deadline_exceeded", transient=True)
        return value


@dataclass(frozen=True)
class ReconcilerSettings:
    workers: int = 4
    claim_seconds: int = 30
    idle_seconds: float = 1.0
    heartbeat_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not 1 <= self.workers <= 16 or not 10 <= self.claim_seconds <= 55 or not 0.1 <= self.idle_seconds <= 5:
            raise ValueError("Reconciler settings out of bounds.")


def capacity_report(
    tenants: int, *, rate_per_second: float, interval: float = ACTIVE_INTERVAL_SECONDS,
    lease: float = FRESH_SECONDS, calls_per_fetch: int = CALLS_PER_FETCH,
    fetch_seconds: float = 25.0, jitter: float = JITTER_SECONDS, lag: float = 0.0,
) -> dict[str, Any]:
    """Pure safety arithmetic for the 60s lease and the 20s schedule.

    Renewals chain only if the next apply lands before the previous lease ends:
    ``interval + jitter + scheduling_lag + fetch_time < lease``. Throughput is bounded by the
    Stripe request budget: ``tenants * calls_per_fetch <= rate * interval``.
    """
    if tenants < 0 or rate_per_second <= 0 or interval <= 0 or lag < 0:
        raise ValueError("Invalid capacity inputs.")
    sustainable = int(rate_per_second * interval // calls_per_fetch)
    demand = tenants * calls_per_fetch / interval
    # Overload converts directly into scheduling lag: the backlog drains at rate/calls per second.
    backlog_lag = 0.0 if tenants <= sustainable else tenants / (rate_per_second / calls_per_fetch) - interval
    effective_lag = max(lag, backlog_lag)
    margin = lease - (interval + jitter + effective_lag + fetch_seconds)
    status = "ok"
    if effective_lag >= LAG_CRITICAL_SECONDS or margin < MIN_LEASE_MARGIN_SECONDS:
        status = "critical"
    elif effective_lag >= LAG_WARN_SECONDS or demand > 0.8 * rate_per_second:
        status = "warning"
    return {
        "tenants": tenants, "max_sustainable_tenants": sustainable,
        "request_utilization": round(demand / rate_per_second, 3),
        "scheduling_lag_seconds": round(effective_lag, 3),
        "worst_case_lease_margin_seconds": round(margin, 3),
        "lease_chain_safe": margin >= MIN_LEASE_MARGIN_SECONDS, "status": status,
    }


def simulate_schedule(
    tenants: int, *, throughput_per_second: float, interval: float = ACTIVE_INTERVAL_SECONDS,
    lease: float = FRESH_SECONDS, horizon: float = 600.0, fetch_seconds: float = 1.0,
) -> dict[str, float]:
    """Deterministic oldest-due-first simulation used to validate starvation prevention."""
    if tenants < 1 or throughput_per_second <= 0:
        raise ValueError("Invalid simulation inputs.")
    queue = [(index * interval / tenants, index) for index in range(tenants)]
    heapq.heapify(queue)
    lease_until = [float("-inf")] * tenants
    served = [0] * tenants
    max_lag = 0.0
    now = 0.0
    slot = 1.0 / throughput_per_second
    lapsed = 0.0
    while queue and now < horizon:
        due, tenant = heapq.heappop(queue)
        now = max(now, due)
        max_lag = max(max_lag, now - due)
        started = now
        now += slot
        applied = started + fetch_seconds
        if served[tenant] and lease_until[tenant] < applied:
            lapsed += applied - lease_until[tenant]
        lease_until[tenant] = max(lease_until[tenant], started + lease)
        served[tenant] += 1
        heapq.heappush(queue, (started + interval, tenant))
    return {
        "max_lag_seconds": max_lag, "min_served": float(min(served)), "max_served": float(max(served)),
        "lapsed_lease_seconds": lapsed,
    }


class Reconciler:
    def __init__(
        self, store: PostgreSQLReconcilerStore, authority: SubscriptionAuthority, bounded: BoundedStripe,
        settings: ReconcilerSettings = ReconcilerSettings(), *, heartbeat_path: str | None = None,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self.store, self.authority, self.bounded, self.settings = store, authority, bounded, settings
        self.heartbeat_path, self.wall = heartbeat_path, wall
        self.counters: dict[str, int] = {}
        self._lock = threading.Lock()

    def _count(self, key: str) -> None:
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + 1

    def process(self, claim: Claim) -> str:
        try:
            outcome = self.store.complete(
                claim, lambda pinned, repin: self.authority.current(claim.customer, pinned, repin),
            )
        except BillingUnavailable:
            # Database unavailable: nothing was granted or extended; the claim expires on its own.
            outcome = "database_unavailable"
        self._count(outcome if outcome.startswith(("applied", "rejected")) else outcome[:40])
        return outcome

    def step(self) -> int:
        """Claim and fully process at most one tenant; the claim is never held while idle."""
        claims = self.store.claim_due(1, self.settings.claim_seconds)
        for claim in claims:
            self.process(claim)
        return len(claims)

    def heartbeat(self) -> None:
        if self.heartbeat_path is None:
            return
        try:
            status = self.store.status()
        except BillingUnavailable:
            status = {"status_unavailable": True}
        with self._lock:
            counters = dict(self.counters)
        body = json.dumps({"at": int(self.wall()), "counters": counters, "database": status}, sort_keys=True)
        temporary = self.heartbeat_path + ".tmp"
        descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(body + "\n")
        os.replace(temporary, self.heartbeat_path)

    def serve(self, stopped: threading.Event) -> None:
        def worker() -> None:
            while not stopped.is_set():
                try:
                    worked = self.step()
                except BillingUnavailable:
                    worked = 0
                    self._count("database_unavailable")
                except Exception:
                    LOG.error("billing_reconciler: worker_error")
                    worked = 0
                if not worked:
                    stopped.wait(self.settings.idle_seconds)

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.settings.workers)]
        for thread in threads:
            thread.start()
        while not stopped.wait(self.settings.heartbeat_seconds):
            try:
                self.heartbeat()
            except Exception:
                LOG.error("billing_reconciler: heartbeat_failed")
        for thread in threads:
            thread.join(timeout=self.bounded.deadline + 5)
