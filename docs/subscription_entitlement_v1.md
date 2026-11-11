# Offline subscription entitlement policy V1

## Boundary

`gvai/subscription_entitlement.py` is a pure, deterministic policy reference.
It performs no Stripe verification, database access, network calls, clock lookup,
key issuance, provisioning, deployment or execution. It is not wired into the
pilot, commercial HTTP adapter or evaluator. An affirmative decision means only
paid eligibility in this offline model, not an authorized API request, payment
receipt, signed grant or permission to operate independent STOP controls.

The existing pilot and advisory accounting behavior is unchanged. This phase
does not make the $99/month product available, select its quota, configure Stripe
or activate Lab-01.

## Trusted inputs

All records are frozen, typed dataclasses. Malformed normalized records and
invalid timestamp/configuration types raise fixed `ValueError` messages.
Well-formed rejected evidence returns an explicit denial reason and disposition.
The module logs nothing and accepts no credentials or secrets.

- `SubscriptionAssociation` binds one account, Stripe customer, customer tenant,
  subscription and approved recurring Price. The existing commercial identifier
  validation is reused, including rejection of the internal tenant.
- `PaidInvoice` contains a unique invoice ID, its independently established
  association, an inclusive start/exclusive end service interval, and an explicit
  verification flag.
- `SubscriptionEvidence` contains one normalized event and the reconciled
  subscription snapshot. Its certainty flag is required, not assumed.
- `EntitlementState` is trusted, caller-retained policy state for exactly one
  association. Do not construct it from customer input or discard its tombstones.

A future adapter must verify signatures, sandbox/account context, actual paid
invoice status, relevant service lines, the $99/month Price and trusted account
membership before setting verification/certainty. Boolean flags are not proofs.
No raw Stripe payload parser or API-version compatibility is supplied here.

`revision` is a monotonically increasing, independently fenced reconciliation
revision for this subscription, **not** a Stripe event timestamp or delivery
sequence. `observed_at` records the trusted reconciliation observation time.
Retries must reuse the same normalized event ID and contents; a new authoritative
reconciliation requires a new evidence ID and revision. Future durable processing
must preserve that distinction rather than renormalize an old delivery as new
proof. Distinct Stripe events referring to the same invoice do not add coverage.

Callers supply integer Unix seconds as `now` and an explicit positive
`max_evidence_age`. Trusted time, nondecreasing clocks and fencing are caller
responsibilities. This component does not defend against caller-controlled
timestamps or replacing trusted policy state.

## Policy and transitions

`apply_entitlement_evidence` returns a new state, processing disposition
(`applied`, `duplicate`, `rejected`) and current decision. Inputs are never
mutated. `evaluate_entitlement` reassesses retained state at the supplied time;
previous decisions must not be cached as authorization.

Access requires all of:

1. No latched operator suspension or terminal cancellation.
2. A fresh, certain snapshot with subscription status exactly `active`.
3. A verified paid invoice interval containing `now`.
4. No effective scheduled cancellation boundary.

Coverage is the union of verified service intervals. Overlapping/adjacent
renewals extend coverage; gaps and future intervals cannot authorize unpaid
time. `access_until` is capped by paid coverage, evidence freshness and scheduled
cancellation. Every end boundary is exclusive. No unpaid grace is granted.

Supported normalized event labels:

| Event | Policy effect |
|---|---|
| `checkout.session.completed` | Snapshot only; never supplies paid coverage. |
| `customer.subscription.created` | Reconcile subscription state; creation alone does not grant. |
| `customer.subscription.updated` | Reconcile status and optional effective `cancel_at`. |
| `customer.subscription.deleted` | Requires canceled status; certain evidence latches terminal denial. |
| `invoice.paid` | Adds verified, correctly associated service coverage when evidence is fresh and certain. Activation still requires active state. |
| `invoice.payment_failed` | No added coverage. Existing paid coverage remains usable only while status is active and evidence is fresh. |
| `invoice.payment_action_required` | Same access rule as payment failure; no paid extension. |

Verified invoice evidence can precede an active snapshot without granting early
access. Outdated nonterminal snapshots are rejected, not applied as current truth.
The future adapter must reconcile an out-of-order invoice against current state
under a new revision if it has not already been recorded.

Certain canceled status is a deny-only tombstone even when its revision/time is
older than the latest snapshot. Later paid events cannot restore the same
subscription. Scheduled cancellation is not terminal until effective/canceled;
a newer certain active snapshot may reverse the schedule.
`suspend_entitlement` separately latches operator suspension, which takes decision
precedence over cancellation and cannot be cleared by payment evidence.
No unsuspend or tombstone-reset operation exists. New-subscription admission and
independently authorized administrative recovery are future work.

Exact event duplicates do not refresh observation time or add coverage. Reusing an
event ID with changed contents, reusing the latest revision for another event,
or changing an accepted invoice's immutable coverage marks retained state
uncertain and denies. Only a strictly newer, certain reconciliation can clear
uncertainty; duplicates cannot. Accepted uncertain/stale evidence adds no payment
coverage. Association mismatches, future observations and outdated snapshots are
rejected without replacing previously accepted state, and the transition itself
returns a denial.

## Assumptions and deferred guarantees

- The conservative initial policy denies `past_due`, `unpaid`, `paused`,
  `trialing`, `incomplete` and `incomplete_expired`, even during remaining paid
  coverage. Allowing prepaid access under `past_due` or any positive grace needs
  separate policy approval and tests.
- Freshness duration, monetary/discount/refund policy, paid-plan allowance,
  account authentication, customer notifications and recurring key rotation are
  not selected by this component.
- State retains event and invoice history without pruning so old duplicates can
  be identified. This is an offline reference, not a bounded production store,
  durable inbox, transactional worker or concurrent idempotency guarantee.
- Process restarts, persisted-state integrity, restoration fencing, atomic
  reservation checks, cancellation delivery latency and secret custody require
  future infrastructure. No external API or database tests are implied.

## Validation

With the repository's existing pytest environment:

```sh
PYTHONDONTWRITEBYTECODE=1 /usr/local/py-utils/venvs/pytest/bin/python -m pytest -q \
  -p no:cacheprovider tests/test_subscription_entitlement.py
```

Tests use only synthetic identifiers and injected times. They cover activation,
pending/failed payments, renewals, duplicates/conflicts, ordering, cancellation,
suspension, association validation, stale/uncertain proof, interval boundaries,
immutable records and deterministic results.
