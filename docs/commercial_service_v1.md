# Commercial Evaluation Service V1

## Status and scope

Phase 6F adds an offline service orchestrator in
`gvai/commercial_service.py`. It composes the existing customer API-key verifier,
`CommercialAuthorizer`, usage reservation facade, and pure advisory evaluator.
It is a library boundary for founder review, not a deployed service, production
authentication system, billing integration, safety certification, or launch
approval. The $99/month target is not an allowance, entitlement, or activated
subscription.

The service performs no worker execution, tool call, action enforcement, or
supervisor STOP operation. Evaluator `BLOCK` is advisory; it does not halt a
customer system. The independent supervisor STOP architecture remains outside
customer identity, quota, and evaluation authority.

## Trusted construction and request contract

Trusted server code constructs `CommercialEvaluationService` with an existing
`CommercialUsage` instance. That usage facade is constructed with the existing
`CommercialAuthorizer` and trusted usage store. The authorizer is already wired
to a `CustomerIdentityVerifier`, such as `CustomerApiKeys`. The service does not
accept an authorizer decision or identity object from the caller, nor does it
implement another authorization path.

The in-process call is:

```python
service.evaluate(
    credential,
    resource_id,
    request_id,
    telemetry,
    reported_effects,
)
```

There are no tenant, role, capability, allowance, billing, period, or STOP
arguments. `resource_id` is resolved through server-owned ownership metadata.
`request_id` must meet the existing strict v1 identifier rules. `telemetry` is
the strict evaluation telemetry object and `reported_effects` is an exact list
of known caller-reported effect names. Evaluation schema fields, numeric bounds,
and effect vocabulary remain owned by `gvai.evaluation`; malformed inputs are
rejected before quota reservation.

Successful evaluation response:

```json
{
  "outcome": "evaluated",
  "reason": "evaluated",
  "evaluation": {
    "version": "gvai-evaluation-v1",
    "request_id": "req-2026-001",
    "decision": "ALLOW",
    "risk_score": 1.45,
    "risk_band": "green",
    "explanation": "The existing telemetry guard classified this sample green. No authority-expansion effect was reported. This is not authorization or enforcement.",
    "evaluation_status": "ok",
    "advisory_only": true,
    "enforcement_applied": false
  }
}
```

Authorization denials return `outcome: "denied"` and
`reason: "authorization_denied"`; quota, missing-policy, clock-rollback, and
other non-replay quota denials return `reason: "quota_denied"`. A repeated
request ID returns `reason: "replay"` and never re-enters evaluation. Invalid
evaluation payloads return `reason: "invalid_request"`. Accounting outages and
unexpected evaluator failures return `outcome: "error"` with the fixed reasons
`accounting_failure` or `evaluation_failure`. These responses include neither
credential data nor exception details. A future HTTP adapter must map internal
authorization reasons to uniform public errors to avoid resource enumeration.

An advisory evaluation whose decision is `BLOCK` still has
`outcome: "evaluated"` and `reason: "evaluated"`; it is not an authorization or
quota denial. The response has no `allowed`, `authorized`, or execution-permit
field. `ALLOW`, `QUALIFY`, and `BLOCK` describe only the pure evaluator's advisory
result.

## Trust and evaluation flow

1. The service copies and validates a bounded strict v1 evaluation request. No
   caller-supplied tenant or role is accepted. Invalid payloads do not reserve
   quota.
2. `CommercialUsage.reserve` performs fresh verification and authorization via
   `CommercialAuthorizer`, which checks current credential state, capability,
   resource ownership, tenant equality, resource kind, and expiry. The tenant
   comes only from verified server-side identity and ownership data.
3. Only an exact fresh `RESERVED` result with `may_evaluate is True` proceeds.
   Authorization denial, missing policy, exhausted quota, clock rollback,
   accounting error, and replay do not invoke the evaluator. Replay is a
   successful accounting observation, not a new execution grant.
4. The existing pure `evaluate_request` contract processes the validated
   snapshot. It does not execute or stop work and retains its deterministic
   advisory decisions.
5. The service completes the reservation with `succeeded=True` only for an
   `evaluation_status` of `ok`; an evaluator error is completed as failed.
   Evaluation output is returned only after the completion transition succeeds.

The service imports no executor or worker implementation and never calls
supervisor STOP APIs. The evaluator's existing external-control rule considers
only caller-reported effect labels and does not invoke STOP.

Authorization is point-in-time. If a credential is revoked after reservation,
the already-reserved in-flight evaluation may still run; the later completion
reauthorizes and can deny the response. Its unit remains consumed and the
reservation may remain `RESERVED`. This prototype does not provide immediate
cancellation or atomic authorization, evaluation, and completion.

## Accounting, retries, and failures

A newly accepted reservation consumes one unit immediately, before evaluation.
Every completed evaluation consumes the same one unit regardless of an advisory
`ALLOW`, `QUALIFY`, or `BLOCK` decision. An evaluator failure is marked failed
when completion succeeds; it still consumes its unit. Completion is a terminal
accounting update, not an additional charge or refund.

The unit is not refunded for evaluation errors, cancellation, process failure,
lost responses, abandoned reservations, or completion-store failure. If
evaluation succeeds but completion cannot be recorded, the service returns
`accounting_failure` and withholds the evaluation result. The reservation may
remain reserved, but its unit remains consumed. A later retry with the same ID
is a replay and cannot evaluate again. A new request ID is a new attempt and
requires another available unit.

If the reservation write commits but acknowledgement is lost, the usage facade
fails closed; retrying the same ID yields replay, not another grant. If failure
occurs before reservation commit, the same ID may reserve on retry, matching
the existing usage-store transaction behavior. No response cache exists, so a
lost successful response cannot be recovered by this service. The caller must
not treat replay as permission to run again or infer the prior evaluation
result. These semantics preserve the existing usage contract and introduce no
refund, result-recovery, or exactly-once behavior.

## Production blockers and future HTTP adapter

This reference still depends on process-local API-key and usage stores, trusted
injected clocks, and trusted server-side ownership data. It has no durable
revocation, distributed quota atomicity, authenticated transport, TLS
termination, rate limit, request-body limit, audit pipeline, result cache,
customer management flow, payment state, or billing. In-memory restart or
replica boundaries can bypass quotas and revoke history. Clock rollback can
still affect API-key validity. Allowance and attempt-accounting policy require
founder approval; the $99/month price implies no unit count.

Before a future authenticated HTTP adapter, separately review and implement:

- Durable identity, ownership, API-key, revocation, and quota backends with
  current reads and explicit transaction/idempotency guarantees.
- Independently trusted account and key-management flows; customer request
  claims must never set tenant, role, capability, billing, or resource ownership.
- TLS, credential-header handling, strict body and request limits, rate limits,
  uniform unauthorized/not-found responses, and redaction in logs, tracing,
  metrics, and error reporting.
- Explicit mapping of service outcomes to HTTP status codes without turning an
  advisory evaluation decision into an execution permission.
- Defined response-loss, retention, reconciliation, clock, rollover, and
  revocation-race behavior, with adversarial and distributed-backend tests.
- Separate founder/security review before any routes, paid access, product
  claims, or launch.

The service accepts exact built-in `dict` and `list` inputs only. It copies at
most the schema maximum plus one item per snapshot attempt and rejects observed
size changes or inconsistent repeated snapshots before reservation. This
bounds copy work but cannot make arbitrary caller-owned mutable objects
race-free; a future transport must parse into request-owned immutable or
otherwise safely synchronized data before calling the service.

No HTTP endpoint, customer billing, Stripe configuration, website change, DNS
change, deployment, or host change is part of this phase. The public website,
GitHub Pages, https://gvaisafety.com, contact@gvaisafety.com, and GvAI.io remain
unchanged.
