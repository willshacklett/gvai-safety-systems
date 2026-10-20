Offline approval lifecycle reference model
==========================================

``gvai.approval_lifecycle_model`` is a pure, immutable scenario model, not a
verifier, supervisor, state backend or credential issuer. It imports no runtime,
registry, shutdown verifier or envelope parser. All ModelResult objects have
allowed=False, authenticated=False and false truthiness, even when their state
records modeled consumption or completion. No result is a bearer capability.
HARD GATE remains unchanged and deny-only.

Scope
-----

SyntheticRequest contains fabricated scenario identifiers, not simulated
production identity. Modeling an attempt assumes hypothetical successful
independent authentication and gate checks; it does not implement either.
There is no callback to claim verification succeeded. Passing an envelope,
registry entry or model output is not a supported interface.

Context binds the execution domain, supervisor/environment/tenant/boot,
workload digest, action digest, exact effects, policy digest/epoch, grants epoch,
observation digest and revocation/shutdown generations. Scenario requests also
bind issuer, principal, scope, decision reference, approval ID, challenge and
integer validity window. The action digest stands for an already frozen complete
descriptor including executable, arguments, inputs, resources, destinations and
limits. The model does not resolve resources, derive effects or authenticate
observations. Unlike the envelope, it uses small synthetic IDs, not UUID tokens.

One transition is one hypothetical serialization point. Both race orderings
are explored by tests; callers must not fork the same immutable state and treat
the resulting branches as shared replay protection. There are no thread locks,
cross-process coordination, persistence or production concurrency guarantees.

Modeled rules
-------------

* Attempt consumes (domain, issuer, approval_id) and
  (domain, supervisor, boot, challenge) together with a modeled-running record.
  Different approval IDs/issuers cannot reuse the same challenge in that context.
* Consumption is retained on every subsequent transition, including completion,
  failure, shutdown and restart. It is never undone; no automatic retry exists.
* Exact context equality is required. Context changes invalidate outstanding
  requests and mark modeled-running attempts cancel_required. Lifecycle identity
  and control generations cannot be reset through context_change. Every accepted
  context update requires a strictly greater policy epoch; an A-B-A digest
  change therefore cannot revive an outstanding A request.
* issued_at <= not_before <= now < expires_at, maximum lifetime 60 seconds.
  Exact expiry cancels modeled-running attempts and prevents modeled completion.
  Time rollback/uncertainty permanently blocks admission in that model instance.
* Shutdown latches permanently, even with uncertain time. Revocation increments the control generation
  and conservatively invalidates all outstanding requests/running attempts.
* Verifier/store/audit failure, crash or uncertain cancellation latches
  uncertainty and marks modeled-running attempts cancel_required.
* Restart retains tombstones and the stop latch, increments boot and remains
  blocked pending independent recovery. No recovery/unstop event is provided.
* Invalid requests cannot consume IDs or acquire shutdown authority.

Completion is only a scenario label. Cancellation obligations are labels too:
no process is launched, stopped or promoted. Final external effects cannot be
undone. An operator-provided ModelState can be fabricated or replaced; it is not
tamper-resistant state. The model has no authenticated observation freshness,
key/grant lookup or trusted clock source and is not a resource-bounded service.

Acceptance and remaining dependencies
------------------------------------

Deterministic tests cover duplicate/challenge consumption, control race orderings,
expiry, policy/grants/workload/action changes, unavailable dependencies, rollback,
crash/restart preservation and permanent stop. Existing offline parser, HARD GATE,
registry and website suites remain regression checks; no live OS workload is used.

Separate human approval is required before authentication-provider work, real
key provisioning or approval issuance, durable control-plane implementation,
infrastructure changes or any execution integration. A future trusted supervisor
still needs independent authentication, protected trust configuration, reliable
observations/time, durable atomic state and actual cancellation/promotion
synchronization. This reference model establishes none of those operational
properties and must not be wired into the executor.
