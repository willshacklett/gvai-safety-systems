# Self-service slice v1 (Stripe TEST mode, advisory-only)

Loopback-only account server (`gvai/self_service.py`) over migration 008. It adds no
enforcement or shutdown capability. Evaluations remain advisory-only.

Flow: `POST /v1/signup` (account token shown once) -> `POST /v1/account/checkout` ->
Stripe webhook (existing #50 path) -> `POST /v1/account/api-key` (single-use claim) ->
`POST /v1/evaluations`.

## Tests

`GVAI_RUN_SELF_SERVICE_POSTGRES=1 python -m pytest tests/test_self_service.py` needs Docker and a
cached `postgres:16`. Set `GVAI_REQUIRE_SELF_SERVICE_POSTGRES=1` in CI so a missing prerequisite
fails instead of skipping. Stripe is faked; real Stripe test mode is unverified.

## Known gaps (must close before any customer use)

- **Entitlement freshness (M2):** addressed by the bounded reconciler in
  `docs/subscription_reconciliation_v1.md` (implemented and locally tested; real Stripe behaviour and
  deployment are unverified; capacity is ~80 active tenants at the Stripe test-mode rate limit).
  `GET /v1/account` now reports `entitlement_state` and `access_until` and no longer ignores the lease.
- **Key recovery:** if the claim response is lost after commit, the key is unrecoverable and the
  claim latch cannot be cleared. An audited operator reissue flow is not implemented.
- **Key lifetime (launch blocker):** keys last 365 days, cannot be rotated, and are not revoked by
  cancellation; the runtime entitlement check is the only gate.
- **Signup abuse:** the limiter is global and in-memory. Per-client limiting belongs at ingress.
  Stripe customers created before a failed DB insert are orphaned (tagged `gvai_tenant`
  metadata); the Stripe client permits only GET/POST, so cleanup is a manual/reconcile job.
- **Privilege:** the process uses the owner DB role and the Stripe secret; narrow before exposure.
- **No account recovery:** the account token is the only credential.
