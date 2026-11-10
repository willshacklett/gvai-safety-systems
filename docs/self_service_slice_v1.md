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

- **Entitlement freshness:** the paid runtime requires `verified_until > now` (60s) and no
  periodic reconcile loop exists, so a claimed key stops working shortly after the last webhook.
- **Key recovery:** if the claim response is lost after commit, the key is unrecoverable and the
  claim latch cannot be cleared. An audited operator reissue flow is not implemented.
- **Key lifetime:** keys last 365 days and are not revoked by cancellation; the runtime
  entitlement check is the only gate.
- **Signup abuse:** the limiter is global and in-memory. Per-client limiting belongs at ingress.
  Stripe customers created before a failed DB insert are orphaned (tagged `gvai_tenant`
  metadata); the Stripe client permits only GET/POST, so cleanup is a manual/reconcile job.
- **Privilege:** the process uses the owner DB role and the Stripe secret; narrow before exposure.
- **No account recovery:** the account token is the only credential.
