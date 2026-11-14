# Customer Zero durable advisory smoke V1

Status: new test-only candidate. Only resource-free validation is authorized for
this build. No real HTTP/PostgreSQL integration result, deployment approval,
independent launcher approval, threat-detection claim or enforced STOP follows.

## Immutable source and scope

Base L: `3c117260901cb15877512161cb24fa8e5587aa73` from
`feature/lab01-commercial-staging-v1`. Import N:
`c3fd88a236f32aa9b84e6baaa212cb4db79d02ca` from
`feature/ask-gv-self-protection-advisory-v1`.

New branch: `feature/customer-zero-advisory-smoke-v1`.
Durable worktree: `/workspaces/gvai-customer-zero-advisory-smoke-v1`.
All five paths were absent at L before writing:

| File | Provenance |
| --- | --- |
| `ask-gv/decision-client.mjs` | Exact N blob `7cb255a896036f669b034c6858d2b74d4ebecc46` |
| `tests/ask-gv/decision-client.test.mjs` | Exact N blob `92fbe60cb1d1565326aace17ae08d91368506b56` |
| `tests/ask-gv/customer-zero-commercial-smoke-driver.mjs` | New one-shot test driver |
| `tests/integration/test_customer_zero_commercial_smoke.py` | New pure contracts and separately gated disposable case |
| `docs/customer_zero_advisory_smoke_v1.md` | This boundary/evidence document |

Product/backend/custody APIs, SQL, migrations, provider controls, STOP/ARM,
package manifests and deployment/CI remain unchanged. This does not reconstruct,
invoke, approve or replace the missing eight-file harness/trusted launcher.
No other worktree or preserved branch is changed.

## Driver contract and private transport

Importing the new Node driver defines functions; it does not read stdin, start a
listener or evaluate. `runSmoke(config,{fetchImpl,signal,evidence})` requires an
explicit transport; there is no default native transport. It calls the real
unchanged `createDecisionClient` once, checks the outgoing request, and calls
`operation.provider('not_attempted')` exactly once. That method only records an
observation; no provider exists in this driver.

The generated request ID is a fresh `askgv-<UUIDv4>`; no test-supplied ID or retry
API is added. Body keys remain exactly version/request_id/resource_id/telemetry/
reported_effects. The five counters are zero, latency is null and effects empty.
The checked method, bearer header, byte length, JSON media type, signal and
redirect policy are the unchanged client's actual fetch arguments.

CLI input is private JSON-lines on stdin, never a key in argv or environment.
No secret environment fallback is supported. Contract initial frame:

```json
{"mode":"contract","config":{"endpoint":"http://127.0.0.1:8080/v1/evaluations","project":"customer-zero-contract","key":"FAKE-contract-only-key"}}
```

This mode injects a pipe-backed fake fetch. It emits one fixed synthetic request
frame `{type:"request",body:<actual body>}`. The parent responds privately with
`{status:<integer>,body:<real serialized service response or test mutation>}`.
The real client validates that response, including request correlation, schema,
advisory_only=true and enforcement_applied=false. There is no HTTP or network in
this mode. The private request frame is synthetic protocol data, not a public
observation; it contains no key/header/prompt/customer content. Parent tests keep
it in memory. Final frame is `{type:"result",result:<sanitized allowlist>}`.

Output contains only version, evidence label, request count/ID, observed status,
accepted advisory flag (true only for an accepted evaluated response, null on
unavailability), enforcement=false and two bounded correlated observations.
Explanations, raw responses, keys, DSNs and exceptions are excluded. A failure
produces a fixed HOLD frame/nonzero exit; it is never a fabricated success.
HTTP status is null if no response reached the wrapper. It is only a mocked
status in contract mode, never evidence of a real HTTP response.

Client deadline remains the original 500 ms across headers/body. No retries,
refunds, quota reset or result synthesis. Subprocess deadline is a separate
8-second outer bound (explicit smaller bounds for fault tests). Private frame
input is bounded to 16 KiB per frame / 32 KiB total, emitted frame to 8 KiB and
final result to 4 KiB; parent reads each output stream live up to16 KiB (not an
unbounded `communicate`). Parent writes nonblocking bounded pipe messages and
kills/reaps its owned active process group on failure/deadline/overflow. Errors
are redacted. Trusted Python callbacks are not a hard real-time isolation layer;
the test invocation itself should also have a finite supervisor deadline.

## Resource-free validation

Use preexisting Node24.22.2 and Python with existing backend dependencies. No
npm/pip install, blanket suite, listener, database, browser or provider is needed.
Inspect the exact tests/imports before each invocation. Example selected commands
for a later authorized rerun, all from the new worktree:

```sh
timeout 30s node --check tests/ask-gv/customer-zero-commercial-smoke-driver.mjs
timeout 30s node --test tests/ask-gv/decision-client.test.mjs
PYTHONDONTWRITEBYTECODE=1 timeout 90s python -B tests/integration/test_customer_zero_commercial_smoke.py
```

Default Python execution runs only `PureContracts` plus a visibly skipped
`DisposableSmoke` case. The pure class uses stdlib unittest, finite private-pipe
Node processes, synthetic in-memory keys/authorizer/quota, the preserved real
Python evaluator/service and response serializer. It does not import existing
test modules. It validates the actual client body -> real service envelope ->
actual client's strict parser round trip. It checks one request, zero telemetry,
correlation, advice flags, provider-not-attempted, replay at the service layer,
error/invalid-envelope unavailability, cancellation/deadline, redaction, bounded
output/process termination, import safety and fail-closed missing approval.

No-resource round trip is **connectivity contract evidence only**. A fixed zero
sample predictably produces ALLOW/green/0; that is not meaningful threat
detection, prompt safety, actual spend monitoring, safe-effects proof or an
execution grant. Service-layer replay is not proof of an HTTP409 or PostgreSQL
transaction. A mocked HTTP status is labeled mocked. No listener is created even
when the synthetic endpoint contains a loopback URL.

## Future disposable section: not authorized or run by this build

`DisposableSmoke.test_disposable_http_postgresql_smoke` is skipped unless
`GVAI_CUSTOMER_ZERO_DISPOSABLE=1`. Opting in additionally requires:

- `GVAI_CUSTOMER_ZERO_EXECUTION_AUTHORIZED=one-disposable-advisory-smoke`;
- absolute `GVAI_CUSTOMER_ZERO_FIXTURE_FILE` and its independently supplied
  `GVAI_CUSTOMER_ZERO_FIXTURE_SHA256`;
- absolute `GVAI_CUSTOMER_ZERO_APPROVAL_FILE` and its independently supplied
  `GVAI_CUSTOMER_ZERO_APPROVAL_SHA256`.

These environment values are non-secret admission inputs, not credentials.
Missing/mismatched prerequisites after opt-in cause HOLD/failure, not a skip or
PASS. This code never creates an approval. An independent reviewer/operator must
supply approval and its digest out of band after reviewing the candidate,
fixture isolation and a distinct explicit resource-execution authorization.
A digest detects changed bytes; it does not authenticate the reviewer or prove
isolation. Anyone controlling all these inputs can self-assert them; independent
custody/review is a required external trust boundary, not provided by this test.
Do not set these inputs merely to make tests pass. No authorization issuer or
replacement trusted launcher is implemented here.

Both input files must be non-symlink regular files, single link, current-user
owned, mode0400/0600, <=16 KiB, immediately in a current-user-owned0700 directory.
The file bytes must match the supplied SHA256 before parsing (strict duplicate
and nonfinite JSON rejection). Parent directory custody remains a trusted
operator prerequisite; this is not a proof against same-UID replacement/races.
Only synthetic disposable secrets may appear in the private fixture file; never
Lab-01, production or real customer credentials. No such files are generated by
this build or by default tests.

Fixture exact fields:

- `fixture_id`: `customer-zero-` plus1..64 lowercase letters/digits/hyphens;
- `synthetic_only`: true (operator attestation, not a proof);
- `project`: same identifier prefix/shape, reviewed owned evaluation resource;
- `evaluation_key`: evaluate-only synthetic `gvai_customer_v1_...` key;
- `usage_key`: distinct usage-read synthetic customer key;
- `expected_database`: `gvai_advisory_test_customer_zero_` plus1..40 lowercase
  letters/digits/underscores;
- `expected_runtime_role`: `customer_zero_` plus1..40 lowercase
  letters/digits/underscores;
- `expected_server_version`: exact six-digit PostgreSQL server_version_num;
- `runtime_config`: exact L staging config keys mode/database_dsn/
  verifier_secret_hex/authority/port/max_connections. Mode private-staging,
  port integer0, max_connections integer2,32-byte lowercase hex verifier secret.
  Authority is exactly authority_id=customer-zero-disposable, epoch=1,
  trust_domain=customer-zero-disposable. DSN requires literal127.0.0.1, approved
  database/user/password and only host/hostaddr/port/dbname/user/password fields.

Approval exact fields: `scope`=one-disposable-advisory-smoke, `fixture_id`,
`fixture_sha256`, `candidate_sha256`, `authorized`=true, nonempty identifier
`review_id`, integer `expires_unix` (future, at most24 hours away). Fixture ID and
fixture hash must match. Candidate digest is SHA256 of UTF-8 records sorted by
relative file path, one per five scoped files:
`relative_path + NUL + lowercase_file_sha256 + newline`.
Approval lives outside the candidate, so it creates no circular self-hash.
Changing any scoped file invalidates approval. Existing imports also remain
pinned by the documented Git blobs. After commit, separately record its SHA.

The later reviewer must independently provision an isolated disposable database,
non-superuser schema owner and distinct restricted runtime, apply only reviewed
migrations001-003, initialize the exact synthetic authority and active pilot
cap3, and issue evaluate-only and usage-read keys. Runtime must have only schema
USAGE and the three advisory entry EXECUTE grants. This test implements no
Docker/DB/role/key lifecycle, migrations or schema reset; it must not reuse an
existing arbitrary DSN just because its name matches. DB identity labels are
checks, not proof of disposal or uniqueness. Review exact runtime/dependency and
infrastructure identities; L's psycopg requirement is a range, not an exact lock.

Only after admission, the test constructs L PrivateStagingApplication: this
connects to PostgreSQL and binds loopback HTTP, even before start(). It verifies
actual database/user/server version, L runtime-role/function rules and baseline
allowance3/consumed0/reserved0/completed0/failed0. The evaluation key must not read
usage. It then starts only the commercial loopback listener at a random port.
Node receives only endpoint/project/evaluation key plus non-secret admission
identity through stdin. It receives no DSN, verifier, usage key or owner secret.
A minimized child environment includes only PATH/TZ and externally approved
resource-admission scope/digest. Standalone driver native mode rejects absent
admission environment, invalid fixture/candidate digests or nonliteral-loopback
endpoints; valid JSON alone does not activate native mode.

Future native mode calls global fetch once with the unchanged client, and
requires Node24.22.2. No OpenAI, provider or Ask GV server path is imported.
Acceptance: actual HTTP200 and evaluated0/green/ALLOW with matching ID/advice
flags, provider-not-attempted, then durable usage allowance3/consumed1/reserved0/
completed1/failed0/remaining2. Connection leases/listener are shut down in finally.
No refund/retry or database deletion is performed. External infrastructure and
post-run reconciliation/cleanup remain reviewer/operator responsibilities.
If a client times out, rejects a response, or a shutdown fails, result is HOLD;
committed units may still be charged. Reconcile actual durable state before any
new invocation, including after an empty/partial result. Do not rerun against a
nonzero baseline or reset counts. The candidate's explicit minimal acceptance
does not assert evaluator invocation count via DB internals; count/correlation
and usage are the available evidence, not full exactly-once proof.

## Incomplete and intentionally unchanged

- Actual HTTP/PostgreSQL smoke, real auth/role enforcement and durable charge:
  NOT RUN. Default skip is nonexecution, not integration success.
- Native-fetch cancellation, response loss, real replay/conflict diagnostics,
  clean restart/crash durability, quota exhaustion, auth/expiry/revocation,
  accounting/commit ambiguity and infrastructure shutdown/cleanup matrix remain
  later separately reviewed slices. No mocked result substitutes for them.
- N4 expiry during synchronized authority-lock wait; N7 lock-client abort/late
  database outcome; N8 real connection-capacity exhaustion/privilege revocation;
  N12 key revocation between reservation acknowledgment/completion remain OPEN.
- Node validateDecision requires decision to follow score/band, but Python can
  validly BLOCK a caller-reported authority-expansion effect while score remains
  green. Fixed empty-effects adapter input avoids that incompatibility here.
  Neither validator nor evaluator is relaxed; no red score is invented.
- Advisory never enforces independent STOP. BLOCK/error/timeout do not control
  provider admission. Existing disable/drain/budget/circuit and non-atomic
  readiness windows remain unchanged. Abort is not remote termination or quota
  rollback. No STOP/ARM authority integration or grant is added.
- P1: old diagnostic fault matrix shares a latched stderr stream state, so later
  matrix cases do not freshly exercise fallback writes. Not fixed or closed by
  new clean-sink tests.
- P2: old advisory Python fixture has an unbounded Node check_output; default
  Python CI lacks explicit supported Node setup and docs omit that fixture.
  New driver subprocesses are bounded, but old fixture/CI/docs finding stays OPEN.
- Commercial evaluator starts fresh guard state per request. Fixed zeros do not
  measure tokens/spend/cumulative risk or threats; empty reported effects prove
  nothing about actual effects. Meaningful measured telemetry is future work.
- Logs are bounded best-effort observations, not guaranteed durable audit
  delivery; same-process timing is not hard real-time isolation. Host isolation,
  private ingress/TLS, secret mounts, audit retention and independent release
  review remain unverified. No billing, paid entitlement or production approval.

Smallest next preservation action: review the exact five-file diff, pins, test
results and omissions, then separately authorize staging exactly these five
paths and one local checkpoint commit on this new branch. No commit, push,
resource run or missing-launcher approval is included in this build.
