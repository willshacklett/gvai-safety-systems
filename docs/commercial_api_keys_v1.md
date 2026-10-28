# Customer API-Key Foundation V1

## Status and boundary

Phase 6D is an isolated, offline, **nonproduction** lifecycle component in
`gvai/commercial_api_keys.py`. It supports founder review of a future $99/month
subscription, not launch readiness. It creates no customer accounts, HTTP
routes, billing, network connections, worker execution, or deployments.

Never let the thing behind the switch own the switch.

`CustomerApiKeys.verify` implements the existing `CustomerIdentityVerifier`
protocol. Pass that object to `CommercialAuthorizer`; do not add another
authorization layer or treat a returned identity as an allow decision.
The existing authorizer continues to decide resource ownership, tenant equality,
commercial capability, resource kind, and expiration. No existing evaluation,
identity, supervisor, website, or deployment behavior is changed.

## Issuance and one-time presentation

Only independently trusted server code may call `issue` or `revoke`. Neither
method is a customer-facing endpoint or authorized by evaluation/usage grants.
An independently authenticated account-management flow must establish principal,
tenant membership, capabilities, and expiry before calling issuance. This
repository does **not** implement that flow. Never unpack customer request
claims into management arguments. The reserved internal tenant is rejected.
Only exact `CommercialCapability` enum values are accepted: `evaluation:run`
and `usage:read`. An empty grant set grants nothing.

Keys have the form `gvai_customer_v1_<32 lowercase hex ID>_<64 lowercase hex secret>`.
The distinct prefix identifies customer credentials, never supervisor authority.
Both components come from `secrets.token_hex`, using 16 random ID bytes and
32 random secret bytes (256 bits of secret entropy). They contain no tenant,
principal, scopes, or signed client claims. Deterministic randomness is patched
only inside tests, not exposed as an issuance option.

`issue` returns an ephemeral `IssuedApiKey`. Its `take_secret()` method returns
the credential once and clears the handoff's reference; subsequent calls return
`None`. Its repr does not expose the secret. The caller must deliver the value
once through a protected channel and then discard it. No reveal/recovery API
exists. Python strings cannot be reliably zeroized; memory dumps, debugger
access, retained caller references, and hostile code in the trusted process
are outside this guarantee. Do not serialize handoff internals or capture
credential-bearing stack-frame locals in tracing/error reporting.

## Verifier and storage model

Supply an independently generated secret of at least 32 bytes as
`verifier_secret`. There is no default, environment lookup, fallback credential,
or reuse of a supervisor key. Missing, short, or incorrectly typed configuration
disables issuance and verification; it never enables a development bypass.
Revocation remains possible without verifier configuration.

The stored verifier is HMAC-SHA256 over a versioned customer-only domain separator
and the complete ASCII credential, including its lookup ID. Only the keyed
32-byte verifier is stored, not the plaintext key or its random secret suffix.
Use a secret manager with separate custody for this HMAC secret. A plain unsalted
hash, user password, or supervisor signing secret is not a substitute. The
high-entropy random credential does not require password hashing.

`ApiKeyRecord` holds the nonsecret key ID, server-selected principal, tenant,
typed commercial grants, creation time, exclusive expiration, revocation flag,
and keyed verifier. Verifiers are excluded from record repr. Metadata remains
customer-sensitive and requires access controls; never place secrets in identity
metadata. No logs are emitted. Verification returns an existing identity or
`None`, never credentials or underlying exception text. Issuance errors have a
fixed message with no retained exception context. Revocation reports a Boolean;
`False` is never proof of successful revocation.

`ApiKeyStore` is a trusted storage interface. `insert_if_absent` must atomically
reject all duplicate IDs, including revoked IDs; issuance retries at most three
times and never overwrites an existing record. Only literal `True` acknowledges
insertion/revocation. `lookup` must return the current canonical record and must
not fall back to stale records during an outage. `revoke` must atomically and
monotonically mark a known ID revoked; repeated revocation succeeds. The supplied
`InMemoryApiKeyStore` uses a thread lock and immutable records. It is not a secure
production key store, durable revocation database, or multi-process backend.
Losing it loses records and revocation history. A backend error after a write
may leave an unpresented orphan record; do not retry an uncertain revocation as
though it had succeeded. Production operations need durable reconciliation.

## Verification, expiration, and revocation

Every verification strictly parses the credential, looks up the ID, validates
the record, recomputes the keyed verifier, and compares fixed-length bytes with
`hmac.compare_digest`. Unknown, malformed, wrongly typed, expired, revoked,
inconsistent, or unverifiable inputs return `None`. Store, HMAC, comparison,
and clock exceptions also deny. The entire request path is **not** constant-time:
unknown IDs and malformed inputs exit early. Only verifier comparison has that
guarantee; prevent enumeration through uniform HTTP errors and rate limits.

The clock must return a finite nonnegative number. Creation metadata is integer
Unix seconds; expiration is an explicitly supplied integer and valid only while
`created_at <= now < expires_at`. There is no expiry grace period. A trusted
time source and rollback resistance are **not implemented**. A rollback within
a previous validity interval can extend validity; injected time is trusted.

No identity or allow decision is cached. Existing authorizer calls reverify
current state. Revocation applies to subsequent lookups on that store object;
it does not cancel already authorized or running work. Lookup, verification,
authorization, and later data access are not one transaction. Production
adapters must specify consistency and handle revocation/ownership races at the
actual operation, across replicas and restarts.

## Rotation

For customer-key rotation, issue a replacement with server-approved grants,
deliver it once, and explicitly revoke the old ID after a bounded overlap.
Issuance alone does not revoke previous keys; this prototype does not implement
overlap deadlines, key-count limits, automatic replacement, or account disablement.

For verifier-secret rotation, each adapter has one configured secret. Replacing
it invalidates existing credentials under that adapter and requires key reissuance;
there is no fallback to previous secrets or plaintext-assisted migration. Old
adapters retaining the old secret can still verify old active keys, so operators
must retire every old adapter and revoke affected IDs consistently. This is not
a distributed rotation service. Restoring an old secret does not undo revocation
in a retained store, but stale backups can restore revoked records and must not
be trusted without a durable revocation strategy.

## Commercial authorization and STOP isolation

Future trusted route code must choose a fixed commercial capability enum and
call `CommercialAuthorizer.authorize(credential, capability, resource_id)`.
Proceed only when `decision.allowed is True`. Resolve ownership server-side,
bind the checked resource and tenant to the actual query, and never accept tenant,
scope, principal, supervisor authority, or identity objects as request proof.
The evaluator remains advisory and is not automatically protected by this module.

There are no STOP, shutdown, execution, issuance, or policy-management grants.
The module imports no supervisor/control implementation and calls none. Customer
keys cannot authenticate signed supervisor commands; supervisor credentials and
command envelopes cannot authenticate customer access. Trusted-parent emergency
STOP and signed external STOP remain independent of customer-key issuance,
expiration, revocation, and verifier outages. Keep credentials, stores, issuers,
deployment permissions, and revocation domains separate. Python does not enforce
isolation against malicious code already running in the trusted parent process.

## Production and HTTP prerequisites

Before any authenticated HTTP service or paid subscription:

- Implement independently verified accounts, tenant membership, provisioning,
  account disablement, and separate authenticated key-management authorization.
- Provision a reviewed secure key store, secret manager, durable revocation,
  consistent current reads, collision constraints, backup protections, compromise
  response, rotation/overlap policy, and trusted rollback-resistant time.
- Enforce tenant-bound data access and race semantics; never cache allow decisions.
- Add TLS, credential-header handling, transport/body limits, uniform public
  errors, log/trace/analytics redaction, safe one-time delivery, rate limits,
  quotas, and audit events containing only approved nonsecret metadata.
- Test denied requests cannot reach evaluation or usage reads. Add metering and
  billing separately; neither is implemented by `usage:read` authorization.
- Obtain founder and security review. This foundation is not production approval.

## Offline validation

Focused tests are in `tests/test_commercial_api_keys.py`, alongside unchanged
commercial identity, evaluation, identity, external-command, and STOP regressions.
Threaded tests exercise only in-process locks; they start no workers or subprocesses.
Do not run sandbox, subprocess, acceptance, or other worker-executing tests for
this phase. No network, package download, host modification, or deployment is needed.

The public website remains https://gvaisafety.com, contact remains
contact@gvaisafety.com, and GvAI.io is preserved.
