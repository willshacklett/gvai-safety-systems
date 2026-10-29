# Trusted Commercial Identity Foundation V1

## Status

Phase 6C adds an offline, server-side authorization contract in
`gvai/commercial_identity.py`. It is not production authentication, an HTTP
service, a tenant database, an API-key issuer, or launch approval. The $99/month
subscription remains a future business target. No accounts, live credentials,
network calls, billing, worker execution, or deployment changes are included.

## Trusted identity boundary

`CommercialAuthorizer` is constructed by trusted server code with an independent
`CustomerIdentityVerifier`, `CommercialOwnershipStore`, and trusted clock.
Only an opaque credential string is passed to the verifier. Request mappings,
identity objects, internal identity contexts, and STOP command envelopes are
not credentials. Missing evidence, unknown evidence, malformed verifier output,
and verifier exceptions deny access.

The verifier must authenticate the evidence in a dedicated customer credential
namespace, check current revocation and account/tenant membership status, and
derive principal, tenant, grants, and expiry from authoritative server state.
It must never copy tenant, role, scope, capabilities, or expiry from request
fields or merely decode an unsigned token. Internal supervisor credentials must
not be registered or accepted by this verifier. A credential string alone is
not proof; the injected verifier is the authentication trust boundary.

`VerifiedCustomerIdentity` is verifier output, not a token, sealed identity,
request schema, or public constructor-based proof. It deliberately has no role
or internal scope. The reserved `gvai-internal` tenant and all noncommercial
grants are rejected. Only exact typed records and capability enums are accepted.
An empty grant set grants nothing. Every authorization invokes the verifier
again; no reusable identity context or allow token is issued.

## Resource ownership and capabilities

The caller may select a resource ID, but cannot provide its tenant or kind.
`lookup(resource_id)` must resolve the current canonical record from trusted
server-owned state. IDs must be unique across this store; an implementation
must not search a caller-selected tenant or trust caller-supplied ownership
labels. It must return `None` for unknown, deleted, or unowned resources, never
infer ownership from ID prefixes or create ownership on demand.

| Server-selected capability | Required resource kind | Meaning |
| --- | --- | --- |
| `CommercialCapability.EVALUATE` (`evaluation:run`) | `EVALUATION` | Authorize advisory evaluation against an existing evaluation resource |
| `CommercialCapability.READ_USAGE` (`usage:read`) | `USAGE` | Authorize reading a tenant-owned usage resource |

Resource ID, tenant, and kind must be valid; the lookup must return the exact
requested ID. The verified customer tenant must equal the stored owner tenant.
Capabilities cannot cross resource kinds. Missing data, mismatches, malformed
records, and lookup exceptions deny access. Ownership is looked up on every
call; no caller-provided `TenantResource` is accepted. Provisioning resources
and tenant membership is outside this contract.

The future route must choose a fixed capability enum in server code, call
`authorize(credential, capability, resource_id)`, and proceed only when
`decision.allowed is True`. Authorization performs no evaluation or data read;
the existing advisory evaluator remains unchanged and is not automatically
protected by this component. Usage-read authorization does not implement usage
metering or storage. Neither request IDs nor telemetry confer ownership.

## Default-deny outcomes

`CommercialAuthorizationDecision.reason` is a
`CommercialAuthorizationReason` enum; `allowed` is true only for `AUTHORIZED`.
`bool(decision)` equals `decision.allowed`: authorized decisions evaluate true,
and every denial evaluates false. This is a fail-closed safeguard against
accidental Boolean use, not a replacement for explicit authorization checks.
Integrations must still check `decision.allowed is True` before proceeding.
Denials distinguish missing/invalid identity, verification failure, revocation,
expiry, unsupported/ungranted capability, invalid/unknown resource, invalid
ownership, lookup failure, tenant/kind mismatch, and authorization failure.
Unexpected validation and clock exceptions produce `AUTHORIZATION_FAILED`.
Expiry is exclusive: `now >= expires_at` denies, with no grace period. Time
must be a finite nonnegative number from the trusted clock.

The component emits no logs and returns no credential, full identity, ownership
record, or underlying exception text. Successful decisions include the resolved
`tenant_id` for immediate server-side data binding; denied decisions use `None`.
This field is excluded from repr, must not be copied from request claims, and
does not make the decision a reusable permit or public response schema.
Future adapters and middleware must also
redact credential material, including from tracing and error reports. These
typed reasons are internal diagnostics: future HTTP responses must avoid
resource enumeration by mapping unknown and unauthorized resources to a
uniform public response.

## Threat assumptions and STOP isolation

Untrusted customers may forge claims, choose other tenants' resource IDs,
submit internal credential objects, and retry stale credentials. Those inputs
do not grant authority. The verifier, ownership backend, clock, server code,
and dependency injection are independently trusted and outside the customer's
or governed agent's control. A compromised trusted adapter can lie; structural
validation cannot detect authoritative-looking false ownership or grants.
Python objects and module boundaries do not defend against malicious code
already executing in the trusted process.

There is no customer capability for STOP, shutdown, execution, policy changes,
credential issuance, or authority expansion. This module imports no supervisor
or external-command implementation and invokes none. Existing signed command
verification, replay protection, and trusted-parent emergency STOP remain
separate under `external_control_contract_v1.md`. Customer and supervisor keys,
issuers, storage, and revocation domains must remain separate in any deployment.
Never let the thing behind the switch own the switch.

## Known limitations and HTTP prerequisites

- Phase 6C fixtures supply a test-only verifier and ownership store in
  `tests/test_commercial_identity.py`; their opaque labels are not real API
  keys. Phase 6D adds a separate offline API-key verifier reference, documented
  below. Neither phase supplies a production authentication or ownership backend.
- There is no durable account, tenant membership, ownership, or revocation
  backend, distributed consistency guarantee, replay defense for customer
  requests, rate limit, quota, billing, or HTTP transport.
- Verification and lookup are not a transaction. An allow decision is a
  point-in-time check, not a durable permit or cancellation mechanism. Future
  data access must bind the checked resource and tenant to the actual query
  and handle ownership/revocation races atomically as required. Do not cache
  allow decisions or reuse them for another resource or operation.
- Clock correctness and rollback resistance are deployment requirements; the
  injected clock is trusted. Expiry is checked after ownership lookup, but a
  clock rollback can extend validity without an independent trusted time source.
- Before authenticated HTTP routes: implement and review real authentication,
  durable ownership/membership and revocation adapters, secure resource
  provisioning, tenant-bound data access, safe error mapping, TLS termination,
  request limits, rate limits, audit redaction, and fail-closed outage handling.
  Explicitly connect authorization before evaluation or usage reads and test
  that denied requests never reach either operation. Obtain founder approval.

## API-key lifecycle foundation

Phase 6E adds a separate offline [usage and quota reference](commercial_usage_v1.md).
It uses the tenant from the same authorization decision, reauthorizes each
operation, and adds no supervisor or quota-management capability. The original
evaluator remains unchanged and is not automatically metered. Durable storage
and production accounting remain unimplemented.

Phase 6F adds an offline [commercial evaluation service](commercial_service_v1.md)
that composes the API-key verifier, this authorizer through the usage facade,
and the unchanged pure evaluator. It does not add another authorization path,
worker execution, STOP access, HTTP routes, or billing.

Phase 6D now supplies an offline, nonproduction `CustomerIdentityVerifier`
adapter and process-local lifecycle reference in `gvai/commercial_api_keys.py`.
See [Customer API-Key Foundation V1](commercial_api_keys_v1.md) for issuance,
one-time presentation, keyed verifiers, expiry, revocation, rotation, and
remaining production requirements. The Phase 6C authorization contract is
unchanged; no production authentication or secure durable backend is supplied.

## Production API-key requirements

Future issuance must authenticate the customer through an independently trusted
account flow, establish tenant membership server-side, and allow only bounded
commercial grants. Generate high-entropy random secrets, show them once, and
store only an appropriate one-way verifier with a nonsecret lookup identifier;
never store or log raw keys. Define expiry, constant-time verification where
applicable, rotation, overlap limits, immediate durable revocation, compromise
response, and tenant/account disablement. Check revocation on every request
across replicas and restarts, with explicit fail-closed cache semantics. Key
management itself must not be authorized merely by these evaluation/usage
capabilities. The Phase 6D reference implements only the documented offline
subset; production key management remains unimplemented.
