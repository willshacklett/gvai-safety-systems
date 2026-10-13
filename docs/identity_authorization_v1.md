# Identity and Authorization Foundation V1

## Scope

This module provides framework-independent identity-context and authorization contracts for a future GVAI Intelligence gateway. It is not a production login, authentication provider, session system, customer API, or multi-tenant deployment. It performs no network access and provisions no credentials.

## Trust boundary

`IdentityAuthority` accepts opaque evidence only through an injected `IdentityVerifier`. The verifier is the independent authentication boundary: it must validate evidence using a separately trusted identity source and return `VerifiedIdentityClaims` only after successful verification. It must not copy role, scope, tenant, or capabilities from untrusted request fields. Missing results and verifier errors deny identity creation.

`IdentityContext` cannot be constructed through its public initializer; it is issued by `IdentityAuthority` after claim validation. `IdentityScope.INTERNAL` is a distinct verified claim and is never inferred from a role name or tenant string. Internal identities must use the reserved `gvai-internal` tenant. Customer identities cannot use that tenant. The authority checks each verified role against an explicitly supplied trusted `IdentityPolicy` and rejects claims that exceed the role's grants.

Python module boundaries are not a sandbox against malicious code already executing in the trusted process. Frozen dataclasses and the context issuance seal prevent ordinary construction or accidental mutation, but Python reflection such as `object.__setattr__` is not a security boundary. Keep the verifier, policy, and issued contexts server-side and outside the governed agent's control; do not serialize or hand contexts to untrusted agents or plugins. Do not treat HTTP headers, decoded tokens, arbitrary mappings, agent-provided claims, or direct object construction as proof of identity.

## Authorization

`IdentityAuthorizer` denies missing or unissued contexts, unknown capabilities/tools, absent grants, scope mismatches, and tenant mismatches. Resource authorization requires exact scope and tenant equality. Tool authorization requires a named `tool:<name>` capability granted by the trusted role policy. There are no implicit grants: an empty or incomplete policy denies by default.

The role-to-capability mapping is trusted configuration. It should be split deliberately between internal roles and customer roles; shared role names do not cross scopes. Each authorization rechecks the requested capability against the current policy entry for the exact `(scope, role)` as well as the capability set captured in the issued context. A removed or reassigned grant therefore denies stale contexts. Tenant identity comes from verified claims and is compared to the resource tenant on each authorization decision.

`TenantResource` is metadata, not proof of ownership. `authorize_resource` compares the supplied `scope` and `tenant_id`; it does not resolve `resource_id` or verify those labels against a data store. A future API must obtain this metadata from a trusted server-side resource/ownership lookup using the resource identifier. Never populate `TenantResource` from request headers, request payloads, or model output. Until that integration exists, this module alone cannot guarantee tenant isolation for caller-supplied resource labels.

## Future integration

A future API should authenticate at a trusted boundary, construct the context through `IdentityAuthority`, and pass that context to server-side authorization before data access or tool dispatch. A future model gateway should receive only the least-privilege context and tool set. Safety policy, invariant enforcement, and external shutdown authority remain separate trusted controls and cannot be granted or modified by an agent identity.
