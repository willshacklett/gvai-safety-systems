# Identity and Authorization Foundation V1

## Scope

This module provides framework-independent identity-context and authorization contracts for a future GVAI Intelligence gateway. It is not a production login, authentication provider, session system, customer API, or multi-tenant deployment. It performs no network access and provisions no credentials.

## Trust boundary

`IdentityAuthority` accepts opaque evidence only through an injected `IdentityVerifier`. The verifier is the independent authentication boundary: it must validate evidence using a separately trusted identity source and return `VerifiedIdentityClaims` only after successful verification. It must not copy role, scope, tenant, or capabilities from untrusted request fields. Missing results and verifier errors deny identity creation.

`IdentityContext` cannot be constructed through its public initializer; it is issued by `IdentityAuthority` after claim validation. `IdentityScope.INTERNAL` is a distinct verified claim and is never inferred from a role name or tenant string. Internal identities must use the reserved `gvai-internal` tenant. Customer identities cannot use that tenant. The authority checks each verified role against an explicitly supplied trusted `IdentityPolicy` and rejects claims that exceed the role's grants.

Python module boundaries are not a sandbox against malicious code already executing in the trusted process. Callers must keep the verifier, policy, and issued contexts outside the governed agent's control. Do not treat HTTP headers, decoded tokens, arbitrary mappings, agent-provided claims, or direct object construction as proof of identity.

## Authorization

`IdentityAuthorizer` denies missing or unissued contexts, unknown capabilities/tools, absent grants, scope mismatches, and tenant mismatches. Resource authorization requires exact scope and tenant equality. Tool authorization requires a named `tool:<name>` capability granted by the trusted role policy. There are no implicit grants: an empty or incomplete policy denies by default.

The role-to-capability mapping is trusted configuration. It should be split deliberately between internal roles and customer roles; shared role names do not cross scopes. Tenant identity comes from verified claims and is compared to the resource tenant on each authorization decision.

## Future integration

A future API should authenticate at a trusted boundary, construct the context through `IdentityAuthority`, and pass that context to server-side authorization before data access or tool dispatch. A future model gateway should receive only the least-privilege context and tool set. Safety policy, invariant enforcement, and external shutdown authority remain separate trusted controls and cannot be granted or modified by an agent identity.
