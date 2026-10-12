from dataclasses import replace

import pytest

from gvai.identity import (
    INTERNAL_TENANT_ID,
    AuthorizationDecision,
    IdentityAuthority,
    IdentityAuthorizer,
    IdentityContext,
    IdentityPolicy,
    IdentityScope,
    TenantResource,
    VerifiedIdentityClaims,
)


POLICY = IdentityPolicy(
    {
        (IdentityScope.INTERNAL, "engineer"): frozenset(
            {"repo:read", "tool:tests.run"}
        ),
        (IdentityScope.INTERNAL, "security"): frozenset(
            {"audit:read", "tool:audit.search"}
        ),
        (IdentityScope.CUSTOMER, "business"): frozenset(
            {"regional:read", "tool:regional.analyze"}
        ),
        (IdentityScope.CUSTOMER, "government"): frozenset(
            {"regional:read", "tool:regional.analyze", "tool:scenario.run"}
        ),
    }
)


class CredentialVerifier:
    def __init__(self, verified: dict[object, VerifiedIdentityClaims]) -> None:
        self._verified = verified

    def verify(self, evidence: object) -> VerifiedIdentityClaims | None:
        return self._verified.get(evidence)


def customer_claims(principal: str, tenant: str) -> VerifiedIdentityClaims:
    return VerifiedIdentityClaims(
        principal_id=principal,
        tenant_id=tenant,
        scope=IdentityScope.CUSTOMER,
        role="business",
        capabilities=frozenset({"regional:read", "tool:regional.analyze"}),
    )


def make_authority():
    claims = {
        "customer-a-credential": customer_claims("customer-a", "tenant-a"),
        "customer-b-credential": customer_claims("customer-b", "tenant-b"),
        "engineer-credential": VerifiedIdentityClaims(
            principal_id="engineer-1",
            tenant_id=INTERNAL_TENANT_ID,
            scope=IdentityScope.INTERNAL,
            role="engineer",
            capabilities=frozenset({"repo:read", "tool:tests.run"}),
        ),
        "security-credential": VerifiedIdentityClaims(
            principal_id="security-1",
            tenant_id=INTERNAL_TENANT_ID,
            scope=IdentityScope.INTERNAL,
            role="security",
            capabilities=frozenset({"audit:read", "tool:audit.search"}),
        ),
    }
    return IdentityAuthority(CredentialVerifier(claims), POLICY)


def test_identity_context_can_only_be_issued_by_authority():
    with pytest.raises(TypeError, match="IdentityAuthority"):
        IdentityContext(
            principal_id="forged",
            tenant_id=INTERNAL_TENANT_ID,
            scope=IdentityScope.INTERNAL,
            role="security",
            capabilities=frozenset({"tool:audit.search"}),
        )


def test_malformed_unissued_context_is_denied_without_exception():
    forged = object.__new__(IdentityContext)
    result = IdentityAuthorizer(POLICY).authorize_capability(
        forged,
        "repo:read",
    )

    assert result == AuthorizationDecision(False, "unverified_identity")


def test_unverified_request_payload_cannot_assert_internal_identity():
    authority = make_authority()
    forged_payload = {
        "principal_id": "attacker",
        "tenant_id": INTERNAL_TENANT_ID,
        "scope": "internal",
        "role": "security",
        "capabilities": ["tool:audit.search"],
    }

    assert authority.authenticate(forged_payload) is None
    assert authority.authenticate(None) is None


def test_internal_scope_requires_verified_internal_claims():
    authority = make_authority()

    engineer = authority.authenticate("engineer-credential")
    security = authority.authenticate("security-credential")

    assert engineer is not None
    assert engineer.scope is IdentityScope.INTERNAL
    assert engineer.tenant_id == INTERNAL_TENANT_ID
    assert security is not None
    assert security.role == "security"


@pytest.mark.parametrize(
    "claims",
    [
        VerifiedIdentityClaims(
            principal_id="p1",
            tenant_id="tenant-a",
            scope=IdentityScope.CUSTOMER,
            role="unknown-role",
            capabilities=frozenset(),
        ),
        VerifiedIdentityClaims(
            principal_id="p2",
            tenant_id=INTERNAL_TENANT_ID,
            scope=IdentityScope.CUSTOMER,
            role="business",
            capabilities=frozenset({"regional:read"}),
        ),
        VerifiedIdentityClaims(
            principal_id="p3",
            tenant_id="tenant-a",
            scope="internal",
            role="security",
            capabilities=frozenset({"tool:audit.search"}),
        ),
        VerifiedIdentityClaims(
            principal_id="p4",
            tenant_id="tenant-a",
            scope=IdentityScope.CUSTOMER,
            role="security",
            capabilities=frozenset(),
        ),
    ],
)
def test_unknown_roles_and_forged_scope_tenant_combinations_fail_closed(claims):
    authority = IdentityAuthority(CredentialVerifier({"credential": claims}), POLICY)

    assert authority.authenticate("credential") is None


def test_claimed_capability_outside_role_grants_is_privilege_escalation():
    claims = replace(
        customer_claims("customer-a", "tenant-a"),
        capabilities=frozenset({"regional:read", "tool:tests.run"}),
    )
    authority = IdentityAuthority(CredentialVerifier({"credential": claims}), POLICY)

    assert authority.authenticate("credential") is None


def test_verification_absence_or_failure_never_creates_identity():
    class BrokenVerifier:
        def verify(self, _evidence):
            raise RuntimeError("auth service unavailable")

    authority = IdentityAuthority(BrokenVerifier(), POLICY)
    assert authority.authenticate("anything") is None


def test_customers_are_isolated_from_each_others_tenant_resources():
    authority = make_authority()
    authorizer = IdentityAuthorizer(POLICY)
    customer_a = authority.authenticate("customer-a-credential")
    customer_b = authority.authenticate("customer-b-credential")
    tenant_a_resource = TenantResource(
        IdentityScope.CUSTOMER,
        "tenant-a",
        "region-1",
    )
    tenant_b_resource = TenantResource(
        IdentityScope.CUSTOMER,
        "tenant-b",
        "region-2",
    )

    assert authorizer.authorize_resource(
        customer_a, tenant_a_resource, "regional:read"
    ) == AuthorizationDecision(True, "authorized")
    assert authorizer.authorize_resource(
        customer_a, tenant_b_resource, "regional:read"
    ) == AuthorizationDecision(False, "tenant_mismatch")
    assert authorizer.authorize_resource(
        customer_b, tenant_a_resource, "regional:read"
    ) == AuthorizationDecision(False, "tenant_mismatch")


def test_internal_and_customer_scopes_cannot_cross():
    authority = make_authority()
    authorizer = IdentityAuthorizer(POLICY)
    engineer = authority.authenticate("engineer-credential")
    customer = authority.authenticate("customer-a-credential")
    customer_resource = TenantResource(
        IdentityScope.CUSTOMER,
        "tenant-a",
        "region-1",
    )
    internal_resource = TenantResource(
        IdentityScope.INTERNAL,
        INTERNAL_TENANT_ID,
        "repo-1",
    )

    assert authorizer.authorize_resource(
        engineer, internal_resource, "repo:read"
    ).allowed
    assert authorizer.authorize_resource(
        engineer, customer_resource, "repo:read"
    ) == AuthorizationDecision(False, "scope_mismatch")
    assert authorizer.authorize_resource(
        customer, internal_resource, "regional:read"
    ) == AuthorizationDecision(False, "scope_mismatch")


def test_tools_require_known_named_capability_and_matching_scope():
    authority = make_authority()
    authorizer = IdentityAuthorizer(POLICY)
    customer = authority.authenticate("customer-a-credential")
    engineer = authority.authenticate("engineer-credential")

    assert authorizer.authorize_tool(
        customer,
        "regional.analyze",
        scope=IdentityScope.CUSTOMER,
    ).allowed
    assert authorizer.authorize_tool(
        customer,
        "tests.run",
        scope=IdentityScope.CUSTOMER,
    ) == AuthorizationDecision(False, "capability_not_granted")
    assert authorizer.authorize_tool(
        customer,
        "unregistered.tool",
        scope=IdentityScope.CUSTOMER,
    ) == AuthorizationDecision(False, "unknown_tool")
    assert authorizer.authorize_tool(
        customer,
        "regional.analyze",
        scope=IdentityScope.INTERNAL,
    ) == AuthorizationDecision(False, "scope_mismatch")
    assert authorizer.authorize_tool(
        engineer,
        "audit.search",
        scope=IdentityScope.INTERNAL,
    ) == AuthorizationDecision(False, "capability_not_granted")


def test_missing_identity_unknown_capability_and_missing_grants_deny():
    authorizer = IdentityAuthorizer(POLICY)
    identity = make_authority().authenticate("customer-a-credential")

    assert authorizer.authorize_capability(
        None, "regional:read"
    ) == AuthorizationDecision(False, "missing_identity")
    assert authorizer.authorize_capability(
        identity, "unregistered:capability"
    ) == AuthorizationDecision(False, "unknown_capability")
    assert authorizer.authorize_capability(
        identity, "tool:scenario.run"
    ) == AuthorizationDecision(False, "capability_not_granted")
