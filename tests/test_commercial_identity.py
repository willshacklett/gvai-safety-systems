from dataclasses import replace

import pytest

from gvai.commercial_identity import (
    CommercialAuthorizationDecision,
    CommercialAuthorizationReason as Reason,
    CommercialAuthorizer,
    CommercialCapability as Capability,
    CommercialResourceKind as Kind,
    CommercialResourceOwnership as Ownership,
    VerifiedCustomerIdentity,
)
from gvai.identity import INTERNAL_TENANT_ID, IdentityScope, VerifiedIdentityClaims


class TestOnlyTrustedVerifier:
    """Test fixture only: opaque labels are NOT production authentication."""

    __test__ = False

    def __init__(self, identities):
        self.identities = identities
        self.calls = []

    def verify(self, credential):
        self.calls.append(credential)
        return self.identities.get(credential)


class TestOnlyOwnershipStore:
    """Test fixture only: not persistent, concurrent, or production-ready."""

    __test__ = False

    def __init__(self, resources):
        self.resources = resources
        self.calls = []

    def lookup(self, resource_id):
        self.calls.append(resource_id)
        return self.resources.get(resource_id)


@pytest.fixture
def boundary():
    identity = VerifiedCustomerIdentity(
        "customer-a", "tenant-a", frozenset(Capability), expires_at=2000
    )
    verifier = TestOnlyTrustedVerifier({"test-credential": identity})
    store = TestOnlyOwnershipStore(
        {
            "project-a": Ownership("project-a", "tenant-a", Kind.EVALUATION),
            "project-b": Ownership("project-b", "tenant-b", Kind.EVALUATION),
            "usage-a": Ownership("usage-a", "tenant-a", Kind.USAGE),
        }
    )
    return CommercialAuthorizer(verifier, store, clock=lambda: 1000), verifier, store


@pytest.mark.parametrize("reason", list(Reason))
def test_decision_boolean_and_explicit_allowed_checks_agree_for_every_reason(reason):
    decision = CommercialAuthorizationDecision(reason)
    expected = reason is Reason.AUTHORIZED

    assert decision.allowed is expected
    assert bool(decision) is decision.allowed
    branch_allowed = False
    if decision:
        branch_allowed = True
    assert branch_allowed is expected
    assert ("allow" if decision.allowed is True else "deny") == (
        "allow" if decision else "deny"
    )


@pytest.mark.parametrize(
    "capability,resource_id",
    [(Capability.EVALUATE, "project-a"), (Capability.READ_USAGE, "usage-a")],
)
def test_authorized_access_uses_trusted_verifier_and_ownership(boundary, capability, resource_id):
    authorizer, verifier, store = boundary
    result = authorizer.authorize("test-credential", capability, resource_id)
    assert result.allowed is True
    assert bool(result) is True
    assert result.reason is Reason.AUTHORIZED
    assert verifier.calls == ["test-credential"]
    assert store.calls == [resource_id]


@pytest.mark.parametrize(
    "credential,reason",
    [
        (None, Reason.MISSING_IDENTITY),
        ("", Reason.INVALID_IDENTITY),
        ("unknown", Reason.INVALID_IDENTITY),
        ("x" * 4097, Reason.INVALID_IDENTITY),
        (b"test-credential", Reason.INVALID_IDENTITY),
        ({"tenant_id": "tenant-a", "role": "admin", "scope": "internal",
          "capabilities": ["evaluation:run"]}, Reason.INVALID_IDENTITY),
    ],
)
def test_missing_invalid_or_self_declared_identity_denied(boundary, credential, reason):
    authorizer, _, store = boundary
    result = authorizer.authorize(credential, Capability.EVALUATE, "project-a")
    assert result.allowed is False
    assert bool(result) is False
    assert result.reason is reason
    assert store.calls == []


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"revoked": True}, Reason.REVOKED_IDENTITY),
        ({"expires_at": 1000}, Reason.EXPIRED_IDENTITY),
        ({"expires_at": 999}, Reason.EXPIRED_IDENTITY),
        ({"expires_at": True}, Reason.INVALID_IDENTITY),
        ({"expires_at": float("inf")}, Reason.INVALID_IDENTITY),
        ({"revoked": "false"}, Reason.INVALID_IDENTITY),
        ({"tenant_id": INTERNAL_TENANT_ID}, Reason.INVALID_IDENTITY),
        ({"tenant_id": ""}, Reason.INVALID_IDENTITY),
        ({"principal_id": None}, Reason.INVALID_IDENTITY),
        ({"capabilities": frozenset()}, Reason.CAPABILITY_NOT_GRANTED),
        ({"capabilities": frozenset({"evaluation:run"})}, Reason.INVALID_IDENTITY),
        ({"capabilities": frozenset({"supervisor:stop"})}, Reason.INVALID_IDENTITY),
        ({"capabilities": list(Capability)}, Reason.INVALID_IDENTITY),
    ],
)
def test_invalid_or_inactive_verified_identity_denied(boundary, changes, reason):
    authorizer, verifier, _ = boundary
    verifier.identities["test-credential"] = replace(
        verifier.identities["test-credential"], **changes
    )
    result = authorizer.authorize("test-credential", Capability.EVALUATE, "project-a")
    assert not result.allowed
    assert result.reason is reason


def test_claim_objects_are_not_credentials_or_compatible_internal_identities(boundary):
    authorizer, verifier, _ = boundary
    customer = verifier.identities["test-credential"]
    assert authorizer.authorize(customer, Capability.EVALUATE, "project-a").reason is Reason.INVALID_IDENTITY
    verifier.identities["test-credential"] = VerifiedIdentityClaims(
        "supervisor", INTERNAL_TENANT_ID, IdentityScope.INTERNAL,
        "security", frozenset({"evaluation:run", "supervisor:stop"}),
    )
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").reason is Reason.INVALID_IDENTITY


def test_cross_tenant_and_unknown_resources_denied(boundary):
    authorizer, _, _ = boundary
    cross_tenant = authorizer.authorize("test-credential", Capability.EVALUATE, "project-b")
    assert cross_tenant.reason is Reason.TENANT_MISMATCH
    assert cross_tenant.allowed is False
    assert bool(cross_tenant) is False
    unknown = authorizer.authorize("test-credential", Capability.EVALUATE, "unknown")
    assert unknown.reason is Reason.RESOURCE_NOT_FOUND
    assert unknown.allowed is False
    assert bool(unknown) is False


@pytest.mark.parametrize(
    "resource",
    [
        {},
        {"resource_id": "project-a", "tenant_id": "tenant-a", "kind": "evaluation"},
        Ownership("project-b", "tenant-a", Kind.EVALUATION),
        Ownership("project-a", None, Kind.EVALUATION),
        Ownership("project-a", "", Kind.EVALUATION),
        Ownership("project-a", INTERNAL_TENANT_ID, Kind.EVALUATION),
        Ownership("project-a", "tenant-a", "evaluation"),
    ],
)
def test_missing_or_inconsistent_ownership_denied(boundary, resource):
    authorizer, _, store = boundary
    store.resources["project-a"] = resource
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").reason is Reason.INVALID_OWNERSHIP


@pytest.mark.parametrize("resource_id", [None, "", "../project-a", {}, "x" * 129])
def test_invalid_resource_selector_denied(boundary, resource_id):
    authorizer, verifier, store = boundary
    result = authorizer.authorize("test-credential", Capability.EVALUATE, resource_id)
    assert result.reason is Reason.INVALID_RESOURCE
    assert verifier.calls == store.calls == []


@pytest.mark.parametrize(
    "capability",
    [None, "evaluation:run", "supervisor:stop", "shutdown", "policy:write", "tool:execute"],
)
def test_only_server_selected_commercial_capability_enum_is_accepted(boundary, capability):
    authorizer, verifier, store = boundary
    result = authorizer.authorize("test-credential", capability, "project-a")
    assert not result.allowed
    assert result.reason is Reason.UNSUPPORTED_CAPABILITY
    assert verifier.calls == store.calls == []


@pytest.mark.parametrize(
    "capability,resource_id",
    [(Capability.EVALUATE, "usage-a"), (Capability.READ_USAGE, "project-a")],
)
def test_capability_cannot_cross_resource_kind(boundary, capability, resource_id):
    authorizer, _, _ = boundary
    assert authorizer.authorize("test-credential", capability, resource_id).reason is Reason.RESOURCE_KIND_MISMATCH


def test_reverification_and_ownership_lookup_happen_on_every_call(boundary):
    authorizer, verifier, store = boundary
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").allowed
    store.resources["project-a"] = Ownership("project-a", "tenant-b", Kind.EVALUATION)
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").reason is Reason.TENANT_MISMATCH
    verifier.identities["test-credential"] = replace(verifier.identities["test-credential"], revoked=True)
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").reason is Reason.REVOKED_IDENTITY
    assert len(verifier.calls) == 3
    assert len(store.calls) == 2


@pytest.mark.parametrize("dependency,reason", [("verifier", Reason.VERIFICATION_FAILED), ("store", Reason.OWNERSHIP_LOOKUP_FAILED), ("clock", Reason.AUTHORIZATION_FAILED)])
def test_dependency_failures_are_typed_and_do_not_leak_secrets(boundary, dependency, reason, caplog, capsys):
    authorizer, verifier, store = boundary

    def fail(*_args):
        raise RuntimeError("secret-credential-must-not-leak")

    if dependency == "verifier":
        verifier.verify = fail
    elif dependency == "store":
        store.lookup = fail
    else:
        authorizer._clock = fail
    result = authorizer.authorize("test-credential", Capability.EVALUATE, "project-a")
    assert result.allowed is False
    assert bool(result) is False
    assert result.reason is reason
    captured = capsys.readouterr()
    output = repr(result) + caplog.text + captured.out + captured.err
    assert "secret-credential" not in output
    assert "test-credential" not in output


@pytest.mark.parametrize(
    "now,reason",
    [
        (float("nan"), Reason.AUTHORIZATION_FAILED),
        (float("inf"), Reason.AUTHORIZATION_FAILED),
        (-1, Reason.AUTHORIZATION_FAILED),
        (True, Reason.AUTHORIZATION_FAILED),
        ("1000", Reason.AUTHORIZATION_FAILED),
        (None, Reason.AUTHORIZATION_FAILED),
        (2000, Reason.EXPIRED_IDENTITY),
        (2001, Reason.EXPIRED_IDENTITY),
    ],
)
def test_unusable_clock_or_expiry_fails_closed(boundary, now, reason):
    _, verifier, store = boundary
    authorizer = CommercialAuthorizer(verifier, store, clock=lambda: now)
    result = authorizer.authorize("test-credential", Capability.EVALUATE, "project-a")
    assert result.allowed is False
    assert bool(result) is False
    assert result.reason is reason


def test_expiry_is_rechecked_without_reusing_an_allow_decision(boundary):
    _, verifier, store = boundary
    current_time = [1999]
    authorizer = CommercialAuthorizer(verifier, store, clock=lambda: current_time[0])
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").allowed
    current_time[0] = 2000
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").reason is Reason.EXPIRED_IDENTITY


def test_removed_credential_and_removed_ownership_deny_previous_access(boundary):
    authorizer, verifier, store = boundary
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").allowed
    del store.resources["project-a"]
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").reason is Reason.RESOURCE_NOT_FOUND
    del verifier.identities["test-credential"]
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").reason is Reason.INVALID_IDENTITY


@pytest.mark.parametrize(
    "verified,reason",
    [
        (None, Reason.INVALID_IDENTITY),
        ({}, Reason.INVALID_IDENTITY),
        (object.__new__(VerifiedCustomerIdentity), Reason.AUTHORIZATION_FAILED),
    ],
)
def test_malformed_verifier_output_never_authorizes(boundary, verified, reason):
    authorizer, verifier, _ = boundary
    verifier.identities["test-credential"] = verified
    result = authorizer.authorize("test-credential", Capability.EVALUATE, "project-a")
    assert result.allowed is False
    assert bool(result) is False
    assert result.reason is reason


def test_customer_authorization_cannot_invoke_evaluation_or_supervisor_controls(boundary, monkeypatch):
    from gvai import evaluation
    from gvai.external_control import GVExternalControlPlane
    from gvai.runtime_policy import GVRuntimePolicy

    def forbidden(*_args, **_kwargs):
        pytest.fail("authorization must not evaluate, execute, or reach STOP")

    monkeypatch.setattr(evaluation, "evaluate_request", forbidden)
    for control in (GVExternalControlPlane, GVRuntimePolicy):
        monkeypatch.setattr(control, "evaluate_internal_shutdown", forbidden)
        monkeypatch.setattr(control, "evaluate_command", forbidden)
    authorizer, _, _ = boundary
    assert authorizer.authorize("test-credential", Capability.EVALUATE, "project-a").allowed
    assert authorizer.authorize("test-credential", "shutdown", "project-a").reason is Reason.UNSUPPORTED_CAPABILITY
    assert authorizer.authorize(
        {"command_type": "shutdown", "auth": {"signature": "test-only"}},
        Capability.EVALUATE, "project-a",
    ).reason is Reason.INVALID_IDENTITY
