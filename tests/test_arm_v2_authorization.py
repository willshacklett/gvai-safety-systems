"""Stage A verifies wire authority only, never activation or freshness."""

import json
from dataclasses import FrozenInstanceError, replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_stop_latch as sl


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def canonical(envelope):
    return json.dumps(
        envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


@pytest.fixture
def rig():
    stop, legacy, arm = [Ed25519PrivateKey.generate() for _ in range(3)]
    ring = sl.ArmV2Keyring(
        {"stop": public(stop)}, {"legacy": public(legacy)},
        {"v2": sl.ArmV2VerificationKey("authority", "supervisor", public(arm))},
    )
    unsigned = sl.ArmV2Authorization(
        "latch", 1, "v2", "authority", "supervisor", "auth-1", 0, 100, 110,
        bytes(64),
    )
    signed = replace(unsigned, signature=arm.sign(unsigned.signing_bytes()))
    return ring, signed, stop, legacy, arm


def v1(key, kind):
    key_id = "stop" if kind == "stop" else "legacy"
    return {
        "version": 1, "latch_id": "latch", "sequence": 1,
        "command_type": kind, "key_id": key_id,
        "signature": key.sign(sl.signing_bytes("latch", 1, kind, key_id)).hex(),
    }


def test_positive_canonical_vector_roundtrip_and_signature(rig):
    ring, signed, *_ = rig
    expected = (
        b'GVAI-ARM-AUTHORIZATION-V2\n'
        b'{"authority_id":"authority","authorization_id":"auth-1",'
        b'"command_type":"arm","key_id":"v2","latch_id":"latch",'
        b'"not_after":110,"not_before":100,"sequence":1,"stop_generation":0,'
        b'"trust_domain":"supervisor","version":2}'
    )
    assert signed.signing_bytes() == expected
    envelope = sl.arm_v2_envelope(signed)
    assert sl.parse_arm_v2(dict(reversed(list(envelope.items())))) == signed
    assert sl.decode_authorization_command(canonical(envelope), require_arm_v2=True) == signed
    assert ring.verify_arm_v2(signed, expected_latch_id="latch")
    with pytest.raises(FrozenInstanceError):
        signed.not_after = 111


@pytest.mark.parametrize("field", sorted(sl._ARM_V2_FIELDS))
def test_each_missing_field_rejected(rig, field):
    envelope = sl.arm_v2_envelope(rig[1])
    del envelope[field]
    with pytest.raises(ValueError, match="malformed_envelope"):
        sl.parse_arm_v2(envelope)


@pytest.mark.parametrize("value", [None, [], "arm", 1, b"{}"])
def test_non_mapping_rejected(value):
    with pytest.raises(ValueError):
        sl.parse_arm_v2(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("extra", 1), ("version", True), ("version", 1), ("version", 2.0),
        ("command_type", "stop"), ("command_type", None),
        ("signature", "A" * 128), ("signature", "0" * 126),
        ("signature", "g" * 128), ("signature", None),
    ] + [
        (field, value)
        for field in ("sequence", "stop_generation", "not_before", "not_after")
        for value in (True, None, "100", 100.0, -1, 2**53 + 1, float("nan"), float("inf"))
    ] + [
        (field, value)
        for field in ("latch_id", "key_id", "authority_id", "trust_domain", "authorization_id")
        for value in ("", "a b", "\u00e9", "a" * 129, None, 1)
    ] + [("sequence", 0), ("not_before", 110), ("not_before", 111), ("not_after", 100)],
)
def test_malformed_fields_rejected(rig, field, value):
    with pytest.raises(ValueError):
        sl.parse_arm_v2(dict(sl.arm_v2_envelope(rig[1]), **{field: value}))


@pytest.mark.parametrize("field", [
    "latch_id", "key_id", "authority_id", "trust_domain", "authorization_id",
    "sequence", "stop_generation", "not_before", "not_after", "signature",
])
def test_direct_construction_cannot_bypass_validation(rig, field):
    with pytest.raises(ValueError):
        replace(rig[1], **{field: None})


@pytest.mark.parametrize("generation", [0, 2**53])
def test_numeric_boundaries_and_genesis_are_structural_only(rig, generation):
    ring, signed, _, _, arm = rig
    unsigned = replace(
        signed, sequence=2**53, stop_generation=generation,
        not_before=0, not_after=2**53,
    )
    signed = replace(unsigned, signature=arm.sign(unsigned.signing_bytes()))
    assert sl.parse_arm_v2(sl.arm_v2_envelope(signed)) == signed
    assert ring.verify_arm_v2(signed, expected_latch_id="latch")


@pytest.mark.parametrize("field,value", [
    ("latch_id", "other"), ("sequence", 2), ("key_id", "other"),
    ("authority_id", "other"), ("trust_domain", "other"),
    ("authorization_id", "other"), ("stop_generation", 1),
    ("not_before", 99), ("not_after", 111), ("signature", "0" * 128),
])
def test_signature_tampering_rejected_by_production_verifier(rig, field, value):
    ring, signed, *_ = rig
    parsed = sl.parse_arm_v2(dict(sl.arm_v2_envelope(signed), **{field: value}))
    assert not ring.verify_arm_v2(parsed, expected_latch_id="latch")


@pytest.mark.parametrize("field,value", [
    ("authority_id", "other"), ("trust_domain", "other"),
    ("key_id", "legacy"), ("key_id", "stop"), ("latch_id", "other"),
])
def test_valid_signature_cannot_override_pinned_binding(rig, field, value):
    ring, signed, _, _, arm = rig
    changed = replace(signed, **{field: value})
    changed = replace(changed, signature=arm.sign(changed.signing_bytes()))
    assert not ring.verify_arm_v2(changed, expected_latch_id="latch")


def test_wrong_signers_and_domains_rejected(rig):
    ring, signed, stop, legacy, arm = rig
    for key in (stop, legacy, Ed25519PrivateKey.generate()):
        forged = replace(signed, signature=key.sign(signed.signing_bytes()))
        assert not ring.verify_arm_v2(forged, expected_latch_id="latch")
    for payload in (
        sl.signing_bytes("latch", 1, "arm", "v2"),
        signed.signing_bytes()[len(sl.ARM_V2_DOMAIN):],
    ):
        forged = replace(signed, signature=arm.sign(payload))
        assert not ring.verify_arm_v2(forged, expected_latch_id="latch")


@pytest.mark.parametrize("before,after", [(0, 1), (2**53 - 1, 2**53)])
def test_verification_is_not_expiration_or_generation_enforcement(rig, before, after):
    ring, signed, _, _, arm = rig
    authorization = replace(
        signed, not_before=before, not_after=after, stop_generation=2**53,
    )
    authorization = replace(
        authorization, signature=arm.sign(authorization.signing_bytes()),
    )
    assert ring.verify_arm_v2(authorization, expected_latch_id="latch")


@pytest.mark.parametrize("field,value", [
    ("version", 3), ("version", True), ("command_type", "stop"),
])
def test_dispatcher_does_not_downgrade_malformed_v2(rig, field, value):
    envelope = dict(sl.arm_v2_envelope(rig[1]), **{field: value})
    with pytest.raises(ValueError):
        sl.parse_authorization_command(envelope)


@pytest.mark.parametrize("require", [False, True])
def test_v1_stop_bytes_digest_and_verification_unchanged(rig, require):
    ring, _, stop, legacy, _ = rig
    envelope = v1(stop, "stop")
    baseline = sl.parse_command(envelope)
    parsed = sl.parse_authorization_command(envelope, require_arm_v2=require)
    assert parsed == baseline
    assert parsed.signing_bytes() == baseline.signing_bytes()
    assert parsed.digest() == baseline.digest()
    assert sl.command_envelope(parsed) == envelope
    assert sl.decode_authorization_command(canonical(envelope), require_arm_v2=require) == baseline
    assert ring.verify(parsed)
    original = sl.StopLatchKeyring({"stop": public(stop)}, {"legacy": public(legacy)})
    assert original.verify(parsed)


def test_legacy_policy_is_not_wired_to_live_latch(rig):
    ring, signed, stop, legacy, _ = rig
    envelope = v1(legacy, "arm")
    assert ring.verify(sl.parse_authorization_command(envelope))
    with pytest.raises(ValueError, match="legacy_arm_rejected"):
        sl.parse_authorization_command(envelope, require_arm_v2=True)
    with pytest.raises(ValueError, match="legacy_arm_rejected"):
        sl.decode_authorization_command(canonical(envelope), require_arm_v2=True)
    anchor, store = sl.InMemoryTrustedAnchor(), sl.InMemoryCommandStore()
    latch = sl.StopLatch("latch", ring, anchor, store)
    assert sl.parse_authorization_command(sl.arm_v2_envelope(signed)) == signed
    assert ring.verify_arm_v2(signed, expected_latch_id="latch")
    assert anchor.read() == sl.GENESIS_HEAD and store.load() is None
    assert not latch.permit().allowed
    assert not latch.apply(sl.arm_v2_envelope(signed)).accepted
    assert latch.apply(envelope).accepted
    assert latch.permit().allowed


@pytest.mark.parametrize("raw", [
    None, "", b"", b"\xff", b"{", b"[]" , b"null",
    b'{"version":2,"version":2}', b'{"x":{"x":1,"x":2}}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
    b" " * (sl.ARM_V2_MAX_JSON_BYTES + 1),
    b"[" * 2000 + b"]" * 2000,
])
def test_raw_json_faults_rejected(raw):
    with pytest.raises(ValueError):
        sl.decode_authorization_command(raw)


def test_noncanonical_json_rejected(rig):
    envelope = sl.arm_v2_envelope(rig[1])
    for raw in (
        canonical(envelope) + b"\n",
        json.dumps(envelope).encode("utf-8"),
        canonical(envelope).replace(b'"latch"', b'"\\u006catch"'),
        canonical(envelope).replace(b'"sequence":1', b'"sequence":1.0'),
    ):
        with pytest.raises(ValueError):
            sl.decode_authorization_command(raw)
    with pytest.raises(ValueError):
        sl.parse_authorization_command(envelope, require_arm_v2="yes")


def test_json_size_boundary(rig):
    raw = canonical(sl.arm_v2_envelope(rig[1]))
    with pytest.raises(ValueError, match="noncanonical_json"):
        sl.decode_authorization_command(raw + b" " * (sl.ARM_V2_MAX_JSON_BYTES - len(raw)))
    with pytest.raises(ValueError, match="invalid_json_size_or_type"):
        sl.decode_authorization_command(raw + b" " * (sl.ARM_V2_MAX_JSON_BYTES + 1 - len(raw)))


def test_key_configuration_rejects_reuse_and_bad_bindings(rig):
    _, _, stop, legacy, arm = rig
    stops, arms = {"stop": public(stop)}, {"legacy": public(legacy)}
    binding = sl.ArmV2VerificationKey("authority", "supervisor", public(arm))
    bad_maps = [
        {}, {"stop": binding}, {"": binding}, {"v2": public(arm)},
        {"v2": sl.ArmV2VerificationKey("authority", "supervisor", public(stop))},
        {"v2": sl.ArmV2VerificationKey("authority", "supervisor", public(legacy))},
        {"v2": binding, "v3": binding},
    ]
    for keys in bad_maps:
        with pytest.raises(sl.StopLatchConfigError):
            sl.ArmV2Keyring(stops, arms, keys)
    with pytest.raises(sl.StopLatchConfigError):
        sl.ArmV2Keyring(stops, arms, {"v2": binding}, [public(arm)])
    for values in (("", "supervisor", public(arm)), ("authority", None, public(arm)),
                   ("authority", "supervisor", b"short"),
                   ("authority", "supervisor", arm)):
        with pytest.raises(sl.StopLatchConfigError):
            sl.ArmV2VerificationKey(*values)


def test_verification_api_errors_are_explicit_and_no_signing_api(rig):
    ring, signed, *_ = rig
    with pytest.raises(ValueError, match="invalid_latch_id"):
        ring.verify_arm_v2(signed, expected_latch_id="")
    with pytest.raises(ValueError, match="invalid_authorization_type"):
        ring.verify_arm_v2(None, expected_latch_id="latch")
    assert not hasattr(ring, "sign")
    assert not hasattr(sl, "sign_command")
