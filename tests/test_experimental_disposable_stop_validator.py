"""Synthetic, non-host fixtures for the I8E offline validation boundary."""

import copy
import hashlib
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_disposable_stop_validator as v


def public(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )


def signed(key, payload):
    return {"payload": payload, "signature": key.sign(v.DOMAIN + v.canonical(payload)).hex()}


def command(case, target, key):
    envelope = {
        "version": 1, "latch_id": target, "sequence": case["root"]["pid"],
        "command_type": "stop", "key_id": "stop-fixture", "signature": "0" * 128,
    }
    envelope["signature"] = key.sign(v.stop_signing_bytes(envelope)).hex()
    return envelope


@pytest.fixture(scope="module")
def campaign():
    keys = {role: Ed25519PrivateKey.generate() for role in v.KEY_ROLES}
    scope = "gvai-i8e-fixture"
    identities = {
        role: {
            "uid": 1000 + index, "gid": 2000 + index,
            "unit": scope + "-" + role + ".service",
            "cgroup": "/" + scope + "/" + role,
            "profile": scope + "-" + role,
        }
        for index, role in enumerate(v.ROLES)
    }
    resources = []
    for identity in identities.values():
        resources.extend(
            {"kind": kind, "id": str(identity[kind]), "owner": "root"}
            for kind in ("uid", "gid", "unit", "cgroup", "profile")
        )
    channels = {}
    for name, source, destination in (
        ("service", "client", "backend"), ("notice", "gate", "backend"),
        ("backend-stop", "stop_signer", "backend"),
        ("controller-stop", "stop_signer", "controller"),
        ("gate-control", "stop_signer", "gate"),
        ("arm-control", "arm_signer", "gate"),
        ("effects", "backend", "observer"), ("evidence", "observer", "collector"),
    ):
        path = "/run/" + scope + "/" + name + ".sock"
        channels[name] = {
            "source": source, "destination": destination, "socket": path,
            "mode": "0600", "ancestors_owner": "root",
        }
        resources.append({"kind": "socket", "id": path, "owner": source})
    for kind, name, owner in (
        ("disk", "vm-root", "root"), ("disk", "fault-disk", "root"),
        ("disk", "observer-disk", "root"),
        ("directory", "/run/" + scope + "/state", "gate"),
        ("mount", "/run/" + scope + "/fault", "root"),
        ("evidence-store", "/run/" + scope + "/evidence", "collector"),
        ("network", "deny-all-no-production", "root"),
    ):
        resources.append({"kind": kind, "id": name, "owner": owner})
    authorities = {
        role: {
            "key_id": role + "-fixture",
            "public_key": public(keys[role]).hex(),
            "fingerprint": hashlib.sha256(public(keys[role])).hexdigest(),
            "custodian": custodian, "synthetic": True,
        }
        for role, custodian in zip(
            v.KEY_ROLES, ("stop_signer", "arm_signer", "gate", "observer"),
        )
    }
    budget = {"cpu": 1, "memory_bytes": 1000000, "tasks": 32, "fds": 64, "backlog": 8}
    manifest = {
        "version": v.VERSION, "scope": scope, "target": "synthetic-latch",
        "candidate": "a" * 40, "harness": "a" * 64,
        "environment": {
            "python_executable": "/opt/experiment/bin/python3.11",
            "python_version": "3.11.9", "python_implementation": "CPython",
            "packages_sha256": "a" * 64, "image_sha256": "b" * 64,
            "configuration_sha256": "c" * 64, "kernel": "synthetic-linux",
            "architecture": "synthetic-x86_64", "systemd": "synthetic-version",
            "apparmor": "enforce", "cgroup": "v2",
        },
        "vm": {"id": "disposable-vm-1", "boot": "boot-1", "secondary_id": "console-1",
               "disposable": True, "expiry_ns": 10**18},
        "authorities": authorities, "identities": identities,
        "resources": resources,
        "cgroups": [
            {"path": i["cgroup"], "owner_uid": 0, "delegated": False}
            for i in identities.values()
        ],
        "channels": channels,
        "storage": {
            "root_disk": "vm-root", "fault_disk": "fault-disk",
            "evidence_disk": "observer-disk",
            "evidence_store": "/run/" + scope + "/evidence",
        },
        "teardown": {
            "vm": "disposable-vm-1", "secondary_id": "console-1",
            "operator": "outside-operator", "external": True, "verified": True,
            "expires_ns": 10**18, "guest_independent": True, "guard_ns": 5 * v.NS,
        },
        "loads": {"idle": budget, "maximum": dict(budget, cpu=2)},
        "reservations": {role: dict(budget) for role in ("observer", "controller", "collector")},
        "clock": {"source": "observer-monotonic", "resolution_ns": 1, "uncertainty_ns": 10},
        "cases": [], "replay_policy": "authentic-stop-deny-only",
    }
    scenario_sets = {claim: scenarios | v.BOUNDARIES for claim, scenarios in v.SCENARIOS.items()}
    scenario_sets["startup"] = v.STARTUP_SCENARIOS
    for claim, scenarios in scenario_sets.items():
        for scenario in sorted(scenarios):
            for load in ("idle", "maximum"):
                for repetition in range(20):
                    index = len(manifest["cases"])
                    invocations = {
                        role: format((index + 1) * 100 + role_index, "032x")
                        for role_index, role in enumerate(v.ROLES)
                    }
                    case = {
                        "id": f"{claim}-{scenario}-{load}-{repetition}",
                        "claim": claim, "scenario": scenario, "load": load,
                        "repetition": repetition,
                        "track": v.STARTUP_TRACK if claim == "startup" else v.SYNTHETIC_TRACK,
                        "invocations": invocations,
                        "root": {
                            "pid": 10000 + index * 10, "start_ns": index * 100 * v.NS,
                            "invocation": invocations["backend"],
                            "cgroup": identities["backend"]["cgroup"],
                        },
                    }
                    case["stop_digest"] = v.stop_digest(
                        command(case, manifest["target"], keys["stop"]),
                    )
                    manifest["cases"].append(case)
    approved = v.digest(manifest)
    artifact = b"synthetic observer trace; NOT host evidence"
    artifact_hash = hashlib.sha256(artifact).hexdigest()
    bundle = {
        "version": v.VERSION, "manifest": approved, "records": [],
        "artifacts": {artifact_hash: artifact.hex()},
    }
    for index, case in enumerate(manifest["cases"]):
        t = (index * 100 + 1) * v.NS
        data = {
            "stop": command(case, manifest["target"], keys["stop"]),
            "controls": {
                "before_ns": t, "after_ns": t + 30 * v.NS,
                "effects_before": 3, "effects_after": 3,
                "observer_before": 1, "observer_after": 1,
                "control_invocation": case["invocations"]["client"],
                "workload_effects_before": 3,
                "scenario_pass": case["scenario"], "boundaries_pass": sorted(v.BOUNDARIES),
            },
            "observation": {
                "source": authorities["observer"]["fingerprint"],
                "boot": manifest["vm"]["boot"], "complete": True,
                "start_ns": t, "end_ns": t + 30 * v.NS, "uncertainty_ns": 10,
                "storage": "blocked" if case["claim"] == "A" else "healthy",
            },
            "artifacts": [artifact_hash],
        }
        window = {
            "window_start_ns": t + 3 * v.NS, "window_end_ns": t + 14 * v.NS,
            "attempts": 10, "restart_attempts": 3, "unauthorized_execution": 0,
            "new_effects": 0, "replacements_inhibited": True,
        }
        if case["claim"] == "A":
            result = dict(
                window, trigger_ns=t + v.NS, reply_ns=t + v.NS + 100,
                install_ns=t + v.NS + 10, cancel_ns=t + v.NS + 200,
                stall_start_ns=t, stall_end_ns=t + 2 * v.NS,
                permits_valid_until_ns=t + 3 * v.NS, no_stop_effects=5,
                denial_reply="VETO_DENIAL_CONFIRMED",
            )
            result["window_start_ns"] = result["install_ns"]
        elif case["claim"] == "B":
            result = {
                "release_ns": t + v.NS, "durable_ns": t + 2 * v.NS,
                "reconcile_ns": t + 3 * v.NS, "restart_reconcile_ns": t + 4 * v.NS,
                "sync_readback": True, "healthy_control_digest": "b" * 64,
                "healthy_control_reconciled": True,
            }
            result.update({
                field: case["stop_digest"] for field in
                ("command_digest", "anchor_digest", "store_digest", "receipt_digest",
                 "reconciled_digest", "restarted_digest")
            })
        elif case["claim"] == "C":
            root = case["root"]
            child = dict(root, pid=root["pid"] + 1, start_ns=root["start_ns"] + 1)
            grandchild = dict(root, pid=root["pid"] + 2, start_ns=root["start_ns"] + 2)
            result = dict(
                window, trigger_ns=t + v.NS, accept_ns=t + v.NS + 100,
                terminated_ns=t + 2 * v.NS,
                controller_invocation=case["invocations"]["controller"],
                tree=[{"process": root, "parent": None},
                      {"process": child, "parent": root},
                      {"process": grandchild, "parent": child}],
                exits=[root, child, grandchild], survivors=[],
                effects_seen=[root, child, grandchild],
                ignored_cancel=True, ignored_term=True, cgroup_empty=True, external_action=True,
            )
            result["window_start_ns"] = result["terminated_ns"]
        else:
            data["controls"]["workload_effects_before"] = 0
            result = {
                "activation_ns": t + v.NS, "inhibition_observed_ns": t + v.NS + 100,
                "window_start_ns": t + v.NS, "window_end_ns": t + 12 * v.NS,
                "candidate": manifest["candidate"], "unmodified": True,
                "preauthorization_used": False, "inhibition_observed": True,
                "fresh_authority": True, "challenges": sorted(v.STARTUP_CHALLENGES),
                "protected_effects": 0, "predecessor": None,
                "requests": [{
                    "time_ns": t + 2 * v.NS, "process": case["root"],
                    "otherwise_valid": True, "admitted": False,
                }],
            }
            if case["scenario"] == "replacement":
                result["predecessor"] = dict(
                    case["root"], start_ns=case["root"]["start_ns"] - 1,
                    invocation="f" * 32,
                )
        data["result"] = result
        payload = {
            "version": v.VERSION, "manifest": approved, "case": case["id"],
            "observer": authorities["observer"]["fingerprint"],
            "observer_invocation": case["invocations"]["observer"],
            "vm": manifest["vm"]["id"], "boot": manifest["vm"]["boot"],
            "target": manifest["target"], "invocation": case["invocations"]["backend"],
            "cgroup": identities["backend"]["cgroup"],
            "stop_fingerprint": authorities["stop"]["fingerprint"],
            "seq": 0, "previous": v.ZERO, "time_ns": t + 30 * v.NS,
            "kind": "measurement", "data": data,
        }
        seal = dict(payload, seq=1, previous=v.digest(payload), kind="seal", data={"complete": True})
        bundle["records"].extend([signed(keys["observer"], payload), signed(keys["observer"], seal)])
    return manifest, bundle, keys


def run(manifest, bundle, keys, approved=None, pins=None):
    if approved is None:
        approved = v.digest(manifest)
    if pins is None:
        key = public(keys["observer"])
        pins = {hashlib.sha256(key).hexdigest(): key}
    return v.evaluate(v.canonical(manifest), v.canonical(bundle),
                      approved_manifest_sha256=approved, observer_public_keys=pins)


@pytest.fixture
def sample(campaign):
    manifest, full, keys = campaign
    selected = []
    for claim in ("A", "B", "C"):
        record = next(r for r in full["records"]
                      if r["payload"]["kind"] == "measurement" and
                      r["payload"]["case"].startswith(claim + "-"))
        selected.extend(full["records"][full["records"].index(record):][:2])
    return manifest, dict(
        full, records=copy.deepcopy(selected), artifacts=copy.deepcopy(full["artifacts"]),
    ), keys


def resign(bundle, keys):
    for index in range(0, len(bundle["records"]), 2):
        measurement = bundle["records"][index]["payload"]
        seal = bundle["records"][index + 1]["payload"]
        seal["previous"] = v.digest(measurement)
        bundle["records"][index] = signed(keys["observer"], measurement)
        bundle["records"][index + 1] = signed(keys["observer"], seal)


def test_complete_two_track_campaign_passes(campaign):
    result = run(*campaign)
    assert (result.A, result.B, result.C) == ("PASS", "PASS", "PASS"), result.diagnostics[:5]
    assert result.startup == result.campaign == "PASS"
    assert len(result.cases) == 2040
    assert not result.diagnostics


def test_incomplete_campaign_never_passes(sample):
    result = run(*sample)
    assert (result.A, result.B, result.C) == ("UNKNOWN",) * 3
    assert sum(verdict == "PASS" for _, verdict in result.cases) == 3


@pytest.mark.parametrize("attack", [
    "forged-ack", "stale-boot", "wrong-invocation", "wrong-observer-invocation",
    "wrong-target", "wrong-vm", "wrong-key", "tampered-stop", "untrusted-key",
    "missing-positive", "missing-observer", "observation-gap", "short-window",
    "ack-only", "missing-artifact", "altered-artifact", "missing-seal",
    "duplicate-record", "broken-chain", "reordered-record", "clock-understated",
    "uncertain-clock", "stale-permits", "not-blocked", "wrong-controller",
    "self-exit-only", "unknown-process", "missing-grandchild-control", "wrong-process-start",
    "float-time", "bool-time", "future-record", "signed-before-observation",
    "missing-exit", "wrong-control", "workload-never-executed", "window-gap",
])
def test_adversarial_unknown(sample, attack):
    manifest, bundle, keys = sample
    a = bundle["records"][0]["payload"]
    c = bundle["records"][4]["payload"]
    selected = a
    if attack == "forged-ack":
        bundle["records"][0]["signature"] = "0" * 128
    elif attack == "stale-boot":
        a["boot"] = "previous-boot"
    elif attack == "wrong-invocation":
        a["invocation"] = "f" * 32
    elif attack == "wrong-observer-invocation":
        a["observer_invocation"] = "f" * 32
    elif attack == "wrong-target":
        a["target"] = "other-target"
    elif attack == "wrong-vm":
        a["vm"] = "other-vm"
    elif attack == "wrong-key":
        a["stop_fingerprint"] = "f" * 64
    elif attack == "tampered-stop":
        a["data"]["stop"]["latch_id"] = "other-target"
    elif attack == "untrusted-key":
        result = run(manifest, bundle, keys, pins={})
        assert (result.A, result.B, result.C) == ("UNKNOWN",) * 3
        return
    elif attack == "missing-positive":
        a["data"]["controls"]["effects_before"] = 0
    elif attack == "missing-observer":
        a["data"]["controls"]["observer_after"] = 0
    elif attack == "observation-gap":
        a["data"]["observation"]["complete"] = False
    elif attack == "short-window":
        a["data"]["result"]["window_end_ns"] = a["data"]["result"]["window_start_ns"] + v.NS
    elif attack == "ack-only":
        a["data"]["result"] = {"denial_reply": "VETO_DENIAL_CONFIRMED"}
    elif attack == "missing-artifact":
        bundle["artifacts"] = {}
    elif attack == "altered-artifact":
        bundle["artifacts"] = {next(iter(bundle["artifacts"])): "00"}
    elif attack == "missing-seal":
        bundle["records"].pop(1)
    elif attack == "duplicate-record":
        bundle["records"].insert(1, bundle["records"][0])
    elif attack == "broken-chain":
        bundle["records"][1]["payload"]["previous"] = "f" * 64
    elif attack == "reordered-record":
        bundle["records"][:2] = bundle["records"][1::-1]
    elif attack == "clock-understated":
        a["data"]["observation"]["uncertainty_ns"] = 0
    elif attack == "uncertain-clock":
        a["data"]["observation"]["uncertainty_ns"] = None
    elif attack == "stale-permits":
        a["data"]["result"]["permits_valid_until_ns"] = 0
    elif attack == "not-blocked":
        a["data"]["observation"]["storage"] = "healthy"
    elif attack == "wrong-controller":
        selected = c
        c["data"]["result"]["controller_invocation"] = "f" * 32
    elif attack == "self-exit-only":
        selected = c
        c["data"]["result"]["external_action"] = False
    elif attack == "unknown-process":
        selected = c
        c["data"]["result"]["exits"][0] = dict(c["data"]["result"]["exits"][0], pid=999999)
    elif attack == "missing-grandchild-control":
        selected = c
        c["data"]["result"]["effects_seen"].pop()
    elif attack == "wrong-process-start":
        selected = c
        c["data"]["result"]["exits"][0] = dict(c["data"]["result"]["exits"][0], start_ns=0)
    elif attack == "float-time":
        a["time_ns"] = 1.5
    elif attack == "bool-time":
        a["time_ns"] = True
    elif attack == "future-record":
        a["time_ns"] = 10**18 + 1
    elif attack == "signed-before-observation":
        a["time_ns"] = 0
    elif attack == "missing-exit":
        selected = c
        c["data"]["result"]["exits"].pop()
    elif attack == "wrong-control":
        a["data"]["controls"]["control_invocation"] = a["invocation"]
    elif attack == "workload-never-executed":
        a["data"]["controls"]["workload_effects_before"] = 0
    elif attack == "window-gap":
        a["data"]["result"]["window_start_ns"] += 1
    if attack not in {
        "forged-ack", "missing-seal", "duplicate-record", "broken-chain",
        "reordered-record", "float-time",
    }:
        resign(bundle, keys)
    result = run(manifest, bundle, keys)
    assert dict(result.cases).get(selected["case"], "UNKNOWN") == "UNKNOWN", result.diagnostics
    assert "PASS" not in (result.A, result.B, result.C)


@pytest.mark.parametrize("attack,claim", [
    ("A1-overrun", "A"), ("A2-overrun", "A"), ("B1-overrun", "B"),
    ("C0-overrun", "C"), ("C1-overrun", "C"), ("surviving-child", "C"),
    ("nonempty-cgroup", "C"), ("post-veto-admission", "A"),
    ("post-kill-effect", "C"), ("unauthorized-restart", "C"),
    ("false-durability", "B"), ("uncertainty-overrun", "A"),
])
def test_independently_observed_failures(sample, attack, claim):
    manifest, bundle, keys = sample
    index = {"A": 0, "B": 2, "C": 4}[claim]
    payload = bundle["records"][index]["payload"]
    result = payload["data"]["result"]
    if attack == "A1-overrun":
        result["reply_ns"] = result["trigger_ns"] + v.NS
    elif attack == "A2-overrun":
        result["cancel_ns"] = result["install_ns"] + v.NS // 2
    elif attack == "B1-overrun":
        result["reconcile_ns"] = result["release_ns"] + 5 * v.NS
        result["restart_reconcile_ns"] = result["reconcile_ns"] + v.NS
    elif attack == "C0-overrun":
        result["accept_ns"] = result["trigger_ns"] + v.NS
    elif attack == "C1-overrun":
        result["terminated_ns"] = result["accept_ns"] + 2 * v.NS
        result["window_start_ns"] = result["terminated_ns"]
    elif attack == "surviving-child":
        result["survivors"].append(result["exits"].pop())
    elif attack == "nonempty-cgroup":
        result["cgroup_empty"] = False
    elif attack in ("post-veto-admission", "unauthorized-restart"):
        result["unauthorized_execution"] = 1
    elif attack == "post-kill-effect":
        result["new_effects"] = 1
    elif attack == "false-durability":
        result["reconciled_digest"] = "c" * 64
    elif attack == "uncertainty-overrun":
        payload["data"]["observation"]["uncertainty_ns"] = v.NS
    resign(bundle, keys)
    evaluated = run(manifest, bundle, keys)
    assert getattr(evaluated, claim) == "FAIL", evaluated.diagnostics
    assert dict(evaluated.cases)[payload["case"]] == "FAIL"


@pytest.mark.parametrize("missing", ["seal", "window", "other-case", "invalid-record",
                                    "unrelated-artifact"])
def test_failure_precedence(sample, missing):
    manifest, bundle, keys = sample
    a = bundle["records"][0]["payload"]
    a["data"]["result"]["reply_ns"] = a["data"]["result"]["trigger_ns"] + v.NS
    if missing == "window":
        a["data"]["result"]["window_end_ns"] = a["data"]["result"]["window_start_ns"]
    resign(bundle, keys)
    if missing == "seal":
        bundle["records"].pop(1)
    elif missing == "other-case":
        bundle["records"] = bundle["records"][:2]
    elif missing == "invalid-record":
        bundle["records"].append({"payload": {}, "signature": "0" * 128})
    elif missing == "unrelated-artifact":
        bundle["artifacts"]["f" * 64] = "00"
    result = run(manifest, bundle, keys)
    assert result.A == "FAIL"
    assert result.C == "UNKNOWN"


def test_standalone_verified_violation_survives_missing_measurement(sample):
    manifest, bundle, keys = sample
    payload = bundle["records"][4]["payload"]
    case = next(c for c in manifest["cases"] if c["id"] == payload["case"])
    violation = dict(
        payload, kind="violation", seq=9, previous="f" * 64,
        data={"code": "unauthorized-restart", "process": case["root"],
              "artifacts": list(bundle["artifacts"])},
    )
    bundle["records"] = [signed(keys["observer"], violation)]
    result = run(manifest, bundle, keys)
    assert result.C == "FAIL"
    violation["boot"] = "wrong-boot"
    bundle["records"] = [signed(keys["observer"], violation)]
    assert run(manifest, bundle, keys).C == "UNKNOWN"


@pytest.mark.parametrize("measurement,claim,first,last,limit", [
    (0, "A", "trigger_ns", "reply_ns", v.NS),
    (0, "A", "install_ns", "cancel_ns", v.NS // 2),
    (2, "B", "release_ns", "reconcile_ns", 5 * v.NS),
    (4, "C", "trigger_ns", "accept_ns", v.NS),
    (4, "C", "accept_ns", "terminated_ns", 2 * v.NS),
])
def test_exact_deadline_including_uncertainty(sample, measurement, claim, first, last, limit):
    manifest, bundle, keys = sample
    payload = bundle["records"][measurement]["payload"]
    result = payload["data"]["result"]
    result[last] = result[first] + limit - payload["data"]["observation"]["uncertainty_ns"]
    if claim == "B":
        result["restart_reconcile_ns"] = result["reconcile_ns"] + v.NS
    if last == "terminated_ns":
        result["window_start_ns"] = result[last]
    resign(bundle, keys)
    evaluated = run(manifest, bundle, keys)
    assert dict(evaluated.cases)[payload["case"]] == "PASS", evaluated.diagnostics[:5]
    result[last] += 1
    if last == "terminated_ns":
        result["window_start_ns"] = result[last]
    resign(bundle, keys)
    assert getattr(run(manifest, bundle, keys), claim) == "FAIL"


def test_exact_window_lower_bound(sample):
    manifest, bundle, keys = sample
    payload = bundle["records"][0]["payload"]
    result = payload["data"]["result"]
    result["window_end_ns"] = result["window_start_ns"] + 10 * v.NS + 10
    resign(bundle, keys)
    assert dict(run(manifest, bundle, keys).cases)[payload["case"]] == "PASS"
    result["window_end_ns"] -= 1
    resign(bundle, keys)
    assert dict(run(manifest, bundle, keys).cases)[payload["case"]] == "UNKNOWN"


@pytest.mark.parametrize("value", [None, [], {}, True, -1, "1", 2**64])
def test_malformed_observation_types_fail_closed(sample, value):
    manifest, bundle, keys = sample
    payload = bundle["records"][0]["payload"]
    payload["data"]["result"]["attempts"] = value
    resign(bundle, keys)
    assert dict(run(manifest, bundle, keys).cases)[payload["case"]] == "UNKNOWN"


def test_v1_known_wire_vector(sample):
    manifest, bundle, _ = sample
    envelope = bundle["records"][0]["payload"]["data"]["stop"]
    assert v.stop_signing_bytes(envelope) == (
        b'GVAI-STOP-LATCH-V1\n'
        b'{"command_type":"stop","key_id":"stop-fixture",'
        b'"latch_id":"synthetic-latch","sequence":10000,"version":1}'
    )
    assert v.stop_digest(envelope) == manifest["cases"][0]["stop_digest"]


@pytest.mark.parametrize("attack", [
    "unapproved", "production-vm", "shared-key", "fingerprint", "controller-observer",
    "delegated", "cgroup-owner", "nested-cgroup", "socket-owner", "socket-mode",
    "socket-routing", "shared-storage", "no-teardown", "wrong-teardown",
    "guest-teardown", "expired-teardown", "missing-resource", "extra-resource",
    "production-network", "missing-load", "duplicate-case",
    "reused-invocation", "production-track", "zero-reservation", "extra-field",
    "wrong-python", "complain-profile", "cgroup-v1", "relative-python",
])
def test_invalid_manifests_are_unknown(campaign, attack):
    original, bundle, keys = campaign
    m = copy.deepcopy(original)
    if attack == "unapproved":
        m["target"] = "not-approved"
    elif attack == "production-vm":
        m["vm"]["disposable"] = False
    elif attack == "shared-key":
        m["authorities"]["arm"].update({
            k: m["authorities"]["stop"][k] for k in ("public_key", "fingerprint")
        })
    elif attack == "fingerprint":
        m["authorities"]["stop"]["fingerprint"] = "f" * 64
    elif attack == "controller-observer":
        m["identities"]["observer"] = m["identities"]["controller"]
    elif attack == "delegated":
        m["cgroups"][0]["delegated"] = True
    elif attack == "cgroup-owner":
        m["cgroups"][0]["owner_uid"] = 1000
    elif attack == "nested-cgroup":
        m["identities"]["controller"]["cgroup"] += "/backend"
    elif attack == "socket-owner":
        next(r for r in m["resources"] if r["kind"] == "socket")["owner"] = "backend"
    elif attack == "socket-mode":
        m["channels"]["backend-stop"]["mode"] = "0666"
    elif attack == "socket-routing":
        m["channels"]["backend-stop"]["source"] = "client"
    elif attack == "shared-storage":
        m["storage"]["fault_disk"] = m["storage"]["evidence_disk"]
    elif attack == "no-teardown":
        m["teardown"]["verified"] = False
    elif attack == "wrong-teardown":
        m["teardown"]["vm"] = "production"
    elif attack == "guest-teardown":
        m["teardown"]["guest_independent"] = False
    elif attack == "expired-teardown":
        m["teardown"]["expires_ns"] = 0
    elif attack == "missing-resource":
        m["resources"].pop()
    elif attack == "extra-resource":
        m["resources"].append({"kind": "unit", "id": "production.service", "owner": "root"})
    elif attack == "production-network":
        m["resources"].append({"kind": "network", "id": "production", "owner": "root"})
    elif attack == "missing-load":
        m["loads"].pop("maximum")
    elif attack == "duplicate-case":
        m["cases"].append(m["cases"][0])
    elif attack == "reused-invocation":
        m["cases"][1]["invocations"] = m["cases"][0]["invocations"]
        m["cases"][1]["root"]["invocation"] = m["cases"][0]["root"]["invocation"]
    elif attack == "production-track":
        m["cases"][0]["track"] = "production-rearm"
    elif attack == "zero-reservation":
        m["reservations"]["observer"]["cpu"] = 0
    elif attack == "extra-field":
        m["allow_rearm"] = True
    elif attack == "wrong-python":
        m["environment"]["python_version"] = "3.14.7"
    elif attack == "complain-profile":
        m["environment"]["apparmor"] = "complain"
    elif attack == "cgroup-v1":
        m["environment"]["cgroup"] = "v1"
    elif attack == "relative-python":
        m["environment"]["python_executable"] = "python3.11"
    approved = v.digest(original) if attack == "unapproved" else v.digest(m)
    result = run(m, bundle, keys, approved=approved)
    assert (result.A, result.B, result.C) == ("UNKNOWN",) * 3
    assert result.diagnostics[0].startswith("manifest:")


@pytest.mark.parametrize("raw", [
    b"{}", b"[]", b'{"version":1,"version":2}', b'{"x":NaN}',
    b'{"x":1.5}', b"\xff", b'{"unfinished":', b"[" * 2000,
])
def test_malformed_input_is_explicit_unknown(campaign, raw):
    manifest, _, keys = campaign
    result = v.evaluate(v.canonical(manifest), raw,
                        approved_manifest_sha256=v.digest(manifest),
                        observer_public_keys={
                            hashlib.sha256(public(keys["observer"])).hexdigest(): public(keys["observer"]),
                        })
    assert (result.A, result.B, result.C) == ("UNKNOWN",) * 3
    assert result.diagnostics


def test_no_host_or_production_imports():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(v))
    imports = {
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports == {
        "hashlib", "json", "re", "collections", "dataclasses", "typing",
        "cryptography.exceptions",
        "cryptography.hazmat.primitives.asymmetric.ed25519",
    }
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                   node.func.id in {"open", "exec", "eval", "__import__"}
                   for node in ast.walk(tree))


def test_result_is_immutable(sample):
    result = run(*sample)
    with pytest.raises(AttributeError):
        result.A = "PASS"


@pytest.mark.parametrize("pins", [None, {"f" * 64: b"short"}, {"bad": bytes(32)}])
def test_invalid_external_pin_configuration_is_unknown(sample, pins):
    manifest, bundle, _ = sample
    result = v.evaluate(v.canonical(manifest), v.canonical(bundle),
                        approved_manifest_sha256=v.digest(manifest),
                        observer_public_keys=pins)
    assert (result.A, result.B, result.C) == ("UNKNOWN",) * 3
    assert result.diagnostics[0].startswith("manifest:")


@pytest.fixture
def startup_sample(campaign):
    manifest, full, keys = campaign
    records = next(
        full["records"][i:i + 2] for i in range(0, len(full["records"]), 2)
        if full["records"][i]["payload"]["case"].startswith("startup-replacement-")
    )
    return manifest, dict(full, records=copy.deepcopy(records),
                          artifacts=copy.deepcopy(full["artifacts"])), keys


def reapprove(manifest, bundle, keys):
    """Model separate fixture approval, not approval by the evaluator."""
    bundle["manifest"] = v.digest(manifest)
    for record in bundle["records"]:
        record["payload"]["manifest"] = bundle["manifest"]
    resign(bundle, keys)


def test_synthetic_only_campaign_cannot_pass(campaign):
    original, full, keys = campaign
    manifest, bundle = copy.deepcopy(original), copy.deepcopy(full)
    manifest["cases"] = [c for c in manifest["cases"] if c["claim"] != "startup"]
    bundle["records"] = [r for r in bundle["records"]
                         if not r["payload"]["case"].startswith("startup-")]
    reapprove(manifest, bundle, keys)
    result = run(manifest, bundle, keys)
    assert (result.A, result.B, result.C) == ("PASS",) * 3
    assert result.startup == result.campaign == "UNKNOWN"


@pytest.mark.parametrize("omission", ["all-records", "one-record", "one-case", "one-scenario"])
def test_missing_startup_coverage_never_campaign_pass(campaign, omission):
    original, full, keys = campaign
    manifest, bundle = copy.deepcopy(original), copy.deepcopy(full)
    startup = [c["id"] for c in manifest["cases"] if c["claim"] == "startup"]
    if omission == "all-records":
        bundle["records"] = [r for r in bundle["records"] if r["payload"]["case"] not in startup]
    elif omission == "one-record":
        bundle["records"] = [r for r in bundle["records"]
                             if not (r["payload"]["case"] == startup[0] and
                                     r["payload"]["kind"] == "measurement")]
    else:
        removed = {startup[0]} if omission == "one-case" else {
            c["id"] for c in manifest["cases"]
            if c["claim"] == "startup" and c["scenario"] == "socket-activation"
        }
        manifest["cases"] = [c for c in manifest["cases"] if c["id"] not in removed]
        bundle["records"] = [r for r in bundle["records"] if r["payload"]["case"] not in removed]
        reapprove(manifest, bundle, keys)
    result = run(manifest, bundle, keys)
    assert result.startup == result.campaign == "UNKNOWN"
    assert (result.A, result.B, result.C) == ("PASS",) * 3


@pytest.mark.parametrize("attack", [
    "forged", "boot", "invocation", "candidate", "modified", "missing-state",
    "invalid-request", "no-requests", "expired-authority", "short-window",
    "window-gap", "missing-observer", "missing-effects-control", "missing-challenge",
    "same-predecessor", "missing-predecessor", "unbound-request", "missing-seal",
])
def test_unverified_startup_is_unknown(startup_sample, attack):
    manifest, bundle, keys = startup_sample
    p = bundle["records"][0]["payload"]
    r = p["data"]["result"]
    if attack == "forged":
        bundle["records"][0]["signature"] = "0" * 128
    elif attack == "boot":
        p["boot"] = "stale"
    elif attack == "invocation":
        p["invocation"] = "f" * 32
    elif attack == "candidate":
        r["candidate"] = "f" * 40
    elif attack == "modified":
        r["unmodified"] = False
    elif attack == "missing-state":
        r["inhibition_observed"] = None
    elif attack == "invalid-request":
        r["requests"][0]["otherwise_valid"] = False
    elif attack == "no-requests":
        r["requests"] = []
    elif attack == "expired-authority":
        r["fresh_authority"] = False
    elif attack == "short-window":
        r["window_end_ns"] = r["window_start_ns"] + v.NS
    elif attack == "window-gap":
        r["window_start_ns"] += 1
    elif attack == "missing-observer":
        p["data"]["controls"]["observer_after"] = 0
    elif attack == "missing-effects-control":
        p["data"]["controls"]["effects_after"] = 0
    elif attack == "missing-challenge":
        r["challenges"].pop()
    elif attack == "same-predecessor":
        r["predecessor"] = copy.deepcopy(r["requests"][0]["process"])
    elif attack == "missing-predecessor":
        r["predecessor"] = None
    elif attack == "unbound-request":
        r["requests"][0]["process"] = dict(r["requests"][0]["process"], invocation="f" * 32)
    elif attack == "missing-seal":
        bundle["records"].pop()
    if attack not in ("forged", "missing-seal"):
        resign(bundle, keys)
    result = run(manifest, bundle, keys)
    assert dict(result.cases)[p["case"]] == "UNKNOWN"
    assert result.startup == result.campaign == "UNKNOWN"


@pytest.mark.parametrize("violation", ["admission", "effect", "preauthorized", "cleared"])
@pytest.mark.parametrize("missing", [False, True])
def test_startup_fail_precedence_and_independence(startup_sample, violation, missing):
    manifest, bundle, keys = startup_sample
    p = bundle["records"][0]["payload"]
    r = p["data"]["result"]
    if violation == "admission":
        r["requests"][0]["admitted"] = True
    elif violation == "effect":
        r["protected_effects"] = 1
    elif violation == "preauthorized":
        r["preauthorization_used"] = True
    else:
        r["inhibition_observed"] = False
    if missing:
        r["challenges"] = []
    resign(bundle, keys)
    if missing:
        bundle["records"].pop()
    result = run(manifest, bundle, keys)
    assert dict(result.cases)[p["case"]] == "FAIL"
    assert result.startup == result.campaign == "FAIL"
    assert (result.A, result.B, result.C) == ("UNKNOWN",) * 3


def test_startup_without_protected_work_positive_control(startup_sample):
    result = run(*startup_sample)
    assert list(dict(result.cases).values()).count("PASS") == 1
    assert result.startup == result.campaign == "UNKNOWN"


def test_synthetic_failure_survives_absent_startup_inventory(campaign):
    original, full, keys = campaign
    manifest, bundle = copy.deepcopy(original), copy.deepcopy(full)
    manifest["cases"] = [c for c in manifest["cases"] if c["claim"] != "startup"]
    p = bundle["records"][0]["payload"]
    p["data"]["result"]["reply_ns"] = p["data"]["result"]["trigger_ns"] + v.NS
    bundle["records"] = [r for r in bundle["records"]
                         if not r["payload"]["case"].startswith("startup-")]
    reapprove(manifest, bundle, keys)
    result = run(manifest, bundle, keys)
    assert result.A == result.campaign == "FAIL"
    assert result.startup == "UNKNOWN"
    assert result.B == result.C == "PASS"


def test_startup_failure_does_not_relabel_synthetic_claims(campaign):
    manifest, full, keys = campaign
    bundle = copy.deepcopy(full)
    p = next(r["payload"] for r in bundle["records"]
             if r["payload"]["case"].startswith("startup-") and
             r["payload"]["kind"] == "measurement")
    p["data"]["result"]["requests"][0]["admitted"] = True
    resign(bundle, keys)
    result = run(manifest, bundle, keys)
    assert result.startup == result.campaign == "FAIL"
    assert (result.A, result.B, result.C) == ("PASS",) * 3


def test_old_schema_does_not_gain_startup_acceptance(campaign):
    original, full, keys = campaign
    manifest, bundle = copy.deepcopy(original), copy.deepcopy(full)
    manifest["version"] = "gvai-disposable-stop/v1"
    result = run(manifest, bundle, keys)
    assert result.startup == result.campaign == "UNKNOWN"
    assert (result.A, result.B, result.C) == ("UNKNOWN",) * 3


def test_old_domain_signature_is_not_accepted(startup_sample):
    manifest, bundle, keys = startup_sample
    p = bundle["records"][0]["payload"]
    bundle["records"][0]["signature"] = keys["observer"].sign(
        b"gvai-disposable-stop/v1\x00" + v.canonical(p),
    ).hex()
    result = run(manifest, bundle, keys)
    assert dict(result.cases)[p["case"]] == "UNKNOWN"
    assert result.campaign == "UNKNOWN"
