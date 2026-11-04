"""TEST ONLY: offline evaluation of externally approved synthetic observations.

No host discovery, activation, production authority, or rearm interface exists here.
"""

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Mapping, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


VERSION = "gvai-disposable-stop/v2"
DOMAIN = b"gvai-disposable-stop/v2\x00"
STOP_V1_DOMAIN = b"GVAI-STOP-LATCH-V1\n"
ROLES = (
    "stop_signer", "arm_signer", "gate", "backend", "client",
    "controller", "observer", "collector",
)
KEY_ROLES = ("stop", "arm", "gate", "observer")
KINDS = {
    "disk", "unit", "socket", "directory", "uid", "gid", "profile",
    "mount", "network", "cgroup", "evidence-store",
}
SCENARIOS = {
    "A": {
        "blocked-read", "blocked-write", "blocked-fsync", "blocked-replace",
        "races", "replay", "invalid-authority", "late-arm-notices",
        "replacement-inhibited", "transport-ambiguity",
    },
    "B": {
        "healthy-release", "transaction-barriers", "lost-reply",
        "corrupt-metadata", "substitution", "conflict-legacy", "replay",
    },
    "C": {
        "uncooperative-tree", "fork-exec-reparent", "escape-pid-reuse",
        "restart-socket-activation",
    },
}
SYNTHETIC_TRACK = "synthetic-preauthorized-session"
STARTUP_TRACK = "unmodified-startup"
STARTUP_SCENARIOS = {"ordinary-startup", "replacement", "socket-activation"}
STARTUP_CHALLENGES = {
    "arm", "late-arm", "delayed-notice", "higher-counter", "new-notice-boot",
}
BOUNDARIES = {
    "socket-paths", "socket-peers", "listener-routing", "signed-authority",
    "files-credentials", "apparmor", "systemd-cgroups", "network", "pressure",
}
VIOLATIONS = {
    "A": {"post-veto-admission", "cleared-denial", "false-denial-confirmation"},
    "B": {"false-durable-confirmation", "authority-history-corruption"},
    "C": {"surviving-descendant", "post-termination-effect", "unauthorized-restart"},
    "startup": {"cleared-inhibition", "unauthorized-startup-execution"},
}
NS = 1_000_000_000
ZERO = "0" * 64


class SchemaError(ValueError):
    """Malformed or unsupported offline input."""


@dataclass(frozen=True)
class Evaluation:
    """Independent synthetic A/B/C, startup and combined offline verdicts."""

    A: str
    B: str
    C: str
    cases: Tuple[Tuple[str, str], ...]
    diagnostics: Tuple[str, ...]
    startup: str = "UNKNOWN"
    campaign: str = "UNKNOWN"


def _aggregate(values):
    values = set(values)
    return "FAIL" if "FAIL" in values else (
        "PASS" if values == {"PASS"} else "UNKNOWN")


def canonical(value):
    """Sorted ASCII JSON; the input decoder separately excludes floats."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _require(condition, message):
    if not condition:
        raise SchemaError(message)


def _fields(value, names):
    _require(type(value) is dict and set(value) == set(names.split()), "object fields")


def _text(value):
    _require(type(value) is str and 0 < len(value) <= 512, "text")
    _require(all(32 <= ord(c) < 127 for c in value), "ASCII text")
    return value


def _integer(value):
    _require(type(value) is int and 0 <= value <= 2**63 - 1, "nonnegative integer")
    return value


def _hex(value, size=64):
    _require(
        type(value) is str and re.fullmatch("[0-9a-f]{" + str(size) + "}", value),
        "lowercase hexadecimal",
    )
    return value


def _identifier(value):
    _require(type(value) is str and
             re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value),
             "V1 identifier")


def stop_signing_bytes(envelope):
    """Independent, verification-only V1 wire encoding; no latch is imported."""
    _fields(envelope, "version latch_id sequence command_type key_id signature")
    _require(type(envelope["version"]) is int and envelope["version"] == 1 and
             envelope["command_type"] == "stop", "V1 STOP only")
    _require(1 <= _integer(envelope["sequence"]) <= 2**53, "V1 sequence")
    _identifier(envelope["latch_id"])
    _identifier(envelope["key_id"])
    _hex(envelope["signature"], 128)
    return STOP_V1_DOMAIN + canonical({k: val for k, val in envelope.items() if k != "signature"})


def stop_digest(envelope):
    return hashlib.sha256(
        stop_signing_bytes(envelope) + bytes.fromhex(envelope["signature"]),
    ).hexdigest()


def _list(value):
    _require(type(value) is list, "array")
    return value


def _strings(value):
    result = [_text(item) for item in _list(value)]
    _require(len(result) == len(set(result)), "duplicate array entry")
    return set(result)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def _no_float(value):
    raise SchemaError("floats and nonfinite numbers are unsupported")


def _decode(raw):
    _require(type(raw) is bytes and len(raw) <= 64 * 1024 * 1024, "input size/type")
    return json.loads(
        raw.decode("utf-8"), object_pairs_hook=_pairs,
        parse_float=_no_float, parse_constant=_no_float,
    )


def _path(value, prefix):
    _text(value)
    _require(
        value.startswith(prefix + "/") and
        all(part not in ("", ".", "..") for part in value.split("/")[1:]),
        "path outside exact experiment scope",
    )


def _process(value, identity):
    _fields(value, "pid start_ns invocation cgroup")
    _require(_integer(value["pid"]) > 0, "PID")
    _integer(value["start_ns"])
    _require(value["invocation"] == identity["invocation"], "process invocation")
    _require(value["cgroup"] == identity["cgroup"], "process cgroup")
    return (value["pid"], value["start_ns"])


def _manifest(m, approved_digest, observer_keys):
    _hex(approved_digest)
    _require(digest(m) == approved_digest, "manifest not externally approved")
    _require(isinstance(observer_keys, Mapping), "observer pin mapping")
    for fingerprint, public in observer_keys.items():
        _hex(fingerprint)
        _require(type(public) is bytes and len(public) == 32 and
                 hashlib.sha256(public).hexdigest() == fingerprint, "observer pin encoding")
    _fields(m, "version scope vm target candidate harness environment authorities identities resources "
            "cgroups channels storage teardown loads reservations clock cases replay_policy")
    _require(m["version"] == VERSION, "manifest version")
    scope = _text(m["scope"])
    _require(re.fullmatch("gvai-i8e-[a-z0-9-]+", scope), "experiment scope")
    _hex(m["candidate"], 40)
    _hex(m["harness"])
    environment = m["environment"]
    _fields(environment, "python_executable python_version python_implementation "
            "packages_sha256 image_sha256 configuration_sha256 kernel architecture "
            "systemd apparmor cgroup")
    _require(environment["python_implementation"] == "CPython" and
             type(environment["python_version"]) is str and
             re.fullmatch(r"3\.11\.[0-9]+", environment["python_version"]),
             "CPython 3.11 required")
    _text(environment["python_executable"])
    _require(environment["python_executable"].startswith("/") and
             all(p not in ("", ".", "..")
                 for p in environment["python_executable"].split("/")[1:]),
             "absolute interpreter")
    for field in ("packages_sha256", "image_sha256", "configuration_sha256"):
        _hex(environment[field])
    for field in ("kernel", "architecture", "systemd"):
        _text(environment[field])
    _require(environment["apparmor"] == "enforce" and environment["cgroup"] == "v2",
             "host features")
    _identifier(m["target"])
    _require(m["replay_policy"] == "authentic-stop-deny-only", "replay policy")
    _fields(m["vm"], "id boot secondary_id disposable expiry_ns")
    for field in ("id", "boot", "secondary_id"):
        _text(m["vm"][field])
    _require(m["vm"]["id"] != m["vm"]["secondary_id"], "second VM identifier")
    _require(m["vm"]["disposable"] is True, "not disposable")
    _require(_integer(m["vm"]["expiry_ns"]) > 0, "expiry")
    _fields(m["authorities"], "stop arm gate observer")
    fingerprints = set()
    for role, custodian in zip(KEY_ROLES, ("stop_signer", "arm_signer", "gate", "observer")):
        key = m["authorities"][role]
        _fields(key, "key_id public_key fingerprint custodian synthetic")
        _identifier(key["key_id"])
        public = bytes.fromhex(_hex(key["public_key"]))
        _require(hashlib.sha256(public).hexdigest() == _hex(key["fingerprint"]),
                 "authority fingerprint")
        _require(key["synthetic"] is True and key["custodian"] == custodian,
                 "synthetic key custody")
        fingerprints.add(key["fingerprint"])
    _require(len(fingerprints) == 4, "authority key separation")
    _require(len({key["key_id"] for key in m["authorities"].values()}) == 4,
             "authority key ID separation")
    observer = m["authorities"]["observer"]
    _require(
        observer_keys.get(observer["fingerprint"]) ==
        bytes.fromhex(observer["public_key"]), "observer not externally pinned",
    )
    _fields(m["identities"], " ".join(ROLES))
    for role in ROLES:
        identity = m["identities"][role]
        _fields(identity, "uid gid unit cgroup profile")
        _require(_integer(identity["uid"]) > 0 and _integer(identity["gid"]) > 0,
                 "nonroot experiment identity")
        for field in ("unit", "profile"):
            _require(_text(identity[field]).startswith(scope + "-"), "role scope")
        _path(identity["cgroup"], "/" + scope)
        _require(identity["cgroup"].count("/") == 2, "sibling cgroup boundary")
    for field in ("uid", "gid", "unit", "cgroup", "profile"):
        _require(len({v[field] for v in m["identities"].values()}) == len(ROLES),
                 "role identity separation")
    resources = {}
    for resource in _list(m["resources"]):
        _fields(resource, "kind id owner")
        kind, name = resource["kind"], _text(resource["id"])
        _require(kind in KINDS and resource["owner"] in ("root", *ROLES),
                 "resource kind/owner")
        _require((kind, name) not in resources, "resource collision")
        resources[kind, name] = resource["owner"]
        if kind in {"socket", "directory", "mount", "evidence-store"}:
            _path(name, "/run/" + scope)
    _require({kind for kind, _ in resources} == KINDS, "inventory kinds")
    for identity in m["identities"].values():
        for field in ("uid", "gid", "unit", "cgroup", "profile"):
            _require(resources.get((field, str(identity[field]))) == "root",
                     "root-controlled role resource")
    for kind in ("uid", "gid", "unit", "cgroup", "profile"):
        _require({name for resource_kind, name in resources if resource_kind == kind} ==
                 {str(i[kind]) for i in m["identities"].values()},
                 "unreferenced identity resource")
    groups = {}
    for group in _list(m["cgroups"]):
        _fields(group, "path owner_uid delegated")
        _require(group["path"] not in groups, "duplicate cgroup")
        _require(type(group["owner_uid"]) is int and group["owner_uid"] == 0
                 and group["delegated"] is False, "cgroup ownership/delegation")
        groups[group["path"]] = group
    _require(set(groups) == {i["cgroup"] for i in m["identities"].values()},
             "exact cgroup inventory")
    expected_channels = {
        "service": ("client", "backend"),
        "notice": ("gate", "backend"),
        "backend-stop": ("stop_signer", "backend"),
        "controller-stop": ("stop_signer", "controller"),
        "gate-control": ("stop_signer", "gate"),
        "arm-control": ("arm_signer", "gate"),
        "effects": ("backend", "observer"),
        "evidence": ("observer", "collector"),
    }
    _fields(m["channels"], " ".join(expected_channels))
    sockets = set()
    for name, (source, destination) in expected_channels.items():
        channel = m["channels"][name]
        _fields(channel, "source destination socket mode ancestors_owner")
        _require((channel["source"], channel["destination"]) == (source, destination),
                 "channel authority")
        _require(channel["mode"] == "0600" and channel["ancestors_owner"] == "root",
                 "socket protection")
        _require(resources.get(("socket", channel["socket"])) == source,
                 "socket inventory ownership")
        sockets.add(channel["socket"])
    _require(len(sockets) == len(expected_channels), "separate sockets")
    _require(sockets == {n for k, n in resources if k == "socket"}, "extra socket")
    _fields(m["storage"], "root_disk fault_disk evidence_disk evidence_store")
    _require(len({m["storage"][k] for k in ("root_disk", "fault_disk", "evidence_disk")}) == 3,
             "storage isolation")
    _require({n for k, n in resources if k == "disk"} ==
             {m["storage"][k] for k in ("root_disk", "fault_disk", "evidence_disk")},
             "exact disk inventory")
    _require(resources.get(("evidence-store", m["storage"]["evidence_store"])) == "collector",
             "evidence store")
    _require(resources.get(("network", "deny-all-no-production")) == "root",
             "network isolation")
    _require({n for k, n in resources if k == "network"} == {"deny-all-no-production"},
             "unexpected network attachment")
    _fields(m["teardown"], "vm secondary_id operator external verified expires_ns "
            "guest_independent guard_ns")
    teardown = m["teardown"]
    _require(teardown["vm"] == m["vm"]["id"] and
             teardown["secondary_id"] == m["vm"]["secondary_id"], "teardown target")
    _require(_text(teardown["operator"]) not in ROLES, "out-of-band operator")
    _require(all(teardown[k] is True for k in ("external", "verified", "guest_independent")),
             "out-of-band teardown prerequisites")
    _require(teardown["expires_ns"] == m["vm"]["expiry_ns"] and
             type(teardown["guard_ns"]) is int and teardown["guard_ns"] == 5 * NS,
             "teardown bounds")
    _fields(m["loads"], "idle maximum")
    for load in m["loads"].values():
        _fields(load, "cpu memory_bytes tasks fds backlog")
        for number in load.values():
            _require(_integer(number) > 0, "finite positive load budget")
    _require(all(m["loads"]["maximum"][k] >= v for k, v in m["loads"]["idle"].items()),
             "maximum load")
    _fields(m["reservations"], "observer controller collector")
    for reservation in m["reservations"].values():
        _fields(reservation, "cpu memory_bytes tasks fds backlog")
        for number in reservation.values():
            _require(_integer(number) > 0, "reserved trusted-role budget")
    _fields(m["clock"], "source resolution_ns uncertainty_ns")
    _require(m["clock"]["source"] == "observer-monotonic", "clock source")
    _require(_integer(m["clock"]["resolution_ns"]) > 0, "clock resolution")
    _require(_integer(m["clock"]["uncertainty_ns"]) >= m["clock"]["resolution_ns"],
             "clock uncertainty")
    counts = Counter()
    cases = {}
    for case in _list(m["cases"]):
        _fields(case, "id claim scenario load repetition track root stop_digest invocations")
        case_id = _text(case["id"])
        claim = case["claim"]
        _require(claim in (*SCENARIOS, "startup"), "claim")
        startup = claim == "startup"
        _require(case["scenario"] in (
            STARTUP_SCENARIOS if startup else SCENARIOS[claim] | BOUNDARIES), "scenario")
        _require(case["load"] in m["loads"] and _integer(case["repetition"]) < 20,
                 "load/repetition")
        _require(case["track"] == (STARTUP_TRACK if startup else SYNTHETIC_TRACK), "track")
        _fields(case["invocations"], " ".join(ROLES))
        for invocation in case["invocations"].values():
            _hex(invocation, 32)
        _require(len(set(case["invocations"].values())) == len(ROLES),
                 "case invocation separation")
        _process(case["root"], _backend_identity(m, case))
        _hex(case["stop_digest"])
        _require(case_id not in cases, "case collision")
        cases[case_id] = case
        counts[case["track"], claim, case["scenario"], case["load"], case["repetition"]] += 1
    expected = {
        (SYNTHETIC_TRACK, claim, scenario, load, repetition)
        for claim, scenarios in SCENARIOS.items()
        for scenario in scenarios | BOUNDARIES
        for load in ("idle", "maximum") for repetition in range(20)
    }
    expected |= {
        (STARTUP_TRACK, "startup", scenario, load, repetition)
        for scenario in STARTUP_SCENARIOS
        for load in ("idle", "maximum") for repetition in range(20)
    }
    _require(set(counts) <= expected and all(n == 1 for n in counts.values()),
             "approved case matrix contains duplicate or unsupported cells")
    _require(len({c["invocations"]["backend"] for c in cases.values()}) == len(cases),
             "fresh backend invocation per case")
    _require(len({(c["root"]["pid"], c["root"]["start_ns"]) for c in cases.values()}) ==
             len(cases), "fresh process per case")
    _require(len({c["stop_digest"] for c in cases.values()}) == len(cases),
             "fresh signed command per case")
    return cases


def _coverage_complete(cases, claim):
    scenarios = STARTUP_SCENARIOS if claim == "startup" else SCENARIOS[claim] | BOUNDARIES
    expected = {(scenario, load, repetition) for scenario in scenarios
                for load in ("idle", "maximum") for repetition in range(20)}
    actual = {(case["scenario"], case["load"], case["repetition"])
              for case in cases.values() if case["claim"] == claim}
    return actual == expected


def _backend_identity(m, case):
    return dict(m["identities"]["backend"], invocation=case["invocations"]["backend"])


def _signature(public, payload, signature):
    Ed25519PublicKey.from_public_bytes(public).verify(
        bytes.fromhex(_hex(signature, 128)), DOMAIN + canonical(payload),
    )


def _binding(payload, m, case, approved):
    _fields(payload, "version manifest case observer observer_invocation vm boot target invocation cgroup "
            "stop_fingerprint seq previous time_ns kind data")
    _require(payload["version"] == VERSION and payload["manifest"] == approved,
             "evidence schema/manifest")
    for key, expected in {
        "case": case["id"], "vm": m["vm"]["id"], "boot": m["vm"]["boot"],
        "target": m["target"], "observer": m["authorities"]["observer"]["fingerprint"],
        "invocation": case["invocations"]["backend"],
        "observer_invocation": case["invocations"]["observer"],
        "cgroup": m["identities"]["backend"]["cgroup"],
        "stop_fingerprint": m["authorities"]["stop"]["fingerprint"],
    }.items():
        _require(payload[key] == expected, "evidence identity: " + key)
    _integer(payload["seq"])
    _hex(payload["previous"])
    _require(_integer(payload["time_ns"]) <= m["vm"]["expiry_ns"], "expired evidence")


def _tree(value, root, identity):
    nodes = _list(value)
    _require(len(nodes) >= 3, "positive child/grandchild tree")
    known = set()
    depths = {}
    for node in nodes:
        _fields(node, "process parent")
        key = _process(node["process"], identity)
        _require(key not in known, "duplicate process")
        if node["parent"] is None:
            _require(not known and node["process"] == root, "tree root")
            depths[key] = 0
        else:
            parent = _process(node["parent"], identity)
            _require(parent in known, "unknown parent")
            _require(key[1] >= parent[1], "child starts before parent")
            depths[key] = depths[parent] + 1
        known.add(key)
    _require(max(depths.values()) >= 2, "grandchild positive control")
    return known


def _measurement(data, m, case, failures, signed_at):
    _fields(data, "stop controls observation artifacts result")
    stop = data["stop"]
    wire = stop_signing_bytes(stop)
    _require(stop["latch_id"] == m["target"] and
             stop["key_id"] == m["authorities"]["stop"]["key_id"], "STOP binding")
    _require(stop_digest(stop) == case["stop_digest"], "exact signed STOP digest")
    Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(m["authorities"]["stop"]["public_key"]),
    ).verify(bytes.fromhex(stop["signature"]), wire)
    artifacts = _list(data["artifacts"])
    _require(len(artifacts) >= 1, "raw evidence references")
    for artifact in artifacts:
        _hex(artifact)
    controls = data["controls"]
    _fields(controls, "before_ns after_ns effects_before effects_after observer_before "
            "observer_after control_invocation workload_effects_before "
            "scenario_pass boundaries_pass")
    for key in ("before_ns", "after_ns", "effects_before", "effects_after",
                "observer_before", "observer_after"):
        _integer(controls[key])
    _require(all(controls[k] > 0 for k in
                 ("effects_before", "effects_after", "observer_before", "observer_after")),
             "missing positive liveness/effect controls")
    _require(controls["control_invocation"] == case["invocations"]["client"],
             "independent effect control identity")
    workload_effects = _integer(controls["workload_effects_before"])
    if case["claim"] != "startup":
        _require(workload_effects > 0, "workload not executing before STOP")
    _require(controls["scenario_pass"] == case["scenario"], "scenario positive control")
    _require(_strings(controls["boundaries_pass"]) == BOUNDARIES, "boundary controls")
    observation = data["observation"]
    _fields(observation, "source boot complete start_ns end_ns uncertainty_ns storage")
    _require(observation["source"] == m["authorities"]["observer"]["fingerprint"] and
             observation["boot"] == m["vm"]["boot"] and
             observation["complete"] is True, "independent continuous observation")
    start, end = (_integer(observation[k]) for k in ("start_ns", "end_ns"))
    uncertainty = _integer(observation["uncertainty_ns"])
    _require(uncertainty >= m["clock"]["uncertainty_ns"], "uncertainty understated")
    _require(start <= controls["before_ns"] < controls["after_ns"] <= end <=
             m["vm"]["expiry_ns"], "observation/control interval")
    _require(case["root"]["start_ns"] <= controls["before_ns"], "future subject process")
    _require(signed_at >= end, "measurement signed before observation")
    _require(observation["storage"] in ("blocked", "healthy"), "storage state")
    result = data["result"]
    if case["claim"] == "startup":
        _startup_measurement(result, m, case, controls, uncertainty, workload_effects, failures)
        return
    def timing(first, last, limit):
        a, b = (_integer(result[k]) for k in (first, last))
        _require(controls["before_ns"] <= a <= b <= controls["after_ns"], "event order")
        if b - a + uncertainty > limit:
            failures.append("deadline: " + first + " -> " + last)

    def window(anchor):
        first, last = (_integer(result[k]) for k in ("window_start_ns", "window_end_ns"))
        _require(result[anchor] == first <= last <= controls["after_ns"], "window order/gap")
        _require(last - first - uncertainty >= 10 * NS, "insufficient observation window")
        _require(_integer(result["attempts"]) > 0 and
                 _integer(result["restart_attempts"]) > 0, "missing adversarial attempts")
        for field in ("unauthorized_execution", "new_effects"):
            if _integer(result[field]) > 0:
                failures.append(field)
        _require(result["replacements_inhibited"] is True, "replacement inhibition unknown")

    if case["claim"] == "A":
        _fields(result, "trigger_ns reply_ns install_ns cancel_ns stall_start_ns "
                "stall_end_ns permits_valid_until_ns no_stop_effects "
                "denial_reply window_start_ns window_end_ns attempts restart_attempts "
                "unauthorized_execution new_effects replacements_inhibited")
        _require(observation["storage"] == "blocked", "ARM not blocked")
        _require(_integer(result["stall_start_ns"]) <= result["trigger_ns"] and
                 _integer(result["stall_end_ns"]) >= max(result["reply_ns"], result["cancel_ns"]),
                 "ARM blockage not continuous")
        _require(_integer(result["permits_valid_until_ns"]) >= result["stall_end_ns"] and
                 _integer(result["no_stop_effects"]) > 0, "expiry/inhibition false positive")
        _require(result["denial_reply"] == "VETO_DENIAL_CONFIRMED", "missing denial")
        timing("trigger_ns", "reply_ns", NS)
        timing("install_ns", "cancel_ns", NS // 2)
        _require(result["trigger_ns"] <= result["install_ns"] <= result["reply_ns"],
                 "installation not independently bound")
        window("install_ns")
    elif case["claim"] == "B":
        _fields(result, "release_ns durable_ns reconcile_ns restart_reconcile_ns "
                "command_digest anchor_digest store_digest receipt_digest "
                "reconciled_digest restarted_digest sync_readback healthy_control_digest "
                "healthy_control_reconciled")
        _require(observation["storage"] == "healthy", "storage still blocked")
        timing("release_ns", "durable_ns", 5 * NS)
        timing("release_ns", "reconcile_ns", 5 * NS)
        _require(result["durable_ns"] <= result["reconcile_ns"] <=
                 _integer(result["restart_reconcile_ns"]) <= controls["after_ns"],
                 "durability/restart order")
        for field in ("command_digest", "anchor_digest", "store_digest", "receipt_digest",
                      "reconciled_digest", "restarted_digest"):
            _hex(result[field])
            if result[field] != case["stop_digest"]:
                failures.append("false exact recording: " + field)
        _require(result["sync_readback"] is True, "missing sync/readback")
        _require(_hex(result["healthy_control_digest"]) != case["stop_digest"] and
                 result["healthy_control_reconciled"] is True, "durability positive control")
    else:
        _fields(result, "trigger_ns accept_ns terminated_ns controller_invocation tree exits survivors "
                "effects_seen ignored_cancel ignored_term cgroup_empty external_action "
                "window_start_ns window_end_ns attempts restart_attempts "
                "unauthorized_execution new_effects replacements_inhibited")
        _require(result["controller_invocation"] == case["invocations"]["controller"],
                 "controller identity")
        tree = _tree(result["tree"], case["root"], _backend_identity(m, case))
        seen = {_process(p, _backend_identity(m, case))
                for p in _list(result["effects_seen"])}
        _require(seen == tree and result["ignored_cancel"] is True and
                 result["ignored_term"] is True, "uncooperative tree positive control")
        exits = [_process(p, _backend_identity(m, case)) for p in _list(result["exits"])]
        _require(len(exits) == len(set(exits)) and set(exits) <= tree, "exit identities")
        survivors = [_process(p, _backend_identity(m, case))
                     for p in _list(result["survivors"])]
        _require(len(survivors) == len(set(survivors)) and set(survivors) <= tree
                 and not set(survivors) & set(exits), "survivor identities")
        if survivors or result["cgroup_empty"] is False:
            failures.append("surviving descendant/nonempty cgroup")
        _require(type(result["cgroup_empty"]) is bool and result["external_action"] is True,
                 "external cgroup action not observed")
        timing("trigger_ns", "accept_ns", NS)
        timing("accept_ns", "terminated_ns", 2 * NS)
        timing("trigger_ns", "terminated_ns", 3 * NS)
        window("terminated_ns")
        _require(set(exits) | set(survivors) == tree, "missing exit/survival observation")


def _startup_measurement(result, m, case, controls, uncertainty, workload_effects, failures):
    _fields(result, "activation_ns inhibition_observed_ns window_start_ns window_end_ns "
            "candidate unmodified preauthorization_used inhibition_observed "
            "requests fresh_authority challenges protected_effects predecessor")
    _require(result["candidate"] == m["candidate"] and result["unmodified"] is True,
             "ordinary candidate provenance")
    _require(type(result["preauthorization_used"]) is bool and
             type(result["inhibition_observed"]) is bool, "startup state observations")
    activation = _integer(result["activation_ns"])
    observed = _integer(result["inhibition_observed_ns"])
    first, last = (_integer(result[k]) for k in ("window_start_ns", "window_end_ns"))
    _require(controls["before_ns"] <= activation <= observed <= last <= controls["after_ns"]
             and first == activation and case["root"]["start_ns"] <= activation,
             "continuous startup observation")
    if workload_effects or result["preauthorization_used"] or not result["inhibition_observed"]:
        failures.append("startup inhibition violated")
    if _integer(result["protected_effects"]) > 0:
        failures.append("startup protected effect")
    requests = _list(result["requests"])
    _require(len(requests) > 0, "missing valid startup requests")
    for request in requests:
        _fields(request, "time_ns process otherwise_valid admitted")
        _require(request["process"] == case["root"], "startup request process")
        _require(first <= _integer(request["time_ns"]) <= last, "startup request time")
        _require(type(request["admitted"]) is bool, "startup admission observation")
        if request["admitted"]:
            failures.append("unauthorized startup admission")
        _require(request["otherwise_valid"] is True, "invalid-request false positive")
    _require(result["fresh_authority"] is True, "expired-authority false positive")
    _require(_strings(result["challenges"]) == STARTUP_CHALLENGES, "startup challenge coverage")
    if case["scenario"] == "replacement":
        predecessor = result["predecessor"]
        _fields(predecessor, "pid start_ns invocation cgroup")
        _hex(predecessor["invocation"], 32)
        _require(predecessor["invocation"] not in case["invocations"].values(),
                 "replacement reused invocation")
        old = _process(predecessor, dict(_backend_identity(m, case),
                                       invocation=predecessor["invocation"]))
        _require(old != (case["root"]["pid"], case["root"]["start_ns"]) and
                 predecessor["start_ns"] < case["root"]["start_ns"], "replacement identity")
    else:
        _require(result["predecessor"] is None, "unexpected predecessor")
    # Ten seconds is the existing contract's restart/reactivation observation target.
    _require(last - first - uncertainty >= 10 * NS, "insufficient startup window")


def evaluate(manifest_json: bytes, evidence_json: bytes, *,
             approved_manifest_sha256: str,
             observer_public_keys: Mapping[str, bytes]) -> Evaluation:
    """Evaluate untrusted JSON against out-of-band approval and observer pins.

    Invalid input is explicitly UNKNOWN. Authenticated standalone violations can
    establish FAIL even when another record or the chain is missing.
    """
    errors = (SchemaError, ValueError, TypeError, KeyError, UnicodeError,
              RecursionError, OverflowError, InvalidSignature)
    try:
        m = _decode(manifest_json)
        cases = _manifest(m, approved_manifest_sha256, observer_public_keys)
    except errors as error:
        return Evaluation("UNKNOWN", "UNKNOWN", "UNKNOWN", (),
                          ("manifest: " + type(error).__name__ + ": " + str(error),))
    diagnostics = []
    records = {case_id: [] for case_id in cases}
    failures = {case_id: [] for case_id in cases}
    invalid = set()
    global_invalid = False
    try:
        bundle = _decode(evidence_json)
        _fields(bundle, "version manifest records artifacts")
        _require(bundle["version"] == VERSION and
                 bundle["manifest"] == approved_manifest_sha256, "bundle binding")
        raw_records = _list(bundle["records"])
        _require(type(bundle["artifacts"]) is dict, "artifact inventory")
    except errors as error:
        return Evaluation("UNKNOWN", "UNKNOWN", "UNKNOWN", (),
                          ("bundle: " + type(error).__name__ + ": " + str(error),))
    valid_artifacts = set()
    for artifact, contents in bundle["artifacts"].items():
        try:
            _hex(artifact)
            _require(type(contents) is str and len(contents) > 0 and len(contents) % 2 == 0 and
                     re.fullmatch("[0-9a-f]*", contents) is not None, "artifact encoding")
            _require(hashlib.sha256(bytes.fromhex(contents)).hexdigest() == artifact,
                     "artifact digest")
            valid_artifacts.add(artifact)
        except errors as error:
            global_invalid = True
            diagnostics.append("artifact: " + type(error).__name__ + ": " + str(error))
    public = bytes.fromhex(m["authorities"]["observer"]["public_key"])
    for index, record in enumerate(raw_records):
        case_id = None
        try:
            _fields(record, "payload signature")
            payload = record["payload"]
            _require(type(payload) is dict, "record payload")
            case_id = payload.get("case")
            _require(type(case_id) is str and case_id in cases, "unknown case")
            _signature(public, payload, record["signature"])
            _binding(payload, m, cases[case_id], approved_manifest_sha256)
            kind = payload["kind"]
            _require(kind in ("measurement", "violation", "seal"), "record kind")
            if kind != "seal":
                _require(type(payload["data"]) is dict, "observation data")
                for artifact in _list(payload["data"].get("artifacts")):
                    _require(type(artifact) is str and artifact in valid_artifacts,
                             "missing raw artifact")
            if kind == "violation":
                _fields(payload["data"], "code artifacts process")
                _require(payload["data"]["code"] in
                         VIOLATIONS[cases[case_id]["claim"]] | {"privilege-escape", "substitution"},
                         "violation code")
                _require(len(_list(payload["data"]["artifacts"])) > 0, "violation evidence")
                for artifact in payload["data"]["artifacts"]:
                    _hex(artifact)
                _require(payload["data"]["process"] == cases[case_id]["root"],
                         "violation process identity")
                failures[case_id].append(payload["data"]["code"])
            elif kind == "measurement":
                _measurement(payload["data"], m, cases[case_id], failures[case_id],
                             payload["time_ns"])
            else:
                _fields(payload["data"], "complete")
                _require(payload["data"]["complete"] is True, "incomplete seal")
            records[case_id].append(payload)
        except errors as error:
            if type(case_id) is str and case_id in cases:
                invalid.add(case_id)
            else:
                global_invalid = True
            diagnostics.append("record " + str(index) + ": " +
                               type(error).__name__ + ": " + str(error))
    verdicts = {}
    for case_id, case in cases.items():
        chain = records[case_id]
        try:
            _require(not global_invalid and case_id not in invalid, "invalid record")
            _require(len(chain) >= 2 and chain[-1]["kind"] == "seal", "missing case seal")
            _require(sum(p["kind"] == "measurement" for p in chain) == 1 and
                     sum(p["kind"] == "seal" for p in chain) == 1, "case record count")
            previous, timestamp = ZERO, 0
            for sequence, payload in enumerate(chain):
                _require(payload["seq"] == sequence and payload["previous"] == previous,
                         "broken event chain")
                _require(payload["time_ns"] >= timestamp, "nonmonotonic event chain")
                previous, timestamp = digest(payload), payload["time_ns"]
            verdicts[case_id] = "PASS"
        except errors as error:
            verdicts[case_id] = "UNKNOWN"
            diagnostics.append(case_id + ": " + str(error))
        if failures[case_id]:
            verdicts[case_id] = "FAIL"
            diagnostics.extend(case_id + ": " + reason for reason in failures[case_id])
    campaign = {}
    for claim in (*SCENARIOS, "startup"):
        values = {verdicts[cid] for cid, case in cases.items() if case["claim"] == claim}
        if not _coverage_complete(cases, claim):
            values.add("UNKNOWN")
            diagnostics.append(claim + ": incomplete required track coverage")
        campaign[claim] = _aggregate(values)
    return Evaluation(campaign["A"], campaign["B"], campaign["C"],
                      tuple(verdicts.items()), tuple(diagnostics),
                      campaign["startup"], _aggregate(campaign.values()))
