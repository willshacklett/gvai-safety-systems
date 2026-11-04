# I8E offline disposable STOP validator

Status: **EXPERIMENTAL, TEST ONLY**. This is an offline evidence-format kernel,
not a host adapter, executable runbook, authority service or acceptance result.
The [I8B contract](disposable_stop_veto_acceptance_v1.md) remains authoritative.
No production startup inhibition, authority state or deployment file changes.
PR #48 remains Draft.

Implementation:
[experimental_disposable_stop_validator.py](../gvai/experimental_disposable_stop_validator.py).
The [dedicated fixtures](../tests/test_experimental_disposable_stop_validator.py)
are generated synthetic data, not recovered or newly measured host evidence.

## Trust boundary and API

`evaluate(manifest_json, evidence_json, *,
approved_manifest_sha256, observer_public_keys)` accepts bytes and returns an
immutable `Evaluation` containing separate synthetic-session A/B/C verdicts,
an independent `startup` inhibition verdict, a combined `campaign` verdict,
case verdicts and diagnostics. Campaign PASS requires all four verdicts PASS;
an observed FAIL takes precedence over any missing coverage. Neither track
substitutes for the other. It performs no file I/O, host discovery, network requests,
subprocess creation, signaling or production imports. It cannot grant execution
permission or perform rollback.

The caller supplies **outside the bundle**:

- The SHA-256 of an independently approved, complete manifest.
- A mapping of observer public-key SHA-256 fingerprints to pinned raw Ed25519
  public keys. The manifest's observer key must match a pin exactly.

These are approval inputs, not values extracted from a received bundle.
Approval must include observer/instrumentation review, synthetic-key custody,
case coverage, the resource inventory and the evidence-export trust boundary.
Approving whatever digest/key a bundle supplies defeats this boundary.

Signatures establish attribution, not observer honesty, completeness or actual
isolation. Root, kernel and trusted-observer compromise remain outside the
model. No self-reported `trusted` flag or backend acknowledgement establishes
independently observed effects.

## Strict v2 encoding (I8G coverage remediation)

Manifest and bundle versions are `gvai-disposable-stop/v2`. The signature domain
is also bumped: v1 manifests/records cannot be silently promoted to the two-track
schema and require fresh external approval. Unknown/missing
fields, duplicate JSON keys, floats/nonfinite values, invalid UTF-8, negative
or boolean integers and unsupported versions are rejected as UNKNOWN with
diagnostics. Each input is limited to 64 MiB. Integer observations are
nanoseconds on one observer's monotonic clock, bounded by signed 64-bit range.
This is not a streaming or arbitrary-size evidence format.

Canonical encoding is ASCII JSON with sorted object keys, compact separators
and ASCII escapes. Hashes are lowercase SHA-256 hex. Observer signatures are
Ed25519 over `b"gvai-disposable-stop/v2\x00" + canonical(payload)`.
The manifest pin hashes its canonical encoding, **not original file bytes**.
Raw artifacts are hashed as bytes, not reserialized.

The implementation's exact-field checks are the executable schema; fixtures
provide a complete constructive example. Schema changes require a version
change and new approval.

### Manifest

| Fields | Required meaning |
|---|---|
| `version`, `scope`, `target`, `candidate`, `harness` | Version, unique `gvai-i8e-*` experiment prefix, V1 target identifier, full 40-hex baseline Git commit and reviewed harness/source-inventory SHA-256. |
| `environment` | One absolute CPython 3.11 executable/version for all Python roles, package/image/effective-configuration hashes, kernel, architecture, systemd, enforcing AppArmor and cgroup v2. These bind the approved environment; later independent instrumentation must verify effective state. |
| `vm` | Exact provider ID, different secondary identifier, boot ID, explicit disposable designation and experiment expiry on the observer's monotonic clock. |
| `authorities` | Distinct STOP, ARM, gate and observer key IDs/public keys/fingerprints, fixed custodians and synthetic designation. No private keys. STOP/ARM/gate keys never become observer roots. |
| `identities` | Distinct nonroot UID/GID, unit, profile and sibling cgroup for STOP signer, ARM signer, gate, backend, client, controller, observer and collector. |
| `resources` | Exact approved typed inventory: disks, units, sockets, directories, UIDs/GIDs, profiles, mounts, network policy, cgroups and evidence store. Identity resources must be root-controlled and fully referenced. |
| `cgroups` | Exact identity cgroups, root ownership and no delegation. Controller/observer cannot be workload descendants. |
| `channels` | Separate local service, notice, backend-STOP, controller-STOP, STOP gate-control, ARM gate-control, effect and evidence sockets. Root-controlled ancestors, mode 0600 and one approved source/destination pair each. |
| `storage` | Three distinct inventoried root/fault/evidence disks and the collector-owned evidence store. |
| `teardown` | Matching provider/secondary IDs, external operator, affirmative verified guest-independent mechanism, matching expiry and fixed 5 s cleanup guard. These are approved prerequisites, not proof of provider access or deletion. |
| `loads`, `reservations` | Frozen finite idle/maximum CPU, memory, tasks, FDs and backlog budgets; separate positive observer/controller/collector reservations. |
| `clock` | `observer-monotonic`, positive resolution and bounded uncertainty at least as large as resolution. |
| `cases` | Exact claim/scenario/load/repetition inventory, track, root PID/start-time identity, invocation IDs for every role and exact signed STOP digest. Backend invocation/process and command are fresh per case. |
| `replay_policy` | `authentic-stop-deny-only`; no authority history reset or production rearm. |

CPU budgets use integer millicores; all time values use nanoseconds.
The package and configuration hashes refer to independently approved inventories
including installation sources, effective units/drop-ins/profiles, role
interpreters and dependency/native-extension hashes. They are provenance pins,
not replacements for capturing those inventories as raw host evidence.

For 0600 sockets the approved **caller owns the socket**, while its ancestors
remain root-controlled. A future privileged activation adapter would deliver
the listener FD to the separate destination service. This does not claim that
unmodified deployment units already implement this routing. Listener provenance
and effective accepted/client peer identities still need independent
observation, including systemd-created-listener credential semantics.

Only deny-all/no-production networking is supported. There is no guest evidence
export network exception in v2; allowlisting one needs a reviewed schema change.
Fault/evidence mount paths are confined to the experiment path; actual mount
backing, ownership, collisions and effective resource reservations cannot be
discovered offline.

The fixed scenario inventory covers the A/B/C cases and all nine boundary
families in I8B. Each has exactly 20 distinct repetitions at idle and maximum
load: **1,920 synthetic-session cases**. Separately, `startup` cases must use
the `unmodified-startup` track and cover `ordinary-startup`, `replacement` and
`socket-activation`, each with 20 repetitions at both loads (120 cases).
**2,040 cases** are necessary for full campaign PASS. Track/claim mismatches,
duplicate cells and unsupported scenarios are invalid. An approved partial
inventory is evaluable but its incomplete claim is UNKNOWN (not PASS); this
preserves authenticated FAILs even when inventory or records are missing.
A family such as transaction-barriers or
fork/exec/reparent is a reviewed observer attestation over referenced raw
artifacts, not an automatic enumeration of every kernel event or I6D barrier.
Approval must check that the concrete case recipe covers every required
subcase; adding scenarios/repetitions requires a schema revision, not omission
or averaging of failing runs.

### Bundle and signed records

The bundle has exactly `version`, `manifest`, `records` and `artifacts`.
`artifacts` maps raw-byte SHA-256 to lowercase hex-encoded contents. Every
measurement/violation must reference present, digest-matching artifacts.
The validator does not interpret arbitrary raw artifact formats.

Every signed record has exactly `payload` and `signature`. Payload fields are:

`version`, `manifest`, `case`, `observer`, `observer_invocation`, `vm`, `boot`,
`target`, `invocation`, `cgroup`, `stop_fingerprint`, `seq`, `previous`,
`time_ns`, `kind`, `data`.

The manifest binds every identity. `invocation` is the case's backend invocation;
the observer has its own separately bound invocation. `previous` hashes the
preceding canonical payload; sequence starts at zero with a zero hash.
Timestamps must be nondecreasing. A complete case contains exactly one
measurement and a final signed `seal` with `{"complete": true}`; standalone
violation records may also occur. Missing, reordered, repeated or truncated
records cannot PASS. The seal is the observer's completeness attestation for
the approved observation period, not proof against a dishonest observer.

Measurement `data` contains:

- `stop`: the exact existing V1 public signed STOP envelope. This module
  independently verifies the fixed V1 wire domain, target, key ID, sequence and
  Ed25519 signature without importing the latch. Its command digest is SHA-256
  of V1 signing bytes plus signature bytes. It is not a new STOP command format.
- `controls`: before/after times, positive observer pulses and independent
  client-control effects, the client's invocation, pre-STOP workload effects,
  the reviewed scenario result and all boundary controls.
- `observation`: pinned observer source, boot, completeness, start/end,
  conservative uncertainty and storage state.
- `artifacts`: referenced raw trace digests.
- `result`: the claim-specific observations below.

Independent control effects after C come from the separate client control
source, **not the terminated workload**. C additionally requires pre-STOP
effects from every recorded member of its positive child/grandchild tree.
Startup uses the same independent observer/client positive controls but requires
zero protected-workload effects: an ordinary inhibited backend cannot be
required to execute protected work as a positive control.

| Claim | Mandatory observations |
|---|---|
| A | Trigger/reply, independently instrumented installation/cancellation, continuous ARM stall covering both bounds, fresh permit validity, same-fault no-STOP effects, exact denial reply, post-install observation window, attempted work/restart counts and zero unauthorized admissions/newly admitted effects. |
| B | Blockage release, durable/reconcile/restart-reconcile times, matching exact command digest reported in command/anchor/store/receipt/reconciliation/restart observations, sync/readback and a distinct successful healthy-storage positive control. |
| C | Authenticated trigger/controller acceptance, correct controller invocation, external action, complete observed tree with PID/start/invocation/cgroup identities and parent links, per-member positive effects, uncooperative behavior, explicit exit/survivor observations, cgroup emptiness and posttermination work/restart/effect observations. |
| startup | Ordinary candidate provenance; no preauthorization/setup seam; directly observed inhibition; otherwise-valid fresh-authority requests bound to the exact root process, all denied; no protected effects; continuous activation-to-window observation; ARM, late ARM, delayed notices, higher counters and changed notice-boot challenges; replacement predecessor identity where applicable. |

Startup result fields are exactly `activation_ns`, `inhibition_observed_ns`,
`window_start_ns`, `window_end_ns`, `candidate`, `unmodified`,
`preauthorization_used`, `inhibition_observed`, `requests`, `fresh_authority`,
`challenges`, `protected_effects`, `predecessor`. Requests contain `time_ns`,
`process`, `otherwise_valid`, `admitted`. Activation method is bound through the
approved scenario and observer's scenario control; it is not inferred from a
service reply. Each replacement case records a different earlier process/start
identity and invocation in the same experiment cgroup; other startup scenarios
require `predecessor: null`.

The startup window begins exactly at activation and uses the existing 10 s
restart/reactivation observation target, with uncertainty subtracted; it adds
no execution-admission or cancellation deadline for inhibited startup. An
explicitly admitted request, protected effect, cleared inhibition or applied
preauthorization is FAIL. Missing observation, modified/unbound candidate,
invalid/expired requests, missing controls/challenges or insufficient window
is UNKNOWN. Acknowledgements alone are never inhibition evidence. This does
not add or authorize a production rearm mechanism.

Digest fields in B report the **embedded signed command's digest**, not the
hash of each enclosing file. Original bytes have separate artifact hashes.
Missing exit observations are UNKNOWN, not inferred surviving descendants.
Explicitly observed survivors or a populated purportedly terminated cgroup
are failures. Dynamic children must appear in the complete observer tree;
missing/unbound/escaped process identities require UNKNOWN or an independently
authenticated violation record, never inference from an empty initial list.

A/C windows begin exactly at installation/termination, last at least 10 s
after subtracting uncertainty, and require attempted work and restart.
`new_effects` in A means effects from **new post-veto admissions**, not
irreversible effects admitted before the veto. Replacement-inhibited evidence
always describes the ordinary unmodified startup track. The manifest's
synthetic preauthorization label is never an instruction to reauthorize a
replacement process.

Signed `violation` data contains an enumerated claim-specific violation code,
nonempty raw-artifact references and the exact case root process identity.
It can establish FAIL independently of a missing measurement, seal or chain.
An escaped descendant is reported through a root-bound violation plus raw
identity evidence, not by accepting an unbound process as the original subject.

## Verdicts and limits

- **PASS:** the required matrix for the scoped claim/track is complete, every case passes provenance,
  controls, continuous observation, identity, chain and measurement rules.
- **FAIL:** an authenticated, identity-bound observation establishes a concrete
  violation or measured upper-bound breach. FAIL survives later missing or
  invalid records, including a broken case chain.
- **UNKNOWN:** missing/untrusted/forged/stale/inconsistent input, absent controls,
  observation gaps or unsupported schema. It cannot promote a claim.

A verified violation has priority over UNKNOWN and PASS. Invalid manifest
approval or an unreadable/ambiguous entire JSON document prevents establishing
the authority boundary at all and returns UNKNOWN.

Targets remain A1 <=1 s, A2 <=0.5 s, B1 <=5 s **after healthy-storage release**,
C0 <=1 s, C1 <=2 s and C0+C1 <=3 s, including uncertainty. Acknowledgements alone
never establish PASS. Results are evaluated independently per claim/track and across
all its cases; `campaign` explicitly aggregates A/B/C and startup without
relabeling startup denial as interruption, durability or termination.
An invalid unrelated record blocks
PASS but cannot erase a verified violation.

### Deliberately unresolved / not proved

- No live VM identity, provider access/expiry, teardown completion, key custody,
  collision detection, socket/peer provenance, effective AppArmor/network/
  systemd/cgroup policy or actual scheduler reservation is established here.
- Observer observations and positive-control assertions must come from a later
  independently reviewed adapter. A pinned key can sign false measurements.
  Raw artifacts are present/hash-checked, not semantically interpreted.
- This is a fixed single-boot experiment schema. Boot changes need new approved
  evidence scope; cross-host clocks, key rotation/revocation during a campaign,
  arbitrary case extensions and power-loss durability are unsupported.
- The result is a snapshot, not an append-only persistence service. A caller
  must retain earlier FAIL results and all approved evidence; submitting a
  different approval or discarding an earlier failed evaluation does not
  authorize promotion.
- No timeout submission result is rewritten by a later state observation.
  Transport-ambiguity fixtures belong to the observer's reviewed scenario;
  this evaluator exposes A/B/C state claims and startup inhibition, not a client-success API.
- Historical tests, generated passing fixtures and this validator's own tests
  cannot demonstrate host denial, durable STOP recording or process termination.
- Python 3.11 syntax/runtime and the complete I8B environment evidence are still
  required before any later host milestone. A newer interpreter's test result
  is not a Python 3.11 runtime result.

Independent review of this offline kernel is the next gate. No host experiment,
privileged adapter/controller, deployment or production rearm is authorized.
