# Ask GV pure invite admission policy V1

**Candidate policy only. No credentials, requests, storage or gateway are created.**
Base `6db328eda9672fccf6f3162a379da8ed09a93bb8`, branch proposed and created under
separate authorization: `feature/public-ask-gv-invite-admission-v1`, worktree
`/workspaces/gvai-public-ask-gv-invite-admission-v1`. Source origin:
`https://github.com/willshacklett/gvai-safety-systems`.

This slice adds only this document, `ask-gv/invite-admission-policy.mjs` and
`tests/ask-gv/invite-admission-policy.test.mjs`. Browser, relay, facts, permanent
feedback, config, templates, budget custody and Customer Zero stay unchanged.
The public endpoint remains empty and approved endpoint origin remains unset.

## Decision boundary and API

`evaluateInvitePolicy(asciiJsonText)` accepts one primitive string of serialized
JSON, never objects/getters/proxies/callbacks. It returns a frozen fixed record:

```json
{"version":"ask-gv-invite-policy-result-v1","decision":"conditional_allow","reason":"eligible_for_atomic_claim","external_evidence_verified":false,"credential_issued":false,"request_executed":false,"storage_authenticated":false,"durable_atomicity_proven":false}
```

`decision` is exactly `conditional_allow`, `deny` or `hold`. No exception from
untrusted input is returned or thrown; grammar/schema errors become a fixed HOLD.
No invite/session IDs, code/token/digest, private field or raw error is echoed.

Every positive evidence claim is **supplied and unverified**, even in a conditional
allow. It may be false or forged. This module does not hash credentials, authenticate
matches, check storage, issue a code/session, update state, reserve a request or
observe the real clock. A future runtime adapter must independently establish those
facts and repeat checks at its actual commit/forward boundary. No pure result is an
executable approval, an issuer, proof of identity or authority to bypass a missing
gateway, operator, store, revocation source or release gate.

`POLICY_LIMITS` is an exported frozen candidate constant object. It is not an
operational allowance or external approval. The module has no imports or effects:
no filesystem, RNG, private records, locks/fsync, native fetch, sockets/listeners,
subprocesses, timers, wall-clock/monotonic reads or ambient environment access.

## Canonical transport and finite bounds

- ASCII JSON transport only, maximum 32,768 bytes/characters. Non-ASCII values can
  be JSON-escaped but still must meet decoded field schemas. This modest text cap
  bounds parsing for a 32-record candidate and is not an HTTP/body limit approval.
- JSON grammar validated, then a bounded structural walk rejects **every duplicate
  decoded member name** at every object depth, including Unicode-escaped aliases.
  Maximum depth 8 (root 0) and 2,048 values: generous for these shallow bounded
  records, limiting adversarial complexity. Array entries each count as values;
  property names do not. JSON.parse grammar allocation is already text-bounded.
- Integer tokens must be unsigned canonical decimal (`0` or nonzero digit followed
  by digits). No `-0`, negative, fraction or exponent spelling. Numeric fields are
  nonnegative safe integers, at most 9,007,199,254,740,991; generations start at 1.
- Times use **milliseconds**: `*_ms` UTC epoch and explicit process-monotonic
  milliseconds. Every interval has positive duration; lower bound inclusive,
  expiry exclusive (`now >= expires` fails). No implicit current time.
- IDs: decoded lowercase ASCII `[a-z][a-z0-9-]{0,63}`. The 64-character cap bounds
  opaque correlation labels; not a generator or personal identifier format.
- Codes and bearer payloads: decoded unpadded base64url of exactly 32 bytes,
  43 characters, with final character in `AEIMQUYcgkosw048` (zero unused pad bits).
  Session representation exactly `Bearer ` plus that payload, single space and
  case-sensitive prefix. No padding, whitespace, comma, aliases or CR/LF. This
  validates representation, **not entropy, possession truth or cryptography**.
- Digests: exactly 64 lowercase hex characters, declared future SHA256 bytes.
  They are supplied record data, not computed or authenticated here. A match claim
  is separate and unverified. Future runtime must hash canonical decoded credential
  bytes with the agreed algorithm; no test fixture is a real valid hash/code pair.
- Exact key sets at every record. Unknown keys, versions, types or missing fields
  HOLD. Object key order and JSON whitespace are immaterial; decoded string
  spellings are canonical. Escaped equivalent ASCII text is allowed; duplicate
  decoded property names are not. No permissive URL normalization.

Candidate bounds inherited from plan: 32 active invites, 24-hour maximum invitation
lifetime, 15-minute maximum session lifetime, 5 forwards per session. This pure
representation conservatively caps **all invite records** (including revoked) at
32, and active session IDs at 32: finite scan/memory without inventing archive or
GC authority. Durable consumed records must never be discarded to meet this cap.
A larger revoked archive needs a separately reviewed runtime representation.

Additional explicit candidate decisions:
- Metadata snapshot lifetime is at most 24 hours, using existing invite horizon to
  require review rather than an unbounded policy. This is NOT automatic renewal.
- Evidence age at most 1,000 ms on BOTH supplied clocks; age 1,000 is accepted,
  future or 1,001 fails. The short tolerance allows bounded adapter processing,
  not a one-second cache permission. Revocation must be reread each request and
  rechecked before forward. No age check proves source freshness/authenticity.
- Clock history must not go backwards on either clock. Difference between their
  supplied elapsed intervals must be at most 1,000 ms, inclusive. This conservative
  candidate alarm bounds tolerated divergence but is not clock-health proof.
- Origin text max128, path max64, method max8 printable ASCII characters. These
  cover only the small planned routes and existing page origins with finite inputs;
  not approval of longer routes, headers or new origins.
- Proposed runtime 6 redemptions/IP/min and 30 global/min remain EXTERNAL gates.
  No IP/rate-window model or independently verified counters exist in this slice.

## Exact schema fields

All version values below use literal prefix `ask-gv-invite-policy-`.
Every listed key is required and all other keys are forbidden. There is no hash
map with user-selected prototype names and no permissive header object API.

| Record | Exact keys and constraints |
| --- | --- |
| Input | `version:input-v1`, `action:redeem/forward/logout`, `invite_id:ID`, `policy`, `consumption`, `session:null or Session`, `capacity`, `clock`, `request`, `external` |
| Policy | `version:metadata-v1`, `generation:integer>=1`, `state:enabled/disabled`, `issued_at_ms`, `expires_at_ms` (positive <=24h interval), `origins` (1..2 unique exact existing page origins), `invites` (0..32 Invite records) |
| Invite | `version:invite-v1`, `id`, `code_digest`, `generation:integer>=1`, `state:active/revoked/disabled`, `issued_at_ms`, `expires_at_ms` (positive <=24h interval) |
| Consumption | `version:consumption-v1`, `invite_id`, `invite_generation:integer>=1`, `state:unused/consumed/uncertain`, `revision`, `expected_revision` (nonnegative; consumed revision>=1) |
| Session | `version:session-v1`, `id`, `token_digest`, `invite_id`, `invite_generation`, `policy_generation` (generations>=1), `state:active/revoked/logged_out`, `created_at_ms`, `expires_at_ms`, `created_mono_ms`, `expires_mono_ms`, `forwarded_attempts:0..5` |
| Capacity | `version:capacity-v1`, `active_session_ids` (0..32 unique IDs) |
| Clock | `version:clock-v1`, `now_ms`, `mono_ms`, `previous_ms`, `previous_mono_ms`, `certain:boolean` |
| Request | `version:request-v1`, `method`, `path`, `origin`, `credential` (code for redeem, exact bearer for other actions) |
| External | `version:external-v1`, `policy_generation`, `observed_at_ms`, `observed_mono_ms`, `gateway`, `operator`, `storage`, `revocation` (each `supplied_ok/missing/uncertain`), `release:supplied_open/closed/missing/uncertain`, `credential_match:supplied_match/mismatch/missing/uncertain` |

Policy origins are a subset of existing public-page origins
`https://gvaisafety.com` and `https://www.gvaisafety.com`, not approved backend
origins or endpoint activation. Invite IDs AND code digests must each be unique.
Duplicate origins/session IDs or invite aliases HOLD as ambiguous policy.
Session IDs refer to current bounded active-session snapshot; the pure module
cannot detect hidden duplicate tokens or absent runtime records outside that input.

Exact action routes (no queries, slash suffix, escaping or case normalization):

| Action | Method | Path | Meaning of conditional recommendation |
| --- | --- | --- | --- |
| redeem | POST | /v1/ask-gv/session | Eligible to attempt a FUTURE atomic claim, not to issue a session |
| forward | POST | /v1/ask-gv | Eligible for a future single forward after external checks/attempt debit |
| logout | DELETE | /v1/ask-gv/session | Eligible for future local session removal, no forward or refill |

OPTIONS is outside this three-action model and gets route denial. It will need a
separately reviewed gateway preflight path, not a bearer/session grant. Logout's
browser memory clearing never requires a positive result; expired/missing session
can still be cleared locally. No body/content-type/header parser is implemented;
`request` is already normalized external evidence. Future adapter must reject
multiple raw headers and other transport ambiguities before constructing it.

## Evaluation order, states and reasons

Schema validation FIRST for all fields, even if another gate would deny. Thus
malformed uncertainty cannot accidentally permit progress. Then fixed precedence:
clock certainty -> clock rollback/divergence -> missing/uncertain external gates ->
release closed/credential mismatch -> evidence age/generation -> policy state/time ->
Origin/route -> target invite state/time -> consumption identity/generation/state/
revision -> action-specific session/capacity/expiry/limit checks. One bounded
reason is returned, not a private multi-error diagnostic.

- Metadata future/expired -> HOLD stale policy; disabled -> DENY.
- Invite must exist and be active, with issued <= now < expiry.
- Consumption must match invite ID/generation; uncertainty -> HOLD; revision
  disagreement -> HOLD conflict. Revisions are simulated supplied snapshots, not CAS.
- Redeem requires `session:null`, unused consumption and fewer than32 live session
  IDs. Consumed -> replay DENY. Eligibility changes **nothing**; two concurrent
  unused snapshots can both be eligible. A future exclusive durable claim decides
  the actual winner. This API has no after-claim session-issuance action.
- Forward/logout require consumed matching record, supplied session ID present in
  active IDs, matching invite and current global policy generations, active state.
  A global policy generation change invalidates old sessions (conservative cohort
  reauthorization); a changed invite generation invalidates that invite's session.
- Session UTC and monotonic positive durations must be equal and <=15min; UTC
  creation cannot precede invite or current policy issuance; UTC expiry cannot
  outlive invite expiry. Either clock before creation denies not-yet-valid;
  either clock at/past expiry denies expired. No real process epoch binding is
  authenticated: runtime restart MUST invalidate all session records externally.
- Forward count5 denies forward; counts0..4 may be conditionally eligible. Count>5
  is malformed HOLD. At5 local logout may still be recommended. No count changes.

Fixed complete reason taxonomy:

```
HOLD: input_invalid policy_ambiguous clock_uncertain clock_rollback clock_divergence
      external_missing external_uncertain evidence_stale policy_stale
      consumption_uncertain consumption_conflict consumption_missing session_missing
DENY: release_closed credential_mismatch policy_disabled origin_mismatch
      route_mismatch invite_missing invite_inactive invite_not_yet_valid invite_expired
      generation_changed invite_replay session_inactive session_not_yet_valid
      session_expired capacity_exhausted attempts_exhausted
CONDITIONAL: eligible_for_atomic_claim eligible_for_single_forward eligible_for_local_logout
```

Malformed types/grammar/duplicates do not emit raw parser exceptions. Unknown data
or versions always HOLD, never default to an enabled or trusted state.

## Complete public synthetic input example

All strings below are fixed public fixtures. The code is a representation of zero
bytes, not entropy or an operational invitation. Digests are intentionally dummy
strings; no real relationship/match or issuance is established. Positive external
claims are unverified assumptions, not an approval file. This is documentation,
not filesystem-backed authorization state. UTC values are synthetic timestamps.

Redeem (result reason `eligible_for_atomic_claim`):

```json
{
  "version": "ask-gv-invite-policy-input-v1",
  "action": "redeem",
  "invite_id": "invite-example",
  "policy": {
    "version": "ask-gv-invite-policy-metadata-v1",
    "generation": 1,
    "state": "enabled",
    "issued_at_ms": 1799999999000,
    "expires_at_ms": 1800003600000,
    "origins": [
      "https://gvaisafety.com"
    ],
    "invites": [
      {
        "version": "ask-gv-invite-policy-invite-v1",
        "id": "invite-example",
        "code_digest": "1111111111111111111111111111111111111111111111111111111111111111",
        "generation": 1,
        "state": "active",
        "issued_at_ms": 1799999999000,
        "expires_at_ms": 1800003600000
      }
    ]
  },
  "consumption": {
    "version": "ask-gv-invite-policy-consumption-v1",
    "invite_id": "invite-example",
    "invite_generation": 1,
    "state": "unused",
    "revision": 1,
    "expected_revision": 1
  },
  "session": null,
  "capacity": {
    "version": "ask-gv-invite-policy-capacity-v1",
    "active_session_ids": []
  },
  "clock": {
    "version": "ask-gv-invite-policy-clock-v1",
    "now_ms": 1800000000000,
    "mono_ms": 100000,
    "previous_ms": 1799999999900,
    "previous_mono_ms": 99900,
    "certain": true
  },
  "request": {
    "version": "ask-gv-invite-policy-request-v1",
    "method": "POST",
    "path": "/v1/ask-gv/session",
    "origin": "https://gvaisafety.com",
    "credential": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  },
  "external": {
    "version": "ask-gv-invite-policy-external-v1",
    "policy_generation": 1,
    "observed_at_ms": 1800000000000,
    "observed_mono_ms": 100000,
    "gateway": "supplied_ok",
    "operator": "supplied_ok",
    "storage": "supplied_ok",
    "revocation": "supplied_ok",
    "release": "supplied_open",
    "credential_match": "supplied_match"
  }
}
```

Forward (result reason `eligible_for_single_forward`):

```json
{
  "version": "ask-gv-invite-policy-input-v1",
  "action": "forward",
  "invite_id": "invite-example",
  "policy": {
    "version": "ask-gv-invite-policy-metadata-v1",
    "generation": 1,
    "state": "enabled",
    "issued_at_ms": 1799999999000,
    "expires_at_ms": 1800003600000,
    "origins": [
      "https://gvaisafety.com"
    ],
    "invites": [
      {
        "version": "ask-gv-invite-policy-invite-v1",
        "id": "invite-example",
        "code_digest": "1111111111111111111111111111111111111111111111111111111111111111",
        "generation": 1,
        "state": "active",
        "issued_at_ms": 1799999999000,
        "expires_at_ms": 1800003600000
      }
    ]
  },
  "consumption": {
    "version": "ask-gv-invite-policy-consumption-v1",
    "invite_id": "invite-example",
    "invite_generation": 1,
    "state": "consumed",
    "revision": 1,
    "expected_revision": 1
  },
  "session": {
    "version": "ask-gv-invite-policy-session-v1",
    "id": "session-example",
    "token_digest": "2222222222222222222222222222222222222222222222222222222222222222",
    "invite_id": "invite-example",
    "invite_generation": 1,
    "policy_generation": 1,
    "state": "active",
    "created_at_ms": 1799999999000,
    "expires_at_ms": 1800000899000,
    "created_mono_ms": 99000,
    "expires_mono_ms": 999000,
    "forwarded_attempts": 0
  },
  "capacity": {
    "version": "ask-gv-invite-policy-capacity-v1",
    "active_session_ids": [
      "session-example"
    ]
  },
  "clock": {
    "version": "ask-gv-invite-policy-clock-v1",
    "now_ms": 1800000000000,
    "mono_ms": 100000,
    "previous_ms": 1799999999900,
    "previous_mono_ms": 99900,
    "certain": true
  },
  "request": {
    "version": "ask-gv-invite-policy-request-v1",
    "method": "POST",
    "path": "/v1/ask-gv",
    "origin": "https://gvaisafety.com",
    "credential": "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  },
  "external": {
    "version": "ask-gv-invite-policy-external-v1",
    "policy_generation": 1,
    "observed_at_ms": 1800000000000,
    "observed_mono_ms": 100000,
    "gateway": "supplied_ok",
    "operator": "supplied_ok",
    "storage": "supplied_ok",
    "revocation": "supplied_ok",
    "release": "supplied_open",
    "credential_match": "supplied_match"
  }
}
```

Logout at exhausted forward count (reason `eligible_for_local_logout`):

```json
{
  "version": "ask-gv-invite-policy-input-v1",
  "action": "logout",
  "invite_id": "invite-example",
  "policy": {
    "version": "ask-gv-invite-policy-metadata-v1",
    "generation": 1,
    "state": "enabled",
    "issued_at_ms": 1799999999000,
    "expires_at_ms": 1800003600000,
    "origins": [
      "https://gvaisafety.com"
    ],
    "invites": [
      {
        "version": "ask-gv-invite-policy-invite-v1",
        "id": "invite-example",
        "code_digest": "1111111111111111111111111111111111111111111111111111111111111111",
        "generation": 1,
        "state": "active",
        "issued_at_ms": 1799999999000,
        "expires_at_ms": 1800003600000
      }
    ]
  },
  "consumption": {
    "version": "ask-gv-invite-policy-consumption-v1",
    "invite_id": "invite-example",
    "invite_generation": 1,
    "state": "consumed",
    "revision": 1,
    "expected_revision": 1
  },
  "session": {
    "version": "ask-gv-invite-policy-session-v1",
    "id": "session-example",
    "token_digest": "2222222222222222222222222222222222222222222222222222222222222222",
    "invite_id": "invite-example",
    "invite_generation": 1,
    "policy_generation": 1,
    "state": "active",
    "created_at_ms": 1799999999000,
    "expires_at_ms": 1800000899000,
    "created_mono_ms": 99000,
    "expires_mono_ms": 999000,
    "forwarded_attempts": 5
  },
  "capacity": {
    "version": "ask-gv-invite-policy-capacity-v1",
    "active_session_ids": [
      "session-example"
    ]
  },
  "clock": {
    "version": "ask-gv-invite-policy-clock-v1",
    "now_ms": 1800000000000,
    "mono_ms": 100000,
    "previous_ms": 1799999999900,
    "previous_mono_ms": 99900,
    "certain": true
  },
  "request": {
    "version": "ask-gv-invite-policy-request-v1",
    "method": "DELETE",
    "path": "/v1/ask-gv/session",
    "origin": "https://gvaisafety.com",
    "credential": "Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  },
  "external": {
    "version": "ask-gv-invite-policy-external-v1",
    "policy_generation": 1,
    "observed_at_ms": 1800000000000,
    "observed_mono_ms": 100000,
    "gateway": "supplied_ok",
    "operator": "supplied_ok",
    "storage": "supplied_ok",
    "revocation": "supplied_ok",
    "release": "supplied_open",
    "credential_match": "supplied_match"
  }
}
```

## Pure validation and later acceptance

Selected source has only `node:test`, `node:assert/strict` and this pure module as
imports. No imported test modules, service fixtures or provider adapters. Fixtures
are fixed public synthetic strings and clocks. No actual credentials are generated,
no real hash is computed, no listener/storage/RNG/subprocess/transport is available.

Under separately inspected finite outer supervision, only:

```
node --check ask-gv/invite-admission-policy.mjs
node --check tests/ask-gv/invite-admission-policy.test.mjs
node tests/ask-gv/invite-admission-policy.test.mjs
```

Direct node:test execution avoids a separate test-runner worker. Outer candidate
validation deadline 30 seconds, syntax 10 seconds, combined live output 128 KiB;
these are tooling limits, not operational timeouts. No blanket suites or install.

Pure tests cover conditional/deny/HOLD, exact versions/keys/bounds, duplicates,
encoded-name aliases, malformed JSON and numbers, time/capacity boundaries,
revocation/generation/missing gates, consumed replay/revision uncertainty,
canonical bearer, exact Origin/routes, redaction and repeatability. The synthetic
concurrency test explicitly accepts two identical unused snapshots before a
simulated consumed record makes replays fail. It proves no mutual exclusion.
A syntactically valid unrelated code with supplied_match can remain conditional;
the test makes explicit that this module authenticates no real credential match.

Later, separate approval is required for:

1. Runtime adapter hashing/constant-time comparisons, secure independent RNG and
   individualized delivery, input/header parsing, session map/process identity,
   actual per-request policy freshness, serialized count debit, private gateway.
2. Persistent atomic claim BEFORE any session issuance. Real filesystem ownership,
   no-follow/single-link validation, locking, exclusive create, fsync ordering,
   crash/lost response/replay/concurrent writer and rollback/restore reconciliation
   tests cannot be proved by this model. Root-owned generations and off-host
   custody required; this module creates no store or approval record.
3. Revocation updates, logout vs queued forwards, bounded in-flight cancellation,
   UTC/monotonic clock health, restart wiping sessions while preserving used codes.
   Real revoke/disable can race forward; no atomic STOP/refund claim.
4. Browser memory-only sessions, explicit per-visitor Authorization with
   credentials:omit, no shared secret, CSRF/Origin/JSON/preflight checks; no cookie
   or Authorization assumed to reach relay. Existing Nginx header stripping/direct
   proxy/token injection must be reviewed, not bypassed. Only gateway holds relay
   ingress token; bearer never reaches relay/provider. Unknown duplicate raw headers
   and malformed encodings must fail before evidence construction.
5. Dedicated host/UID/private Unix socket/firewall/TLS/domain/renewal, immutable
   source/runtime custody and independent whole-job containment. No Lab-01,
   Customer Zero, private logs, tenant/billing or STOP/ARM authority in public chat.
6. Actual CLI/browser/HTTP/proxy/disposable-storage tests, then separately bounded
   paid model compatibility and deployment approvals. No real resources in this slice.
7. Provider finite100-attempt custody remains independent and unchanged, not a
   verified dollar cap. Model prices/input tokens/enforced spend and privacy/
   retention/consent/contact ownership remain HOLD; no auto refill, refunds or retry.
   Facts still expire 2027-02-10. No silent date extension or production claim.

Public invitation gateway, issuer, session generation, actual cryptographic
identity, durable one-use consumption and operational release remain MISSING.
Root/host compromise and coordinated local-state rollback require independent
external controls; supplied flags cannot supply them. Session/token replay beyond
provided evidence and historical revocations not present in input are unverified.

Customer Zero F2/F3/R1-R6, P1/P2, N4/N7/N8/N12, effect-based BLOCK mismatch,
meaningful telemetry and independent STOP/ARM remain open. All-zero telemetry/empty
effects ALLOW/green/0 is connectivity only, not risk detection or enforcement.
Advisory never enforces STOP or proves remote termination/refunds.

No commit, push, merge, PR, activation or deployment authorized by this document.
Review the exact three new paths and external blockers before any preservation.
