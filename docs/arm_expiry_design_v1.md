# ARM V2 expiration design V1 (reconstructed prototype)

Base: `fb225cb6bf7707638f620cf465ce988cf3439b5f`.
This is a reconstruction, **not recovery of lost commit `6ca9252`**.
The original reconstruction added only tests and this document. Stage A adds
isolated ARM V2 parsing/signature verification; Stage B1 adds isolated freshness
validation. No deployment, Lab-01
change, commercial staging change, or independent enforcement is claimed.

## Completed Stage A: isolated verification

Implementation base: `f6e0fe741bdf0d9245a838685cb38d8d9a28626b`.
[`experimental_stop_latch.py`](../gvai/experimental_stop_latch.py) now provides:

- Frozen, construction-validated `ArmV2Authorization`, `arm_v2_signing_bytes`,
  `parse_arm_v2` and `arm_v2_envelope`. Version 2 and command type ARM are fixed
  by the model. Signing bytes include every unsigned field and the V2 domain.
  Production provides no private-key signing API.
- `parse_authorization_command(..., require_arm_v2=False)` accepts V2 ARM and
  V1 commands; `require_arm_v2=True` rejects legacy ARM but retains V1 STOP.
  This is a **parser policy**, not production enforcement.
- `decode_authorization_command` accepts only nonempty bytes up to 4096 bytes,
  decodes strict UTF-8, rejects duplicate keys and nonfinite JSON constants,
  and requires exact canonical JSON bytes (sorted keys, ASCII escaping, compact
  separators, no trailing whitespace). Mapping input may be reordered; it
  cannot detect duplicates already discarded by an upstream decoder.
- `ArmV2Keyring` retains inherited V1 verification unchanged and adds
  `verify_arm_v2(..., expected_latch_id=...)`. Separate V2 public keys are pinned
  through `ArmV2VerificationKey` to explicit authority/trust-domain identities.
  Reused V1 key IDs, key bytes, forbidden keys and duplicate V2 key bytes fail
  configuration. Invalid API input raises explicit errors; signature or target/
  binding mismatches return false.

STOP generation is an exact integer in `[0, 2**53]`; zero denotes genesis.
Validity bounds use the same range, with strict `not_before < not_after`.
Verification authenticates these fields but **does not check current time,
current generation, identity consumption, revocation or permission to run**.
The live latch still uses its unchanged V1 parser, digest, activation, store
and permit logic; it rejects V2 envelopes. No networking or timeout is changed.

[`test_arm_v2_authorization.py`](../tests/test_arm_v2_authorization.py) exercises
production parsing, canonical serialization and signature verification with
ephemeral Ed25519 keys, including malformed fields, raw JSON, tampering,
authority binding, cross-domain rejection, policy compatibility and absence
of activation side effects. These are ordinary passing tests, not xfails.
The reconstructed prototype and its enforcement xfails remain unchanged.

## Completed Stage B1: isolated freshness validation

Base: `b2be87298abf469d6e528be2d112e332b170ffba`.
[`arm_v2_freshness.py`](../gvai/arm_v2_freshness.py) adds a separate
`ArmV2FreshnessValidator`. Stage A parsing, signing and verification are
unchanged. Call `validate(authorization)` only after Stage A authentication
for the expected latch and pinned authority. A structurally valid dataclass
is **not proof of authentication**; the freshness component does not reverify
signatures and must never be exposed as an authentication endpoint.

The trusted supervisor must configure three providers at construction:
`TrustedClock.read()`, `StopGenerationAuthority.read()` and
`TrustedClockHighWater.observe(now)`. No request-side current-time or generation
argument is accepted. The authorization's signed generation is compared to
the authority's reading, never treated as the authority's current value.
Interfaces alone cannot prove independence: a compromised caller controlling
construction/providers can lie. Providers must be scoped to the expected
latch/trust domain and protected outside the workload. Do not expose their
selection to an untrusted requestor.

Clock and generation samples must be exact integers in `[0, 2**53]`; bool,
float (including integral floats), null, malformed values, NaN and infinity
deny. Any generation mismatch, including a future generation, denies.
Validity uses `not_before <= now < not_after`. Generation zero is genesis.
The configured high-water provider must atomically observe and record a valid
clock sample, return false on sticky rollback, and fail explicitly if its state
is corrupt/unavailable. Valid samples advance the mark even if generation or
window checks subsequently deny. Equal samples are accepted. Rollback denial
is sticky in the validator as well as the reference provider.

`VolatileClockHighWater(initial)` is a lock-protected, in-process reference.
Its initial mark must come from trusted configuration; it is not inferred from
the authorization. Reusing the object preserves history across validator
instances, but losing/recreating it loses history. **There is no restart-
persistent or independent anti-rollback enforcement implemented.** A durable
independent provider is required before such a claim. Clock/generation provider
errors and invalid samples deny that call; only detected rollback is sticky.

Stable decision codes:

| Verdict | Reason |
| --- | --- |
| ALLOW | `freshness_passed` |
| DENY | `invalid_authorization` |
| DENY | `clock_unavailable`, `invalid_clock`, `clock_rollback` |
| DENY | `high_water_unavailable`, `invalid_high_water_result` |
| DENY | `generation_unavailable`, `invalid_generation` |
| DENY | `stop_generation_mismatch` |
| DENY | `authorization_premature`, `authorization_expired` |

Provider exceptions are converted to explicit denial codes without exposing
exception details. Bad provider configuration raises `ValueError`. Inputs are
snapshotted and structurally revalidated; subclass inputs are rejected.
`ALLOW` means **sampled freshness checks passed only**, not execution permission.
No identity consumption, revocation, sequence enforcement or replay prevention
is added. Repeated authentic authorization may pass again within its window
and unchanged generation. Independently sampled time and generation are not an
atomic authority transaction: STOP can advance or time can expire after a read.
This module cannot close admission/commit/permit races and must not be used
as a cached execution capability.

[`test_arm_v2_freshness.py`](../tests/test_arm_v2_freshness.py) uses ephemeral
signing keys and injected providers to cover real Stage A authentication,
freshness boundaries, invalid inputs, failures, sticky rollback, shared-mark
history, restart loss and replay/authentication limitations. Production latch,
external gate, persistence, STOP sequencing, network and timeouts are untouched.
There is no workload shutdown enforcement or Lab-01/staging change.

Focused validation: **86 Stage B1 tests passed**, **148 Stage A tests passed**
and **58 existing latch tests passed**; combined **292 passed**, with no failures,
skips, expected failures or XPASSes. Run with the existing test runtime:

```sh
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=/usr/local/py-utils/venvs/pytest/lib/python3.14/site-packages \
/opt/conda/bin/python -m pytest -p no:cacheprovider -q \
  tests/test_arm_v2_freshness.py tests/test_arm_v2_authorization.py \
  tests/test_experimental_stop_latch.py
```

## Stage B2: test-only STOP race protection model

Base: `59a58db3d86fe61188077d46ef220ca556cb2fdf`.
[`test_arm_v2_stop_race.py`](../tests/test_arm_v2_stop_race.py) adds an
in-memory authority model **only in tests**. Stage A and B1 production code,
the live latch/gate, STOP behavior, persistence and timeouts remain unchanged.

The simulated trusted authority owns a monotonic generation, generation
high-water reference, revocation set and B1 clock high-water reference.
Its reentrant lock serializes every operation decision, STOP increment and
revocation. Each operation reparses/verifies ARM with Stage A, checks revocation
and invokes B1 with the authority's own generation provider. Cached decisions
are not accepted as requests. The atomicity is **relative to modeled STOP and
revocation operations using this lock**, not a transaction with the real world.

Linearization points:

- STOP linearizes when generation and its high-water reference are incremented
  together under the lock. Its success means generation advanced in memory,
  not STOP authentication, durable recording or workload halt.
- An ARM operation decision linearizes when its result is formed inside the
  same critical section, after authentication, revocation and freshness checks.
  STOP cannot change generation between these checks and the decision.
  A trusted injected clock reading is still a sample; real time can expire
  afterward. No workload action occurs in this test model.

Event-controlled races exercise both acquisition orders, without sleeps:
STOP-first advances generation and the old ARM receives DENY. ARM-first may
receive freshness ALLOW; STOP then advances generation, and every subsequent
operation with the old ARM receives DENY. The earlier immutable ALLOW still
exists as a historical result; it cannot be reused as permission or retroactively
prove a workload stopped. A new separately signed authorization bound to the
new generation may pass. Same-generation replay is not consumed and can pass
until expiration/revocation/STOP; this is explicitly tested, not claimed solved.

STOP never reads the ARM clock, and still advances after clock failure or
rollback. It can fail if authority state is unavailable, corrupt, rolled back
or generation is exhausted; such failures deny subsequent ARM decisions.
Valid-looking coherent rollback of **all** volatile reference state is not
detectable. Restart tests retain the same state object to prove logic continuity,
test corrupt/missing state denial, and explicitly show that resetting everything
to genesis can reapprove old ARM. This is not process-restart durability.

Future enforcement must put generation, revocation, signing policy, clock and
anti-rollback state behind an independent supervisor identity with durable
transactional authority. The protected backend must obtain a fresh operation-
bound decision at its action boundary, reject old-generation capabilities,
and invalidate/interdict in-flight work on STOP or authority silence. STOP
must have an independently enforced path not indefinitely blocked behind
ARM processing or I/O. This model holds a shared lock and proves ordering,
**not bounded STOP latency**, clock independence from lock availability,
host isolation, production-grade atomicity, persistent anti-rollback or
independent shutdown. No Lab-01, staging or deployment changes are made.

Focused results: **39 B2 cases passed**, **86 B1 cases passed**, **148 Stage A
cases passed**, and **58 latch cases passed**; combined **331 passed**, no
failures, skips, expected failures or XPASSes. Command:

```sh
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=/usr/local/py-utils/venvs/pytest/lib/python3.14/site-packages \
/opt/conda/bin/python -m pytest -p no:cacheprovider -q \
  tests/test_arm_v2_stop_race.py tests/test_arm_v2_freshness.py \
  tests/test_arm_v2_authorization.py tests/test_experimental_stop_latch.py
```

## Evidence and test interpretation

[`test_arm_expiry_prototype.py`](../tests/test_arm_expiry_prototype.py) uses the
real V1 latch and gate logic with in-memory anchor/store/seed substitutes.
Fixed test signing keys, explicit events and a manually advanced clock select
interleavings. Five-second waits are deadlock watchdogs, not latency assertions.
There are no sockets, disk stalls, sleeps, fsync delays or host experiments.

Passing `test_current_*` cases preserve observations, including unsafe limitations:

- ARM n+1 can hold the latch lock while persisting; authenticated STOP n+2
  waits. On release both succeed and the final state is STOPPED. This is an
  eventual-state observation, **not bounded STOP response or preemption**.
- At the same sequence, first committer wins in either order. ARM-first leaves
  ARMED because the conflicting STOP is rejected. STOP-first stays STOPPED.
- A simulated client abandoning its wait does not cancel an in-flight ARM.
  The anchor can already be advanced; later persistence returns acceptance.
  This models server behavior, not a measurement of transport timeout logic.
  Current reconciliation authenticates STOP only, and rejects ARM queries.
- Replayed ARM after STOP is rejected by sequence. An unused ARM signed before
  STOP, at the next contiguous sequence, can still reopen the latch indefinitely.
  Sequence freshness is not authorization freshness.
- Process loss after anchor advancement but before persistence faults a new
  verifier on missing/stale store, whether the previous state was genesis,
  ARMED or STOPPED. The crashed verifier's in-memory status is not evidence.
- V1 has no ARM time window. Gate token TTL does not expire ARM authority.
  Clock exceptions escape gate authorization, and rollback still issues tokens.
  These defects are asserted openly as current behavior, not hidden by xfail.

Proposed requirements use `xfail(strict=True, raises=MissingRequirement)`.
Only explicit contract violations raise that exception. Setup errors, worker
errors and ordinary assertions are not expected failures. An XPASS fails the
suite and requires review/removal of the marker. No blanket xfail or skip is used.

**Important coverage boundary:** V1 cannot accept a signed V2 envelope.
Expiration/STOP-generation probes therefore use accepted V1 ARM commands and
a declared test-side time window; the window is deliberately not enforced or
attached to production state. They expose the missing checks without letting
parser rejection masquerade as correct expiration enforcement. They are not
end-to-end V2 tests. Separate proposed valid-wire tests fail because V2 admission
is absent. Once V2 exists, migrate time probes to real signed V2 admission and
the production trusted clock interface.

Passing signature tests prove that the **test-defined** canonical V2 bytes bind
expiration, authority, trust domain, generation, authorization identity,
sequence and latch identity. V1 rejects tampered V2 envelopes as malformed:
this is explicitly **not evidence of a production V2 signature verifier**.
Stage A's separate tests now cover that verifier directly; this paragraph
describes the unchanged reconstruction tests, not Stage A coverage.

## Proposed signed ARM V2 authorization

Use a separate `GVAI-ARM-AUTHORIZATION-V2\n` signing domain and strict canonical
ASCII JSON, signed with Ed25519. Exact proposed fields:

| Field | Meaning |
| --- | --- |
| `version` | Integer 2, no coercion |
| `command_type` | `arm` only in this authorization domain |
| `latch_id`, `sequence` | Bound target and command anti-replay position |
| `key_id`, `authority_id`, `trust_domain` | Pinned independent ARM authority |
| `authorization_id` | Unique, tracked authorization identity |
| `stop_generation` | Independently recorded STOP generation at issuance |
| `not_before`, `not_after` | Signed half-open authorization window |
| `signature` | Lowercase hex Ed25519 signature over all other fields |

Reject missing/extra fields, duplicate JSON keys, unsupported versions, invalid
identifiers, invalid signature encoding, wrong-role keys, wrong targets and
untrusted authority/domain bindings. A claimed authority string alone conveys
no authority: pinned configuration must bind it to the key and trust domain.
Never strip V2 fields to make V1 accept them, fall back to unsigned expiration,
or reuse receipt/service/token signing keys.

Proposed time format: exact integer epoch seconds in `[0, 2**53]`,
`not_before < not_after`; reject bool, float, string, null, negative, overflow,
NaN and infinity, both in signed fields and clock readings. Admission and permit
are valid only for `not_before <= trusted_now < not_after`. Equality at expiration
denies; equality at not-before is valid. Tests cover both valid wire boundaries
and denied legacy time-contract boundaries. Stage A covers invalid signed-window parsing. Authority revocation, clock
high-water restart and backend integration remain future production acceptance
tests, not proven by this reconstruction or Stage A.

## Independent trusted authority and STOP generation

Governing invariant: the protected workload must not own its authorization,
clock, generation, persistence anchor, permit signer, or enforcement switch.
The ARM authority and supervisor must use independently protected identities,
credentials and storage. In-memory test references prove none of this isolation.
Signing keys for ARM, STOP, permits and commercial receipts remain separated.

STOP has its own durable, independently monotonic generation, separate from
the ordinary command sequence. Every accepted STOP invalidates all older ARM
authorizations and outstanding permits. Fresh ARM must be issued **after** that
STOP against the current generation; guessed future command sequences, old
signed requests and client retry cannot reopen it. Within a generation, STOP
is terminal. A separately authenticated opening/rearm establishes a new
operating generation; no service-owned counter can substitute for it.

The existing [STOP-generation journal](../gvai/stop_generation_journal.py) is
prior art for terminal STOP and separately signed OPEN. It is disconnected from
the V1 latch/gate. This proposal requires an explicit future integration design,
not a second divergent generation store or an assertion that wiring exists.

## STOP priority and concurrency

Authenticate STOP independently before acting; unauthenticated input must not
be a kill switch. A trusted STOP increments/latches its generation even when
an old ARM has the same command sequence or has stalled during persistence.
STOP cannot wait indefinitely behind ARM I/O. The current ARM-first conflict
behavior is a known gap, covered by a strict expected failure.

At ARM admission, after any lock/queue wait, before committing authority, and
before permit issuance, atomically compare the latest independent STOP
generation and revalidate signed freshness. An ARM that crosses expiration or
loses to STOP must never become usable, even if its command anchor advanced.
Do not solve STOP priority by rewinding an anchor or replacing a digest at the
same sequence: generation invalidation and command replay ordering are distinct.
Define the STOP linearization point and denial acknowledgement separately from
durability acknowledgement and independently verified backend halt.

## Fresh authorization at permit time

ARM acceptance is not a permanent capability. Every new permit must reverify
current authorization identity, signature/trust policy, time window, generation
and revocation state at the authorization linearization point. Token expiration
must not exceed ARM `not_after`; bind tokens to authorization identity and STOP
generation as well as operation, arguments and backend instance.

The backend must reject old-generation tokens and enforce the same expiry
bound, including during active operations where the resource supports
interruption. STOP notice loss or service silence must deny via an independently
enforced watchdog. Do not claim zero execution window, instantaneous halt or
Lab-01 compliance from these latch-only tests.

## Fail-closed clock and rollback

The supervisor owns a trusted, independently protected clock interface.
Read failure or an invalid sample returns an explicit denial/fault reason,
never a fallback to workload time, a default timestamp or an uncaught exception
represented as success. STOP must remain operable without a healthy ARM clock.

Maintain an independently durable high-water reading across restarts.
Rollback is sticky: once time goes below that high-water mark, deny ARM/permits
until independent repair/reprovisioning, even if later samples look valid.
Equal readings are allowed; a forward jump past expiration denies normally.
An in-process monotonic clock can measure waits but cannot on its own establish
absolute signed expiration or restart continuity. Decide clock uncertainty
bounds and conservative denial policy before deployment; do not grant grace
beyond signed expiration. Explicit recovery must not replay expired authority.

## Legacy ARM and enforcement mode

V2 enforcement mode must reject V1 ARM even when correctly signed and
contiguous. Never infer expiration from request arrival, local metadata or a
client's timeout. Preserve V1 behavior only in an explicitly separate legacy
mode; deny downgrade in configured V2 mode. STOP must remain available via an
explicitly authenticated compatibility policy. The current code has **no V2
enforcement mode** (the Stage A parser policy is disconnected): a paired
passing legacy observation and strict expected failure record this requirement
without pretending it is configured today.

## Crash recovery and delayed-commit ambiguity

Anchor advancement and untrusted persistence are not one transaction in V1.
The tested torn state denies after restart; availability recovery must not
turn an inconsistent anchor/store into ARMED. Never roll back the trusted head
or silently reconstruct missing authority from client state.

A future durable intent/commit protocol must bind signed authorization,
generation and expiration to the independently held head. On restart verify
the full chain and current time/generation. A cryptographically valid but expired
ARM record must still deny. If recovery cannot prove validity and completion,
remain STOPPED/FAULT; permit fresh independently issued reauthorization only
through the defined recovery procedure.

A client timeout means **UNKNOWN**, not cancellation, rejection or acceptance.
If commit completes later but authorization expired meanwhile or STOP
intervened, it cannot grant permission. Historical persistence and present
permission are separate claims. Extend authenticated read-only reconciliation
to ARM identity with explicit applied/not-applied/unknown distinctions and
current usability; a read never rearms. A not-applied read does not rule out a
still-in-flight commit. Physical backend halt requires separate evidence.

## Focused validation

From the dedicated worktree:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m pytest -p no:cacheprovider -q -rxX \
  tests/test_arm_expiry_prototype.py tests/test_experimental_stop_latch.py
```

Verified reconstruction results:

| Selection | Passed | Strict xfailed | Failed / skipped / XPASS |
| --- | --- | --- | --- |
| ARM expiration prototype | 27 | 24 | 0 / 0 / 0 |
| Existing STOP latch regressions | 58 | 0 | 0 / 0 / 0 |
| Combined focused run | 85 | 24 | 0 / 0 / 0 |

The default interpreter lacked pytest and cryptography. The successful command
reused existing installations without installing dependencies or writing caches:

```sh
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=/usr/local/py-utils/venvs/pytest/lib/python3.14/site-packages \
/opt/conda/bin/python -m pytest -p no:cacheprovider -q \
  tests/test_arm_expiry_prototype.py tests/test_experimental_stop_latch.py
```

Expected failures are a requirements ledger, not a release gate proving V2
security. The original reconstruction made no production changes.

Stage A validation adds `tests/test_arm_v2_authorization.py` to the same focused
command above. Only isolated authorization APIs are added to production code;
deployment configuration and Lab-01 artifacts remain out of scope.

Verified Stage A results: 148 Stage A cases passed, 58 existing latch cases
passed, and the reconstructed prototype retained 27 passes and 24 strict
expected failures. Combined: **233 passed, 24 xfailed**, with no failures,
skips or XPASSes. All original latch functions, classes and module assignments
were also compared against the Stage A base via AST and remained unchanged.
