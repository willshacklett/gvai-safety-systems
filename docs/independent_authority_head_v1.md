# Experimental independent authority-head checkpoints V1

Phase 6J.3 is an isolated experimental foundation, not production approval.
The implementation is `gvai/experimental_authority_head.py`. It supplies no
signing keys, signer, database reader, live trust provider, service registration,
schema/privilege change, activation, deployment, or supervisor integration.
V1 reservation event hashes and receipt envelope encoding remain unchanged.
The PostgreSQL adapter still refuses authenticated-head reads. The existing
experimental receipt signer's injected head-verifier interface is unchanged;
this new checkpoint API is not automatically wired into it.

## Checkpoint contract

The signature input is exactly the ASCII domain prefix
`gvai-independent-authority-head-checkpoint-v1` followed by one NUL byte,
followed by canonical JSON with sorted keys, separators `,` and `:`, ASCII
escaping, no NaN, and no whitespace. The JSON contains exactly these fields:

| Field | Meaning |
| --- | --- |
| `contract_version` | Integer `1`, not boolean |
| `purpose` | Literal `independent_authority_head` |
| `authority_id` | Pinned V1 authority identifier |
| `authority_epoch` | Pinned positive V1 epoch |
| `trust_domain` | Pinned V1 trust-domain identifier |
| `sequence` | Integer in `[0, 2^63 - 1]`, not boolean |
| `event_head_hash` | Exactly 64 lowercase hexadecimal characters |
| `signing_key_id` | Explicitly pinned independent checkpoint key identifier |
| `signature_algorithm` | Literal `Ed25519` |

The detached signature is exactly 64 immutable bytes. A checkpoint contains
an immutable `AuthorityHeadState`, key ID, signature, version, purpose, and
algorithm. Sequence zero requires the V1 all-zero genesis hash. For nonzero
sequences the hash is the V1 canonical `ReservationEvent.event_hash`, not a
new hash of a database row. This verifier compares the supplied head; it does
not independently recompute the entire database history or prove that a
signed hash was derived from a legitimate committed event.

There is no permissive wire decoder. Callers must construct validated typed
objects; a future transport parser must reject duplicate/extra fields and
noncanonical encodings. Never reinterpret a receipt signature as a checkpoint
signature or modify receipt bytes to add checkpoint metadata.

## Keys and identity

`ExperimentalAuthorityHeadVerifier` pins the complete authority identity and
a bounded map of checkpoint key IDs to 32-byte Ed25519 public keys. It copies
key pins and revocations into immutable configuration. Unknown and revoked
IDs fail closed. Every signature binds identity, epoch, trust domain, sequence,
hash, key ID, purpose, algorithm, and version under the independent domain.

Checkpoint keys must be separately generated, controlled, and provisioned.
Never reuse customer receipt-signing keys or supervisor STOP keys. The required
`other_purpose_key_ids` and `other_purpose_public_keys` exclusions reject declared
reuse by either ID or raw public-key bytes, including renamed keys. Their
complete inventory must be supplied by a trusted provisioner; the verifier
cannot discover undeclared reuse or prove independent key custody. Empty
exclusions in the tests mean no other-purpose keys are provisioned in that
ephemeral test environment, not permission for production reuse. No production
key material is read or created. Rotation/revocation requires approved new
configuration; revoking a key never resets the high-water record.

## Three distinct verification claims

`verify_signature(checkpoint)` establishes only signature authenticity against
pinned, nonrevoked keys and the expected authority. A valid old signature is
not proof of current freshness.

`verify_checkpoint(checkpoint, database_head)` reports:

1. `signature_authentic`: the canonical checkpoint signature verifies.
2. `database_consistent`: the supplied database identity/sequence/hash exactly
   match the signed checkpoint. This is not a PostgreSQL isolation guarantee.
3. `high_water_confirmed`: an injected independently trusted provider atomically
   accepted this exact state against already provisioned high-water history.

`accepted` requires all three. Invalid signatures and inconsistent database
observations never reach the provider. Missing provider/state, provider
exceptions/outages, malformed responses, lower sequences, or equal-sequence
hash conflicts cannot produce acceptance. There is no fallback to PostgreSQL,
a receipt cache, a new genesis record, or an older signed checkpoint.

## Independent high-water contract

`IndependentHighWaterProvider.check_and_advance(checkpoint, timeout_seconds=...)`
is an injected trust boundary outside PostgreSQL. It must:

- Use an independently provisioned record keyed by the complete authority
  identity/epoch/domain; reject absent state rather than bootstrap from input.
- Accept only checkpoints authenticated by the trusted verifier; it must not
  expose an untrusted direct write path.
- Atomically reject a lower sequence or conflicting hash at equal sequence.
- Permit idempotent equal-sequence/equal-hash observations and monotonic advances.
- Durably persist advancement before returning the exact accepted state.
- Provide linearizable semantics across processes/clients, bounded timeout,
  authenticated responses, independent availability, and no silent restore/reset.
- Fail closed on unavailable state, errors, identity mismatch, and ambiguous writes.

The verifier calls this combined compare/advance operation rather than a racy
read-then-write pair. It validates the returned state's exact type and equality;
it first authenticates a detached checkpoint snapshot, then passes a separate
deeply detached copy (including head and authority identity) to the provider.
The response is compared against the private authenticated snapshot, never
against callback-controlled state. Any provider mutation of the supplied
checkpoint's fields fails high-water confirmation. Frozen dataclasses alone
do not enforce this isolation: Python callbacks can bypass their assignment
guard with `object.__setattr__`.
The verifier cannot police a dishonest provider returning the input without persistence.
No production provider is implemented. The locked in-memory fake lives only in
the security tests. Its concurrency tests prove process-local test behavior,
not cross-process linearizability, durable independent rollback protection,
provider authentication, or disaster recovery safety.

An acceptance has the provider operation's linearization point, not an indefinite
lease. Another concurrent call may immediately advance the head. Verification
does not authorize execution, guarantee a current mutable database read, or
atomically fence downstream use against a later advance. The caller must keep
restored service fenced and use consistent, bounded, independently obtained
post-commit database evidence. Higher signed sequences can skip checkpoints;
the signer/history reconciliation boundary must establish chain continuity.

## Freshness limits and recommended production boundary

Rollback detection is relative to independently known history. A matching old
database snapshot plus a valid old signature is rejected when independent state
has advanced. If the independent provider has never observed newer history,
this API cannot detect withheld newer checkpoints. There is no wall-clock
recency, challenge-response freshness, expiration, or current-tip discovery
claim. Losing/resetting both database and high-water history defeats protection.
Compromise of the checkpoint signer or trust provider can attest false history
or raise high water to deny service. Timeouts are an obligation of the injected
provider, not enforced by interrupting arbitrary Python calls.

Recommended production boundary: separately administered checkpoint signing
and durable linearizable high-water storage, independent of PostgreSQL hosts,
database credentials, backups, receipt-signing custody, and supervisor controls.
Use authenticated bounded transport, independently protected append-only history,
explicit trust provisioning/revocation, monitored checkpoint publication, and
founder-approved epoch transitions. Fence startup/restores until independently
verified history is reconciled. A future current-tip/recency policy and durable
fault/race/recovery validation are required before claiming current freshness
or enabling a production integration.

## Offline adversarial evidence and STOP

Tests use newly generated ephemeral Ed25519 keys, no serialized private keys,
and no live database or checkpoint service. They reproduce forged/altered
checkpoints; unknown/revoked/wrong keys; wrong authority/epoch/domain; purpose,
algorithm, version, and signature-domain substitution; malformed hashes and
signatures; old valid signed snapshots; conflicting equal-sequence hashes;
missing/unavailable/erroring trust; invalid provider responses; and concurrent
monotonic, conflicting, and idempotent updates.

The Phase 6J.3 audit reproduced a callback-substitution defect in the original
experimental verifier: the provider could change the authenticated checkpoint
sequence from 7 to 8 or its hash to 64 `b` characters, return that altered head,
and receive `accepted=True` despite an invalid unchanged signature and a
mismatching original database observation. Ordinary unsigned field alterations
were rejected. The defect was a comparison against a mutable callback argument
after signature/database validation, not an Ed25519 validation bypass. Regression
tests now cover head replacement, nested head/identity mutation, and signature
substitution; they require rejection and preservation of the caller's checkpoint.

Exact offline reproduction (use the existing approved test environment):

```python
import runpy
from dataclasses import replace

Test = runpy.run_path("tests/test_experimental_authority_head.py")[
    "ExperimentalAuthorityHeadTests"
]
for field, value in (("sequence", 8), ("event_hash", "b" * 64)):
    test = Test("test_valid_checkpoint")
    test.setUp()

    class SubstitutingProvider:
        def check_and_advance(self, checkpoint, *, timeout_seconds):
            altered = replace(checkpoint.head, **{field: value})
            object.__setattr__(checkpoint, "head", altered)
            return altered

    verifier = test.make_verifier(independent_high_water=SubstitutingProvider())
    result = verifier.verify_checkpoint(test.checkpoint, test.head)
    print(field, result, verifier.verify_signature(test.checkpoint),
          test.checkpoint.head == test.head)
```

Original result for both fields: all three verification claims `True`, caller
signature validity `False`, and caller/database equality `False`. Fixed result:
signature authenticity and database consistency `True` for the private original
snapshot, high-water confirmation `False`, caller signature validity `True`,
and caller/database equality `True`. Acceptance must be `False` after callback
substitution. Severity is medium: this requires a mutating injected provider;
there is no untrusted transport or production integration in this experiment.
In the pre-fix source, signature validation was at lines 189-207, database
comparison at 216-222, and the vulnerable provider call/response comparison
at 227-239. The original 27 checkpoint tests passed despite this defect.

Existing commercial, PostgreSQL, receipt-signing, and offline tests remain
required. Offline PostgreSQL tests do not validate live database execution,
durability, privileges, isolation, or restored-service safety. No production
activation is authorized. STOP for founder review before any commit or further
integration, provisioning, service registration, activation, or deployment.
