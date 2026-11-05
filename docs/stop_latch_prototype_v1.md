# Experimental STOP Latch Prototype V1

Governing principle: *never let the thing behind the switch own the switch.*

## What this is — and is not

`gvai/experimental_stop_latch.py` is an **in-process verification** prototype. It decides, inside the verifier's own process, whether signed STOP/ARM commands are authentic, contiguous and not rolled back, and reports `permit()` accordingly.

It is **not independently enforced shutdown.** Nothing here terminates, freezes, or network-isolates a workload. A caller that ignores `permit()`, or code with control of the verifier process, the injected anchor, or the store, defeats it. `ENFORCEMENT_MODEL == "in_process_verification_only"` and `INDEPENDENT_ENFORCEMENT_IMPLEMENTED is False` are exported to make this machine-checkable.

**No protection against a compromised commercial service is claimed.** If the commercial service hosts the verifier, the anchor, or the store, a compromise of it owns the switch. Such protection requires an external enforcement boundary (separate host/account/credentials that can cut the workload's power, network or credentials regardless of what the service says), which is not implemented or tested here.

## Design

- **Signed envelope:** `version, latch_id, sequence, command_type (stop|arm), key_id, signature`, strict parse (no extras, no bool/float ints, lowercase hex). Ed25519 over `b"GVAI-STOP-LATCH-V1\n" + canonical JSON` (domain separation; bound to `latch_id`).
- **Key separation:** public-key-only keyring split into stop keys and arm keys. A stop key can only stop; an arm key can only arm. Key IDs/bytes cannot be shared across roles or with an explicit `forbidden_public_keys` set (e.g. receipt/API signing keys). The verifier holds no private material; the module has no signing function.
- **Fail-closed start:** latch begins `stopped`; only a signed, contiguous ARM opens it.
- **Sequence continuity:** ARM requires `sequence == anchor + 1`. An authentic STOP with a higher sequence is honoured across a gap (stopping is the safe direction) and flagged. Replays and stale commands are rejected without state change. Forged/unauthenticated commands never change state, so they cannot be used as a kill switch or to re-open.
- **Trusted high-water anchor:** a monotonic `(sequence, command digest)` head behind the `TrustedAnchor` protocol with atomic compare-and-advance. The untrusted store holds the last signed command; on load it is re-verified and must equal the anchor head exactly. Anchor rewind, anchor divergence, store rollback, store forks at the same sequence, deleted or tampered store all produce a sticky `fault` that denies everything and cannot be cleared by any command (out-of-band re-provisioning required).
- **Availability failures deny:** anchor or store errors deny `permit()`; an authentic STOP is applied locally even if the anchor cannot record it (then latch is `fault`).

## Limitations

- `InMemoryTrustedAnchor` / `InMemoryCommandStore` are test references in the same process; they provide **no** independence, durability, or multi-process safety. A real anchor must live under separate authority (separate credentials, append-only/monotonic, not writable by the commercial service).
- A crash between anchor advance and store write leaves a `fault` on restart (safe, but requires re-provisioning).
- No transport, key management, rotation, revocation, clock/expiry, or multi-replica coordination. A second verifier replica seeing an advanced anchor will fault.
- Ed25519 requires the `cryptography` package (added to `requirements-dev.txt`; not a runtime dependency of other modules).
- Nothing verifies that a worker actually stopped.

## Next step

An independently enforced boundary (separate-host enforcer that owns the anchor and acts on STOP) is required before any compromised-service claim. Building and testing that probably requires the Linux host (cgroup/systemd/AppArmor-level enforcement); this prototype does not.
