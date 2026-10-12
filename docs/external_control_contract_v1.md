# External Control Contract V1

## Purpose and trust boundary

V1 defines an authenticated, one-use `shutdown` command for a specific workload. It is a library contract, not a network endpoint or deployed control service. The issuer, signing-key custody, verifier configuration, trusted clock, and replay/revocation backend must be outside the governed workload's authority. The workload must not receive signing keys or permission to change verifier or control-state data.

## Envelope

The envelope is a JSON object with exactly these fields:

```json
{
  "version": 1,
  "command_id": "00000000-0000-4000-8000-000000000001",
  "command_type": "shutdown",
  "target_id": "worker-7",
  "issuer_id": "control-service",
  "issued_at": 1800000000,
  "expires_at": 1800000060,
  "auth": {
    "algorithm": "HMAC-SHA256",
    "key_id": "control-key-v1",
    "signature": "lowercase-hex-sha256-mac"
  }
}
```

Identifiers are restricted to ASCII letters, digits, `.`, `_`, `:`, `/`, and `-`; command IDs are canonical lowercase UUID strings. Times are integer Unix seconds. Extra/missing fields, coercions, booleans in integer fields, unknown versions, and command types other than `shutdown` are rejected.

The signature covers version, command ID/type, target, issuer, issue/expiry times, algorithm, and key ID. V1 canonical bytes are ASCII JSON with sorted keys, `,` and `:` separators without whitespace, ASCII escapes, and no non-finite numbers. The signature field is excluded from the signed payload. The verifier keyring is indexed by `(issuer_id, key_id)` so each trusted issuer/key pair is explicit. V1 uses HMAC-SHA256 with keys injected into the verifier; key provisioning, secure storage, rotation, and compromise response are deployment responsibilities.

## Verification and state semantics

Authorization proceeds in this order: strict envelope validation, exact target match, validity-window checks, authentication, then one atomic state operation that checks revocation and consumes `(issuer_id, command_id)`. Only an accepted `shutdown` reaches the existing absolute-precedence halt decision. Any malformed input, failed verifier, unavailable clock/state, replay, or revocation halts with a generic denial.

The default maximum clock skew is five seconds. A command is rejected if `issued_at > now + skew` or `expires_at < now - skew`; the expiry boundary is therefore inclusive within that skew. `expires_at` must be after `issued_at`, and the validity interval may not exceed 300 seconds by default. Replay state must be retained through `expires_at + skew`.

The state interface requires `consume_if_active` to atomically check issuer/command revocation and claim the command ID. This operation and revocation must be linearizable: if revocation wins the state operation ordering, authorization fails; if consumption wins first, later revocation does not retroactively terminate work. A caller needing termination of already-running work must separately signal and verify worker cancellation.

`InMemoryExternalControlState` uses a process-local lock and only supports threads sharing that one object. It is a reference/test implementation, not safe for multiple processes, replicas, restarts, or production persistence. A production backend must implement atomic consumption and revocation across every verifier instance; this repository does not provide such a backend or claim distributed replay protection.

## Limitations

HMAC is symmetric authentication, not a public-key signature. Every verifier holding a key can also forge commands; use a separately controlled issuer/verifier key boundary and do not expose verifier keys to workloads. The pre-existing `shutdown_requested` Boolean remains for trusted internal compatibility; external inputs must use `evaluate_command` and the verifier contract. V1 has no transport, endpoint, account identity, key-management service, durable revocation database, automatic process termination, or distributed transaction. Authorization is not evidence that a supervisor has stopped a worker. No production readiness or Railway capability is implied.
