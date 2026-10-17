# External Control Contract V1

## Purpose and trust boundary

V1 defines an authenticated, one-use `shutdown` command for a specific workload. It is a library contract, not a network endpoint or deployed control service. The issuer, signing-key custody, verifier configuration, trusted clock, and replay/revocation backend must be outside the governed workload's authority. The workload must not receive signing keys or permission to change verifier or control-state data.

The existing threat model places the policy and supervisor in the trusted parent GV runtime; untrusted OS-sandbox work runs in a separate Bubblewrap child with no parent policy object or repository mount. `GVExternalControlPlane.evaluate_internal_shutdown` and `GVRuntimePolicy.evaluate_internal_shutdown` are trusted-parent-only emergency APIs. Never expose these methods through a workload RPC, tool, plugin, or request field. This boundary does not protect against arbitrary untrusted code running inside the trusted parent process.

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

Authorization proceeds in this order: strict envelope validation, exact target match, validity-window checks, authentication, then one atomic state operation that checks revocation and consumes `(issuer_id, command_id)`. Only an accepted `shutdown` reaches the immediate halt decision. A malformed, forged, expired, replayed, revoked, or unverifiable external command is denied without halting the workload; this prevents an unauthenticated sender from using invalid requests as a kill switch. The associated action is denied while the command is rejected. Only a verified command or the explicit trusted-parent emergency API sets `halted=True`.

The default maximum clock skew is five seconds. A command is rejected if `issued_at > now + skew` or `expires_at < now - skew`; the expiry boundary is therefore inclusive within that skew. `expires_at` must be after `issued_at`, and the validity interval may not exceed 300 seconds by default. Replay state must be retained through `expires_at + skew`.

The state interface requires `consume_if_active` to atomically check issuer/command revocation and claim the command ID. This operation and revocation must be linearizable: if revocation wins the state operation ordering, authorization fails; if consumption wins first, later revocation does not retroactively terminate work. A caller needing termination of already-running work must separately signal and verify worker cancellation.

`InMemoryExternalControlState` uses a process-local lock and records the highest wall-clock second it has observed. If a later state operation supplies an earlier time, it rejects with `clock_rollback` before pruning or consuming IDs. It continues rejecting lower times until the clock catches up to that high-water mark. This prevents a forward clock step from pruning an ID and a subsequent rollback from reopening that ID's replay window. It only supports threads sharing that one object and is not safe for multiple processes, replicas, restarts, or production persistence. A production backend must implement atomic consumption, revocation, and rollback-resistant expiry across every verifier instance; this repository does not provide such a backend or claim distributed replay protection.

## Supervisor execution boundary

Command authorization alone does not stop a process. `GVTrustedSupervisor`
in `gvai/supervisor.py` connects its `shutdown(envelope)` method to cancellation.
The trusted supervisor owns execution
authorization, the active process handle, an irreversible shutdown latch, and
the decision to promote disposable output. Applications requiring actual
shutdown must use this execution boundary rather than treating a policy
decision as cancellation evidence.

The supervisor authenticates and consumes the command before latching
shutdown. Rejected commands do not request cancellation; an independent audit
storage failure still causes a fail-closed stop. A valid shutdown also latches
when no worker is running, and a later execution cannot clear that latch.
Worker completion messages cannot reset control state or authorize promotion.
Start registration and promotion are serialized against the latch; work
promoted before shutdown is not rolled back.

Cancellation evidence comes from parent-side signaling and process-exit
confirmation, not worker-reported events. Audit evidence must distinguish
command acceptance, cancellation attempts, confirmed exit, and failures; keys
and authentication signatures do not belong in audit records. If cancellation
or auditing fails, shutdown remains latched and output cannot be promoted.
Configure the executor's `audit_root` for file-backed evidence; without it,
evidence is process-local only. Wait confirmation concerns the Bubblewrap
process; descendant cleanup additionally relies on the PID namespace,
parent-death behavior, process-group signaling, and no-spawn seccomp boundary.

The execution boundary retains the existing fixed worker action set,
namespace isolation, seccomp restrictions, environment filtering, and refusal
to fall back when sandbox enforcement is unavailable. It does not accept
arbitrary Python, shell commands, plugins, or worker-supplied authority.

The one-second acceptance criterion is measured using authenticated shutdown
of a running sandbox on a Linux host supporting the actual enforcement
boundary. Unit tests with simulated processes are race and logic tests only.
Unavailable enforcement must produce explicit security-critical skips, not a
claim that the shutdown latency or OS containment has been verified.

## Limitations

HMAC is symmetric authentication, not a public-key signature. Every verifier holding a key can also forge commands; use a separately controlled issuer/verifier key boundary and do not expose verifier keys to workloads. The legacy `shutdown_requested` Boolean remains in the method signatures for call compatibility, but `True` is denied without halting; it is not an authenticated shutdown mechanism. `GVRuntimePolicy.evaluate_command` and `GVExternalControlPlane.evaluate_command` remain authorization-only APIs; use the trusted supervisor for cancellation. Trusted parent code may use the explicit emergency-stop APIs, but must not expose them to workers. These APIs are only separated from workload authority by the documented parent/child process boundary; Python does not enforce caller identity within a process. V1 has no transport, endpoint, account identity, key-management service, durable revocation database, or distributed transaction. Process-local shutdown and audit evidence are not durable cross-restart or distributed guarantees. No production readiness or Railway capability is implied.
