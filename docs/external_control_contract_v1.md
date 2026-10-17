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

## Limitations

HMAC is symmetric authentication, not a public-key signature. Every verifier holding a key can also forge commands; use a separately controlled issuer/verifier key boundary and do not expose verifier keys to workloads. The legacy `shutdown_requested` Boolean remains in the method signatures for call compatibility, but `True` is denied without halting; it is not an authenticated shutdown mechanism. `GVRuntimePolicy.evaluate_command` and `GVExternalControlPlane.evaluate_command` are policy-only APIs: they authorize a decision but do not terminate a process. Use the trusted supervisor integration below when cancellation is required. Trusted parent code may use the explicit `evaluate_internal_shutdown` methods to obtain emergency-stop decisions, but must still enforce cancellation. These APIs are only separated from workload authority by the documented parent/child process boundary; Python does not enforce caller identity within a process. V1 itself has no transport, endpoint, account identity, key-management service, durable revocation database, automatic process termination, or distributed transaction. Authorization is not evidence that a supervisor has stopped a worker. No production readiness or Railway capability is implied.

## Trusted supervisor integration

The supervisor is trusted host code, not code running in the governed worker.
Its identity authority, role grants, resource ownership metadata, effect policy,
external-command verifier, output destination, and audit storage must be supplied
and controlled by the host. None may be taken from worker claims. Identity
authorization does not grant external shutdown authority; shutdown uses the
separately configured, target-bound command verifier.

`gvai.supervisor.TrustedSupervisor` is configured through keyword-only
`target_id`, `authority`, `authorizer`, `guard`, `command_verifier`, `resources`,
and `root` arguments. `resources` is a host-owned resource-ID-to-`TenantResource`
mapping, not request-supplied tenant labels. The optional resource capability
defaults to `resource:execute`; tool grants remain separately required. Optional
`input_root` must not overlap the supervisor root.

The host calls `execute(evidence, resource_id, action, observation)`; the
supervisor authenticates evidence and authorizes the resource and fixed action
before starting the sandbox. The observation is trusted parent runtime state,
not worker-supplied recoverability data. `shutdown(envelope)` verifies and
consumes a command for the configured target before latching and canceling.
Rejected commands raise `ExternalCommandRejected`. The returned confirmation
and deadline fields must be checked; acceptance alone is not cancellation.

Permitted output is staged in `root/generation-<uuid>/` and published through
an atomic `root/current` symlink change, rather than copied into a live output
tree. Consumers must resolve `current` once for each transaction to avoid
mixing generations. Previously published output is not revoked by shutdown,
but pending generations cannot become current after shutdown. Audit snapshots
are available through `evidence`, with host-side records in
`root/control.jsonl`. Keep this root outside worker mounts and under exclusive
trusted-host control.

Supervision additionally requires readable host procfs. The parent creates a
dedicated session/process group and omits Bubblewrap's separate `--new-session`
option so the fixed worker remains in that group. Cancellation covers the whole
group; confirmation combines launcher reaping with an independent procfs check
for absence of live group members. This relies on the existing fixed worker
having no session-changing or process-spawning operation, and is not an
arbitrary-code containment claim. Worker JSON is not evidence of exit.
Unavailable exit-observation mechanisms prevent launch or output promotion.

Process creation occurs outside the lifecycle lock. If shutdown races an
in-progress launch, it waits for the startup handoff within its deadline and
cancels the handed-off process. A late handoff is still canceled and cannot
promote output, but an uncompleted handoff must return `confirmed=False`, not
claim that the system has already stopped.

The lifecycle must distinguish:

- command rejection, which cannot set the shutdown latch;
- authenticated shutdown acceptance, which permanently prevents new work and
  promotion of pending output for that instance;
- cancellation signaling, which is not itself evidence of process exit;
- independently observed process exit, including the actual return code;
- failure to confirm exit within the acceptance deadline, which must not be
  reported as a successful stop or permit later promotion.

There is no worker-accessible reset or resume operation. Creating a replacement
supervisor is a trusted-host operation, not a way for a worker to clear a latch.
The existing in-memory replay backend still has its documented process-local
limitations; replacement instances do not provide durable replay protection.

The one-second acceptance criterion is measured on a supported Linux sandbox
host, not inferred from a successful policy decision, a kill request, or a
worker-reported status. Run the full suite with `python -m pytest -ra` and report
all security-critical skips. Missing Bubblewrap, libseccomp, or usable namespaces
is a fail-closed condition, not permission to run a weaker backend.
