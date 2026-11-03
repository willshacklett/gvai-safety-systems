# External STOP Gate V1 (simulation)

Builds on the STOP-latch prototype (`docs/stop_latch_prototype_v1.md`, PR #42). Governing principle: *never let the thing behind the switch own the switch.*

## Roles

| Role | Holds | Cannot |
|---|---|---|
| Gate (supervisor process) | STOP latch, anchor + store files, gate signing key, stop/arm **public** keys | — |
| Backend (protected resource, separate process) | gate **public** key only | mint permits, change the gate |
| Commercial service | nothing secret; sockets to gate and backend | issue ARM/STOP, touch the anchor, sign permits, authorize itself |
| Operator (off-line) | stop and arm private keys | — |

## Mechanism

1. Every protected operation is executed by the **backend**, which requires a gate-signed permit: Ed25519, bound to latch ID, operation, SHA-256 of the arguments, anchor head sequence/digest, random nonce and a short expiry (default 5 s); single use.
2. The gate issues permits only while the latch is armed. Gate, command, and permit signatures use distinct domain prefixes; the gate key may not equal any stop/arm key.
3. The gate pushes signed, counter-numbered head notices (on every accepted command and as a heartbeat). The backend denies if it has never heard from the gate, if the last notice is older than `notice_max_age` (default 3 s), if the gate is not armed, or if the token's sequence differs from the latest notice. It rejects replayed or rolled-back notices and notices from a previous gate boot.
4. A service that skips the gate client gains nothing: the backend denies calls without a valid token, so omitting a verifier call cannot bypass enforcement.
5. DENY on: missing authority, bad signature, replay, rollback/fault, unknown operation, oversize/malformed message, gate down or timeout, stale notices.

## Bounded windows

Gate-side STOP can wait behind synchronous ARM persistence; no bounded STOP
latency is claimed. After confirmed recording the gate attempts notification,
whose acknowledgement is separate from termination evidence. If notice delivery
fails, previously issued permits remain usable until expiry or notice staleness.
The backend watchdog requests cancellation of active work; uncooperative-work
termination depends on the configured process boundary, not the STOP receipt.

## I6D local persistence

The live experimental gate requires explicitly provisioned transaction state.
See [STOP reconciliation and transaction contract](stop_reconciliation_v1.md#i6d-local-transaction-and-restart-contract)
for schema, barrier ordering, crash windows and offline provisioning.
Legacy directories are rejected; there is no automatic migration or repair.
Clean restart retains sequence history but never restores old ARM permission:
it starts STOPPED and requires a fresh signed ARM. Unresolved transaction
artifacts fault the gate. Local confirmation does not provide independent
rollback resistance, physical power-loss proof or workload termination.

## I7B independent backend STOP-only veto

The backend now starts **recovery-inhibited**, including first startup. No gate
notice, permit, ARM command, higher sequence/counter or changed boot ID clears
that inhibition. There is deliberately **no production rearm or repair API**.
Consequently, the ordinary entrypoints cannot execute protected work in this
stage, even after a fresh gate ARM. Tests of preexisting authorized sessions
explicitly clear a private field in test setup only; this is not a deployable
authorization mechanism.

`BackendCore(stop_keys=...)` accepts trusted STOP public keys configured by the
supervisor, never supplied by a request. `submit_stop_veto(envelope)` validates
the existing V1 signature, exact envelope, target and STOP command type before
installing a sticky veto under the backend state lock and signaling active
operations to cancel. Gate signing keys and duplicate STOP key bytes are
rejected in this configuration. Operators must retain STOP/ARM key-role
separation; the backend cannot discover private-key custody or misconfiguration.

The veto path performs no gate call, transaction access, filesystem read/write
or synchronization, and does not acquire a gate/latch lock. Ordinary notices
can still update their authenticated history, but can never reopen execution
after a veto. Execution registration and veto installation share the backend
lock. Cancellation is cooperative; already-started effects cannot be undone.
Uncooperative-work exit remains a separate configured application action, not
host-enforced termination.

An authentic historical STOP, including exact replay, is conservatively
idempotently denying. No sequence-storage lookup is required. This intentionally
allows denial by replay of an old authentic STOP; it never advances or rewrites
the gate's durable command history. V1 signing bytes and sequence identities,
I6D transaction recovery and the disconnected C1/C2/C3A prototypes are unchanged.

For **local experiments only**, `backend_process_main` accepts configured
`stop_keys` and an optional `stop_socket`: a separate mode-0600 AF_UNIX listener.
It accepts only `{"type":"stop_veto","envelope":...}`; the existing service and
notice listeners reject that request. `BackendStopClient` submits the signed
envelope directly, without depending on the gate. The listener is not added to
deployment units or the systemd entrypoint. Same-UID tests do not establish OS
isolation; socket mode supplements, but never replaces, signature authentication.

The exact successful reply is:

```json
{"ok":true,"outcome":"VETO_DENIAL_CONFIRMED","execution_denied":true,"durable_stop_recording":"UNKNOWN","backend_termination":"UNVERIFIED"}
```

Lost, malformed, timed-out or internally failed replies are UNKNOWN, never
evidence of non-application. A rejection of a particular invalid request does
not prove execution is currently allowed. Durable STOP recording must still
be separately submitted and reconciled with the gate; it can wait indefinitely
behind ARM storage. The veto performs no persistence. Restart safety comes from
unconditional startup inhibition, not recovery of a durable veto record.

Required isolated-host validation remains: operator/socket/UID separation,
credential confinement, real filesystem hangs, resource exhaustion, scheduling,
systemd restart behavior and cgroup-wide termination. A separate listener does
not reserve CPU, memory, descriptors or threads. No bounded availability,
physical power-loss proof or host-enforced shutdown is claimed.

## What is simulated — read carefully

Gate and backend run as separate child processes, tested over Unix sockets (mode 0600) with JSON messages. All processes share one UID, kernel, and filesystem. **This is simulated process separation, not OS-enforced isolation.** A same-UID attacker can read the gate seed file, rewrite the anchor/store files (the tests show this is *detected* and fails closed on the next check, not *prevented*), ptrace or kill the gate, or replace the backend. Killing the gate denies new work but it also denies STOP delivery beyond notice staleness. Nothing here proves host-level protection against a compromised commercial service.

## Required before any compromised-service claim

- Gate, backend and anchor under separate OS users/containers/hosts with separate credentials; service has no filesystem or signal access to them (e.g. systemd units + AppArmor/namespaces on the Linux host).
- Anchor in storage the service credentials cannot write (append-only / separate account).
- Operator key custody (HSM/offline) and a real ARM/STOP transport.
- Backend as the real choke point for the downstream credential (the service must not hold downstream credentials).
- Multi-replica anchor coordination; restart/crash recovery of the anchor/store pair.
- Host-level tests (Linux host) proving the service user cannot read/write/signal the above.
