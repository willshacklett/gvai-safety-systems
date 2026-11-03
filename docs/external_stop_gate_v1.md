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

Gate-side STOP is immediate and the backend learns of it before the STOP command returns (notice pushed first). If the notice channel fails, a previously issued permit remains usable until its TTL or until notices go stale (≤ `notice_max_age`), whichever first. Already-running operations are not interrupted.

## What is simulated — read carefully

Gate and backend run as separate child processes, tested over Unix sockets (mode 0600) with JSON messages. All processes share one UID, kernel, and filesystem. **This is simulated process separation, not OS-enforced isolation.** A same-UID attacker can read the gate seed file, rewrite the anchor/store files (the tests show this is *detected* and fails closed on the next check, not *prevented*), ptrace or kill the gate, or replace the backend. Killing the gate denies new work but it also denies STOP delivery beyond notice staleness. Nothing here proves host-level protection against a compromised commercial service.

## Required before any compromised-service claim

- Gate, backend and anchor under separate OS users/containers/hosts with separate credentials; service has no filesystem or signal access to them (e.g. systemd units + AppArmor/namespaces on the Linux host).
- Anchor in storage the service credentials cannot write (append-only / separate account).
- Operator key custody (HSM/offline) and a real ARM/STOP transport.
- Backend as the real choke point for the downstream credential (the service must not hold downstream credentials).
- Multi-replica anchor coordination; restart/crash recovery of the anchor/store pair.
- Host-level tests (Linux host) proving the service user cannot read/write/signal the above.
