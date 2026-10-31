# Experimental Trusted Receipt Signer V1

## Status

`gvai/experimental_receipt_signer.py` is an isolated signing boundary. It is
not registered with the commercial service, PostgreSQL adapter, or customer
API. It does not create signing keys, provide a production signer, or authorize
an evaluation.

The boundary accepts only a reservation signing context, not an
application-supplied receipt. It asks an injected, read-only provider for
committed reservation evidence and a trusted authority-head checkpoint. It
checks the committed status, canonical event hash, authority and epoch, tenant,
principal, request and resource digests, and matching idempotency evidence.
It refuses missing, inconsistent, uncommitted, or ambiguous evidence and
unknown or revoked signing keys.

The checkpoint must be independently authenticated and fresh according to the
injected `TrustedCheckpointVerifier`. The signer also requires its authority,
sequence, and event hash to exactly match the committed event. An ordinary
database head row is not a trusted checkpoint. No production evidence provider,
checkpoint verifier, or freshness source is included; without those trusted
dependencies, this module cannot produce a signature. Test-only checkpoints
are rejected by default and can only be enabled explicitly for isolated tests.

## Trust and replay limits

The evidence provider must retrieve committed event and idempotency evidence
independently of the application receipt path. The checkpoint verifier must
validate checkpoint authenticity and freshness against an independent,
rollback-resistant trust source. The Python protocols cannot establish that an
injected implementation actually meets those requirements.

Private signing keys are supplied through an isolated signing interface and
must remain outside PostgreSQL, the reservation adapter, and customer-facing
code. Tests generate ephemeral Ed25519 keys only. No production keys or key
provisioning are provided.

A `REPLAY` receipt remains a `REPLAY` receipt. The signature authenticates the
reservation evidence and does not turn a replay into permission to evaluate or
execute. Consumers must separately enforce the expected receipt status and
must not use a valid signature as execution authorization.

This experiment does not validate PostgreSQL behavior, commit durability,
provider independence, checkpoint freshness in a real deployment, key custody,
or rollback resistance. It is not suitable for production use or customer
traffic.
