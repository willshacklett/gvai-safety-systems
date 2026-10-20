Execution approval V1: offline envelope conformance
=================================================

Status
------

This implements only the parser/canonicalizer increment of Operation Iron Switch
XI. Never let the thing behind the switch own the switch.

``gvai.execution_approval_envelope.parse_execution_approval`` takes serialized
ASCII JSON (bytes or str), explicit integer ``now`` and an exact unsigned
``expected_payload`` snapshot. It returns immutable ``UnauthenticatedEnvelope``
bytes or raises ``EnvelopeRejected``. Both ``authenticated`` and ``allowed``
always return false, and the result has false truthiness.

Successful parsing is not a positive admission, signature verification, human
approval or production acceptance. There is no signing, key generation, signature
provider, issuer lookup, revocation backend, dispatch, network access, file
retrieval or shutdown operation. HARD GATE remains unchanged and deny-only.
Nothing in the runtime or website imports this module. No production credentials
are simulated: test signatures are deliberately non-authenticated repeated hex.

Wire format
-----------

All objects reject extra/missing fields recursively. The envelope contains:

* ``version=1``, ``purpose="execute-once"``, canonical lowercase RFC 4122 UUIDv4
  ``approval_id``, and 64-lowercase-hex ``challenge``.
* ``issuer_id``, ``approver_id``, nonempty ``scope`` (at most 16 sorted unique
  identifiers), and ``human_decision_id``.
* ``audience``: supervisor, environment and tenant identifiers, plus UUIDv4
  ``boot_id``. ``workload``: instance identifier, bundle SHA-256, source revision
  (40 lowercase hex).
* ``action`` and its exact canonical-byte ``action_sha256``. Action contains
  ``tool_id``, executable SHA-256, ordered ``arguments``, ``inputs``, ``resources``,
  ``outputs`` and ``limits``. Arguments allow up to 128 printable-ASCII strings
  of at most 1024 characters. The three resource lists contain up to 128
  ``{id, sha256}`` bindings sorted uniquely by ID. IDs are opaque trusted-resolver
  references, not paths or URLs. For outputs, the digest identifies the frozen
  destination descriptor, not a prediction of generated output bytes.
  Limits contain positive integer duration_seconds (at most 60), memory_bytes
  and output_bytes. Duration must fit within the remaining approval window.
* ``effects``: at most 128 sorted unique identifiers; empty is a syntactically
  expressible no-effect claim, not proof of no effects or permission to execute.
* ``policy``: SHA-256 and epoch. The future policy snapshot must cover invariants,
  effect authority, sandbox setup and authorization configuration.
* ``observation``: id, source_id, SHA-256, sequence, observed_at, expires_at,
  status and halted. Only stable/false is supported. Its lifetime is at most 60
  seconds, with observed_at <= now < expires_at.
* ``control``: epoch, revocation_generation, shutdown_generation.
* ``issued_at``, ``not_before``, ``expires_at``:
  0 <= issued_at <= not_before <= now < expires_at, lifetime at most 60 seconds.
  Exact expiry rejects; no clock grace is applied.
* ``auth``: algorithm exactly Ed25519, key_id identifier, and signature exactly
  128 lowercase hexadecimal characters. This checks encoding only.

Identifiers match ASCII ``[A-Za-z0-9][A-Za-z0-9._:-]{0,127}``; hashes are 64
lowercase hex characters. All integers are non-Boolean, nonnegative signed-64-bit
range. No floats, duplicate keys, nonfinite numbers, unknown fields, BOM or
non-ASCII transport are accepted. Maximum wire size is 65536 bytes and maximum
JSON container depth is eight. Depth is checked before JSON decoding, respecting
quoted strings and escapes. Nested unknown action structures are unsupported.

Canonical output recursively sorts object keys, uses compact JSON separators
and ASCII encoding. Lists retain their specified order; effects/scope/resource
bindings must already have canonical order. Argument order is semantically
significant. Wire whitespace and object-key order may differ without changing
canonical output.

``canonical_envelope`` includes the signature. ``canonical_payload`` removes
only auth.signature, retaining algorithm/key_id. ``signing_bytes`` is exactly
ASCII ``GVAI-EXECUTION-APPROVAL-V1`` plus newline followed by canonical_payload.
The input is JSON alone, not these prefixed signing bytes. Shutdown envelopes,
other purpose/version values and unsupported algorithms reject. No shutdown
key, provider or command canonicalizer is reused.

Context and trust limits
------------------------

The required expected_payload is a full unsigned dictionary, including auth
metadata but excluding signature. It is validated against the same format and
must match byte-for-byte after canonicalization, not merely compare equal under
Python's Boolean/integer coercions. Every signed binding, including epochs,
observation, challenge, scope, action and effects, must match exactly. Changing
the action and recomputing its digest still rejects against an unchanged snapshot.

This snapshot is caller-provided offline test context, not an authenticated,
fresh supervisor state. A caller controlling both objects can make matching
claims. Neither parsing, matching hashes, a human-decision identifier nor a
signature-shaped string authenticates anything. Malformed context, time or
parsing errors reject with a fixed error message; no fallback creates authority.

Real authentication and operational state remain unimplemented:

* Independently administered pinned issuer keys/principal/scope grants, separate
  execution/shutdown trust roots, authenticated human decisions and key lifecycle.
* Trusted, rollback-resistant time and authenticated current observations.
* Durable atomic single-use state keyed by execution domain, issuer and approval
  ID, plus a unique supervisor/boot/attempt challenge. Parsing a token twice
  does not consume it or establish replay protection.
* Authoritative live revocation, shutdown latch, exact current policy/control
  epochs and safety-gate vetoes. Matching supplied generation numbers is not a
  revocation lookup.
* Supervisor synchronization of final recheck/consumption with dispatch, policy
  changes, stop and promotion; cancellation on expiry/revocation/stop, prevention
  of late promotion, durable crash/restart behavior and no automatic retry.

Future approval is only a necessary constraint, never an override of safety
gates. This module does not supersede HARD GATE's smaller diagnostic input shape
or enable its placeholder verifier. Moving to authenticated approval or runtime
integration requires separate review and approval.

Validation scope
----------------

``tests/test_execution_approval_envelope.py`` supplies deterministic fixed-time
synthetic format vectors, recursive canonicalization checks, malformed and
cross-domain rejection, and exact-context substitution tests. Network/process
creation is blocked in these tests. Existing focused HARD GATE, prerequisite,
registry and website tests must remain passing.

Signature authenticity, key revocation, concurrent one-use consumption, races
with shutdown/policy updates, cancellation and crash recovery cannot be proved
by this parser and are not claimed as tested. In particular an altered but
well-shaped signature still parses and remains unauthenticated/denied.
No live agent or OS acceptance suite is needed or authorized.
