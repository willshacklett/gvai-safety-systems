HARD GATE: offline authority-admission contract
=============================================

Never let the thing behind the switch own the switch.

Status and scope
----------------

``gvai.authority_admission.OfflineAuthorityAdmission`` is an isolated,
**deny-only, non-operational** diagnostic contract. Its ``evaluate`` method
always returns ``AdmissionDenial`` with ``allowed=False`` and false truthiness.
There is no positive admission under any conditions in this version, including
apparently complete inputs, a valid registry manifest, or a test replacement
that claims approval verification succeeded.

No genuine independent execution-approval verifier is available in this
checkout. The existing external-command verifier authenticates shutdown
commands, not execution approval; this module does not repurpose it or its keys.
No cryptographic authentication, human approval, production readiness, or
host acceptance is claimed. The private approval-check placeholder always
returns false and is not a configurable provider.

The entry point is a proposed *offline pre-admission* boundary, not a hook in
an executor. The module is not exported from the package initializer, imported
by runtime callers, or connected to the registry, supervisor, or website.
It never executes an action, fetches evidence, loads policy, changes grants,
or issues, cancels, overrides, or reinterprets a stop command.

Existing versus stricter behavior
--------------------------------

Existing runtime policy defaults omitted control status to ``verified``,
and does not independently reject unknown Sentinel status strings. Bare gates
with empty invariant lists permit actions. The runtime guard accepts current
or cached observations without freshness authentication. Those existing
interfaces are unchanged: this module is not a fix or deployment of stricter
runtime behavior, and must not be represented as protecting those paths.

The new offline contract rejects incomplete or unsupported claims and retains
unconditional denial even when all diagnostic prerequisites appear complete.
It does not replace action/effect gates, runtime policy, authenticated shutdown,
or Linux isolation.

API and input contract
----------------------

``evaluate`` takes keyword-only ``target_id``, ``revision``, ``now``,
``control_status``, ``observation``, ``enforcement``, ``approval``, and
``registry_evidence``. Omission defaults to missing, never verified. Return
``reasons`` are fixed diagnostic codes, not reflected input or approval tokens.

* Context: workload identifier and lowercase 40-character source revision.
  ``now`` is an explicit nonnegative integer Unix second, not model-provided
  time. No system clock, implicit context, or registry-derived default is used.
* Control: only the exact string ``verified`` satisfies the syntax prerequisite;
  that string alone does not establish independent ownership.
* Observation: an exact plain dictionary containing ``target_id``, ``revision``,
  ``source_id``, ``status``, ``halted``, ``observed_at``, and ``expires_at``.
  IDs/context must match; status must be known. This conservative version
  diagnoses warning, critical, and irrecoverable as inadmissible, even if an
  existing runtime might permit some restrictive actions. A halt or inconsistent
  halt/state pair denies. Times must be integer seconds with
  ``0 <= observed_at <= now < expires_at`` and lifetime/age at most 60 seconds.
  Exact expiry denies; future, negative, Boolean, float and missing times deny.
* Enforcement: an exact plain dictionary containing nonempty, bounded, unique
  ``invariant_ids`` and ``effect_requirements`` lists and
  ``independent_shutdown=True``. These are claims, not proof of installed
  controls or complete required invariants. Checking names cannot establish
  enforcement, and a true Boolean cannot establish independent shutdown.
* Approval: an exact plain dictionary containing ``issuer_id``, ``target_id``,
  ``revision``, ``issued_at``, ``expires_at``, and a bounded ``signature`` string.
  Target/revision must match. Integer time bounds follow the same rules, with a
  maximum lifetime/age of 300 seconds. A signature-shaped string is not verified.
  Even syntactically valid inputs reach an unavailable verifier and deny.
* Registry evidence: opaque untrusted data. It is not read, fetched, executed,
  or used to establish prerequisites. If present, a diagnostic explicitly marks
  it non-authoritative. Registry READY/ALLOW, compliance, hashes, checksums,
  approval claims, and passing tests cannot clear either unconditional blocker.

Malformed values and ordinary validation/verifier exceptions yield denial.
Process cancellation exceptions such as KeyboardInterrupt may propagate, but
cannot return authorization. Untrusted Python code already in the parent can
tamper with Python objects; this is not a sandbox against that threat.
Never execute an untrusted plugin or verifier in a trusted parent.

Trust and integration blockers
------------------------------

Future positive admission requires a separately reviewed implementation, not
changing a status flag or injecting a mock verifier. Acceptance blockers include:

* A genuinely independent approval authority, authenticated target/action/policy
  binding, validity/replay/revocation semantics, protected trust anchors and
  independently verified human approval. None is implemented here.
* Independently authenticated control ownership and fresh safety observations,
  including rollback-resistant time and observation provenance.
* Trusted mandatory invariant/effect configuration, proof of actual enforcement,
  and a defined action-specific decision with atomic execution/promotion binding.
* Preserved external cancellation/shutdown authority and independent verification
  that running work stops; this diagnostic returns no shutdown instructions.
* An independently reviewed integration that cannot turn exceptions, missing
  evidence, registry-controlled input, or test success into execution authority.

Keep default-deny egress, encrypted storage, authorization, approvals, auditability
and Linux isolation unchanged. Missing prerequisites mean blocked, not weaker
controls. The registry release bytes, integrity manifest, blocked inventory,
production runtime, website allowlist, and deployment configuration are unchanged.

Offline validation
------------------

``tests/test_authority_admission.py`` uses synthetic fixed-time claims and blocks
network/process creation. It covers omitted/unverified control, unknown states,
stale/missing/malformed/contradictory observations, empty/missing enforcement,
registry-only approvals, unauthenticated manifests, invalid approval inputs,
and approval-check exceptions. Tests also replace the private placeholder with a
lying true result to demonstrate that even that result cannot create ALLOW.
Such fixtures are not genuine approval sources.

Run only the focused admission, prerequisite, registry and website test files;
do not collect live OS acceptance suites for this task. Passing these checks
demonstrates an offline denial contract, not runtime safety or deployed control.
