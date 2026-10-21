Independent-switch offline conformance contract v1
=================================================

Scope and authority
-------------------

The test-only harness in ``tests/test_independent_switch_contract.py`` joins
existing restrictive components at their negative-path boundaries. It adds no
production adapter, verifier, supervisor service, launch hook or publication
operation. Never let the thing behind the switch own the switch.

The harness exercises the real envelope parser, deny-only HARD GATE, synthetic
lifecycle transitions, local STOP journal/controller and Linux stop adapter.
Only Linux descriptor/syscall boundaries and storage fault injection are faked.
Temporary journal writes are real. Network calls, process launch and real
signaling are prohibited; no real cgroup descriptors are opened.

Interface matrix
----------------

========================== ================================================
Component                  Meaning and incompatible boundary
========================== ================================================
Envelope parser            Canonical bytes and exact snapshot matching only;
                           signature shape is not authentication.
HARD GATE                  Independent diagnostic claims; always denied.
                           Rich envelope fields are not approval credentials.
Lifecycle model            Synthetic requests with integer boot and modeled
                           replay/fences, not durable shared consumption.
STOP journal/controller    Starts stopped; registration immediately stops
                           containment. Preserves stopped generation rather
                           than provisioning an execution epoch.
Linux STOP adapter         Conditional cleanup evidence on trusted supplied
                           descriptors, not authenticated containment ownership.
Sandbox executor           Not imported or invoked. Existing dispatch and
                           per-file copying are not wired to this contract.
========================== ================================================

Envelope UUID boots are never converted to model integer boots. Gate claims
are separate diagnostic fixtures, not a production envelope projection.
STOP journal generation, model fence, shutdown generation and boot identity
are distinct values; equal numbers do not make them interchangeable.

Negative-path behavior
---------------------

The test-local candidate flow parses a valid-looking envelope and invokes the
real HARD GATE. Denial returns before reservation, launch or publication;
fail-fast callbacks detect any attempted forward operation. This proves the
test wiring obeys denial, not that the existing executor enforces this gate.
The fixture carries an intentionally fabricated signature and no credentials.

Synthetic reservation/dispatch/cancellation scenarios are tested separately.
Every model result remains denied and unauthenticated, including successful
modeled stages. STOP blocks later dispatch. Cleanup success neither changes
an envelope's authentication result nor redeems a gate denial.

The real STOP controller stops syscall-faked containment before journal IO.
Tests cover missing containment, registration after STOP, duplicate STOP,
cached reaping, incomplete kernel evidence, failed kill, persistence failure,
restrictive reopening and saturated generations. Worker completion/cancellation
claims cannot register targets or satisfy kernel cleanup observations.

Correlation is not authentication
--------------------------------

A test-local exact-match assertion requires tenant, attempt, boot and fence.
Missing fields, foreign tenants/attempts, differing boots, integer-for-UUID
substitution, stale/future fences and boolean-for-integer coercion are rejected.
This is a proposed correlation requirement, not a production evidence format,
credential, signature verifier or proof of tenant isolation.

Current cleanup reports contain none of that binding. Tests explicitly show
that a STOP report, cleanup evidence object or worker dictionary cannot serve
as a model cancellation acknowledgement. An exact synthetic request plus its
original fence can record modeled cancellation only; it never authenticates
kernel evidence or clears STOP. Operational evidence binding remains missing.

Measured outcomes and limits
---------------------------

Passing tests establish offline control flow, exact comparisons, syscall
arguments and restrictive local journal behavior under the tested faults.
They do not establish signature authentication, durable approval consumption,
live cgroup provenance, migration resistance, descendant cleanup, AppArmor
attachment, supervisor privilege separation, tenant isolation, bounded STOP,
crash cleanup by a host manager or atomic STOP-fenced output publication.

No production source, security policy, credentials, customer accounts, model
APIs, deployment configuration or website changes belong to this increment.
Existing focused offline suites must remain passing. Sandbox test collection
that probes Bubblewrap is outside this milestone; no live workers are needed.
Repository-versus-integration-base reconciliation remains a separate readiness
blocker. Nothing here authorizes merge, publication or deployment.

Future operational integration requires separately reviewed authentication,
durable single-owner attempt/replay state, protected containment provisioning,
attempt-bound parent evidence, shared STOP/dispatch/publication ordering and
independent host acceptance. The governed worker must not own or modify any
of those enforcement mechanisms.
