# Customer Zero advisory smoke: pre-execution corrections V1

**Resource execution remains BLOCKING / HOLD.** These corrections authorize only
resource-free validation. They do not establish the external frozen-source,
runtime, approval or supervisor boundary identified by the pre-execution review.
Both Python resource admission and Node native admission now unconditionally
HOLD at that missing boundary. No environment flag, fixture record or supplied
digest enables them. Connecting to HTTP/PostgreSQL requires a separately reviewed
future boundary integration and separate explicit execution authorization.

## Preserved provenance and permitted changes

Worktree: `/workspaces/gvai-customer-zero-advisory-smoke-v1`.
Branch: `feature/customer-zero-advisory-smoke-v1`.
Preserved HEAD C: `da20805adf79dac35f79ab99b303960ab66e4a96`.
Backend base L: `3c117260901cb15877512161cb24fa8e5587aa73`.
Node source N: `c3fd88a236f32aa9b84e6baaa212cb4db79d02ca`.

Only these three files change in this correction:

- `tests/integration/test_customer_zero_commercial_smoke.py`;
- `tests/ask-gv/customer-zero-commercial-smoke-driver.mjs`;
- `docs/customer_zero_advisory_smoke_v1.md`.

Imported `ask-gv/decision-client.mjs` stays exactly N blob
`7cb255a896036f669b034c6858d2b74d4ebecc46`, SHA256
`e4e729459eb4510eb4b5498ef885b7c3c5d6a5c803ddeccc2a1fdce7414c8420`.
Imported `tests/ask-gv/decision-client.test.mjs` stays exactly N blob
`92fbe60cb1d1565326aace17ae08d91368506b56`, SHA256
`ae1be8aa0198a84058475936901a0c3a7bffb4f60d2dfab94848546824a7ee59`.
No backend, product API, evaluator, migration, provider, budget, STOP/ARM, billing,
CI or deployment change. No missing eight-file harness/launcher is reconstructed,
invoked, approved or bypassed. Corrections are uncommitted until separately
reviewed and authorized for preservation; C and its GitHub branch remain unchanged.

## F1: effective destination checks

`validate_destination` is pure, bounded and independent of psycopg/libpq. It
accepts only an explicitly narrowed synthetic keyword DSN: exactly `host`,
`hostaddr`, `port`, `dbname`, `user`, `password`, each once. Host and hostaddr must
both be literal127.0.0.1; port must be a canonical single decimal1..65535 and equal
the independently reviewed `expected_database_port` integer. Database and runtime
role must match the reviewed test-only identifiers. No URI, quotes, escapes,
newlines/tabs, duplicate keys, extra parameters, empty values, multi-host/port
lists or inferred defaults. Synthetic passwords deliberately use only16..256
ASCII letters/digits/underscore/hyphen; this is not a general DSN parser or API.
The result is rebuilt in a canonical field order rather than forwarding ambiguous
text. Fixture DSNs using a broader grammar must HOLD, never be silently relaxed.

`refuse_libpq_environment` rejects any ambient PG-prefixed key, including service
inputs, before library loading/connection. It examines keys only, not their
values, and reports only `libpq_environment`. The parent needs a separately
reviewed clean environment and synthetic-only default credential context.
Node's small child environment is not a libpq parent environment sanitizer.

Pure tests use synthetic DSNs and fake mappings, including mappings that raise
if values are read. They never import psycopg or connect. These checks cannot
prove that a loopback port is disposable: the independent custodian must bind the
exact instance/namespace/port and prevent production forwarding or unrelated
mounts/routes **before contact**. Matching DB name/role/version after connecting
cannot undo a contact to the wrong instance. R2 remains OPEN/HOLD.

## F2: drift detection versus external authority

`require_approved_candidate` returns the independently expected digest only after
an equality check. It never substitutes a freshly calculated digest. The same
expected value is retained from approval through pre-connection checks and child
input. The child wrapper verifies both current bytes and the exact supplied child
digest before doing anything; resource execution still stops at the missing
external boundary. A second computation that differs causes `source_integrity`.

Candidate digest format remains SHA256 over sorted five-file records:
`relative_path + NUL + lowercase_file_sha256 + newline`.
Reads are bounded, regular-file/single-link, no-follow and checked for identity
changes. Five-file hashing does **not** bind backend/runtime/installed SQL.

The inert `verify_execution_sources` helper additionally checks independently
expected Git HEAD/path/branch, full clean status (including ignored artifacts and
hidden index flags), actual tracked backend/migration/dependency declaration bytes
against Git blobs, unchanged backend context against L, and origins of already
loaded gvai modules. It does not import product modules. Git reads have finite
deadlines/live output caps. Module file paths do not authenticate already loaded
code objects, import hooks, plugins, dependencies or this mutable verifier.

Node resolution is bound once to an absolute executable/stat identity and checked
for drift before subsequent launches. This is not an independently approved
runtime hash or an attestation of the loaded libraries. The supported later
runtime remains Node24.22.2; pure tests need only an inspected existing runtime.

**F2 remains BLOCKING.** Required external evidence: an independently pinned,
trusted frozen execution tree/import context, exact reviewed correction commit,
Python/Node/dependency/library identities, installed SQL review and safe process
supervision. Code must be protected from untrusted writes throughout execution.
A self-supplied record or environment value cannot authenticate that boundary.
The hard-HOLD functions deliberately have no runtime enable flag. Replacing them
requires a separate reviewed change, not setting another assertion field.
No mutable-code self-authentication or trusted-launcher approval is claimed.

## F3: owned child lifecycle, limited scope

All Popen, identity capture, selector setup, I/O, cancellation and cleanup now sit
inside `OwnedProcess`. The Linux implementation requires pidfds, WNOWAIT, default
SIGCHLD handling and a main-thread trusted exclusive waiter. It records the
child's parent/session/group/start-time identity, retains the leader **unreaped**
even after exit, and never calls `poll()` to discard that PID/session anchor.
Before a group signal it verifies the still-owned unreaped child and exact
identity. No numeric process-group signal occurs after reaping. A new session
means the group is separate from other jobs; no name-based or broad PID kill.

If identity is missing/changed, cleanup does not guess a numeric group: only the
original pidfd may signal its leader, reaping remains finite, and incomplete group
cleanup becomes `cleanup_failure`/HOLD. A partial identity or OS failure is never
reported clean. Leader-exit with descendants still causes anchored group cleanup;
a bounded read-only membership check must confirm no same-session descendants
before reaping, including members that changed process groups. Such an escape is
HOLD rather than permission to signal additional groups.
Kernel/process permission failures or persistent descendants cause HOLD.

Temporary cooperative SIGTERM/SIGINT handlers mark cancellation and are restored
after cleanup. Every live I/O loop checks the flag. Setup errors still close
selectors/pipes/handles and reap within the owned cleanup scope. The client500ms
timer stays unchanged; child communication default8s, individual operations are
bounded, cleanup has finite descendant/reap bounds. Trusted synchronous callbacks
are not preemptible by this helper's clock.

This does NOT control the entire Python service lifetime, uncooperative parent
termination, SIGKILL, a hostile same-process reaper, escaped process sessions,
OS/kernel failure or independently provisioned infrastructure. A separate trusted
supervisor must own the whole job/process set and prove cleanup even when Python
cannot run finally. A plain timeout on Python's group is not that proof because
the child starts a new session. No cgroup/supervisor is created by this source.
F3 whole-job/external-supervisor prerequisite remains OPEN/HOLD. Mock lifecycle
checks prove control flow only; no actual descendant/service/isolation fault run
is claimed. Real resource-free child tests use only leaf Node scripts, no listeners.

## F4/F5: truthful results and precise evidence

`completionFrame` applies narrow Node-side disposable acceptance: one request,
native evidence label, HTTP200, accepted advice-only/false-enforcement, correlated
evaluated ALLOW/green/0 and provider-not-attempted. Unavailable/timeout/cancelled or
other failures produce a sanitized HOLD frame and exit2. Contract-mode negative
tests can still return expected unavailable observations with exit0. Neither mode
changes product advisory admission semantics. Pure mocked classification tests do
not prove actual native transport. Native entry is independently hard-HOLD now.

Node exit0 alone never establishes integration acceptance. Python still requires
the actual database baseline/after counts and full result checks. Default skipped
integration is NOT RUN; it is never PASS. Direct native use remains unauthorized.
No retry, refund, quota reset or fabricated grant/result is added.

`Hold` retains only fixed redacted codes and bounded safe evidence: child-start
acknowledgement, cleanup verification and numeric exit status. Deadline, output
overflow, spawn failure, process exit, protocol and cleanup/ownership failures are
distinct. No raw stderr, DSN, key, response or private exception is emitted.
Selected limit tests require the exact intended code, a private child-start marker
and verified cleanup. Lifecycle/partial-setup/cancellation/ownership-change/reap
faults use deterministic fakes, never real descendant trees or broad signals.
A mocked CLI admission test supplies synthetic private input and fetch/listener/
connect guards; it requires exit2 before any mock fetch invocation. A bounded
source-read test rejects pathname replacement using inert filesystem mocks.
A missing runtime cannot satisfy the deadline/overflow evidence checks.

## Pure validation boundaries

Inspect imports, child snippets and selected test effects before each invocation.
The selected classes are `PureContracts`, `SourceAdmissionContracts`,
`LifecycleFaultContracts`; do not select the disposable class or run blanket suites.
Python bytecode/cache writes should be disabled. Python AST/in-memory compilation,
node --check and exact imported client tests are allowed under finite deadlines
and bounded output. No installation, HTTP listener, native fetch, PostgreSQL,
Docker, provider, migration or infrastructure lifecycle is needed or authorized.
Tests invoke the unchanged client using fake transport/private pipes and the real
Python evaluator/service in synthetic memory. The500ms timeout is unchanged.

Inert context checks on this dirty correction worktree correctly HOLD; a future
clean reviewed correction commit must be explicitly pinned. Mock context tests
exercise backend drift and import-origin rejection without executing backend code.
Successful pure tests do not clear F2 or turn fixture assertions into approval.

## Dormant future fixture contract: not an executable authorization

The prior fixture format additionally requires `expected_database_port`; approval
additionally requires `source_head` for the exact reviewed correction commit.
The existing digest/expiry/fixture checks remain consistency checks only. Approval
and expected hashes need independent custody; caller-controlled values can be
self-asserted. R1 remains OPEN. Expiry/one-run consumption semantics are externally
defined; the source does not mint or consume an authenticated grant (R6 OPEN).
No fixture, approval or credential file is created by this correction or tests.
Resource admission currently HOLDs before reading such files/importing psycopg.

A future reviewed integration must establish a fresh exclusive cap3 pilot, exact
synthetic authority, distinct non-superuser owner/restricted runtime, reviewed
L migrations001-003 and pgcrypto/grants, evaluate-only and usage-read-only keys.
Keep owner credentials out of Python/Node; Node receives only its synthetic
customer key privately. Same-UID delivery reduction is not OS isolation (R3).
Exact runtime/dependency/installed-function identities need external review (R4).
The code has no Docker/DB/migration/role provisioning, refund or schema reset.

The dormant happy case remains narrow: matching-ID actual evaluated advice,
provider-not-attempted, aggregate usage0->1/completed1/remaining2. Exclusive fixture
ownership and sanitized per-run evidence are external requirements. Aggregates do
not prove request-level exactly-once; ambiguous commits/results can still charge.
Quarantine/reconcile before another run, never hide it with a new ID or reset (R5).
No native/DB case, real replay/conflict/restart/cleanup or failure matrix is run.

## Remaining limitations and disposition

R1-R6 stay open wherever noted: independent approval, disposable identity,
same-UID custody, runtime/SQL attestation, accounting attribution/reconciliation,
expiry/single-invocation policy. F1 parsing/environment and F4/F5 source changes
are not independent execution approval; F3 external containment is unverified.
P1 old latched-stream diagnostic matrix and P2 old unbounded Node fixture/default
Python CI/docs gap remain OPEN. N4 expiry under authority lock wait; N7 client abort/
late outcome; N8 capacity exhaustion/privilege revocation; N12 key revocation between
reservation/completion remain OPEN. No earlier mock test is upgraded to runtime proof.

Python can validly produce effect-based BLOCK with a green score; unchanged Node
strict score/band mapping rejects that. Fixed empty effects avoid the mismatch,
not resolve it. Fixed all-zero telemetry/null latency/empty effects ALLOW/green/0
is connectivity evidence only, never meaningful risk/threat detection, actual
spend measurement, safe-effects proof or enforcement. Guard state is fresh per call.
Advisory does not enforce independent STOP/ARM; BLOCK/errors/timeouts do not govern
provider admission or prove remote termination/rollback. No production readiness,
TLS/host isolation/audit retention/billing/launch approval.

STOP for review. No commit, push, preservation checkpoint, PR, merge, deployment
or resource execution is authorized by this correction. Any later changes to the
external boundary need explicit scope and independent review, not a hidden toggle.
