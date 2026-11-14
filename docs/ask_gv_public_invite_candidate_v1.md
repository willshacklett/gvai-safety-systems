# Public Ask GV invite candidate V1 — disabled development only

Base: `64c7c507fa20060d8f2bcdfd8eacd63499718855`
(`feature/ask-gv-permanent-feedback-v1`), incorporating hardening checkpoint
`01b6c122df07e75649267fdbbd65bc27f12ade05`. Only the post-reservation dispatch
reasoning from advisory checkpoint `c3fd88a236f32aa9b84e6baaa212cb4db79d02ca`
is reused. No advisory client, commercial credential or evaluation request is added.

This is a source candidate, not an implemented invite system or permission to
activate. No HTTP listener, provider, infrastructure or deployment is authorized.
The public `ask-gv-config.js` remains byte-identical with an EMPTY endpoint.
No endpoint origin has been approved, and `ASK_GV_APPROVED_ORIGIN` is absent.
The UI requires a separately configured canonical HTTPS origin **and** the exact
`<approved-origin>/v1/ask-gv` URL. Endpoint syntax cannot establish approval.
This mutable public configuration is not cryptographic authorization or a visitor
access gate. A future independently reviewed release must supply both values and
update activation assertions; never infer origin from an endpoint, page location,
query, storage, browser user input or an environment key. No hostname is selected
by this candidate. Tests never configure an approved endpoint or enable chat.

## Changes and preserved behavior

After the single durable reservation, then immediately before native provider
fetch, the server rechecks configuration, operator disable, drain, circuit, corpus
expiry, usable custody and caller cancellation. A remaining count of **zero** is
valid after reservation: this request already owns the final unit. New requests
remain unavailable at zero. Denial after reservation consumes the unit; no refund,
reset, retry or second reservation. The checks reduce a race; an external disable
can still change after the final check. This is **not atomic STOP**, guaranteed
remote cancellation or independent enforcement.

The existing Responses endpoint, approved-fact selection, eight facts, permanent
feedback, request/response schema, privacy/rate/budget/custody boundaries and
provider deadlines remain unchanged. Provider output is maintained fact text,
not arbitrary chat, tools, retrieval or a private repository query. Fixed provider
call target and secrets stay server-side. No tenant, billing, Customer Zero,
STOP/ARM or commercial decision API access is added.

Browser fetch always uses `redirect: 'error'`, overriding per-call attempts to
follow, and refuses a transport that reports a redirected response. The visible
log retains at most 24 message elements (12 successful exchanges); failures can
leave single user messages within the same element cap. Sent history remains four
800-unit entries; summaries remain at most twelve fact combinations. Reset aborts
and increments the epoch, clears log/history/summary and preserves disabled state.
Reset does not delete provider/host/email records. All existing accessible markup,
feedback mailto and fact data stay unchanged.

The two CLI test fixtures use finite direct-child supervision: total 5 seconds,
16 KiB combined output, SIGTERM followed after 250 ms by SIGKILL if the owned child
has not exited, bounded final close wait of 1 second. Stream errors, spawn/setup,
output, deadline, cancellation and uncertain cleanup are distinct redacted errors.
All callers own disposal in test cleanup. No group/name-based kills or numeric PID
signals; only the original ChildProcess handle is used while no exit is observed.
These fixtures run the known leaf Node server, not arbitrary process trees. Exited
leader with open inherited pipes yields cleanup uncertainty, not broad descendant
kills. This is not whole-job/Python/OS-crash containment; an independent external
supervisor is still needed for job termination/escaped descendants. Other older
browser/proxy/HTTP fixtures are outside this correction and need separate effect
review and containment before running. Source corrections do not prove live CLI
termination or integration acceptance.

## Resource-free validation boundary

Only `tests/ask-gv/public-boundary.test.mjs` is intended for this candidate's selected
runtime validation. Inspect its imports and code before invocation. It reads known
source/facts/config files, then runs the real server as a plain strict VM after an exact import fence, with an
in-memory HTTP factory with `.listen` forbidden, synthetic custody and provider
callbacks. No real HTTP modules or native fetch are available to that handler.
It does not natively import backend/hardening test modules or run their tests.
Exact recognized import declarations are removed and bound only to the inspected
synthetic/safe objects; unexpected module syntax fails before evaluation. Function
bodies remain actual source. No experimental VM flags or dependency are needed.
The exact supervisedChild function excerpt is evaluated separately with fake
ChildProcess/event/timer objects; no actual child starts in that test.

The disabled UI runs against a fake DOM with a fail-fast fetch. The message-render
function excerpt is exercised for its visible-element cap without configuring an
endpoint. Endpoint cases are rejection-only: no approved deployment identity or
positive configured-chat result is fabricated. Epoch/reset source checks plus
actual disabled reset are resource-free evidence; full in-flight enabled UI epoch
behavior/mobile/accessibility remain unverified until separately approved mocked
browser testing. Redirect/deadline/overflow tests pass empty target to mocked
fetch only, never to native transport.

Suggested selected invocation, under an independently inspected finite outer
supervisor with bounded stdout/stderr (not a deployment or test permission grant):

```
node tests/ask-gv/public-boundary.test.mjs
```

Use finite outer deadline (30s) and combined output cap (128 KiB), stdin closed,
minimal nonsecret environment and no dependency install. `node --check` may inspect
the six JavaScript sources; Python may perform inert verification/AST reads.
Do not run blanket npm tests, backend.test.mjs or hardening.test.mjs: they contain
real loopback listeners and CLI children. The new backend socket regression is
preserved for a later explicitly authorized disposable check only. Deterministic
in-memory regressions cover final unit, disable during reserve, destroyed caller,
request abort, drain, lost custody and a final-check state change, all against actual handler
code with zero listeners. Mock passing results do not establish deployment safety.

## External launch gates — all HOLD

- Invite admission and revocation are NOT implemented. Origin/IP/token controls
  authenticate ingress and bound abuse, not invited visitors. Independently review
  edge/session identity, CSRF/CORS, preflight, revocation, bypass prevention and
  direct backend isolation before requests can reserve budget. The current browser
  omits credentials and ingress strips cookies/Authorization: do not assume any
  hosted access gateway is compatible. Never expose a shared token in public JS.
- Select/review separate hosting, exact immutable release/runtime, UID, persistent
  custody, firewall/egress, domain, HTTPS/cert renewal, restart/reconciliation,
  operator kill switch and recovery. Do not reuse Lab-01 or Customer Zero by default.
- Approve current public facts/contact address and publish accurate privacy,
  provider/hosting/email retention and region terms. `store:false` is not a
  zero-retention agreement. Facts expire **2027-02-10**; review before that date,
  do not automatically extend. February 2027 launch remains a target, not a promise.
- Validate an exact Responses-compatible model under separate bounded paid-call
  approval. No healthcheck/page load may call a provider. Establish dedicated
  provider project/workload identity, finite attempt allowance, independently
  reviewed enforced spend limits and alerts; 100 lifetime attempts is not a
  verified dollar ceiling. Preserve greatest consumed count after uncertainty.
- Separately authorize disposable HTTP/proxy/browser checks, real account checks,
  preservation commit/push, merge and deployment. Nothing in this candidate
  authorizes them or creates a trusted approval launcher.

Public feedback remains permanent and independent of subscriptions/AI availability:
visitors explicitly choose what to email; no transcript is attached or ingested,
and suggestions do not mutate code/facts/authority. No new forms/CRM/billing.

Customer Zero F2 external source authentication, F3 whole-job containment and R1–R6
remain HOLD; P1/P2 (except these specific test-child corrections), N4/N7/N8/N12,
meaningful telemetry, effect-based BLOCK mismatch and independent STOP/ARM remain
open in their separate workstreams. All-zero telemetry/empty effects ALLOW/green/0
is connectivity only, never meaningful threat detection or an enforcement grant.
