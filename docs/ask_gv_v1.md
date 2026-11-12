# Ask GV V1: local implementation and future operation

Status: uncommitted development only. No backend or frontend deployment has been
performed. The checked-in public endpoint is empty and chat is visibly disabled.
Review and authorization are required before any commit, push, merge, deployment,
DNS change, billing activation or paid provider request.

## Verified baseline and selective reuse

The public homepage fetched during inspection had SHA-256
`d8573afd864eaa51f514cb8d7385d10ff16cf351709cda03792afef04047d5c1`, exactly matching
`index.html` at verified remote main `23299020ea200e268a1d91aa591c49b8a6557ecb`.
Work is isolated on `feature/ask-gv-website-v1` in `/tmp/gvai-ask-gv-v1`.
Existing branch references, the original worktree and its `.release-transfer/`
files, and M2 checkpoint `8f87346` were preserved.

`.github/workflows/deploy-public-site.yml` publishes an explicit static allowlist
through GitHub Pages, only from main and after validation. Pages cannot run this
server code. That workflow is unchanged. The static build adds only four reviewed
Ask GV assets; no server code, state directory, provider credentials, or fact file
is uploaded. No deployment workflow for the new backend is activated.

Reviewed source repository: `willshacklett/GvAI` at
`9646e9a867c7cc94b1386277c9c0d592a427fcdf`.

- `web/fetch.js` is copied as `ask-gv-fetch.js`: a small request wrapper with abort,
  deadline, safe error messages and JSON handling. MIT attribution is in
  `assets/GvAI-MIT-LICENSE.txt`, included in the public artifact.
- `web/intelligence-session.js` was reviewed for bounded history and reset patterns.
  Its regional evidence, actions and workforce integration are not imported.
- `gvai/chat.py`, `gvai/llm.py`, `middleware/openai_compat.py`, and `api_config.js`
  were reviewed. Their broad companion persona, runtime scores/state, permissive
  history, gateway coupling and echo fallback do not fit this public scope.
  They are not imported. Existing GvAI endpoints are never contacted by Ask GV.

## Architecture and grounding contract

Browser -> separately hosted `POST /v1/ask-gv` -> fixed OpenAI Responses URL.
The Node.js server uses built-in modules only (Node 22+; tested on Node 24).
The browser never receives a provider key and never contacts OpenAI directly.

`ask-gv/facts.json` is the complete, locally versioned knowledge set. It records
source baseline, version, review deadline, status, exact fact text and source URLs.
The seven initial topics cover technology, development status, pilot, pricing,
setup plans, platform direction and documentation. These are proposed approved
excerpts from the verified public baseline; the owner must review and approve
this corpus before enabling a backend. No development branch is a pricing or
availability source. Price, uptime, certifications and production readiness are
not invented.

OpenAI selects at most three fact IDs using strict structured output. The server
validates those IDs and renders the maintained fact text verbatim with its status,
version and maintained links. It discards all other provider text. Unknown or
unrelated questions get a bounded verification/contact response. This deliberately
limits V1 to AI-selected factual excerpts rather than open-ended generated prose.
It cannot offer speculative setup commands or infer features from prior answers.
Selection can still be irrelevant or incomplete; the AI accuracy disclosure and
source links remain necessary. Mock tests verify the containment contract, not
real-model answer quality.

History is bounded untrusted JSON in a user message, never system instructions.
There are no model tools, network retrieval, actions, billing connections, tenant
access, filesystem tools, or STOP authority. Prompt injection can influence which
approved excerpts are selected, but cannot introduce new rendered claims or URLs.
Corpus structure/length/links are validated at startup. After the review deadline
(currently 2027-02-10), the backend returns unavailable without a provider call.

Owner maintenance procedure: verify each fact against a public source, update
status and source links, remove stale content, increment version and reviewBy,
rerun all tests, inspect rendered answers, and approve the changes. Immutable
repository links and the recorded baseline support review; live source links
can change and must be reverified. Corpus changes are never accepted from users.

## Limits and cost controls

- JSON body: 12,000 bytes, with an independent 5-second upload deadline.
- Current question: 1,600 UTF-16 code units; history: up to 6 user/assistant items,
  each at most 1,600 units, aggregate at most 6,400 units. UI sends 4 recent items,
  each truncated to 800 units. System/developer roles and extra fields rejected.
- At most 2 concurrent body/provider operations and 32 open connections on the
  executable server. Header size 8 KiB; request/header timeouts 10 seconds.
- 6 accepted POST attempts per direct peer address per minute, with a bounded
  1,000-entry in-memory identity map. Peer addresses are HMACed and not logged.
  Caller-supplied Forwarded/X-Forwarded-For cannot bypass limits.
- Provider deadline: 8 seconds including response-body reading; no retries;
  max_output_tokens: 256; maximum provider response body 32 KiB.
- Durable cap: 100 provider attempts for the entire provisioned ledger lifetime,
  including timeout, refusal, invalid output and provider error. Reservation is
  persisted and fsynced before the provider call. No automatic refund or reset.
  Missing/corrupt/exhausted state fails closed. A process lock prevents two local
  processes from spending the same ledger. Crash-left lock requires operator
  investigation, not automatic deletion. The ledger belongs on a private durable
  filesystem, outside the repository and public artifact.

Estimate cost using the selected model's verified price at approval time. With
the current corpus and body limits, conservatively allow roughly 40,000 input
tokens per request (actual normal inputs should be much smaller), plus 256 output
tokens. For 100 attempts, estimated upper planning allowance is
`4 * input_price_per_million + 0.0256 * output_price_per_million`, excluding hosting,
tax and any provider-specific overhead. This is a planning estimate, not a
currency guarantee. No model or dollar price is assumed verified here. Set a
separate restricted provider project with operator-reviewed model access and
spend controls before activation. Provider dashboard alerts are not a substitute
for the application's durable reservation cap.

A public endpoint can be scripted with a forged Origin. CORS is browser isolation,
not authentication or proof of a human. The global cap bounds exposure even when
IP limits are bypassed or exhausted deliberately. There is no automatic budget
replenishment. If running behind a reverse proxy, all traffic may share one peer
rate bucket; this conservative limitation is intentional. Do not trust arbitrary
forwarding headers to fix it. A later approved ingress design may provide trusted
client identity and edge abuse controls. Do not horizontally scale this file-ledger
backend or run it on ephemeral/serverless storage: multiple independent ledgers
multiply the cap. Use one process and durable volume; multi-host deployment needs
an atomic shared reservation store first.

## Configuration and separately deployable backend

Run `node ask-gv/server.mjs` for the disabled backend on `127.0.0.1:8787`. Disabled
mode makes no provider calls. Local automated tests inject provider mocks and do
not need any real credentials. Never enable a real key during tests.

Future operator configuration (not performed):

| Setting | Meaning |
| --- | --- |
| `ASK_GV_ENABLED` | Exact `1` to opt into calls; otherwise unavailable |
| `OPENAI_API_KEY` | Server secret, delivered through host secret management |
| `OPENAI_MODEL` | Explicit operator-reviewed Responses/structured-output model |
| `ASK_GV_IP_SALT` | Independent random server secret for address hashing |
| `ASK_GV_STATE_DIR` | Absolute private durable directory with attempt ledger |
| `PORT` | Loopback listening port; default 8787 |

Provision `reservations.json` containing `{"reserved":0}` in the private state
directory exactly once for an explicitly approved 100-attempt allowance. Directory
permissions should be 0700, file permissions 0600. Keep backups and count history.
The server never initializes or resets a missing ledger. Replenishing or replacing
it is a new cost authorization decision. Never put keys in CLI arguments, URLs,
static JS, HTML, checked-in env files, logs or browser storage.

Serve this loopback backend behind a separately reviewed HTTPS ingress. Publish
only `/v1/ask-gv`, bound request size and upload/header deadlines at the ingress,
disable request/response body and authorization logging, and restrict outbound
network access to OpenAI. Keep no tenant/billing/runtime credentials on this host.
Use one durable ledger and one process. Configure TLS, process lifecycle and
secret injection without exposing the state directory. CORS allows only
`https://gvaisafety.com` and `https://www.gvaisafety.com`, POST and JSON headers;
no cookies or credentialed CORS are used.

After separate backend review and authorization, set `window.ASK_GV_ENDPOINT` in
`ask-gv-config.js` to the exact reviewed HTTPS endpoint ending `/v1/ask-gv`, with
no credentials/query/fragment. Then review the static artifact and existing Pages
workflow for a later authorized frontend release. A private local test endpoint
is injected only in browser tests; the tracked configuration stays empty.
Disabling can be immediate server-side (`ASK_GV_ENABLED` unset), with a later
frontend config release removing the endpoint. Unavailability never becomes a
fake answer or an echo chatbot.

## Privacy, accessibility and validation

No request bodies, keys, questions, answers or provider errors are logged by the
backend. It keeps only budget count on disk and hashed peer rate buckets in
memory. The browser keeps its conversation in page memory and clears it on reset
or reload. Enabled calls send the bounded conversation and approved corpus to
OpenAI with `store:false`; this does not promise zero retention by OpenAI or an
independent ingress. Confirm applicable provider retention and hosting policies
before launch. Avoid sensitive submissions. Summaries retain up to 12 distinct source combinations, deduplicate answers with
multiple citations, and include only selected approved answer text and sources; transfer to ChatGPT is manual copy/paste, with
no prompt or private conversation embedded in a URL.

The UI has labelled textarea controls, native buttons, keyboard operation, polite
status and conversation announcements, reset cancellation, copy fallback, source
links, noscript guidance and responsive layout. Automated axe checks supplement
keyboard/mobile tests; they do not establish full WCAG conformance or replace
manual assistive-technology review.

Commands for local validation:

```sh
node --test tests/ask-gv/backend.test.mjs
python -m pytest -q
NODE_PATH=/tmp/ask-gv-browser/node_modules PLAYWRIGHT_BROWSERS_PATH=/tmp/ask-gv-browser/browsers node tests/ask-gv/browser.cjs
python scripts/prepare_public_site.py --output /tmp/ask-gv-reviewed-static
```

Browser-only test dependencies (`playwright`, `@axe-core/playwright`) are installed
outside the repository, under `/tmp/ask-gv-browser` (tested with Playwright 1.65.0
and @axe-core/playwright 4.14.0); Chromium runtime libraries
are needed. All remote routes in the browser tests are blocked or fulfilled with
mocks. Backend tests use fake keys and mocked provider calls. Screenshots and test
outputs are disposable `/tmp/ask-*` artifacts. The final task report records the
actual pass/fail counts and verification limits.

Official API documentation consulted during implementation:
https://developers.openai.com/api/docs/guides/structured-outputs and
https://developers.openai.com/api/reference/resources/responses/methods/create.
No real OpenAI call was made to verify account availability or model quality.
