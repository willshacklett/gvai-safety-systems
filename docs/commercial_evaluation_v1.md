# Commercial Evaluation Contract V1

## Status and scope

This is a local, deterministic, advisory-only library contract. It does not
provide an HTTP service, customer authentication, tenant isolation, billing,
worker execution, or production safety certification. The founder-approved
$99/month starter price is a future target only; this contract does not activate
or advertise a product.

The contract evaluates one bounded sample of caller-supplied operational
telemetry and a list of caller-reported authority-expansion effects. It does
not inspect prompts, infer an action's actual effects, or establish that a
customer-reported effect list is complete or truthful.

## Request

```json
{
  "version": "v1",
  "request_id": "req-2026-001",
  "telemetry": {
    "token_delta": 100,
    "tool_calls_delta": 1,
    "error_delta": 0,
    "repeated_action_delta": 0,
    "recursion_depth": 0,
    "latency_ms": null
  },
  "reported_effects": []
}
```

All fields are required except `latency_ms`, which may be omitted or `null`.
Unknown or missing fields, unsupported versions, malformed request IDs, unknown
effect names, duplicate effects, booleans, non-integers, non-finite numbers,
negative values, and values above these input bounds are rejected:

| Field | Inclusive maximum |
| --- | ---: |
| `token_delta` | 1,000,000 |
| `tool_calls_delta` | 10,000 |
| `error_delta` | 10,000 |
| `repeated_action_delta` | 10,000 |
| `recursion_depth` | 1,024 |
| `latency_ms` | 3,600,000 |
| `reported_effects` | Number of known authority-expansion effect names |

The reported-effect vocabulary is fixed to the existing
`AUTHORITY_EXPANSION_EFFECTS` in `gvai.external_control`; it is not an
authorization scope. Invalid requests raise `EvaluationInputError` and must be
rejected by a future HTTP layer, never converted to an allow decision.

## Response and mapping

For the example above, the response is:

```json
{
  "version": "gvai-evaluation-v1",
  "request_id": "req-2026-001",
  "decision": "ALLOW",
  "risk_score": 1.45,
  "risk_band": "green",
  "explanation": "The existing telemetry guard classified this sample green. No authority-expansion effect was reported. This is not authorization or enforcement.",
  "evaluation_status": "ok",
  "advisory_only": true,
  "enforcement_applied": false
}
```

`risk_score` is the existing `GVRuntimeGuard` one-sample telemetry score on its
0–100 scale. The implementation uses its existing default weights and band
thresholds: green below 35 maps to `ALLOW`, yellow from 35 to below 70 maps to
`QUALIFY`, and red from 70 maps to `BLOCK`. These are recommendations only;
they do not authorize, prevent, throttle, halt, or otherwise control a customer
system. The score is not a semantic action-risk score.

The existing external-control rule is applied only to the caller-reported
effect tags. A reported authority-expansion effect maps to advisory `BLOCK`
without exposing its `halted` result. No reported effect means only that the
caller supplied none; it is not proof that the action is safe. Evaluation
failures return `BLOCK`, `evaluation_status: "error"`, and a null score rather
than inventing a numeric risk score. No action is executed or stopped.

## Future commercial stages

1. **6C:** [Trusted server-side customer identity and resource ownership foundation](commercial_identity_v1.md); authenticated HTTP routes remain deferred.
2. **6D:** Secure API-key issuance, hashing, rotation, revocation, and rate limits.
3. **6E:** Durable usage metering, monthly allowance, and quota enforcement.
4. **6F:** Stripe $99/month subscriptions, signed webhook processing, and billing state.
5. **6G:** Self-service customer dashboard for keys, usage, and subscription management.
6. **6H:** Independent security validation and a controlled pilot launch.

These are roadmap items, not implementations or launch approvals. The future
API must keep customer identity and policy separate from internal identities
and supervisor control. Do not expose internal STOP APIs, runtime execution,
policy mutation, or unverified OS-worker isolation. Keep the existing public
website, contact address, GvAI.io, and deployment controls unchanged; product
availability and claims require separate founder approval.
