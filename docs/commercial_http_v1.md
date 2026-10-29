# Local Commercial HTTP API V1

## Status and scope

Phase 6G adds an offline, loopback-only HTTP adapter in
`gvai/commercial_http.py`. It wraps the existing
`CommercialEvaluationService`; it is not a public service, production
authentication system, billing integration, safety certification, or launch
approval. No credential-issuance, usage, health, debug, or supervisor endpoint
is exposed.

The adapter binds only to `127.0.0.1`. It has no outbound network client and
never calls workers, tools, or supervisor STOP operations. `ALLOW`, `QUALIFY`,
and `BLOCK` remain advisory evaluation decisions; the response explicitly
states `advisory_only: true` and `enforcement_applied: false`.

## Local API

The only route is:

```http
POST /v1/evaluations HTTP/1.1
Authorization: Bearer <customer-api-key>
Content-Type: application/json
Content-Length: <required>
```

Credentials in query strings are rejected. The adapter does not provide TLS;
loopback binding is a local-development boundary, not a transport suitable for
remote clients or shared hosts. Duplicate Authorization and Content-Length
headers, transfer encoding, content encoding, and `Expect` are rejected.
Every `Expect` value is rejected, including extension tokens; the adapter never
continues an `Expect: 100-continue` request.

Example request (replace the bearer credential locally; never commit a real
credential):

```json
{
  "version": "v1",
  "request_id": "req-2026-001",
  "resource_id": "project-a",
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

Strict request schema (JSON Schema Draft 2020-12):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["version", "request_id", "resource_id", "telemetry", "reported_effects"],
  "properties": {
    "version": { "const": "v1" },
    "request_id": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" },
    "resource_id": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" },
    "telemetry": {
      "type": "object",
      "additionalProperties": false,
      "required": ["token_delta", "tool_calls_delta", "error_delta", "repeated_action_delta", "recursion_depth"],
      "properties": {
        "token_delta": { "type": "integer", "minimum": 0, "maximum": 1000000 },
        "tool_calls_delta": { "type": "integer", "minimum": 0, "maximum": 10000 },
        "error_delta": { "type": "integer", "minimum": 0, "maximum": 10000 },
        "repeated_action_delta": { "type": "integer", "minimum": 0, "maximum": 10000 },
        "recursion_depth": { "type": "integer", "minimum": 0, "maximum": 1024 },
        "latency_ms": { "type": ["integer", "null"], "minimum": 0, "maximum": 3600000 }
      }
    },
    "reported_effects": {
      "type": "array",
      "uniqueItems": true,
      "maxItems": 11,
      "items": {
        "type": "string",
        "enum": [
          "expands_authority",
          "escalates_permission",
          "acquires_control",
          "creates_persistent_copy",
          "bypasses_control_plane",
          "influences_shutdown_authority",
          "delays_shutdown",
          "reinterprets_shutdown",
          "interferes_rollback",
          "interferes_recovery",
          "tampers_control_plane"
        ]
      }
    }
  }
}
```

The service remains authoritative for strict telemetry/effect validation.
Request bodies are limited to 16 KiB, cumulative header bytes to 16 KiB, and
header count to 32. The stdlib parser limits request lines and individual
header lines to 64 KiB. `create_server` accepts trusted-server configuration
for `max_concurrent_handlers` (1 through 128, default 16) and
`request_timeout` (0.05 through 60 seconds, default 5 seconds). The connection
cap rejects excess connections promptly with a fixed 503 JSON error; it does
not wait for a free handler. One monotonic wall-clock deadline begins when the
connection handler starts and bounds request-line, header, and body reads as
well as response writes. Expired or incomplete requests close without service
evaluation. JSON must be UTF-8, duplicate object keys and non-finite numeric constants are rejected.
Only `application/json` without parameters is accepted. `Content-Length` is
required and must occur exactly once; request transfer/content encodings are
not accepted.

Successful response is the service's response object, for example:

```json
{
  "outcome": "evaluated",
  "reason": "evaluated",
  "evaluation": {
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
}
```

Responses set `Cache-Control: no-store`, close the connection, and omit
credential and tenant identity. Replay does not return a previous result.

## HTTP error behavior

All errors use this fixed JSON shape and fixed messages; exception text and
internal authorization reasons are not exposed:

```json
{"error":{"code":"authorization_denied","message":"Credential is not authorized for this resource."}}
```

| HTTP | Error code | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Invalid JSON, duplicate keys, unsupported fields, invalid schema, transfer encoding, or invalid Content-Length. |
| 400 | `query_not_allowed` | Query string supplied on a POST path. |
| 401 | `authentication_required` | Missing or malformed bearer header. |
| 403 | `authorization_denied` | Invalid/expired/revoked key, missing capability, unknown resource, or tenant mismatch. |
| 404 | `not_found` | Unknown path. |
| 405 | `method_not_allowed` | Non-POST method; response includes `Allow: POST`. |
| 409 | `replay` | Request ID was already reserved or completed; no evaluation is repeated. |
| 413 | `request_too_large` | Body exceeds 16 KiB. |
| 414 | `request_too_large` | Request line exceeds the stdlib 64 KiB parser bound. |
| 415 | `unsupported_media_type` | Unsupported content type or content encoding. |
| 417 | `expectation_not_supported` | `Expect` header is not supported. |
| 431 | `headers_too_large` | Header count or cumulative bytes exceed configured limits. |
| 429 | `quota_denied` | Missing or exhausted quota, clock rollback, or other usage denial. |
| 500 | `evaluation_failure` | Evaluation failed; accounting marks the attempt failed when completion succeeds. |
| 503 | `accounting_failure` | Reservation completion/accounting failed; result withheld and unit may remain consumed. |
| 503 | `service_unavailable` | Service raised unexpectedly or returned an invalid response object. |
| 503 | `service_unavailable` | The configured concurrent-handler cap is full. |

An evaluated `BLOCK` is still HTTP 200 with `outcome: evaluated`. It is never
mapped to an authorization error or represented as a stop/enforcement action.

## Trust boundaries and threat model

- Trusted construction supplies the service, verifier, ownership store, and
  usage policy. There are no customer-controlled tenant, role, capability,
  quota, or ownership claims.
- The bearer credential is passed unchanged to the existing service, which
  re-verifies current key state and reauthorizes resource ownership and tenant
  equality. Invalid credentials and cross-tenant access produce one public
  authorization response.
- The adapter accepts only bounded request-owned JSON values and fixed field
  names. It rejects duplicate JSON members, query strings, unknown fields,
  unsupported methods/media types, and ambiguous framing.
- The server binds to IPv4 loopback only, logs no requests, suppresses
  unexpected handler tracebacks, and adds no outbound connection mechanism.
  This does not isolate malicious same-user processes that can connect to
  loopback, inspect process memory, or control the host.
- The handler cap and request deadline bound this prototype's local connection
  work; they are not production-grade rate limiting, per-client fairness,
  resource isolation, or a defense against host-level denial of service.
- Process-local API-key revocation and quota state are non-durable. Restart,
  multiple processes, or multiple hosts do not share these controls. The
  service's existing reservation/replay semantics still apply within the
  configured service object.
- No HTTP route invokes execution workers or supervisor controls. Existing
  evaluation of caller-reported effects remains advisory and does not invoke
  supervisor STOP.

## Local testing

The adapter tests start a random-port server explicitly bound to
`127.0.0.1`, use only in-memory test credentials/ownership/quota, and shut it
down at test completion. From the repository root:

```sh
/usr/local/py-utils/venvs/pytest/bin/python -m pytest -q tests/test_commercial_http.py
```

In a Python environment with pytest installed, the usual equivalent is
`python -m pytest -q tests/test_commercial_http.py`. No package installation,
public listener, external service, or customer traffic is needed. A trusted
local caller can create a configured service and call
`create_server(service, port=0)`; its actual `127.0.0.1` address and ephemeral
port are available as `server.server_address`. Management and provisioning are
intentionally out of scope and must not be added as request parameters.

## Production blockers and exclusions

This phase is suitable only for local founder review. Before any remote,
shared-host, paid, or customer use, blockers include durable key and revocation
storage; durable cross-process quota transactions and idempotency; trusted
customer/resource provisioning; TLS and a reviewed ingress/authentication
model; rate limits and connection/request concurrency controls; durable audit
and credential redaction across infrastructure; response recovery/retention
policy; health/operations; deployment hardening; and independent security and
founder approval. In-memory usage policies are not a billing entitlement, and
the target monthly price implies no allowance.

This phase makes no commits, pushes, pull requests, merges, deployment,
dependency installation, billing/Stripe activation, DNS/website/host change,
or supervisor STOP modification. The complete offline repository test suite
was run for this phase; no test suites were excluded.
