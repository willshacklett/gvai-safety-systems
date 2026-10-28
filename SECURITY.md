# Security Policy

## Reporting a Vulnerability

GvAI Safety Systems takes security and safety issues seriously.

If you believe you have discovered a security vulnerability, unsafe behavior, or potential misuse risk related to this project, please report it responsibly.

### How to Report
- Open a GitHub issue and clearly mark it as **Security**
- If the issue is sensitive, provide minimal details publicly and request private follow-up

We aim to acknowledge security reports promptly and work toward a responsible resolution.

## Scope
This policy applies to:
- GV core computation
- Sentinel runtime monitoring
- Threshold classification logic
- Example integrations
- Offline commercial identity, authorization, and customer API-key lifecycle

## Safe Use
GvAI Safety Systems is designed to **monitor and surface risk**, not to replace human judgment.
Production deployments should always include appropriate oversight and safeguards.

The [customer API-key foundation](docs/commercial_api_keys_v1.md) is nonproduction.
It does not implement verified customer accounts, a secure production key store,
durable revocation, trusted time, or an authenticated HTTP service. Never log
API keys or reuse supervisor credentials for customer verification. Customer
grants must never control independent supervisor STOP authority.
