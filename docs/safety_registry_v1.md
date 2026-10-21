# Offline safety knowledge registry V1

## Scope and authority

This is an **offline, review-only specimen**, not a published service, executable
policy, integration SDK, or production safety certification. It describes one
existing sandbox network-isolation safeguard. It does not demonstrate new runtime
safety or independently reproduce the historical evidence.

Never let the thing behind the switch own the switch. Knowledge retrieval does
not confer authority. The governed agent must not modify, disable, reinterpret,
or expand its independent enforcement mechanism, verifier configuration,
credentials, approvals, audit retention, resource boundaries, or shutdown controls.

The intended architecture is:

Public knowledge → independent developer evaluation → human-approved pinned
adoption → separately administered enforcement → isolated governed workload.

Nothing imports this registry into the runtime or adds it to the public-site
allowlist. No model calls, endpoints, submission handlers, network access, DNS
changes, deployments, or production configuration changes are introduced.
Repository review visibility is not an approved website cutover.

## Files and format

Paths in JSON are repository-relative identifiers, never filesystem authority,
URLs, or instructions to fetch or execute. Relative file references in this
document are relative to the repository root.

- `registry/schema/registry-1.0.0.schema.json`: JSON Schema Draft 2020-12.
- `registry/releases/0.1.0/registry.json`: release metadata, safeguard, scenario,
  empty failure list, historical evidence, and declarative adoption requirements.
- `registry/releases/0.1.0/integrity.json`: exact-byte SHA-256 manifest for the
  schema and specimen, governed by the schema's `integrity` definition.
- `tests/test_safety_registry.py`: offline validation and negative fixtures.

Schema validation rejects unknown fields, unsupported schema versions, wrong
types, unbounded text, malformed paths, and missing adoption requirements.
Semantic tests additionally enforce globally unique record IDs, resolvable
references, safe allowlisted local file resolution, and matching release versions.
JSON Schema alone cannot enforce cross-record relationships. Text is untrusted
data, even when schema-valid; no schema can establish the truth of prose or make
it safe to execute.

`published_at` is null and `publication_status` is `offline_review_only`.
Publication is deliberately unsupported by this schema version. Null provenance
means unknown, not zero, successful execution, or verified absence.

Keep these dimensions separate:

| Dimension | Meaning |
| --- | --- |
| Implementation status | Implemented, proposed, or unverified code/control |
| Evidence status | Historical unreproduced, independently reproduced, or unverified |
| Assertion type | Measured observation, attributed historical report, claim, or hypothesis |
| Execution status | Reported or measured pass/fail, skipped, or not run |
| Reproduction status | Whether a separately identified party reproduced the result |

The scenario describes a hypothesized prohibited outcome; it is not an observed
failure. `failures: []` means this specimen catalogs no observed failures, **not**
that no failures exist. Future failures require affected safeguard versions,
sanitized evidence references, mitigation status/evidence, and a nullable
supersession reference. Hypothetical failures must remain hypotheses; observed
failures require evidence. Negative test fixtures are synthetic, never findings.

## Evidence and limitations

The historical acceptance artifact is
`experiments/results/gv_v2_acceptance.json`, dated September 9, 2026. The specimen
attributes its network-attempt result, records its platform and exact-byte digest,
and leaves producing revision, complete dependency versions, test counts, and
independent reproducer unknown. The inspected source snapshot is **not** a
substitute for the missing producing revision.

The artifact reports selected outcomes, not production safety. Network-attempt
observations partly originate in the example worker. Generator backend booleans
are not separate measurements. Failed destination reachability alone does not
prove isolation. OS tests can skip when the backend is unavailable, including the
acceptance suite's no-fallback test; a green aggregate suite can omit OS coverage.

The trusted parent evaluates policy after disposable execution. Its output copying
does not demonstrate atomic multi-file promotion. Shutdown authorization is not
proof of running-worker cancellation. Kernel/sandbox compromise, arbitrary hostile
code, covert channels, and trusted-parent compromise are not covered by the
historical result. Encryption deployment and host AppArmor attachment remain
unverified; do not infer their absence or alter them.

Future measured results must identify the producing revision, environment,
dependency/tool versions, prerequisites, exact test identity, expected and
observed outcomes, pass/fail/skip counts, sanitized artifact digest, and reproduction
status. Independent reproduction must supply its own retained evidence record,
identity/attribution, and source revision, rather than relabeling a historical
report. Schema acceptance is not independent attestation.

## Versioning and integrity

Schema, record, and release versions are independent numeric semantic versions.
Breaking format/requirement changes increment the corresponding major version;
compatible additions increment minor; corrections increment patch. Even patch
corrections create a successor release. Never overwrite published releases,
failure records, or historical results. Preserve old affected versions and link
successors. The current `0.1.0` directory is an unpublished review candidate;
subsequent publication requires separate approval and a publication-capable schema.

SHA-256 hashes cover exact checked-in UTF-8 file bytes, including whitespace and
the final newline. Do not reserialize JSON before verification. Evidence digests
cover the original retained artifact; the manifest covers only the schema and
registry. It does not cover itself, this documentation, tests, or dependencies.

**Checksums alone do not authenticate the publisher.** An attacker able to replace
both payload and manifest can replace both hashes. A trusted operator must acquire
the expected manifest digest through an independently trusted review/release
channel, verify it before trusting manifest entries, and reject mismatches. No
authenticated release or signature is claimed here. The fixed expected files are
an allowlist, not permission to read arbitrary manifest paths.

Later detached public-key signatures, publisher key custody/rotation/revocation,
rollback protection, and release attestations require separate design and approval.
Never reuse external shutdown HMAC keys for publication.

## Offline checks

With the reviewed development dependencies installed, from the repository root:

```sh
python -m pytest -q tests/test_safety_registry.py tests/test_public_site.py
python -m unittest discover -s tests -p 'test_public_site.py'
```

These checks read local evidence and source without importing the runtime,
collecting OS suites, running workloads, making model calls, or retrieving remote
schema references. They exercise the existing site builder only in temporary
directories and verify its output is still exactly the existing five-file
allowlist. They do not establish runtime or deployment safety.

The `jsonschema` validator is a pinned, advisory-checked development dependency;
no production dependency is added. Strict local reference validation and duplicate
JSON-key rejection are part of the offline tests, not a deployed consumer API.

## Voluntary adoption

A developer's independently trusted operator must:

1. Retrieve a pinned, reviewed release through an approved channel without
   opening governed-workload egress. Treat all text and references as untrusted.
2. Verify integrity/provenance, applicability, and compatibility; never execute
   registry text, automatically fetch references, or treat a record as a grant.
3. Independently reproduce relevant positive and negative tests on an approved
   isolated host with synthetic inputs. Verify actual isolation and shutdown
   cancellation independently of worker self-report and destination reachability.
4. Integrate only with separately administered enforcement, preserving default-deny
   model egress, encrypted storage, authentication/authorization and tenant
   boundaries, human approvals, auditability, external shutdown, and Linux isolation.
5. Require independent human approval for adoption, updates, and rollback. Keep
   the agent unable to change these requirements. Stop on missing prerequisites
   instead of weakening safeguards; do not roll back to known affected versions.

This specimen alone is insufficient for production adoption. Retrieval does not
imply that ChatGPT, Grok, or any other model ingests, adopts, or enforces content.
There is no universal AI compatibility or autonomous-protection claim.

## Failure feedback

1. Treat outside submissions and attachments as untrusted. Human-triage reports;
   use private handling for sensitive details, never public credentials or logs.
2. Sanitize evidence and reproduce only with separate approval in isolated,
   synthetic conditions. Do not automatically execute attachments or follow URLs.
3. Retain original evidence under appropriate access controls. Label unverified,
   hypothetical, and unreproduced findings honestly.
4. Develop a mitigation and regression tests, including attempts to interfere
   with independent enforcement. A tested mitigation needs linked evidence.
5. Obtain independent human review and publish only through a separately approved
   release process. No automatic merge, deployment, or promotion of outside claims.
6. Create a new immutable version, identify affected versions and supersession,
   and preserve historical failures, results, limitations, and reproduction status.

## Deferred discovery and publication gates

A later controlled cutover could provide linked HTML at `/safety/`, a static
`/safety/v1/index.json`, and versioned JSON releases, with appropriate content
types and sitemap links. Optional GET-only evidence/safeguard APIs are future
possibilities, not implemented endpoints. Indexability guarantees neither indexing
nor model adoption. No runtime-control or public submission endpoint is needed.

Before any publication, a maintainer must reverify the legacy Pages exposure
inventory, actual Pages source, branch protection, independent environment
approval, and administrator-bypass settings documented in
`docs/public_website_foundation.md`. Legacy root publishing may expose repository
files on a main push even though the allowlisted builder excludes them.
Do not merge or publish this specimen under that configuration. Keep the current
website and domain unchanged until separately approved controlled cutover.
