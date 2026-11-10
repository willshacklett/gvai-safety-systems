# Paid Checkout persistence foundation

Based on commercial commit `0be658ce59662a53c9eee81edcdcb7646af37315`.
The preserved Checkout snapshot `1bb3e45f3001049e1e7827841db4f6cf6e434059`
informs immutable requests, tenant serialization and full-record fences.
The entitlement reference `3cc244819ba68a7c273481d77bad22e74f0131b7`
is not imported. There is no second entitlement authority.

## Installation boundary

The explicit [manifest](../migrations/postgresql/paid_checkout_manifest_v1.json)
orders 001, 002, 003, baseline 004, then 007. Never glob SQL files.
Migrations 001-004 are unchanged. Alternate subscription 004 and its dependent
005-006 are excluded. Mixed schemas and unexpected default Checkout ACLs fail
transactionally; they are not repaired. Migration-time administration must
separately verify the baseline file hashes and trusted schema ownership.

007 creates three new tables and five functions. It does not update billing,
pilot, paid-period, quota, key, reservation or authority rows. Installation
requires the existing non-superuser, non-BYPASSRLS schema owner. No roles or
application grants are created. No production installation is authorized.

## Deny-by-default persistence

No installation or worker bindings are seeded. A separately controlled owner
may provision an immutable sandbox account and USD 9900 monthly quantity-one
offer with pinned HTTPS return paths. Worker bindings default disabled and
derive one tenant/membership from the actual PostgreSQL `session_user`, not
caller claims or `SET ROLE`. Dedicated internal logins must have no schema-owner
membership, elevated role flags, table access or schema creation rights.

For disposable tests only, grant schema USAGE plus exact EXECUTE on:

- `prepare_paid_checkout_v1(text,bytea)`
- `read_paid_checkout_v1(text)`
- `block_paid_checkout_v1(text,jsonb,text)`

The private scope helper and trigger function are not runtime entrypoints.
The reader is restricted to that login's tenant and membership. These are not
customer HTTP routes or authentication adapters.

Request bytes must equal PostgreSQL's UTF-8 `jsonb::text` representation of the
exact server-owned version-one binding object. This is a new persistence format,
not the preserved model's JSON encoding or Stripe wire encoding. Unknown keys,
alternate bytes, offer/account/customer/tenant substitution and changed replay
are rejected. JSONB canonical byte equality also rejects duplicate input keys.

One retained request per tenant serializes unresolved purchases across logins.
Exact replay returns the existing record without resetting it. The complete
returned JSON record is required as the expected fence for deny-only transitions:
`prepared -> unknown -> quarantined`, or `prepared -> quarantined`.
No state can leave unknown except for further quarantine; quarantine is terminal.
There is deliberately no closure, deletion, dispatch claim or slot-release API.

`admission_enabled` is constrained false. Prepared persistence is not purchase
admission. No function can create a session, enable admission, issue a key, grant
paid access or change existing paid authorization. Existing pilot history may
remain; revoked billing, an existing subscription, or any legacy Checkout marker
blocks new preparation pending separately authorized reconciliation.

The Python adapter returns only after acknowledged commit. Commit exceptions
raise `CheckoutCommitUnknown`, even if the database committed. A fresh explicit
read may establish stored state, never dispatch authority or automatic recovery.
It does not retry, allocate another attempt or expose database diagnostics.

## Validation and limitations

Use the separately verified Python environment, synthetic credentials and the
cached PostgreSQL image digest; no downloads or production DSNs are accepted:

```sh
GVAI_RUN_PAID_CHECKOUT_POSTGRES=1 PYTHONDONTWRITEBYTECODE=1 \
  /tmp/APPROVED_ENV/venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_paid_checkout_persistence.py
```

The test fixture publishes only a random loopback PostgreSQL port and uses tmpfs
data, a pinned cached image and separately authenticated restricted logins.
Commit acknowledgement loss is injected around real commits/rollbacks; this is
not proof of actual network partition behavior. There is no Stripe API, runtime
integration, migration runner, live-mode support or deployment configuration.
Completing verified closure, dispatch and billing handoff requires a later review.
