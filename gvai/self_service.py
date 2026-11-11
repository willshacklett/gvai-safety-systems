"""Test-mode self-service slice: signup, Checkout handoff and single-use API-key claim.

Owner-privileged and Stripe-secret-holding: run it only as a separate loopback
process, never inside the evaluation runtime. Advisory only; it neither
activates live billing nor enforces anything on a customer workload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import threading
import time
from collections import deque
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Iterator

from gvai.commercial_api_keys import ApiKeyRecord, CustomerApiKeys
from gvai.commercial_http import (
    _BoundedHeaderReader, _DeadlineReader, _LocalThreadingHTTPServer,
    MAX_HEADER_BYTES, MAX_HEADER_COUNT,
)
from gvai.commercial_identity import CommercialCapability
from gvai.stripe_billing import BillingService, BillingUnavailable, StripeAPI, fail, identifier


LOG = logging.getLogger(__name__)
ACCOUNT_PREFIX = "gvai_acct_v1_"
_ACCOUNT_TOKEN = re.compile(re.escape(ACCOUNT_PREFIX) + r"[0-9a-f]{64}\Z")
_DOMAIN = b"gvai-account-token-v1\x00"
KEY_TTL_SECONDS = 365 * 86_400
_CAPABILITIES = frozenset(CommercialCapability)


class SelfServiceError(Exception):
    """Fixed-code failure; the message never carries tokens, keys or database detail."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@contextmanager
def _transaction(connect: Callable[[], Any]) -> Iterator[Any]:
    try:
        with connect() as connection, connection.cursor() as cursor:
            yield cursor
    except SelfServiceError:
        raise
    except Exception:
        LOG.warning("self_service: database_operation_uncertain")
        raise SelfServiceError("unavailable") from None


class _TransactionKeyStore:
    """Inserts the hashed credential inside the claim transaction, never separately."""

    def __init__(self, cursor: Any) -> None:
        self._cursor = cursor

    def insert_if_absent(self, record: ApiKeyRecord) -> bool:
        from datetime import datetime, timezone

        self._cursor.execute(
            "INSERT INTO gvai_authority.customer_credentials "
            "(key_id,tenant_ref,membership_ref,credential_verifier,capabilities,status,created_at,expires_at) "
            "SELECT %s,t.tenant_ref,m.membership_ref,%s,%s,'active',%s,%s "
            "FROM gvai_authority.tenants t JOIN gvai_authority.tenant_memberships m "
            "ON m.tenant_ref=t.tenant_ref WHERE t.tenant_id=%s AND m.principal_id=%s "
            "AND t.status='active' AND m.status='active' "
            "ON CONFLICT (key_id) DO NOTHING RETURNING key_id",
            (record.key_id, record.verifier, sorted(grant.value for grant in record.capabilities),
             datetime.fromtimestamp(record.created_at, timezone.utc),
             datetime.fromtimestamp(record.expires_at, timezone.utc),
             record.tenant_id, record.principal_id),
        )
        return self._cursor.fetchone() is not None

    def lookup(self, key_id: str) -> None:
        raise NotImplementedError

    def revoke(self, key_id: str) -> bool:
        raise NotImplementedError


class PostgreSQLSelfServiceStore:
    """Owner-role adapter. Only the keyed token verifier and key verifier are persisted."""

    def __init__(self, connect: Callable[[], Any], *, verifier_secret: bytes) -> None:
        if type(verifier_secret) is not bytes or len(verifier_secret) < 32:
            raise ValueError("A pinned verifier secret is required.")
        self._connect, self._secret = connect, verifier_secret
        self.require_ready()

    def require_ready(self) -> None:
        with _transaction(self._connect) as cursor:
            cursor.execute("SELECT gvai_authority.billing_integrity_ready_v12()")
            if cursor.fetchone() != (True,):
                raise SelfServiceError("unavailable")

    def token_verifier(self, token: object) -> bytes | None:
        if type(token) is not str or _ACCOUNT_TOKEN.fullmatch(token) is None:
            return None
        return hmac.new(self._secret, _DOMAIN + token.encode("ascii"), hashlib.sha256).digest()

    def create_account(
        self, *, tenant: str, principal: str, resource: str, customer: str, verifier: bytes,
    ) -> None:
        identifier(customer, "cus_")
        self.require_ready()
        with _transaction(self._connect) as cursor:
            cursor.execute(
                "INSERT INTO gvai_authority.tenants(tenant_id,status) VALUES(%s,'active') RETURNING tenant_ref",
                (tenant,),
            )
            ref = cursor.fetchone()[0]
            cursor.execute(
                "INSERT INTO gvai_authority.tenant_memberships(tenant_ref,principal_id,status) "
                "VALUES(%s,%s,'active')", (ref, principal),
            )
            cursor.execute(
                "INSERT INTO gvai_authority.resource_ownerships"
                "(tenant_ref,resource_id,ownership_version,resource_kind,status) "
                "VALUES(%s,%s,1,'evaluation','active')", (ref, resource),
            )
            cursor.execute(
                "INSERT INTO gvai_authority.billing_customers(tenant_ref,customer_id) VALUES(%s,%s)",
                (ref, customer),
            )
            cursor.execute(
                "INSERT INTO gvai_authority.customer_accounts(tenant_ref,token_verifier) VALUES(%s,%s)",
                (ref, verifier),
            )

    def tenant(self, verifier: bytes) -> str | None:
        with _transaction(self._connect) as cursor:
            cursor.execute(
                "SELECT t.tenant_id FROM gvai_authority.customer_accounts a "
                "JOIN gvai_authority.tenants t ON t.tenant_ref=a.tenant_ref "
                "WHERE a.token_verifier=%s AND a.status='active' AND t.status='active'",
                (verifier,),
            )
            row = cursor.fetchone()
        return None if row is None else row[0]

    def status(self, verifier: bytes) -> dict[str, Any] | None:
        with _transaction(self._connect) as cursor:
            cursor.execute(
                "SELECT b.tenant_ref,o.resource_id,a.key_id IS NOT NULL "
                "FROM gvai_authority.customer_accounts a "
                "JOIN gvai_authority.tenants t USING(tenant_ref) "
                "JOIN gvai_authority.billing_customers b USING(tenant_ref) "
                "JOIN gvai_authority.resource_ownerships o ON o.tenant_ref=a.tenant_ref AND o.status='active' "
                "WHERE a.token_verifier=%s AND a.status='active' AND t.status='active' "
                "AND EXISTS (SELECT 1 FROM gvai_authority.tenant_memberships m WHERE m.tenant_ref=a.tenant_ref AND m.status='active') "
                "FOR SHARE OF b", (verifier,),
            )
            row=cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                "SELECT gvai_authority.billing_entitlement_state_v12(tenant_ref),"
                "CASE WHEN access_until>clock_timestamp() THEN extract(epoch FROM access_until)::bigint END FROM gvai_authority.billing_customers WHERE tenant_ref=%s",
                (row[0],),
            )
            state,access=cursor.fetchone()
            if state == "unavailable":
                raise SelfServiceError("unavailable")
        result={"resource_id":row[1],"entitled":state=="active","entitlement_state":state,"api_key_claimed":bool(row[2])}
        if state in ("active","verification_pending"):
            result["access_until"]=int(access)
        return result

    def claim_key(self, verifier: bytes, *, ttl_seconds: int = KEY_TTL_SECONDS) -> str:
        """Issue the only API key for a paid account; plaintext exists only in the return value."""
        issued = None
        with _transaction(self._connect) as cursor:
            cursor.execute(
                "SELECT tenant_ref,key_id FROM gvai_authority.customer_accounts "
                "WHERE token_verifier=%s AND status='active' FOR UPDATE", (verifier,),
            )
            account = cursor.fetchone()
            if account is None:
                raise SelfServiceError("invalid_account")
            cursor.execute(
                "SELECT t.tenant_id,m.principal_id,b.tenant_ref "
                "FROM gvai_authority.billing_customers b "
                "JOIN gvai_authority.tenants t ON t.tenant_ref=b.tenant_ref "
                "JOIN gvai_authority.tenant_memberships m ON m.tenant_ref=b.tenant_ref "
                "WHERE b.tenant_ref=%s AND t.status='active' AND m.status='active' "
                "FOR UPDATE OF t,b", (account[0],),
            )
            owner = cursor.fetchone()
            if owner is None:
                raise SelfServiceError("payment_required")
            cursor.execute("SELECT gvai_authority.billing_entitlement_state_v12(%s)", (owner[2],))
            state=cursor.fetchone()[0]
            if state == "unavailable":
                raise SelfServiceError("unavailable")
            if state != "active":
                raise SelfServiceError("payment_required")
            if account[1] is not None:
                raise SelfServiceError("already_claimed")
            keys = CustomerApiKeys(_TransactionKeyStore(cursor), verifier_secret=self._secret)
            issued = keys.issue(
                principal_id=owner[1], tenant_id=owner[0], capabilities=_CAPABILITIES,
                expires_at=int(time.time()) + ttl_seconds,
            )
            cursor.execute(
                "UPDATE gvai_authority.customer_accounts SET key_id=%s,key_claimed_at=clock_timestamp() "
                "WHERE token_verifier=%s AND key_id IS NULL", (issued.key_id, verifier),
            )
            if cursor.rowcount != 1:
                raise SelfServiceError("already_claimed")
        # Reached only after the claim and hashed credential committed together.
        secret = issued.take_secret()
        if secret is None:
            raise SelfServiceError("unavailable")
        return secret


class SelfService:
    def __init__(
        self, store: PostgreSQLSelfServiceStore, billing: BillingService, api: StripeAPI,
        *, signup_limit: int = 10, signup_window: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._store, self._billing, self._api = store, billing, api
        self._limit, self._window, self._clock = signup_limit, signup_window, clock
        self._signups: deque[float] = deque()
        self._lock = threading.Lock()

    def _admit_signup(self) -> None:
        now = self._clock()
        with self._lock:
            while self._signups and now - self._signups[0] >= self._window:
                self._signups.popleft()
            if len(self._signups) >= self._limit:
                raise SelfServiceError("rate_limited")
            self._signups.append(now)

    def signup(self) -> dict[str, str]:
        self._admit_signup()
        self._store.require_ready()
        suffix = secrets.token_hex(16)
        tenant, principal, resource = "tenant-" + suffix, "principal-" + suffix, "project-" + suffix
        token = ACCOUNT_PREFIX + secrets.token_hex(32)
        verifier = self._store.token_verifier(token)
        try:
            customer = self._api.request(
                "POST", "/v1/customers", {"metadata[gvai_tenant]": tenant},
                idempotency_key="gvai_signup_" + suffix,
            )
            if customer.get("object") != "customer" or customer.get("livemode") is not False:
                raise fail("customer_rejected")
            customer_id = identifier(customer.get("id"), "cus_")
        except BillingUnavailable:
            raise SelfServiceError("unavailable") from None
        self._store.create_account(
            tenant=tenant, principal=principal, resource=resource,
            customer=customer_id, verifier=verifier,
        )
        return {"account_token": token, "resource_id": resource}

    def _verifier(self, token: object) -> bytes:
        verifier = self._store.token_verifier(token)
        if verifier is None:
            raise SelfServiceError("invalid_account")
        return verifier

    def checkout(self, token: object) -> str:
        tenant = self._store.tenant(self._verifier(token))
        if tenant is None:
            raise SelfServiceError("invalid_account")
        self._store.require_ready()
        try:
            return self._billing.checkout(tenant)
        except BillingUnavailable:
            raise SelfServiceError("unavailable") from None

    def status(self, token: object) -> dict[str, Any]:
        result = self._store.status(self._verifier(token))
        if result is None:
            raise SelfServiceError("invalid_account")
        return result

    def claim_key(self, token: object) -> str:
        return self._store.claim_key(self._verifier(token))


_ERRORS = {
    "invalid_account": (401, "A valid account credential is required."),
    "payment_required": (402, "An active paid subscription is required."),
    "already_claimed": (409, "The API key for this account has already been issued."),
    "rate_limited": (429, "Too many requests."),
    "unavailable": (503, "Service unavailable."),
}


def create_self_service_server(
    service: SelfService, port: int = 0, *, request_timeout: float = 5.0,
) -> ThreadingHTTPServer:
    """Loopback-only listener; public exposure needs separately reviewed TLS ingress."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("Invalid self-service listener configuration.")
    return _LocalThreadingHTTPServer(("127.0.0.1", port), _handler_for(service), 8, float(request_timeout))


def _handler_for(service: SelfService) -> type[BaseHTTPRequestHandler]:
    class SelfServiceHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "GVAI-Account"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.rfile.close()
            self.connection.settimeout(None)
            self._deadline_reader = _DeadlineReader(
                self.connection, time.monotonic() + self.server.request_timeout,
            )
            self.rfile = self._deadline_reader

        def parse_request(self) -> bool:
            original = self.rfile
            self.rfile = _BoundedHeaderReader(original)
            try:
                parsed = super().parse_request()
            finally:
                self.rfile = original
            if not parsed:
                return False
            items = list(self.headers.raw_items())
            if (
                self.headers.get_all("Expect") or len(items) > MAX_HEADER_COUNT
                or sum(len(n) + len(v) + 4 for n, v in items) > MAX_HEADER_BYTES
            ):
                self._error(400, "invalid_request", "Request headers are not supported.")
                return False
            if "?" in self.path:
                self._error(400, "query_not_allowed", "Query strings are not accepted.")
                return False
            return True

        def handle_expect_100(self) -> bool:
            self._error(417, "expectation_not_supported", "Expect headers are not supported.")
            return False

        def _bearer(self) -> str | None:
            values = self.headers.get_all("Authorization") or []
            if len(values) != 1:
                return None
            scheme, separator, token = values[0].partition(" ")
            if not separator or scheme.lower() != "bearer" or len(token) > 256 or not token or any(c.isspace() for c in token):
                return None
            return token

        def _bodyless(self) -> bool:
            lengths = self.headers.get_all("Content-Length") or ["0"]
            if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1 or lengths[0] != "0":
                self._error(400, "invalid_request", "Request bodies are not supported.")
                return False
            return True

        def _run(self, action: Callable[[], tuple[int, dict[str, Any]]]) -> None:
            try:
                status, body = action()
            except SelfServiceError as error:
                status, message = _ERRORS[error.code] if error.code in _ERRORS else _ERRORS["unavailable"]
                self._error(status, error.code if error.code in _ERRORS else "unavailable", message)
                return
            except Exception:
                LOG.warning("self_service: request_failed")
                self._error(503, "unavailable", _ERRORS["unavailable"][1])
                return
            self._send(status, body)

        def _authenticated(self, action: Callable[[str], tuple[int, dict[str, Any]]]) -> None:
            if not self._bodyless():
                return
            token = self._bearer()
            if token is None:
                self._error(401, "invalid_account", _ERRORS["invalid_account"][1])
                return
            self._run(lambda: action(token))

        def do_POST(self) -> None:
            if self.path == "/v1/signup":
                if self._bodyless():
                    self._run(lambda: (201, {**service.signup(), "advisory_only": True}))
            elif self.path == "/v1/account/checkout":
                self._authenticated(lambda token: (200, {"checkout_url": service.checkout(token)}))
            elif self.path == "/v1/account/api-key":
                self._authenticated(lambda token: (201, {
                    "api_key": service.claim_key(token), "advisory_only": True,
                    "enforcement_applied": False,
                }))
            else:
                self._error(404, "not_found", "Endpoint not found.")

        def do_GET(self) -> None:
            if self.path == "/v1/account":
                self._authenticated(lambda token: (200, service.status(token)))
            else:
                self._error(404, "not_found", "Endpoint not found.")

        def _method_not_allowed(self) -> None:
            self._error(405, "method_not_allowed", "Method not allowed.")

        do_HEAD = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = _method_not_allowed

        def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
            self._error(code if code in (414, 431) else 400, "invalid_http_request", "HTTP request is invalid.")

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _error(self, status: int, code: str, message: str) -> None:
            self._send(status, {"error": {"code": code, "message": message}})

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            self._deadline_reader.prepare_write()
            body = json.dumps(payload, allow_nan=False, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            if getattr(self, "command", None) != "HEAD":
                self.wfile.write(body)

    return SelfServiceHandler
