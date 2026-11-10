"""Local owner-only billing CLI; never expose these operations as customer routes."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import threading

from gvai.billing_reconciler import BoundedStripe, Reconciler, ReconcilerSettings
from gvai.commercial_http import create_webhook_server
from gvai.postgresql_billing import (
    PAID_ENTRY_FUNCTIONS, RECONCILER_ENTRY_FUNCTIONS, PostgreSQLBillingStore, PostgreSQLPaidUsage,
    PostgreSQLReconcilerStore,
)
from gvai.private_staging import (
    BoundedConnections, PrivateStagingApplication, StagingConfig, _database_connect,
    read_private_json, verify_database_role,
)
from gvai.stripe_billing import BillingConfig, BillingService, StripeREST, SubscriptionAuthority, fail


LOG = logging.getLogger(__name__)
RECONCILER_COMMANDS = frozenset({"reconcile-serve", "webhooks", "status"})


def _billing_connect(dsn):
    base = _database_connect(dsn)

    def connect():
        connection = base()
        try:
            # No provider request is made inside a transaction; abandoned ones are reaped quickly.
            connection.execute("SET idle_in_transaction_session_timeout='10s'")
            connection.commit()
        except Exception:
            connection.close()
            raise fail("billing_connection_configuration_failed") from None
        return connection
    return connect


def _handoff(path: str, url: str) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        json.dump({"url": url}, stream, ensure_ascii=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test-mode operator-only Stripe billing.")
    parser.add_argument("--config", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    bind = commands.add_parser("bind")
    bind.add_argument("--tenant", required=True)
    bind.add_argument("--customer", required=True, help="Pre-created TEST customer ID.")
    for name in ("checkout", "portal"):
        command = commands.add_parser(name)
        command.add_argument("--tenant", required=True)
        command.add_argument("--output", required=True, help="New owner-only URL handoff file.")
    for name in ("reconcile", "revoke", "resume"):
        commands.add_parser(name).add_argument("--tenant", required=True)
    commands.add_parser("webhooks").add_argument("--port", type=int, default=8081)
    commands.add_parser("reconcile-serve")
    commands.add_parser("status")
    commands.add_parser("serve-paid")
    args = parser.parse_args(argv)
    connections = None
    application = server = None
    previous = {}
    try:
        if args.command == "serve-paid":
            application = PrivateStagingApplication(
                StagingConfig.load(args.config), usage_factory=PostgreSQLPaidUsage,
                entry_functions=PAID_ENTRY_FUNCTIONS,
            )
            application.start()
        elif args.command in RECONCILER_COMMANDS:
            data = read_private_json(args.config)
            required = {"mode", "reconciler_database_dsn", "stripe"}
            if (
                not required <= set(data) or not set(data) <= required | {"heartbeat_path", "workers", "rate_per_second"}
                or data["mode"] != "stripe-test-reconciler"
            ):
                raise fail("reconciler_configuration_rejected")
            config = BillingConfig(**data["stripe"])
            connections = BoundedConnections(_billing_connect(data["reconciler_database_dsn"]), maximum=8)
            verify_database_role(connections, operator=False, entry_functions=RECONCILER_ENTRY_FUNCTIONS)
            store = PostgreSQLReconcilerStore(connections)
            bounded = BoundedStripe(StripeREST(config), rate_per_second=float(data.get("rate_per_second", 10)))
            authority = SubscriptionAuthority(bounded, config)
            if args.command == "status":
                print(json.dumps(store.status(), sort_keys=True))
            elif args.command == "webhooks":
                server = create_webhook_server(BillingService(authority, store).webhook, args.port)
            else:
                settings = ReconcilerSettings(workers=int(data.get("workers", 4)))
                reconciler = Reconciler(store, authority, bounded, settings, heartbeat_path=data.get("heartbeat_path"))
                stopped = threading.Event()
                for number in (signal.SIGINT, signal.SIGTERM):
                    previous[number] = signal.signal(number, lambda *_args: stopped.set())
                reconciler.serve(stopped)
        else:
            data = read_private_json(args.config)
            if set(data) != {"mode", "operator_database_dsn", "stripe"} or data["mode"] != "stripe-test-operator":
                raise fail("operator_configuration_rejected")
            config = BillingConfig(**data["stripe"])
            connections = BoundedConnections(_billing_connect(data["operator_database_dsn"]), maximum=2)
            verify_database_role(connections, operator=True)
            store = PostgreSQLBillingStore(connections)
            service = BillingService(SubscriptionAuthority(StripeREST(config), config), store)
            if args.command == "bind":
                service.bind(args.tenant, args.customer)
            elif args.command in {"checkout", "portal"}:
                url = getattr(service, args.command)(args.tenant)
                _handoff(args.output, url)
            elif args.command == "reconcile":
                service.reconcile(args.tenant)
            elif args.command == "revoke":
                store.revoke(args.tenant)
            elif args.command == "resume":
                if not store.resume(args.tenant):
                    raise fail("resume_not_applicable")
            else:
                raise fail("command_rejected")
        if args.command == "reconcile-serve":
            pass
        elif server is not None or application is not None:
            stopped = threading.Event()
            for number in (signal.SIGINT, signal.SIGTERM):
                previous[number] = signal.signal(number, lambda *_args: stopped.set())
            if server is not None:
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
            stopped.wait()
        else:
            if args.command != "status":
                print("Billing operation acknowledged; no secrets printed.")
        return 0
    except Exception:
        LOG.error("stripe_billing: operation_failed_reconcile")
        return 1
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        if application is not None:
            application.stop()
        if connections is not None:
            connections.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
