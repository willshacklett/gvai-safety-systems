from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
import logging
import math
import os
import secrets
import signal
import stat
import sys
import threading
import time
from typing import Any, Callable

from gvai.commercial_api_keys import CustomerApiKeys
from gvai.commercial_http import PrivateHttpEndpoints, create_server
from gvai.commercial_identity import CommercialCapability
from gvai.commercial_reservation_authority import AuthorityIdentity
from gvai.commercial_service import CommercialEvaluationService
from gvai.postgresql_advisory import (
    AdvisoryAccountingUnavailable, AdvisoryPilotUsage, PostgreSQLAdvisoryUsage, PostgreSQLCustomerStore,
)


LOG = logging.getLogger(__name__)
MAX_CONFIG_BYTES = 16_384
ENTRY_FUNCTIONS = (
    "reserve_advisory_v1(text,bytea,text,bigint,text,text,text,text)",
    "complete_advisory_v1(text,bytea,text,text,boolean)",
    "advisory_usage_v1(text,bytea,text)",
)


class StagingUnavailable(RuntimeError):
    """Fixed, redacted operational failure; never includes database inputs."""


def _failure(event: str) -> StagingUnavailable:
    LOG.warning("private_staging: %s", event)
    return StagingUnavailable("Private staging operation unavailable; operator reconciliation required.")


class _ConnectionLease:
    def __init__(self, connection: Any, release: Callable[[], None]) -> None:
        self._connection = connection
        self._release = release
        self._closed = False

    @property
    def autocommit(self) -> bool:
        return self._connection.autocommit

    @autocommit.setter
    def autocommit(self, value: bool) -> None:
        self._connection.autocommit = value

    def cursor(self) -> Any:
        return self._connection.cursor()

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def __enter__(self) -> _ConnectionLease:
        return self

    def __exit__(self, kind: Any, value: Any, traceback: Any) -> None:
        try:
            if kind is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._connection.close()
            except Exception:
                raise _failure("connection_close_failed") from None
            finally:
                self._release()


class BoundedConnections:
    """Capped short-lived connections, not a reconnecting/retrying pool."""

    def __init__(
        self, connect: Callable[[], Any], *, maximum: int = 8, checkout_timeout: float = 0.1,
    ) -> None:
        if not callable(connect) or type(maximum) is not int or not 1 <= maximum <= 32:
            raise ValueError("Invalid connection bound.")
        if (
            type(checkout_timeout) not in (int, float)
            or not math.isfinite(checkout_timeout) or not 0 < checkout_timeout <= 5
        ):
            raise ValueError("Invalid checkout timeout.")
        self._connect = connect
        self._maximum = maximum
        self._timeout = checkout_timeout
        self._condition = threading.Condition()
        self._active = 0
        self._closed = False

    def __call__(self) -> _ConnectionLease:
        deadline = time.monotonic() + self._timeout
        with self._condition:
            while self._active >= self._maximum and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _failure("connection_capacity_exhausted")
                self._condition.wait(remaining)
            if self._closed:
                raise _failure("connections_stopping")
            self._active += 1
        try:
            connection = self._connect()
        except Exception:
            self._release()
            raise _failure("connection_open_failed") from None
        return _ConnectionLease(connection, self._release)

    def _release(self) -> None:
        with self._condition:
            self._active -= 1
            self._condition.notify_all()

    def stop_accepting(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    def shutdown(self, timeout: float = 10) -> None:
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= 60:
            raise ValueError("Invalid shutdown timeout.")
        deadline = time.monotonic() + timeout
        self.stop_accepting()
        with self._condition:
            while self._active:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _failure("connection_drain_timeout")
                self._condition.wait(remaining)


def read_private_json(path: str) -> dict[str, Any]:
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_size > MAX_CONFIG_BYTES
        ):
            raise ValueError
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError
        from gvai.commercial_http import _reject_json_constant, _unique_object
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_json_constant)
        if type(result) is not dict:
            raise ValueError
        return result
    except Exception:
        raise _failure("private_configuration_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _database_connect(dsn: str) -> Callable[[], Any]:
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        parameters = conninfo_to_dict(dsn)
        if (
            parameters.get("host") != "127.0.0.1"
            or parameters.get("hostaddr", "127.0.0.1") != "127.0.0.1"
            or not parameters.get("dbname") or not parameters.get("user")
            or not parameters.get("password")
            or any(name in parameters for name in (
                "service", "passfile", "options", "sslpassword", "sslkey",
            ))
        ):
            raise ValueError
    except Exception:
        raise _failure("database_configuration_invalid") from None

    def connect() -> Any:
        return psycopg.connect(
            dsn, connect_timeout=3,
            options="-c statement_timeout=5000 -c lock_timeout=3000 "
                    "-c idle_in_transaction_session_timeout=5000",
        )
    return connect


@dataclass(frozen=True, repr=False)
class StagingConfig:
    database_dsn: str = field(repr=False)
    verifier_secret: bytes = field(repr=False)
    authority: AuthorityIdentity
    port: int = 8080
    max_connections: int = 8

    @classmethod
    def load(cls, path: str) -> StagingConfig:
        try:
            data = read_private_json(path)
            if (
                set(data) != {"mode", "database_dsn", "verifier_secret_hex", "authority", "port", "max_connections"}
                or data["mode"] != "private-staging"
                or type(data["database_dsn"]) is not str
                or type(data["port"]) is not int or not 0 <= data["port"] <= 65535
                or type(data["max_connections"]) is not int or not 1 <= data["max_connections"] <= 32
                or type(data["authority"]) is not dict
                or set(data["authority"]) != {"authority_id", "epoch", "trust_domain"}
            ):
                raise ValueError
            secret = bytes.fromhex(data["verifier_secret_hex"])
            if len(secret) != 32:
                raise ValueError
            return cls(
                data["database_dsn"], secret, AuthorityIdentity(**data["authority"]),
                data["port"], data["max_connections"],
            )
        except Exception:
            raise _failure("runtime_configuration_invalid") from None


def verify_database_role(factory: BoundedConnections, *, operator: bool = False) -> None:
    """Reject privileged runtime identities and unreviewed authority access."""
    with factory() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT role.rolsuper,role.rolcreatedb,role.rolcreaterole,role.rolbypassrls,"
            "role.rolreplication,owner.rolname,owner.rolsuper,"
            "pg_has_role(current_user,owner.oid,'MEMBER'),current_user=owner.rolname "
            "FROM pg_roles role CROSS JOIN pg_namespace namespace "
            "JOIN pg_roles owner ON owner.oid=namespace.nspowner "
            "WHERE role.rolname=current_user AND namespace.nspname='gvai_authority'"
        )
        row = cursor.fetchone()
        if (
            row is None or any(row[:5]) or row[6]
            or (not row[8] if operator else row[7])
        ):
            raise _failure("database_role_rejected")
        if operator:
            return
        cursor.execute(
            "SELECT has_schema_privilege(current_user,'gvai_authority','USAGE'),"
            "has_schema_privilege(current_user,'gvai_authority','CREATE'),"
            "has_database_privilege(current_user,current_database(),'CREATE')"
        )
        if cursor.fetchone() != (True, False, False):
            raise _failure("runtime_schema_privileges_rejected")
        cursor.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_class relation JOIN pg_namespace namespace "
            "ON namespace.oid=relation.relnamespace WHERE namespace.nspname='gvai_authority' "
            "AND ((relation.relkind IN ('r','p','v','m','f') AND "
            "(has_table_privilege(current_user,relation.oid,"
            "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR "
            "has_any_column_privilege(current_user,relation.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) "
            "OR (relation.relkind='S' AND "
            "has_sequence_privilege(current_user,relation.oid,'USAGE,SELECT,UPDATE'))))"
        )
        if cursor.fetchone() != (False,):
            raise _failure("runtime_table_privileges_rejected")
        for signature in ENTRY_FUNCTIONS:
            cursor.execute(
                "SELECT routine.prosecdef, routine.proconfig, "
                "has_function_privilege(current_user,routine.oid,'EXECUTE'),"
                "routine.proowner=namespace.nspowner "
                "FROM pg_proc routine JOIN pg_namespace namespace ON namespace.oid=routine.pronamespace "
                "WHERE routine.oid=to_regprocedure(%s)", ("gvai_authority." + signature,),
            )
            row = cursor.fetchone()
            if row != (True, ["search_path=pg_catalog, gvai_authority, pg_temp"], True, True):
                raise _failure("runtime_entry_contract_rejected")
        cursor.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_proc routine JOIN pg_namespace namespace "
            "ON namespace.oid=routine.pronamespace WHERE namespace.nspname='gvai_authority' "
            "AND has_function_privilege(current_user,routine.oid,'EXECUTE') "
            "AND NOT EXISTS (SELECT 1 FROM pg_depend dependency "
            "JOIN pg_extension extension ON extension.oid=dependency.refobjid "
            "WHERE dependency.classid='pg_proc'::regclass AND dependency.objid=routine.oid "
            "AND dependency.refclassid='pg_extension'::regclass "
            "AND dependency.deptype='e' AND extension.extname='pgcrypto') "
            "AND routine.oid <> ALL(%s::regprocedure[]))",
            (["gvai_authority." + name for name in ENTRY_FUNCTIONS],),
        )
        if cursor.fetchone() != (False,):
            raise _failure("runtime_function_privileges_rejected")


class PrivateStagingApplication:
    def __init__(self, config: StagingConfig) -> None:
        self._running = threading.Event()
        self.connections = BoundedConnections(
            _database_connect(config.database_dsn), maximum=config.max_connections,
        )
        try:
            verify_database_role(self.connections)
            self.usage = PostgreSQLAdvisoryUsage(
                self.connections, authority=config.authority,
                credential_verifier_secret=config.verifier_secret,
            )
            service = CommercialEvaluationService(self.usage)
            self.server = create_server(
                service, port=config.port,
                private_endpoints=PrivateHttpEndpoints(self.summary, self.ready),
            )
        except Exception:
            self.connections.shutdown()
            raise _failure("startup_failed") from None
        self._thread: threading.Thread | None = None
        self._stopped = False

    def ready(self) -> bool:
        if not self._running.is_set():
            return False
        try:
            verify_database_role(self.connections)
            return True
        except Exception:
            LOG.warning("private_staging: readiness_unavailable")
            return False

    def summary(self, credential: str, resource: str) -> AdvisoryPilotUsage | None:
        if not self._running.is_set():
            raise AdvisoryAccountingUnavailable("Private staging is stopping.")
        return self.usage.summary(credential, resource)

    def start(self) -> None:
        if self._thread is not None or self._stopped:
            raise ValueError("Private staging cannot be restarted.")
        self._running.set()
        self._thread = threading.Thread(target=self.server.serve_forever, name="gvai-private-http")
        try:
            self._thread.start()
        except Exception:
            self._running.clear()
            self.server.server_close()
            self.connections.shutdown()
            raise _failure("server_start_failed") from None

    def stop(self) -> None:
        self._stopped = True
        self._running.clear()
        self.connections.stop_accepting()
        try:
            if self._thread is not None:
                self.server.shutdown()
                self._thread.join(timeout=2)
            self.server.server_close()
        finally:
            self.connections.shutdown()


def _operator(config_path: str, command: str, *, output: str | None, target: str | None) -> None:
    data = read_private_json(config_path)
    if (
        set(data) != {"mode", "operator_database_dsn", "verifier_secret_hex", "pilot_units", "pilot_seconds"}
        or data["mode"] != "private-staging-operator"
        or type(data["operator_database_dsn"]) is not str
        or type(data["pilot_units"]) is not int or not 1 <= data["pilot_units"] <= 1000
        or type(data["pilot_seconds"]) is not int or not 60 <= data["pilot_seconds"] <= 30 * 86400
    ):
        raise _failure("operator_configuration_invalid")
    try:
        secret = bytes.fromhex(data["verifier_secret_hex"])
        if len(secret) != 32:
            raise ValueError
    except Exception:
        raise _failure("operator_verifier_invalid") from None
    connections = BoundedConnections(_database_connect(data["operator_database_dsn"]), maximum=1)
    try:
        verify_database_role(connections, operator=True)
        store = PostgreSQLCustomerStore(connections)
        if command == "suspend":
            if not store.suspend_tenant(target):
                raise _failure("tenant_suspension_not_confirmed")
        elif command == "revoke":
            if not CustomerApiKeys(store, verifier_secret=secret).revoke(target):
                raise _failure("key_revocation_not_confirmed")
        elif command == "provision" and output is not None:
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "w", encoding="ascii") as stream:
                suffix = secrets.token_hex(16)
                tenant, principal, project = "tenant-" + suffix, "principal-" + suffix, "project-" + suffix
                now = int(time.time())
                expiry = now + data["pilot_seconds"]
                store.provision_pilot(
                    tenant_id=tenant, principal_id=principal, resource_id=project,
                    allowance=data["pilot_units"], starts_at=now, expires_at=expiry,
                )
                issued = CustomerApiKeys(store, verifier_secret=secret).issue(
                    tenant_id=tenant, principal_id=principal,
                    capabilities=frozenset(CommercialCapability), expires_at=expiry,
                )
                credential = issued.take_secret()
                if credential is None:
                    raise _failure("key_handoff_unavailable")
                json.dump({
                    "tenant_id": tenant, "principal_id": principal, "resource_id": project,
                    "key_id": issued.key_id, "credential": credential, "expires_at": expiry,
                }, stream, ensure_ascii=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
        else:
            raise _failure("operator_command_invalid")
    finally:
        connections.shutdown()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Loopback-only advisory private staging; no execution enforcement.")
    parser.add_argument("--config", required=True, help="Owner-only JSON configuration file.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("serve")
    provision = commands.add_parser("provision")
    provision.add_argument("--key-output", required=True, help="New owner-only one-time handoff file.")
    commands.add_parser("suspend").add_argument("--tenant", required=True)
    commands.add_parser("revoke").add_argument("--key-id", required=True)
    args = parser.parse_args(argv)
    application = None
    previous_handlers = {}
    status = 0
    try:
        if args.command != "serve":
            _operator(
                args.config, args.command, output=getattr(args, "key_output", None),
                target=getattr(args, "tenant", getattr(args, "key_id", None)),
            )
            print("Operator operation acknowledged; no secrets printed.")
        else:
            config = StagingConfig.load(args.config)
            application = PrivateStagingApplication(config)
            stopped = threading.Event()
            for number in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[number] = signal.signal(number, lambda *_args: stopped.set())
            application.start()
            LOG.warning("private_staging: started_loopback_advisory_only")
            stopped.wait()
    except Exception:
        LOG.error("private_staging: operation_failed_reconcile_before_retry")
        print("Private staging failed; reconcile before retry. No details disclosed.", file=sys.stderr)
        status = 1
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)
        if application is not None:
            try:
                application.stop()
            except Exception:
                LOG.error("private_staging: shutdown_failed")
                status = 1
    return status


if __name__ == "__main__":
    raise SystemExit(main())
