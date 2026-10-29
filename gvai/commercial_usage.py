from __future__ import annotations

import hashlib
import math
import os
import sqlite3
import stat
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Protocol

from gvai.commercial_identity import (
    CommercialAuthorizer,
    CommercialCapability,
    _valid_customer_tenant,
    _valid_identifier,
)


MAX_EVALUATION_UNITS = (1 << 63) - 1


class UsageReason(str, Enum):
    RESERVED = "reserved"
    REPLAY = "replay"
    COMPLETED = "completed"
    FAILED = "failed"
    SUMMARY = "summary"
    UNAUTHORIZED = "unauthorized"
    INVALID_INPUT = "invalid_input"
    POLICY_MISSING = "policy_missing"
    QUOTA_EXHAUSTED = "quota_exhausted"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    CLOCK_ROLLBACK = "clock_rollback"
    ACCOUNTING_ERROR = "accounting_error"


class ReservationState(str, Enum):
    RESERVED = "reserved"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class UsageReservation:
    period: str
    resource_digest: str
    state: ReservationState = ReservationState.RESERVED


@dataclass(frozen=True)
class UsageSummary:
    period: str
    allowance: int
    consumed: int
    remaining: int
    reserved: int
    completed: int
    failed: int


@dataclass(frozen=True)
class UsageResult:
    reason: UsageReason
    reservation: UsageReservation | None = None
    summary: UsageSummary | None = None

    @property
    def outcome(self) -> str:
        if self.reason is UsageReason.ACCOUNTING_ERROR:
            return "error"
        if self.reason in {
            UsageReason.RESERVED, UsageReason.REPLAY, UsageReason.COMPLETED,
            UsageReason.FAILED, UsageReason.SUMMARY,
        }:
            return "success"
        return "denied"

    @property
    def may_evaluate(self) -> bool:
        return self.reason is UsageReason.RESERVED

    def __bool__(self) -> bool:
        return self.may_evaluate


@dataclass(frozen=True)
class _TenantLedger:
    last_seen: float
    counts: dict[str, int]
    reservations: dict[str, UsageReservation]


def _digest(value: str) -> str:
    return hashlib.sha256(b"gvai-usage-v1\x00" + value.encode("ascii")).hexdigest()


class UsageStore(Protocol):
    """Trusted atomic accounting boundary used only after authorization."""

    def _apply(
        self,
        tenant_id: str,
        resource_id: str,
        request_id: str | None,
        operation: str,
    ) -> UsageResult: ...


class InMemoryUsageStore:
    """NONPRODUCTION: one process, one shared object, no durable accounting.

    Construct only in trusted server code. Policies are copied at construction;
    there is no customer policy mutation, refund, reset, or pruning operation.
    """

    def __init__(
        self,
        allowances: Mapping[str, int],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        policies = dict(allowances)
        if any(
            not _valid_customer_tenant(tenant)
            or type(allowance) is not int
            or not 0 <= allowance <= MAX_EVALUATION_UNITS
            for tenant, allowance in policies.items()
        ):
            raise ValueError("Invalid usage policy.")
        self._allowances = policies
        self._clock = clock
        self._lock = threading.Lock()
        self._ledgers: dict[str, _TenantLedger] = {}

    def _apply(
        self,
        tenant_id: str,
        resource_id: str,
        request_id: str | None,
        operation: str,
    ) -> UsageResult:
        with self._lock:
            if tenant_id not in self._allowances:
                return UsageResult(UsageReason.POLICY_MISSING)
            now = self._clock()
            if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
                raise ValueError
            instant = datetime.fromtimestamp(math.floor(now), timezone.utc)
            if instant.year >= 9999:
                raise ValueError
            period = instant.strftime("%Y-%m")
            ledger = self._ledgers.get(tenant_id, _TenantLedger(now, {}, {}))
            if now < ledger.last_seen:
                return UsageResult(UsageReason.CLOCK_ROLLBACK)
            allowance = self._allowances[tenant_id]
            consumed = ledger.counts.get(period, 0)
            if type(consumed) is not int or not 0 <= consumed <= allowance:
                raise ValueError
            counts = ledger.counts.copy()
            reservations = ledger.reservations.copy()
            if operation == "summary":
                states = [record.state for record in reservations.values() if record.period == period]
                if len(states) != consumed or any(type(state) is not ReservationState for state in states):
                    raise ValueError
                summary = UsageSummary(
                    period, allowance, consumed, allowance - consumed,
                    states.count(ReservationState.RESERVED),
                    states.count(ReservationState.COMPLETED),
                    states.count(ReservationState.FAILED),
                )
                result = UsageResult(UsageReason.SUMMARY, summary=summary)
            else:
                key = _digest(request_id)
                resource_digest = _digest(resource_id)
                record = reservations.get(key)
                if record is not None and record.resource_digest != resource_digest:
                    result = UsageResult(UsageReason.CONFLICT)
                elif operation == "reserve":
                    if record is not None:
                        result = UsageResult(UsageReason.REPLAY, reservation=record)
                    elif consumed >= allowance:
                        result = UsageResult(UsageReason.QUOTA_EXHAUSTED)
                    else:
                        record = UsageReservation(period, resource_digest)
                        reservations[key] = record
                        counts[period] = consumed + 1
                        result = UsageResult(UsageReason.RESERVED, reservation=record)
                elif record is None:
                    result = UsageResult(UsageReason.NOT_FOUND)
                else:
                    target = ReservationState(operation)
                    if record.state is target:
                        result = UsageResult(UsageReason.REPLAY, reservation=record)
                    elif record.state is not ReservationState.RESERVED:
                        result = UsageResult(UsageReason.CONFLICT)
                    else:
                        record = UsageReservation(record.period, record.resource_digest, target)
                        reservations[key] = record
                        reason = UsageReason.COMPLETED if target is ReservationState.COMPLETED else UsageReason.FAILED
                        result = UsageResult(reason, reservation=record)
            self._ledgers[tenant_id] = _TenantLedger(now, counts, reservations)
            return result


class SQLiteUsageStore:
    """Opt-in local ledger; initialize a new file explicitly before opening it.

    This experimental store persists quota policy, reservations, and clock
    watermarks. It does not make authentication or ownership transactional.
    """

    _SCHEMA_VERSION = 1
    _BUSY_TIMEOUT_SECONDS = 30.0
    _SCHEMA_STATEMENTS = (
        (
            "table",
            "usage_policy",
            "usage_policy",
            "CREATE TABLE usage_policy (tenant_id TEXT PRIMARY KEY NOT NULL, allowance INTEGER NOT NULL CHECK (typeof(allowance) = 'integer' AND allowance >= 0))",
        ),
        (
            "table",
            "usage_tenant_clock",
            "usage_tenant_clock",
            "CREATE TABLE usage_tenant_clock (tenant_id TEXT PRIMARY KEY NOT NULL, last_seen REAL NOT NULL)",
        ),
        (
            "table",
            "usage_reservations",
            "usage_reservations",
            "CREATE TABLE usage_reservations (tenant_id TEXT NOT NULL, request_digest TEXT NOT NULL CHECK (length(request_digest) = 64), period TEXT NOT NULL CHECK (length(period) = 7), resource_digest TEXT NOT NULL CHECK (length(resource_digest) = 64), state TEXT NOT NULL CHECK (state IN ('reserved', 'completed', 'failed')), PRIMARY KEY (tenant_id, request_digest), FOREIGN KEY (tenant_id) REFERENCES usage_policy(tenant_id))",
        ),
        (
            "index",
            "usage_reservations_by_period",
            "usage_reservations",
            "CREATE INDEX usage_reservations_by_period ON usage_reservations (tenant_id, period)",
        ),
    )

    def __init__(
        self,
        database_path: str | Path,
        allowances: Mapping[str, int],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._path = self._database_path(database_path)
        self._allowances = self._validated_allowances(allowances)
        self._clock = clock
        self._closed = False
        self._lock = threading.Lock()
        self._parent_identity = self._validate_parent(self._path)
        self._file_identity = self._validate_database_file(self._path)
        self._verify_database()

    @classmethod
    def initialize(
        cls,
        database_path: str | Path,
        allowances: Mapping[str, int],
        *,
        clock: Callable[[], float] = time.time,
    ) -> "SQLiteUsageStore":
        """Create a new database once; existing files are never replaced."""
        path = cls._database_path(database_path)
        policies = cls._validated_allowances(allowances)
        parent_identity = cls._validate_parent(path)
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        file_descriptor = os.open(str(path), flags, 0o600)
        try:
            cls._validate_file_stat(os.fstat(file_descriptor))
            if cls._validate_parent(path) != parent_identity:
                raise PermissionError("SQLite usage database parent changed during creation.")
        finally:
            os.close(file_descriptor)

        connection = None
        try:
            cls._validate_database_file(path)
            connection = sqlite3.connect(
                str(path), timeout=cls._BUSY_TIMEOUT_SECONDS, isolation_level=None
            )
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("BEGIN IMMEDIATE")
            for _object_type, _name, _table, statement in cls._SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO usage_policy (tenant_id, allowance) VALUES (?, ?)",
                tuple(policies.items()),
            )
            connection.execute("PRAGMA user_version = 1")
            cls._check_schema(connection)
            cls._check_integrity(connection)
            connection.commit()
        except Exception:
            if connection is not None:
                connection.rollback()
            raise
        finally:
            if connection is not None:
                connection.close()

        return cls(path, policies, clock=clock)

    def close(self) -> None:
        """Disable this store instance; subsequent operations fail closed."""
        with self._lock:
            self._closed = True

    def verify_recovery_integrity(self) -> None:
        """Recheck local structure only; this does not establish freshness."""
        with self._lock:
            if self._closed:
                raise sqlite3.ProgrammingError("Usage database is closed.")
            self._verify_database()

    def _apply(
        self,
        tenant_id: str,
        resource_id: str,
        request_id: str | None,
        operation: str,
    ) -> UsageResult:
        with self._lock:
            if self._closed:
                raise sqlite3.ProgrammingError("Usage database is closed.")
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._check_schema_version(connection)
                self._check_schema(connection)
                result = self._apply_transaction(
                    connection, tenant_id, resource_id, request_id, operation
                )
                connection.commit()
                return result
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    def _apply_transaction(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        resource_id: str,
        request_id: str | None,
        operation: str,
    ) -> UsageResult:
        reasons = UsageReason
        self._check_policy(connection)
        allowance = self._allowances.get(tenant_id)
        if allowance is None:
            return UsageResult(reasons.POLICY_MISSING)
        if type(allowance) is not int or not 0 <= allowance <= MAX_EVALUATION_UNITS:
            raise ValueError("Invalid persisted allowance.")

        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
            raise ValueError("Invalid accounting clock.")
        instant = datetime.fromtimestamp(math.floor(now), timezone.utc)
        if instant.year >= 9999:
            raise ValueError("Accounting clock out of range.")
        period = instant.strftime("%Y-%m")

        watermark = connection.execute(
            "SELECT last_seen FROM usage_tenant_clock WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if watermark is not None:
            last_seen = watermark[0]
            if (
                type(last_seen) not in (int, float)
                or not math.isfinite(last_seen)
                or last_seen < 0
            ):
                raise ValueError("Invalid persisted clock watermark.")
            if now < last_seen:
                return UsageResult(reasons.CLOCK_ROLLBACK)

        states = self._period_states(connection, tenant_id, period)
        consumed = sum(states.values())
        if not 0 <= consumed <= allowance:
            raise ValueError("Persisted quota is inconsistent.")

        if operation == "summary":
            result = UsageResult(
                reasons.SUMMARY,
                summary=UsageSummary(
                    period,
                    allowance,
                    consumed,
                    allowance - consumed,
                    states[ReservationState.RESERVED.value],
                    states[ReservationState.COMPLETED.value],
                    states[ReservationState.FAILED.value],
                ),
            )
        else:
            request_digest = _digest(request_id)
            resource_digest = _digest(resource_id)
            row = connection.execute(
                """SELECT period, resource_digest, state
                   FROM usage_reservations
                   WHERE tenant_id = ? AND request_digest = ?""",
                (tenant_id, request_digest),
            ).fetchone()
            reservation = self._reservation_from_row(row)
            if reservation is not None and reservation.resource_digest != resource_digest:
                result = UsageResult(reasons.CONFLICT)
            elif operation == "reserve":
                if reservation is not None:
                    result = UsageResult(reasons.REPLAY, reservation=reservation)
                elif consumed >= allowance:
                    result = UsageResult(reasons.QUOTA_EXHAUSTED)
                else:
                    cursor = connection.execute(
                        """INSERT INTO usage_reservations
                           (tenant_id, request_digest, period, resource_digest, state)
                           VALUES (?, ?, ?, ?, ?)""",
                        (
                            tenant_id,
                            request_digest,
                            period,
                            resource_digest,
                            ReservationState.RESERVED.value,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("Reservation insert did not affect exactly one row.")
                    persisted = connection.execute(
                        """SELECT tenant_id, request_digest, period, resource_digest, state
                           FROM usage_reservations
                           WHERE tenant_id = ? AND request_digest = ?""",
                        (tenant_id, request_digest),
                    ).fetchone()
                    expected = (
                        tenant_id,
                        request_digest,
                        period,
                        resource_digest,
                        ReservationState.RESERVED.value,
                    )
                    if persisted != expected:
                        raise ValueError("Persisted reservation does not match the grant.")
                    result = UsageResult(
                        reasons.RESERVED,
                        reservation=UsageReservation(period, resource_digest),
                    )
            elif reservation is None:
                result = UsageResult(reasons.NOT_FOUND)
            else:
                target = ReservationState(operation)
                if reservation.state is target:
                    result = UsageResult(reasons.REPLAY, reservation=reservation)
                elif reservation.state is not ReservationState.RESERVED:
                    result = UsageResult(reasons.CONFLICT)
                else:
                    cursor = connection.execute(
                        """UPDATE usage_reservations SET state = ?
                           WHERE tenant_id = ? AND request_digest = ?
                             AND state = 'reserved'""",
                        (target.value, tenant_id, request_digest),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("Completion did not affect exactly one row.")
                    persisted = connection.execute(
                        """SELECT period, resource_digest, state
                           FROM usage_reservations
                           WHERE tenant_id = ? AND request_digest = ?""",
                        (tenant_id, request_digest),
                    ).fetchone()
                    expected = (
                        reservation.period,
                        reservation.resource_digest,
                        target.value,
                    )
                    if persisted != expected:
                        raise ValueError("Persisted completion does not match the transition.")
                    reason = (
                        reasons.COMPLETED
                        if target is ReservationState.COMPLETED
                        else reasons.FAILED
                    )
                    result = UsageResult(
                        reason,
                        reservation=UsageReservation(
                            reservation.period,
                            reservation.resource_digest,
                            target,
                        ),
                    )

        cursor = connection.execute(
            """INSERT INTO usage_tenant_clock (tenant_id, last_seen)
               VALUES (?, ?)
               ON CONFLICT (tenant_id) DO UPDATE SET last_seen = excluded.last_seen""",
            (tenant_id, now),
        )
        if cursor.rowcount != 1:
            raise ValueError("Clock watermark did not affect exactly one row.")
        watermark = connection.execute(
            "SELECT last_seen FROM usage_tenant_clock WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        if watermark is None or float(watermark[0]) != float(now):
            raise ValueError("Persisted clock watermark does not match the transaction.")
        return result

    @staticmethod
    def _period_states(
        connection: sqlite3.Connection, tenant_id: str, period: str
    ) -> dict[str, int]:
        states = {state.value: 0 for state in ReservationState}
        rows = connection.execute(
            """SELECT state, COUNT(*) FROM usage_reservations
               WHERE tenant_id = ? AND period = ? GROUP BY state""",
            (tenant_id, period),
        ).fetchall()
        for state, count in rows:
            if state not in states or type(count) is not int or count < 0:
                raise ValueError("Invalid persisted reservation state.")
            states[state] = count
        return states

    @staticmethod
    def _reservation_from_row(row: tuple[object, ...] | None) -> UsageReservation | None:
        if row is None:
            return None
        period, resource_digest, state = row
        if (
            type(period) is not str
            or len(period) != 7
            or period[4] != "-"
            or type(resource_digest) is not str
            or len(resource_digest) != 64
        ):
            raise ValueError("Invalid persisted reservation.")
        return UsageReservation(period, resource_digest, ReservationState(state))

    def _verify_database(self) -> None:
        connection = self._connect()
        try:
            self._check_schema_version(connection)
            self._check_schema(connection)
            self._check_integrity(connection)
            self._check_policy(connection)
        finally:
            connection.close()

    @classmethod
    def _database_path(cls, database_path: str | Path) -> Path:
        if not isinstance(database_path, (str, Path)):
            raise TypeError("A file-backed SQLite path is required.")
        if str(database_path) == ":memory:":
            raise ValueError("SQLite usage storage must be file-backed.")
        path = Path(os.path.abspath(str(Path(database_path).expanduser())))
        cls._validate_parent(path)
        return path

    @staticmethod
    def _validated_allowances(allowances: Mapping[str, int]) -> dict[str, int]:
        policies = dict(allowances)
        if any(
            not _valid_customer_tenant(tenant)
            or type(allowance) is not int
            or not 0 <= allowance <= MAX_EVALUATION_UNITS
            for tenant, allowance in policies.items()
        ):
            raise ValueError("Invalid usage policy.")
        return policies

    @classmethod
    def _validate_parent(cls, path: Path) -> tuple[int, int]:
        if os.name != "posix" or not hasattr(os, "geteuid"):
            raise PermissionError("SQLite usage storage requires POSIX file ownership controls.")
        components = (path.parent,) + tuple(path.parent.parents)
        for component in components:
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise PermissionError("SQLite usage database path contains an unsafe directory.")
        parent_info = path.parent.lstat()
        if parent_info.st_uid != os.geteuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise PermissionError("SQLite usage database parent must be privately owned.")
        for component in components[1:]:
            info = component.lstat()
            permissions = stat.S_IMODE(info.st_mode)
            if permissions & 0o022 and not permissions & stat.S_ISVTX:
                raise PermissionError("SQLite usage database path has a writable ancestor.")
        return parent_info.st_dev, parent_info.st_ino

    @classmethod
    def _validate_database_file(cls, path: Path) -> tuple[int, int]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            raise FileNotFoundError("Initialized SQLite usage database not found.") from None
        cls._validate_file_stat(info)
        return info.st_dev, info.st_ino

    @staticmethod
    def _validate_file_stat(info: os.stat_result) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise PermissionError(
                "SQLite usage database must be a private, singly linked regular file."
            )

    @staticmethod
    def _normalize_schema_sql(statement: str) -> str:
        return " ".join(statement.split())

    @classmethod
    def _check_schema(cls, connection: sqlite3.Connection) -> None:
        expected = {
            name: (object_type, table, cls._normalize_schema_sql(statement))
            for object_type, name, table, statement in cls._SCHEMA_STATEMENTS
        }
        rows = connection.execute(
            """SELECT type, name, tbl_name, sql FROM sqlite_master
               WHERE substr(name, 1, 7) != 'sqlite_'"""
        ).fetchall()
        actual = {
            name: (object_type, table, cls._normalize_schema_sql(sql or ""))
            for object_type, name, table, sql in rows
        }
        if actual != expected:
            raise ValueError("SQLite usage schema does not match the expected schema.")

    @staticmethod
    def _check_integrity(connection: sqlite3.Connection) -> None:
        result = connection.execute("PRAGMA integrity_check").fetchall()
        if result != [("ok",)]:
            raise ValueError("SQLite usage database integrity check failed.")
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("SQLite usage database foreign-key check failed.")

    def _check_policy(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT tenant_id, allowance FROM usage_policy"
        ).fetchall()
        persisted = dict(rows)
        if len(persisted) != len(rows) or persisted != self._allowances:
            raise ValueError("SQLite usage policy does not match trusted configuration.")

    def _connect(self) -> sqlite3.Connection:
        parent_identity = self._validate_parent(self._path)
        file_identity = self._validate_database_file(self._path)
        if parent_identity != self._parent_identity or file_identity != self._file_identity:
            raise PermissionError("SQLite usage database path was replaced.")
        connection = sqlite3.connect(
            str(self._path),
            timeout=self._BUSY_TIMEOUT_SECONDS,
            isolation_level=None,
        )
        try:
            parent_identity = self._validate_parent(self._path)
            file_identity = self._validate_database_file(self._path)
            if parent_identity != self._parent_identity or file_identity != self._file_identity:
                raise PermissionError("SQLite usage database path changed while opening.")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
            return connection
        except Exception:
            connection.close()
            raise

    @classmethod
    def _check_schema_version(cls, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != cls._SCHEMA_VERSION:
            raise ValueError("Unsupported SQLite usage schema version.")


class CommercialUsage:
    """Offline accounting only. Never evaluates, executes, or controls work.

    Dependencies and completion calls are trusted server code, not request
    schemas. Every call re-enters CommercialAuthorizer; decisions are not cached.
    """

    def __init__(self, authorizer: CommercialAuthorizer, store: UsageStore) -> None:
        self._authorizer = authorizer
        self._store = store

    def reserve(self, credential: object, resource_id: str, request_id: str) -> UsageResult:
        return self._operate(credential, resource_id, request_id, "reserve")

    def complete(
        self, credential: object, resource_id: str, request_id: str, *, succeeded: bool,
    ) -> UsageResult:
        if type(succeeded) is not bool:
            return UsageResult(UsageReason.INVALID_INPUT)
        operation = "completed" if succeeded else "failed"
        return self._operate(credential, resource_id, request_id, operation)

    def summary(self, credential: object, resource_id: str) -> UsageResult:
        return self._operate(credential, resource_id, None, "summary")

    def _operate(
        self, credential: object, resource_id: str, request_id: str | None, operation: str,
    ) -> UsageResult:
        try:
            if operation != "summary" and not _valid_identifier(request_id):
                return UsageResult(UsageReason.INVALID_INPUT)
            capability = (
                CommercialCapability.READ_USAGE if operation == "summary"
                else CommercialCapability.EVALUATE
            )
            decision = self._authorizer.authorize(credential, capability, resource_id)
            if decision.allowed is not True or not _valid_customer_tenant(decision.tenant_id):
                return UsageResult(UsageReason.UNAUTHORIZED)
            if isinstance(self._store, SQLiteUsageStore):
                return UsageResult(UsageReason.ACCOUNTING_ERROR)
            return self._store._apply(decision.tenant_id, resource_id, request_id, operation)
        except Exception:
            return UsageResult(UsageReason.ACCOUNTING_ERROR)
