"""Offline planning only: this module cannot connect, start, migrate, or delete."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Mapping


MIGRATION_SHA256 = "1d61e4786db8c49c752315dfef1643f23961a1b22bb88889d5cdc5943df6642b"
REPETITIONS = 20


class AcceptanceRefused(RuntimeError):
    """Redacted refusal; configuration and driver errors must never be embedded."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise AcceptanceRefused(code)


class Operation(str, Enum):
    CREATE = "create"
    START = "start"
    CONNECT = "connect"
    MIGRATE = "migrate"
    TEST = "test"
    TEARDOWN = "teardown"


@dataclass(frozen=True)
class FutureAuthorization:
    run_id: str
    operations: frozenset[Operation]

    def require(self, run_id: str, operation: Operation) -> None:
        _require(
            self.run_id == run_id
            and type(self.operations) is frozenset
            and all(type(item) is Operation for item in self.operations)
            and type(operation) is Operation
            and operation in self.operations,
            "explicit_run_operation_authorization_required",
        )


@dataclass(frozen=True, repr=False)
class RunConfig:
    run_id: str
    port: int
    opted_in: bool = False
    host: str = "127.0.0.1"
    synthetic_only: bool = False

    @property
    def database(self) -> str:
        return "gvai_billing_test_" + self.run_id

    @property
    def directory(self) -> Path:
        return Path("/tmp") / ("gvai-billing-acceptance-" + self.run_id)

    @property
    def data_directory(self) -> Path:
        return self.directory / "data"

    @property
    def socket_directory(self) -> Path:
        return self.directory / "socket"

    def validate(self, environment: Mapping[str, str] | None = None) -> None:
        _require(
            type(self.run_id) is str
            and re.fullmatch(r"[0-9a-f]{32}", self.run_id) is not None
            and self.run_id != "0" * 32,
            "invalid_run_identity",
        )
        _require(self.opted_in is True, "explicit_opt_in_required")
        _require(self.synthetic_only is True, "synthetic_data_only_required")
        _require(type(self.host) is str and self.host == "127.0.0.1", "loopback_only")
        _require(
            type(self.port) is int and 1024 <= self.port <= 65535 and self.port != 5432,
            "dedicated_port_required",
        )
        source = os.environ if environment is None else environment
        _require(
            not any(
                key.upper().startswith("PG")
                or "DSN" in key.upper()
                or key.upper() in {
                    "DATABASE_URL", "DATABASE_SERVICE", "GVAI_RUN_POSTGRES_INTEGRATION",
                }
                for key in source
            ),
            "inherited_database_configuration_forbidden",
        )
        _require(Path("/tmp").resolve() == Path("/tmp"), "unexpected_temporary_root")

    def require_fresh_directory(self) -> None:
        self.validate({})
        _require(
            not self.directory.exists() and not self.directory.is_symlink(),
            "run_directory_already_exists",
        )


ROLE_ENTRYPOINTS = (
    ("owner", ()),
    ("receiver", ("enqueue_billing_event_v1(text,text,text,text,text,text,bytea)",)),
    ("worker", (
        "claim_billing_events_v1(integer,integer)",
        "begin_billing_reconciliation_v1(text,text,text,text,text,bigint,integer)",
        "apply_billing_reconciliation_v1(text,text,bigint,text,text,text,text,bigint,"
        "text,bigint,text,boolean,timestamptz,text,text,text,text,bigint,boolean,"
        "timestamptz,timestamptz)",
        "retry_billing_event_v1(text,text,text,bigint,text,boolean)",
    )),
    ("paid", (
        "reserve_subscription_advisory_v1(text,bytea,text,bigint,text,text,text,text)",
        "complete_subscription_advisory_v1(text,bytea,text,text,boolean)",
        "subscription_advisory_usage_v1(text,bytea,text)",
    )),
    ("pilot", (
        "reserve_advisory_v1(text,bytea,text,bigint,text,text,text,text)",
        "complete_advisory_v1(text,bytea,text,text,boolean)",
        "advisory_usage_v1(text,bytea,text)",
    )),
)


@dataclass(frozen=True)
class RolePlan:
    purpose: str
    name: str
    entrypoints: tuple[str, ...]


@dataclass(frozen=True, repr=False)
class ClusterIdentity:
    """Expected identity, not proof: future independent inspection is mandatory."""

    system_identifier: str
    host: str
    listen_addresses: tuple[str, ...]
    port: int
    database: str
    data_directory: Path
    socket_directory: Path
    synthetic_only: bool


def compare_cluster_identity(
    config: RunConfig, expected: ClusterIdentity, observed: ClusterIdentity,
) -> None:
    """Compare supplied facts without contacting a server or trusting their source."""
    config.validate({})
    for identity in (expected, observed):
        _require(
            type(identity.system_identifier) is str
            and re.fullmatch(r"[1-9][0-9]{0,19}", identity.system_identifier) is not None
            and int(identity.system_identifier) <= 2**64 - 1,
            "unverified_cluster_identity",
        )
        _require(
            identity.host == config.host
            and identity.listen_addresses == ("127.0.0.1",)
            and type(identity.port) is int and identity.port == config.port
            and identity.database == config.database
            and type(identity.data_directory) is type(config.data_directory)
            and identity.data_directory == config.data_directory
            and type(identity.socket_directory) is type(config.socket_directory)
            and identity.socket_directory == config.socket_directory
            and identity.synthetic_only is True,
            "cluster_isolation_mismatch",
        )
    _require(expected == observed, "cluster_identity_mismatch")


@dataclass(frozen=True)
class AcceptanceCase:
    case_id: str
    requirement: str
    evidence: tuple[str, ...]
    blocker: str = "database_execution_not_implemented_or_authorized"


MANIFEST = (
    AcceptanceCase("A01", "Apply 001-004; invoke every routine and trigger.",
                   ("migration_commits", "routine_results", "source_hashes")),
    AcceptanceCase("A02", "Installation failure/reapply/wrong owner is atomic.",
                   ("sqlstates", "before_after_catalogs")),
    AcceptanceCase("A03", "Upgrade preserves populated pilot data, definitions and ACLs.",
                   ("before_after_rows", "definitions", "acl_diff")),
    AcceptanceCase("A04", "Catalog keys, validated constraints, defaults and timestamp bounds.",
                   ("catalog_snapshot", "negative_input_sqlstates")),
    AcceptanceCase("A05", "Missing/stale/uncertain/inactive/suspended access denies.",
                   ("denial_results", "unchanged_accounting")),
    AcceptanceCase("A06", "Verified payment and interval union never bridge unpaid gaps.",
                   ("invoice_rows", "coverage_boundaries", "denial_results")),
    AcceptanceCase("A07", "Cancellation boundaries and irreversible terminal tombstones.",
                   ("transition_results", "immutable_history")),
    AcceptanceCase("A08", "Duplicate/conflicting deliveries preserve durable identity.",
                   ("inbox_rows", "digest_comparisons", "quarantine_results")),
    AcceptanceCase("A09", "Replay/conflicts/out-of-order reconciliation cannot extend proof.",
                   ("revision_history", "invoice_line_counts", "denial_results")),
    AcceptanceCase("A10", "Concurrent claims, lease steal, crashes and stale fences.",
                   ("barrier_traces", "twenty_repetitions", "committed_effect_counts")),
    AcceptanceCase("A11", "Deferred failures, timeouts and rollback leave no partial effects.",
                   ("commit_sqlstates", "before_after_rows", "head_and_quota_diffs")),
    AcceptanceCase("A12", "Tenant/customer/membership/Price/account/environment isolation.",
                   ("substitution_matrix", "collision_traces", "unrelated_rows_unchanged")),
    AcceptanceCase("A13", "Reserve/complete/replay consume exactly one unit without refunds.",
                   ("event_counts", "attempt_states", "quota_deltas")),
    AcceptanceCase("A14", "Pilot parity and UTC-month quota survive renewals.",
                   ("pilot_comparison", "timezone_matrix", "month_bucket_deltas")),
    AcceptanceCase("A15", "Billing cannot bypass STOP or independent authority identity.",
                   ("authority_identity_diff", "denied_privileges", "stop_regressions")),
    AcceptanceCase("A16", "Rollback disables paid access without deleting payment history.",
                   ("grant_revocation", "no_fallback_results", "retained_evidence")),
    AcceptanceCase("A14-UTC", "True UTC month rollover with real database time.",
                   ("boundary_trace",), "safe_real_rollover_method_not_approved"),
    AcceptanceCase("A16-RESTORE", "Stale restore remains denied until external fencing.",
                   ("external_fence_proof",), "independent_restore_fencing_not_implemented"),
    AcceptanceCase("A06-STRIPE", "External signature/context and authoritative retrieval.",
                   ("independent_verifier_evidence",), "external_stripe_verification_out_of_scope"),
)

CATALOG_CHECKS = (
    "pg_constraint: validated composite FKs, candidate keys, null/check constraints",
    "pg_trigger: enabled attachments, deferred checks under restricted-role commit",
    "pg_proc/pg_namespace: owner, prosecdef, proconfig, trusted schema ownership",
    "pg_roles/pg_auth_members: no escalation, owner membership or grant options",
    "pg_default_acl/aclexplode: inherited and PUBLIC privileges, exact signatures",
    "has_function_privilege/has_table_privilege/has_sequence_privilege/has_schema_privilege",
    "authenticated role sessions: denied DML/DDL/TRUNCATE/SET ROLE/raw and pilot bypass",
    "temporary-object/search_path shadowing cannot redirect definer routines",
)

TRANSACTION_CHECKS = (
    "Compare inbox/reconciliation/invoice/interval/projection before and after rollback.",
    "Compare events/idempotency/attempts/quota/head after failed paid authorization.",
    "Use separate connections and barriers; twenty repetitions; bounded timeouts.",
    "Lost commit acknowledgment is unavailable until reconciliation, never assumed success.",
)


@dataclass(frozen=True)
class AcceptancePlan:
    run_id: str
    roles: tuple[RolePlan, ...]
    manifest: tuple[AcceptanceCase, ...]
    teardown_targets: tuple[Path, ...]

    def evidence_json(self) -> str:
        """Allowlisted foundation report: no raw config, DSN, exception or SQL text."""
        return json.dumps({
            "phase": "offline_foundation",
            "execution_enabled": False,
            "acceptance": "blocked",
            "migration_sha256": MIGRATION_SHA256,
            "cases": [
                {"id": case.case_id, "status": "blocked", "reason": case.blocker}
                for case in MANIFEST
            ],
        }, sort_keys=True)


def prepare_plan(
    config: RunConfig, *, environment: Mapping[str, str] | None = None,
) -> AcceptancePlan:
    config.validate(environment)
    config.require_fresh_directory()
    migration = (
        Path(__file__).resolve().parents[1]
        / "migrations/postgresql/004_subscription_billing_v1.sql"
    )
    _require(not migration.is_symlink(), "migration_symlink_forbidden")
    try:
        digest = hashlib.sha256(migration.read_bytes()).hexdigest()
    except OSError:
        raise AcceptanceRefused("migration_baseline_unreadable") from None
    _require(digest == MIGRATION_SHA256, "migration_baseline_mismatch")
    roles = tuple(
        RolePlan(purpose, "gb_" + config.run_id + "_" + purpose, entrypoints)
        for purpose, entrypoints in ROLE_ENTRYPOINTS
    )
    return AcceptancePlan(
        config.run_id, roles, MANIFEST,
        (config.data_directory, config.socket_directory),
    )


def request_execution(
    config: RunConfig, operation: Operation,
    authorization: FutureAuthorization | None = None,
) -> None:
    config.validate()
    if type(authorization) is not FutureAuthorization:
        raise AcceptanceRefused("future_authorization_required")
    authorization.require(config.run_id, operation)
    raise AcceptanceRefused("execution_not_implemented_identity_and_ownership_unverified")


def teardown_plan(
    config: RunConfig, expected: ClusterIdentity, observed: ClusterIdentity,
    authorization: FutureAuthorization,
) -> tuple[Path, ...]:
    """Return exact candidates only; never stop processes, execute SQL or remove files."""
    config.validate()
    authorization.require(config.run_id, Operation.TEARDOWN)
    compare_cluster_identity(config, expected, observed)
    return config.data_directory, config.socket_directory
