from dataclasses import replace
import json
from pathlib import Path
import re

import pytest

from gvai.postgresql_billing_acceptance import (
    AcceptanceRefused,
    CATALOG_CHECKS,
    ClusterIdentity,
    FutureAuthorization,
    MANIFEST,
    Operation,
    REPETITIONS,
    ROLE_ENTRYPOINTS,
    RunConfig,
    TRANSACTION_CHECKS,
    compare_cluster_identity,
    prepare_plan,
    request_execution,
    teardown_plan,
)


RUN = "1234567890abcdef1234567890abcdef"


def config():
    return RunConfig(RUN, 55489, opted_in=True, synthetic_only=True)


def identity():
    run = config()
    return ClusterIdentity(
        "1234567890123456789", "127.0.0.1", ("127.0.0.1",), run.port,
        run.database, run.data_directory, run.socket_directory, True,
    )


def test_default_refuses_without_opt_in():
    with pytest.raises(AcceptanceRefused, match="explicit_opt_in_required"):
        RunConfig(RUN, 55489).validate({})


@pytest.mark.parametrize("changes", [
    {"run_id": ""}, {"run_id": "0" * 32}, {"run_id": "../other"},
    {"run_id": "A" * 32}, {"run_id": None}, {"opted_in": 1},
    {"synthetic_only": False}, {"host": "localhost"}, {"host": "::1"},
    {"host": "127.0.0.1,example.com"}, {"host": "/tmp"}, {"host": "example.com"},
    {"port": 5432}, {"port": True}, {"port": 0}, {"port": 65536},
])
def test_unsafe_config_refused(changes):
    with pytest.raises(AcceptanceRefused):
        replace(config(), **changes).validate({})


@pytest.mark.parametrize("key", [
    "PGHOST", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGPASSFILE",
    "PGPASSWORD", "PGOPTIONS", "PGPORT", "DATABASE_URL", "OWNER_DSN",
    "GVAI_TEST_POSTGRES_RUNTIME_DSN", "GVAI_RUN_POSTGRES_INTEGRATION",
])
def test_inherited_config_refused_without_exposing_values(key):
    with pytest.raises(AcceptanceRefused) as failure:
        prepare_plan(config(), environment={key: "password=do-not-print"})
    assert str(failure.value) == "inherited_database_configuration_forbidden"
    assert "do-not-print" not in repr(failure.value)


def test_actual_environment_is_checked(monkeypatch):
    monkeypatch.setenv("PGHOST", "remote.invalid")
    with pytest.raises(AcceptanceRefused, match="inherited"):
        prepare_plan(config())


def test_existing_directory_and_dangling_symlink_refused(monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda self: True)
    with pytest.raises(AcceptanceRefused, match="already_exists"):
        prepare_plan(config(), environment={})
    monkeypatch.setattr(Path, "exists", lambda self: False)
    monkeypatch.setattr(Path, "is_symlink", lambda self: True)
    with pytest.raises(AcceptanceRefused, match="already_exists"):
        prepare_plan(config(), environment={})


def test_plan_has_unique_scoped_roles_and_exact_targets():
    plan = prepare_plan(config(), environment={})
    names = [role.name for role in plan.roles]
    assert len(set(names)) == 5
    assert all(RUN in name and len(name) <= 63 for name in names)
    roles = {role.purpose: role.entrypoints for role in plan.roles}
    assert roles["owner"] == ()
    assert len(roles["receiver"]) == 1
    assert len(roles["worker"]) == 4
    assert len(roles["paid"]) == 3
    assert len(roles["pilot"]) == 3
    assert set(roles["paid"]).isdisjoint(roles["pilot"])
    assert all("reserve_v1(" not in item for role in plan.roles for item in role.entrypoints)
    assert plan.teardown_targets == (config().data_directory, config().socket_directory)
    assert all(path.parent == config().directory for path in plan.teardown_targets)


def test_manifest_covers_all_categories_and_explicit_external_blockers():
    assert [case.case_id for case in MANIFEST[:16]] == [
        "A%02d" % number for number in range(1, 17)
    ]
    assert len({case.case_id for case in MANIFEST}) == len(MANIFEST)
    assert {case.case_id for case in MANIFEST[16:]} == {
        "A14-UTC", "A16-RESTORE", "A06-STRIPE",
    }
    assert all(case.requirement and case.evidence and case.blocker for case in MANIFEST)
    assert REPETITIONS == 20
    assert len(CATALOG_CHECKS) == 8
    assert len(TRANSACTION_CHECKS) == 4


def test_role_signatures_match_actual_migration_declarations():
    root = Path(__file__).resolve().parents[1] / "migrations/postgresql"
    source = "\n".join(
        (root / name).read_text() for name in (
            "003_advisory_pilots_v1.sql", "004_subscription_billing_v1.sql",
        )
    )
    declarations = {}
    for name, parameters in re.findall(
        r"CREATE FUNCTION gvai_authority\.(\w+)\((.*?)\)\s*RETURNS",
        source, re.DOTALL,
    ):
        types = (
            [parameter.split()[1] for parameter in parameters.split(",")]
            if parameters.strip() else []
        )
        declarations[name] = name + "(" + ",".join(types) + ")"
    for _, signatures in ROLE_ENTRYPOINTS:
        for signature in signatures:
            assert declarations[signature.split("(")[0]] == signature


def test_changed_or_unreadable_migration_refuses(monkeypatch):
    monkeypatch.setattr(Path, "read_bytes", lambda self: b"changed")
    with pytest.raises(AcceptanceRefused, match="migration_baseline_mismatch"):
        prepare_plan(config(), environment={})

    def unreadable(self):
        raise PermissionError("password=do-not-print")

    monkeypatch.setattr(Path, "read_bytes", unreadable)
    with pytest.raises(AcceptanceRefused) as failure:
        prepare_plan(config(), environment={})
    assert str(failure.value) == "migration_baseline_unreadable"
    assert failure.value.__suppress_context__


def test_report_is_allowlisted_and_never_claims_database_passes():
    plan = prepare_plan(config(), environment={})
    report = json.loads(plan.evidence_json())
    assert report["execution_enabled"] is False
    assert report["acceptance"] == "blocked"
    assert len(report["cases"]) == 19
    assert all(item["status"] == "blocked" for item in report["cases"])
    assert RUN not in plan.evidence_json()
    assert "/tmp" not in plan.evidence_json()
    assert "dsn" not in plan.evidence_json().lower()
    assert "passed" not in plan.evidence_json()
    # Even manually constructed plan fields cannot inject raw evidence.
    poisoned = replace(plan, run_id="password=secret", manifest=())
    assert poisoned.evidence_json() == plan.evidence_json()


@pytest.mark.parametrize("changes", [
    {"system_identifier": ""}, {"system_identifier": "0"},
    {"system_identifier": str(2**64)}, {"system_identifier": "999"},
    {"host": "remote.invalid"}, {"listen_addresses": ("*",)},
    {"listen_addresses": ("127.0.0.1", "::1")}, {"port": 5432},
    {"database": "postgres"}, {"data_directory": Path("/workspaces")},
    {"socket_directory": Path("/tmp")}, {"synthetic_only": False},
])
def test_cluster_mismatch_refused(changes):
    with pytest.raises(AcceptanceRefused):
        compare_cluster_identity(config(), identity(), replace(identity(), **changes))


def test_matching_identity_is_comparison_only():
    assert compare_cluster_identity(config(), identity(), identity()) is None


@pytest.mark.parametrize("operation", list(Operation))
def test_no_operation_can_execute_even_with_scoped_authorization(operation, monkeypatch):
    monkeypatch.setattr("gvai.postgresql_billing_acceptance.os.environ", {})
    with pytest.raises(AcceptanceRefused, match="future_authorization_required"):
        request_execution(config(), operation)
    approval = FutureAuthorization(RUN, frozenset({operation}))
    with pytest.raises(AcceptanceRefused, match="execution_not_implemented"):
        request_execution(config(), operation, approval)


@pytest.mark.parametrize("approval", [
    FutureAuthorization("f" * 32, frozenset({Operation.CONNECT})),
    FutureAuthorization(RUN, frozenset({Operation.CREATE})),
    FutureAuthorization(RUN, frozenset({"connect"})),
])
def test_wrong_run_scope_or_untyped_authorization_refused(approval, monkeypatch):
    monkeypatch.setattr("gvai.postgresql_billing_acceptance.os.environ", {})
    with pytest.raises(AcceptanceRefused, match="explicit_run_operation"):
        request_execution(config(), Operation.CONNECT, approval)


def test_teardown_only_plans_exact_targets_and_requires_identity(monkeypatch):
    monkeypatch.setattr("gvai.postgresql_billing_acceptance.os.environ", {})
    approval = FutureAuthorization(RUN, frozenset({Operation.TEARDOWN}))
    assert teardown_plan(config(), identity(), identity(), approval) == (
        config().data_directory, config().socket_directory,
    )
    with pytest.raises(AcceptanceRefused):
        teardown_plan(config(), identity(), replace(identity(), database="postgres"), approval)
    with pytest.raises(AcceptanceRefused):
        teardown_plan(
            config(), identity(), identity(),
            FutureAuthorization(RUN, frozenset({Operation.CONNECT})),
        )


def test_foundation_has_no_io_execution_dependencies():
    import ast
    import gvai.postgresql_billing_acceptance as foundation

    tree = ast.parse(Path(foundation.__file__).read_text())
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add(node.module.split(".")[0])
    assert roots == {
        "__future__", "dataclasses", "enum", "hashlib", "json", "os", "pathlib", "re", "typing",
    }
    forbidden_calls = {
        "connect", "system", "popen", "mkdir", "unlink", "rmdir", "write_text",
        "write_bytes", "execute", "exec", "eval", "open", "kill", "remove",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else ""
            )
            assert name not in forbidden_calls
