"""Extraction boundaries, not PostgreSQL or host-enforcement evidence."""

import ast
from pathlib import Path

import pytest

from gvai import commercial_usage
from gvai.commercial_reservation_authority import CanonicalReservationRequest


ROOT = Path(__file__).resolve().parents[1]
ACCOUNTING_MODULES = (
    "commercial_reservation_authority",
    "postgresql_reservation_authority",
    "postgresql_advisory",
    "private_staging",
)
ALLOWED_ACCOUNTING_IMPORTS = {
    "gvai.commercial_api_keys",
    "gvai.commercial_http",
    "gvai.commercial_identity",
    "gvai.commercial_reservation_authority",
    "gvai.commercial_service",
    "gvai.commercial_usage",
    "gvai.postgresql_advisory",
    "gvai.postgresql_reservation_authority",
}


@pytest.mark.parametrize("module", ACCOUNTING_MODULES)
def test_accounting_dependencies_are_commercial_only(module):
    tree = ast.parse((ROOT / "gvai" / (module + ".py")).read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    assert {name for name in imports if name.startswith("gvai.")} <= ALLOWED_ACCOUNTING_IMPORTS


def test_experimental_sqlite_ledger_not_imported():
    assert not hasattr(commercial_usage, "SQLiteUsageStore")
    assert "sqlite3" not in vars(commercial_usage)


def test_canonical_accounting_request_binds_payload_project_and_id():
    request = CanonicalReservationRequest.from_bounded_input("request-a", "project-a", b"one")
    assert request == CanonicalReservationRequest.from_bounded_input(
        "request-a", "project-a", b"one",
    )
    for changed in (
        CanonicalReservationRequest.from_bounded_input("request-b", "project-a", b"one"),
        CanonicalReservationRequest.from_bounded_input("request-a", "project-b", b"one"),
        CanonicalReservationRequest.from_bounded_input("request-a", "project-a", b"two"),
    ):
        assert changed.request_digest != request.request_digest
