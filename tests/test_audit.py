import json
from pathlib import Path

from gvai.audit import GVAuditWriter
from gvai.os_sandbox import OSSandboxTransaction


def test_audit_writer_creates_machine_readable_record(
    tmp_path,
):
    transaction = OSSandboxTransaction(
        action="safe_work",
        returncode=0,
        completed=True,
        error=None,
        observed_effects=frozenset(
            {"normal_operation"}
        ),
        events=(),
        allowed=True,
        committed=True,
        halted=False,
        reason="Action permitted.",
        stderr="",
    )

    writer = GVAuditWriter(
        tmp_path / "audit"
    )

    path = writer.write(
        transaction,
        started_at=0.0,
    )

    assert path.exists()

    record = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    assert record["action"] == "safe_work"
    assert record["completed"] is True
    assert record["allowed"] is True
    assert record["committed"] is True
    assert record["halted"] is False

    assert record[
        "observed_effects"
    ] == ["normal_operation"]

    assert record["audit_id"]
    assert record["timestamp_utc"]
    assert record["duration_ms"] >= 0
