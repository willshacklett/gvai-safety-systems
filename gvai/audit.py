from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class GVAuditRecord:
    audit_id: str
    timestamp_utc: str
    duration_ms: float
    action: str
    returncode: int
    completed: bool
    error: str | None
    observed_effects: tuple[str, ...]
    events: tuple[dict[str, Any], ...]
    allowed: bool
    committed: bool
    halted: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class GVAuditWriter:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

    def write(
        self,
        transaction,
        started_at: float,
    ) -> Path:
        duration_ms = (
            time.monotonic() - started_at
        ) * 1000.0

        record = GVAuditRecord(
            audit_id=uuid.uuid4().hex,
            timestamp_utc=(
                datetime.now(timezone.utc)
                .isoformat()
            ),
            duration_ms=round(
                duration_ms,
                3,
            ),
            action=transaction.action,
            returncode=transaction.returncode,
            completed=transaction.completed,
            error=transaction.error,
            observed_effects=tuple(
                sorted(
                    transaction.observed_effects
                )
            ),
            events=tuple(
                transaction.events
            ),
            allowed=transaction.allowed,
            committed=transaction.committed,
            halted=transaction.halted,
            reason=transaction.reason,
        )

        path = (
            self.root
            / f"{record.audit_id}.json"
        )

        path.write_text(
            json.dumps(
                record.to_dict(),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        return path
