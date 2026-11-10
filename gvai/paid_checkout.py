"""Internal persistence only: no admission, payment, dispatch, or entitlement."""

from __future__ import annotations

import logging
from typing import Any, Callable


LOG = logging.getLogger(__name__)


class CheckoutUnavailable(RuntimeError):
    """No successful persistence operation is established."""


class CheckoutCommitUnknown(CheckoutUnavailable):
    """Independently read the same attempt; never dispatch or allocate a retry."""


class PaidCheckoutStore:
    def __init__(self, connect: Callable[[], Any]) -> None:
        self._connect = connect

    def prepare(self, attempt_id: str, request: bytes) -> dict[str, Any]:
        return self._call(
            "SELECT gvai_authority.prepare_paid_checkout_v1(%s,%s)",
            (attempt_id, request),
        )

    def read(self, attempt_id: str) -> dict[str, Any]:
        return self._call(
            "SELECT gvai_authority.read_paid_checkout_v1(%s)", (attempt_id,),
        )

    def block(self, attempt_id: str, expected: dict[str, Any], state: str) -> dict[str, Any]:
        from psycopg.types.json import Jsonb

        return self._call(
            "SELECT gvai_authority.block_paid_checkout_v1(%s,%s,%s)",
            (attempt_id, Jsonb(expected), state),
        )

    def _call(self, statement: str, parameters: tuple[Any, ...]) -> dict[str, Any]:
        connection = None
        committing = False
        try:
            connection = self._connect()
            connection.autocommit = False
            with connection.cursor() as cursor:
                cursor.execute(statement, parameters)
                row = cursor.fetchone()
                if row is None or len(row) != 1 or type(row[0]) is not dict:
                    raise ValueError("Invalid Checkout persistence result.")
                result = row[0]
            committing = True
            connection.commit()
        except Exception:
            if connection is not None and not committing:
                try:
                    connection.rollback()
                except Exception:
                    LOG.warning("paid_checkout: rollback_unconfirmed")
            LOG.warning("paid_checkout: commit_unknown" if committing else "paid_checkout: unavailable")
            if committing:
                raise CheckoutCommitUnknown("Checkout commit unknown; independent review required.") from None
            raise CheckoutUnavailable("Checkout persistence unavailable.") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    LOG.warning("paid_checkout: close_unconfirmed")
                    if committing:
                        raise CheckoutCommitUnknown("Checkout outcome requires independent review.") from None
                    raise CheckoutUnavailable("Checkout connection cleanup unavailable.") from None
        return result
