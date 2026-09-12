"""In-memory Database stand-in for unit tests (no MySQL)."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from vapt_framework.core.exceptions import DatabasePersistenceError


class FakeDatabase:
    """Records parameterized calls and can simulate commit/rollback/failure."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, tuple[Any, ...] | None]] = []
        self.closed = False
        self.committed = False
        self.rolled_back = False
        self.in_transaction = False
        self._next_id = 0
        self.fail_sql: str | None = None
        self.fetchone_result: dict[str, Any] | None = None
        self.fetchall_result: list[dict[str, Any]] = []
        self.connected = True

    def connect(self) -> None:
        self.connected = True
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self.connected = False

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> int:
        self._maybe_fail(sql)
        packed = tuple(params) if params is not None else None
        self.calls.append(("execute", sql, packed))
        if sql.strip().upper().startswith("INSERT"):
            self._next_id += 1
            return self._next_id
        return 0

    def fetchone(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any] | None:
        self._maybe_fail(sql)
        packed = tuple(params) if params is not None else None
        self.calls.append(("fetchone", sql, packed))
        return self.fetchone_result

    def fetchall(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        self._maybe_fail(sql)
        packed = tuple(params) if params is not None else None
        self.calls.append(("fetchall", sql, packed))
        return list(self.fetchall_result)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        self.in_transaction = True
        self.committed = False
        self.rolled_back = False
        try:
            yield
            self.committed = True
        except Exception:
            self.rolled_back = True
            self.committed = False
            raise
        finally:
            self.in_transaction = False

    def _maybe_fail(self, sql: str) -> None:
        if self.fail_sql and self.fail_sql.lower() in sql.lower():
            raise DatabasePersistenceError("forced failure")

    def sql_texts(self) -> list[str]:
        return [item[1] for item in self.calls]
