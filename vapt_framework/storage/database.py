"""MySQL connection wrapper. Domain models never import this module."""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from vapt_framework.config.settings import Settings
from vapt_framework.core.exceptions import DatabaseConnectionError, DatabasePersistenceError
from vapt_framework.utils.logging import get_logger

logger = get_logger("vapt_framework.storage.database")

_CONNECT_ERROR = (
    "Could not connect to MySQL. "
    "Check VAPT_DB_HOST, VAPT_DB_PORT, VAPT_DB_USER, and VAPT_DB_PASSWORD."
)


class Database:
    """Parameterized MySQL access with explicit connect/close and transactions."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        database: str,
        user: str,
        password: str,
    ) -> None:
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self._password = password
        self._connection: Any = None

    @classmethod
    def from_settings(cls, settings: Settings) -> Database:
        return cls(
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
            user=settings.db_user,
            password=settings.db_password,
        )

    def connect(self) -> None:
        if self._connection is not None:
            return
        try:
            import mysql.connector
        except ImportError as exc:
            raise DatabaseConnectionError(
                "mysql-connector-python is not installed."
            ) from exc
        logger.info(
            "Connecting to MySQL host=%s port=%s database=%s user=%s",
            self.host,
            self.port,
            self.database,
            self.user,
        )
        try:
            self._connection = mysql.connector.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self._password,
                autocommit=False,
            )
        except Exception as exc:  # noqa: BLE001 - map driver errors
            self._connection = None
            raise DatabaseConnectionError(_CONNECT_ERROR) from exc

    def close(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.close()
        finally:
            self._connection = None

    def __enter__(self) -> Database:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def execute(self, sql: str, params: Sequence[Any] | None = None) -> int:
        """Run a statement. Return lastrowid when the driver provides one."""
        cursor = self._cursor()
        try:
            cursor.execute(sql, tuple(params) if params is not None else None)
            last = int(getattr(cursor, "lastrowid", 0) or 0)
            return last
        except DatabaseConnectionError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise DatabasePersistenceError("Database statement failed.") from exc
        finally:
            cursor.close()

    def fetchone(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> dict[str, Any] | None:
        cursor = self._cursor()
        try:
            cursor.execute(sql, tuple(params) if params is not None else None)
            row = cursor.fetchone()
            return dict(row) if row is not None else None
        except DatabaseConnectionError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise DatabasePersistenceError("Database query failed.") from exc
        finally:
            cursor.close()

    def fetchall(
        self, sql: str, params: Sequence[Any] | None = None
    ) -> list[dict[str, Any]]:
        cursor = self._cursor()
        try:
            cursor.execute(sql, tuple(params) if params is not None else None)
            rows = cursor.fetchall() or []
            return [dict(row) for row in rows]
        except DatabaseConnectionError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise DatabasePersistenceError("Database query failed.") from exc
        finally:
            cursor.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        conn = self._require()
        try:
            yield
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _require(self) -> Any:
        if self._connection is None:
            raise DatabaseConnectionError("MySQL connection is not open.")
        return self._connection

    def _cursor(self) -> Any:
        conn = self._require()
        try:
            return conn.cursor(dictionary=True)
        except Exception as exc:  # noqa: BLE001
            raise DatabasePersistenceError("Database cursor failed.") from exc
