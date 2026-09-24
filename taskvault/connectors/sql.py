"""SQL databases via any DB-API 2.0 driver (sqlite3, psycopg, mysqlclient, ...)."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
PLACEHOLDER = {"qmark": "?", "format": "%s", "pyformat": "%s", "numeric": ":1", "named": ":k"}


def _ident(name: str) -> str:
    if not IDENT.match(name):
        raise ValueError(f"invalid SQL identifier {name!r}")
    return name


class SQLConnector:
    """Read one row by key. Only the listed columns are ever selected.

        SQLConnector(lambda: psycopg.connect(DSN), "customers", key_column="id",
                     columns=["id", "name", "email", "card_number"], paramstyle="format")
    """

    def __init__(self, connect: Callable[[], Any], table: str, key_column: str,
                 columns: list[str] | None = None, paramstyle: str = "qmark"):
        self.connect, self.table, self.key = connect, _ident(table), _ident(key_column)
        self.columns = [_ident(c) for c in columns] if columns else None
        self.ph = PLACEHOLDER[paramstyle]

    def __call__(self, key: Any) -> dict | None:
        cols = ", ".join(self.columns) if self.columns else "*"
        sql = f"SELECT {cols} FROM {self.table} WHERE {self.key} = {self.ph}"   # noqa: S608 - identifiers validated
        params: Any = {"k": key} if self.ph == ":k" else (key,)
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(sql, params)
            row = cur.fetchone()
            if row is None:
                return None
            names = [d[0] for d in cur.description]
            return dict(zip(names, row, strict=False))
        finally:
            conn.close()


class SQLSink:
    """Update allowed columns of one row: sink(key=..., **fields)."""

    def __init__(self, connect: Callable[[], Any], table: str, key_column: str,
                 writable: list[str], paramstyle: str = "qmark"):
        self.connect, self.table, self.key = connect, _ident(table), _ident(key_column)
        self.writable = {_ident(c) for c in writable}
        self.ph = PLACEHOLDER[paramstyle]
        if self.ph in (":1", ":k"):
            raise ValueError("SQLSink supports qmark/format/pyformat paramstyles")

    def __call__(self, key: Any, **fields: Any) -> int:
        bad = set(fields) - self.writable
        if bad or not fields:
            raise ValueError(f"columns not writable: {sorted(bad) or 'none given'}")
        sets = ", ".join(f"{c} = {self.ph}" for c in fields)
        sql = f"UPDATE {self.table} SET {sets} WHERE {self.key} = {self.ph}"   # noqa: S608
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(sql, (*fields.values(), key))
            conn.commit()
            return cur.rowcount
        finally:
            conn.close()
