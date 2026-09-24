"""Long-term secret storage: secrets live in the vault, your systems keep only references.

Most company data stays in its own systems. The sharpest values - card
numbers, bank accounts, government IDs, credentials - can instead be moved into
the vault, encrypted with the customer's key. Your database then stores a
reference like `tvref_3f9a...` in place of the real value.

    store = SecretStore(cipher, "secrets.db")
    rows = tokenize_rows(rows, fields=["card_number"], source="crm.customer", owner_field="id")
    # write `rows` back to your database: it no longer holds card numbers

When a task reads a record, the vault swaps each reference for a placeholder
the model sees, and only resolves it to the real value at an allowed sink.
Deleting an owner's secrets (`forget_owner`) or the customer key removes them.
"""

from __future__ import annotations

import hashlib
import hmac
import sqlite3
import threading
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from .audit import private_file
from .crypto import Cipher

PREFIX = "tvref_"


def is_ref(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX) and len(value) == len(PREFIX) + 24


class SecretStore:
    def __init__(self, cipher: Cipher, path: str | Path | None = None):
        self.cipher = cipher
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(private_file(path)) if path else ":memory:", check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS secrets (ref TEXT PRIMARY KEY, source TEXT, field TEXT, "
                         "owner TEXT, blob BLOB)")

    def ref_for(self, value: Any, source: str, field: str) -> str:
        """Deterministic per (source, field, value): the same card always gets the same reference."""
        mac = hmac.new(self.cipher.keys.data_key(), f"ref\x00{source}\x00{field}\x00{value}".encode(),
                       hashlib.sha256)
        return PREFIX + mac.hexdigest()[:24]

    def put(self, value: Any, source: str, field: str, owner: str = "company") -> str:
        ref = self.ref_for(value, source, field)
        blob = self.cipher.encrypt(value, aad=ref)
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO secrets VALUES (?,?,?,?,?)", (ref, source, field, owner, blob))
            self._db.commit()
        return ref

    def get(self, ref: str) -> Any:
        with self._lock:
            row = self._db.execute("SELECT blob FROM secrets WHERE ref=?", (ref,)).fetchone()
        if row is None:
            raise KeyError("unknown or deleted secret reference")
        return self.cipher.decrypt(row[0], aad=ref)

    def forget_owner(self, owner: str) -> int:
        """Delete every secret belonging to one owner (e.g. a customer's right to erasure)."""
        with self._lock:
            n = self._db.execute("DELETE FROM secrets WHERE owner=?", (owner,)).rowcount
            self._db.commit()
        return n

    def __len__(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM secrets").fetchone()[0]


def tokenize_rows(store: SecretStore, rows: Iterable[dict[str, Any]], fields: list[str], source: str,
                  owner_field: str | None = None, owner_name: str | None = None) -> list[dict[str, Any]]:
    """Move secret fields into the store; return rows with references instead (for migrating a table)."""
    out = []
    for row in rows:
        row = dict(row)
        owner = f"{owner_name or owner_field}:{row[owner_field]}" if owner_field else "company"
        for f in fields:
            v = row.get(f)
            if v not in (None, "") and not is_ref(v):
                row[f] = store.put(v, source, f, owner)
        out.append(row)
    return out


class VaultedSource:
    """Wrap a connector so any raw secret it returns is moved into the store on first read."""

    def __init__(self, connector: Callable[[Any], dict | None], store: SecretStore, source: str,
                 fields: list[str], owner_name: str | None = None):
        self.connector, self.store, self.source, self.fields = connector, store, source, fields
        self.owner_name = owner_name

    def __call__(self, key: Any) -> dict | None:
        rec = self.connector(key)
        if rec is None:
            return None
        owner = f"{self.owner_name}:{key}" if self.owner_name else "company"
        return {k: (self.store.put(v, self.source, k, owner) if k in self.fields and v not in (None, "")
                    and not is_ref(v) else v) for k, v in rec.items()}
