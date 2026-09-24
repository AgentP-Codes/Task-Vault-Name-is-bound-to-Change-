"""Read-through cache: the vault fetches from the customer's systems on demand and
keeps a short-lived, encrypted copy. Company data stays in its own systems; the
vault never holds a permanent full copy.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .audit import private_file
from .crypto import Cipher


class EncryptedCache:
    def __init__(self, cipher: Cipher, ttl_seconds: float = 300, path: str | Path | None = None,
                 clock: Callable[[], float] = time.time):
        self.cipher, self.ttl, self.clock = cipher, ttl_seconds, clock
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(private_file(path)) if path else ":memory:", check_same_thread=False)
        self._db.execute("CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, src TEXT, blob BLOB, expires REAL)")

    def _key(self, source: str, key: Any) -> str:
        # keyed fingerprint so the cache index doesn't reveal record ids
        return self.cipher.fingerprint(f"{source}\x00{key}")

    def get(self, source: str, key: Any) -> dict | None:
        k = self._key(source, key)
        with self._lock:
            row = self._db.execute("SELECT blob, expires FROM cache WHERE k=?", (k,)).fetchone()
        if not row:
            return None
        if row[1] <= self.clock():
            self.delete(source, key)
            return None
        return self.cipher.decrypt(row[0], aad=k)

    def put(self, source: str, key: Any, record: dict) -> None:
        k = self._key(source, key)
        blob = self.cipher.encrypt(record, aad=k)
        with self._lock:
            self._db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?,?)",
                             (k, source, blob, self.clock() + self.ttl))
            self._db.commit()

    def delete(self, source: str, key: Any) -> None:
        with self._lock:
            self._db.execute("DELETE FROM cache WHERE k=?", (self._key(source, key),))
            self._db.commit()

    def invalidate_source(self, source: str) -> None:
        """Drop every cached record from one source (e.g. after the agent writes to it)."""
        with self._lock:
            self._db.execute("DELETE FROM cache WHERE src=?", (source,))
            self._db.commit()

    def purge_expired(self) -> int:
        with self._lock:
            n = self._db.execute("DELETE FROM cache WHERE expires<=?", (self.clock(),)).rowcount
            self._db.commit()
        return n

    def clear(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM cache")
            self._db.commit()

    def __len__(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
