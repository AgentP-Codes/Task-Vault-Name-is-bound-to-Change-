"""Tamper-evident, hash-chained audit log.

Each entry stores the SHA-256 of the previous entry, so editing, reordering or
deleting any line breaks the chain and `verify()` fails. Raw sensitive values
are never written: only field names, keyed fingerprints and decisions.

The file is created with owner-only permissions and appended to under a lock.
Set `fsync=True` to force each entry to disk before the action runs (slower,
but nothing is lost if the machine crashes). Ship the file to your SIEM or
write-once storage for stronger guarantees: a chain proves order and integrity,
not that the newest entries weren't truncated by someone with file access.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .errors import TaskvaultError

GENESIS = "0" * 64


class AuditError(TaskvaultError):
    pass


def _digest(entry: dict[str, Any]) -> str:
    body = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def private_file(path: str | Path) -> Path:
    """Create `path` (and its folder) with owner-only permissions if it doesn't exist."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
    return path


class AuditLog:
    def __init__(self, path: str | Path | None = None, fsync: bool = False):
        self.path = private_file(Path(path).resolve()) if path else None   # absolute: survives chdir
        self.fsync = fsync
        self._lock = threading.Lock()
        self.entries: list[dict[str, Any]] = []
        if self.path:
            for n, line in enumerate(self.path.read_text().splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    self.entries.append(json.loads(line))
                except json.JSONDecodeError as e:
                    raise AuditError(f"{self.path}:{n} is not valid JSON; the log may be damaged") from e

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            entry = {"seq": len(self.entries), "ts": round(time.time(), 3), "event": event,
                     **fields, "prev": self.head}
            entry["hash"] = _digest(entry)
            if self.path:
                with self.path.open("a") as f:
                    f.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
                    if self.fsync:
                        f.flush()
                        os.fsync(f.fileno())
            self.entries.append(entry)
            return entry

    def verify(self) -> bool:
        return self.first_bad_entry() is None

    def first_bad_entry(self) -> int | None:
        """Index of the first entry that breaks the chain, or None if it's intact."""
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("seq") != i or entry.get("prev") != prev or _digest(body) != entry.get("hash"):
                return i
            prev = entry["hash"]
        return None

    def decisions(self, decision: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("decision") == decision]
