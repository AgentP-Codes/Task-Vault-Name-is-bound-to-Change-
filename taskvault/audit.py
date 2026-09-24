"""Tamper-evident, hash-chained audit log.

Each entry stores the SHA-256 of the previous entry, so editing, reordering or
deleting any line breaks the chain and `verify()` fails. Raw sensitive values
are never written: only field names, keyed fingerprints and decisions.

The file is created with owner-only permissions and appended to under a lock. The lock is an
operating-system file lock, so several processes (e.g. web-server workers) can share one file:
each entry chains from whatever entry is really last in the file.
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
                    hint = (" If the machine crashed while writing, run `taskvault audit repair` to set the "
                            "unfinished last line aside." if n == len(self.path.read_text().splitlines()) else "")
                    raise AuditError(f"{self.path}:{n} is not valid JSON; the log may be damaged.{hint}") from e

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            if not self.path:
                entry = {"seq": len(self.entries), "ts": round(time.time(), 3), "event": event,
                         **fields, "prev": self.head}
                entry["hash"] = _digest(entry)
                self.entries.append(entry)
                return entry
            with self.path.open("a+b") as f, _file_lock(f):
                last = _last_line(f)                      # another process may have written since
                seq, prev = (last["seq"] + 1, last["hash"]) if last else (0, GENESIS)
                entry = {"seq": seq, "ts": round(time.time(), 3), "event": event, **fields, "prev": prev}
                entry["hash"] = _digest(entry)
                f.seek(0, os.SEEK_END)
                f.write((json.dumps(entry, sort_keys=True, default=str) + "\n").encode())
                f.flush()
                if self.fsync:
                    os.fsync(f.fileno())
            self.entries.append(entry)
            return entry

    def verify(self) -> bool:
        """True if the whole chain is intact. With several writers, verify a freshly loaded log
        (`AuditLog(path).verify()`): this object only holds the entries it wrote itself."""
        return self.first_bad_entry() is None

    def first_bad_entry(self) -> int | None:
        """Index of the first entry that breaks the chain, or None if it's intact."""
        # With a file, check the file itself: other processes may have added entries between ours.
        entries = AuditLog(self.path).entries if self.path else self.entries
        prev = GENESIS
        for i, entry in enumerate(entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("seq") != i or entry.get("prev") != prev or _digest(body) != entry.get("hash"):
                return i
            prev = entry["hash"]
        return None

    @staticmethod
    def repair(path: str | Path) -> Path | None:
        """Set aside an unfinished LAST line (left by a crash mid-write) so the log can be used again.

        Only the final line is ever moved, into `<file>.torn-<time>`; damage anywhere else is left
        alone, because that isn't what a crash looks like. Returns the side file, or None.
        """
        path = Path(path)
        data = path.read_bytes()
        body, sep, tail = data.rstrip(b"\n").rpartition(b"\n")
        last = tail if sep else data.rstrip(b"\n")
        try:
            json.loads(last)
            AuditLog(path)                                # raises if the damage is anywhere else
            return None                                   # last line is fine: nothing to repair
        except json.JSONDecodeError:
            pass
        side = path.with_name(f"{path.name}.torn-{int(time.time())}")
        side.write_bytes(last)
        with path.open("r+b") as f:
            f.truncate(len(body) + len(sep) if sep else 0)
        AuditLog(path)                                    # the rest must now load cleanly
        return side

    def decisions(self, decision: str) -> list[dict[str, Any]]:
        return [e for e in self.entries if e.get("decision") == decision]


def _last_line(f) -> dict[str, Any] | None:
    """The last complete entry in an open binary file, reading backwards from the end."""
    f.seek(0, os.SEEK_END)
    end = f.tell()
    if end == 0:
        return None
    chunk, pos, data = 65536, end, b""
    while pos > 0:
        step = min(chunk, pos)
        pos -= step
        f.seek(pos)
        data = f.read(step) + data
        lines = data.rstrip(b"\n").split(b"\n")
        if len(lines) > 1 or pos == 0:
            try:
                return json.loads(lines[-1])
            except json.JSONDecodeError as e:
                raise AuditError(f"the last line of {f.name} is not valid JSON; the log may be damaged") from e
    return None


class _file_lock:
    """Exclusive OS-level lock on an open file, across processes (POSIX flock / Windows locking)."""

    def __init__(self, f):
        self.f = f

    def __enter__(self):
        if os.name == "nt":  # pragma: no cover - exercised on Windows only
            import msvcrt
            self.f.seek(0)
            while True:
                try:
                    msvcrt.locking(self.f.fileno(), msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(self.f.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if os.name == "nt":  # pragma: no cover
            import msvcrt
            self.f.seek(0)
            msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.f.fileno(), fcntl.LOCK_UN)
        return False
