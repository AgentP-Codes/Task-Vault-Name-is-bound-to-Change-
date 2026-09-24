"""Deposit boxes: each holder's data in its own encrypted box, like a bank's safe deposit boxes.

Holders are departments (``department:hr``), individual customers
(``customer:12``) or client companies (``client:acme``). Each holder has its
own boxes, stored as rows in SQLite or Postgres.

Two tiers:

  normal   basic information. The box has its own data key, locked by the
           vault's key, so the vault can open it whenever the policy allows.
  high     higher-tier information (secrets by default). Every item is sealed
           to the holder's *public* key and then locked again with the vault's
           key. Opening needs BOTH keys: the vault's and the holder's. Like a
           deposit slot, anyone can put something in; only the holder's key
           (plus the bank's) gets it out.

Opening a high box asks the holder's key service for the private key. That
service can require a person to approve, and the key is kept in memory only
for a short window (`open_ttl`), then wiped. Every deposit, opening and
withdrawal is written to a per-box, hash-chained log. `forget_holder` deletes a
holder's boxes; an optional company recovery key lets you restore access if a
holder loses theirs.

Performance: crypto is microseconds per item; boxes are rows, so millions of
boxes cost what millions of rows cost. The slow part is fetching a holder's
private key (a network call or a human approval), which is cached per open.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .audit import private_file
from .crypto import KeyProvider, KeyUnavailable
from .errors import TaskvaultError

HOLDER_TYPES = ("department", "customer", "client")
TIERS = ("normal", "high")
REF_RE = re.compile(r"^tvbox:(box_[0-9a-f]{24}):([0-9a-f]{24})$")


class BoxLocked(TaskvaultError):
    """A high-tier box couldn't be opened: the holder's key was unavailable or access was denied."""


def is_box_ref(value: Any) -> bool:
    return isinstance(value, str) and bool(REF_RE.match(value))


def holder_name(kind: str, ident: Any) -> str:
    if kind not in HOLDER_TYPES:
        raise ValueError(f"holder type must be one of {HOLDER_TYPES}")
    ident = str(ident)
    if not ident or ":" in ident:
        raise ValueError("holder id must be non-empty and contain no ':'")
    return f"{kind}:{ident}"


# ------------------------------------------------------------------ holder keys
@dataclass
class OpenRequest:
    holder: str
    box_id: str
    task: Any
    reason: str


class HolderKeys(Protocol):
    def public_key(self, holder: str) -> bytes: ...

    def private_key(self, request: OpenRequest) -> bytes | None: ...


class LocalHolderKeys:
    """Holder key pairs as files in a folder (one per holder, owner-only permissions).

    Suitable for departments and testing. For customers or client companies,
    implement `HolderKeys` against their own key service, so the private key
    never sits with you. `approver` can require a person to allow each opening.
    """

    def __init__(self, folder: str | Path, approver: Callable[[OpenRequest], bool] | None = None):
        self.folder, self.approver = Path(folder), approver
        self.folder.mkdir(parents=True, exist_ok=True)

    def _path(self, holder: str) -> Path:
        return self.folder / (holder.replace(":", "__") + ".key")

    def create(self, holder: str) -> Path:
        path = self._path(holder)
        if path.exists():
            raise FileExistsError(f"{holder} already has a key")
        raw = X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        private_file(path).write_bytes(base64.b64encode(raw))
        return path

    def public_key(self, holder: str) -> bytes:
        return _public_of(self._private(holder))

    def private_key(self, request: OpenRequest) -> bytes | None:
        if self.approver is not None and not self.approver(request):
            return None
        return self._private(request.holder)

    def _private(self, holder: str) -> bytes:
        path = self._path(holder)
        if not path.exists():
            raise KeyUnavailable(f"no key for {holder}")
        return base64.b64decode(path.read_bytes())


class StaticHolderKeys:
    """In-memory holder keys (tests, or wrapping keys fetched elsewhere)."""

    def __init__(self, private_keys: dict[str, bytes] | None = None,
                 approver: Callable[[OpenRequest], bool] | None = None):
        self.keys = dict(private_keys or {})
        self.approver = approver

    def create(self, holder: str) -> bytes:
        raw = X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        self.keys[holder] = raw
        return raw

    def public_key(self, holder: str) -> bytes:
        if holder not in self.keys:
            raise KeyUnavailable(f"no key for {holder}")
        return _public_of(self.keys[holder])

    def private_key(self, request: OpenRequest) -> bytes | None:
        if self.approver is not None and not self.approver(request):
            return None
        return self.keys.get(request.holder)


def _public_of(private_raw: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(private_raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _seal_to(public_raw: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Anonymous public-key encryption: X25519 + HKDF + AES-GCM. Output: eph_pub(32) | nonce(12) | ct."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(public_raw))
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key = HKDF(SHA256(), 32, salt=eph_pub + public_raw, info=b"taskvault-box" + aad).derive(shared)
    nonce = os.urandom(12)
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _open_from(private_raw: bytes, blob: bytes, aad: bytes) -> bytes:
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    priv = X25519PrivateKey.from_private_bytes(private_raw)
    my_pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(SHA256(), 32, salt=eph_pub + my_pub, info=b"taskvault-box" + aad).derive(shared)
    return AESGCM(key).decrypt(nonce, ct, aad)


# ------------------------------------------------------------------- database
class BoxDB:
    """Minimal SQLite / Postgres adapter. Statements use `?`; converted for Postgres."""

    def __init__(self, url: str | Path):
        self._lock = threading.RLock()
        url = str(url)
        if url.startswith(("postgresql://", "postgres://")):
            import psycopg  # optional: pip install "taskvault[postgres]"
            self.dialect = "postgres"
            self.conn = psycopg.connect(url, autocommit=True)
            self.conn.execute("SELECT pg_advisory_lock(7428101)")   # one connection creates the tables at a time
        else:
            path = url[len("sqlite:///"):] if url.startswith("sqlite:///") else url
            self.dialect = "sqlite"
            target = ":memory:" if path == ":memory:" else str(private_file(Path(path).resolve()))
            self.conn = sqlite3.connect(target, check_same_thread=False, isolation_level=None, timeout=30)
            self.conn.execute("PRAGMA busy_timeout=30000")            # wait for other writers, don't fail
            if target != ":memory:":
                # readers don't block writers. Switching a brand-new file to WAL needs an exclusive
                # lock that SQLite won't wait for, so retry briefly if another connection is doing it too.
                _retry_locked(lambda: self.conn.execute("PRAGMA journal_mode=WAL"))
            self.conn.execute("PRAGMA synchronous=NORMAL")
        blob = "BYTEA" if self.dialect == "postgres" else "BLOB"
        real = "DOUBLE PRECISION" if self.dialect == "postgres" else "REAL"
        for ddl in [
            f"CREATE TABLE IF NOT EXISTS tv_boxes (box_id TEXT PRIMARY KEY, holder_fp TEXT NOT NULL, "
            f"holder_label {blob} NOT NULL, tier TEXT NOT NULL, wrapped_dek {blob}, created {real} NOT NULL)",
            "CREATE INDEX IF NOT EXISTS tv_boxes_holder ON tv_boxes (holder_fp)",
            f"CREATE TABLE IF NOT EXISTS tv_items (box_id TEXT NOT NULL, item TEXT NOT NULL, "
            f"blob {blob} NOT NULL, recovery {blob}, PRIMARY KEY (box_id, item))",
            "CREATE TABLE IF NOT EXISTS tv_index (record_fp TEXT NOT NULL, field_fp TEXT NOT NULL, "
            "box_id TEXT NOT NULL, item TEXT NOT NULL, PRIMARY KEY (record_fp, field_fp))",
            f"CREATE TABLE IF NOT EXISTS tv_box_log (box_id TEXT NOT NULL, seq INTEGER NOT NULL, ts {real} NOT NULL, "
            "event TEXT NOT NULL, detail TEXT NOT NULL, prev TEXT NOT NULL, hash TEXT NOT NULL, "
            "PRIMARY KEY (box_id, seq))",
        ]:
            _retry_locked(lambda ddl=ddl: self.execute(ddl))
        if self.dialect == "postgres":
            self.conn.execute("SELECT pg_advisory_unlock(7428101)")

    def lock(self, key: str) -> None:
        """Inside a transaction: serialise writers working on the same key (e.g. one box).
        SQLite transactions already take the write lock up front, so only Postgres needs this."""
        if self.dialect == "postgres":
            self.execute("SELECT pg_advisory_xact_lock(hashtext(?))", (key,))

    def execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        if self.dialect == "postgres":
            sql = sql.replace("?", "%s")
        with self._lock:
            cur = self.conn.execute(sql, params)
            try:
                rows = cur.fetchall()
            except Exception:  # noqa: BLE001 - statements without results
                rows = []
        return [tuple(bytes(v) if isinstance(v, memoryview) else v for v in r) for r in rows]

    def upsert(self, table: str, cols: list[str], values: tuple, key: list[str]) -> None:
        ph = ", ".join("?" for _ in cols)
        if self.dialect == "postgres":
            updates = ", ".join(f"{c}=EXCLUDED.{c}" for c in cols if c not in key)
            sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({ph}) ON CONFLICT ({', '.join(key)}) " + \
                  (f"DO UPDATE SET {updates}" if updates else "DO NOTHING")
        else:
            sql = f"INSERT OR REPLACE INTO {table} ({', '.join(cols)}) VALUES ({ph})"
        self.execute(sql, values)

    def transaction(self):
        return _Tx(self)

    def close(self) -> None:
        self.conn.close()


def _retry_locked(fn: Any, seconds: float = 30.0) -> Any:
    """Run fn, retrying while SQLite reports the database as locked (setup steps only)."""
    deadline = time.monotonic() + seconds
    delay = 0.01
    while True:
        try:
            return fn()
        except sqlite3.OperationalError as e:
            if "locked" not in str(e) or time.monotonic() > deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.5)


class _Tx:
    def __init__(self, db: BoxDB):
        self.db = db

    def __enter__(self):
        self.db._lock.acquire()
        # SQLite: take the write lock at the start, so two writers can't deadlock upgrading later.
        self.db.conn.execute("BEGIN IMMEDIATE" if self.db.dialect == "sqlite" else "BEGIN")
        return self.db

    def __exit__(self, exc_type, exc, tb):
        try:
            self.db.conn.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.db._lock.release()
        return False


# ------------------------------------------------------------------ box store
@dataclass
class BoxInfo:
    box_id: str
    holder: str
    tier: str
    items: int
    created: float


class BoxStore:
    def __init__(self, db: BoxDB | str | Path, vault_keys: KeyProvider, holder_keys: HolderKeys | None = None,
                 recovery_public_key: bytes | None = None, open_ttl: float = 300,
                 tiers: dict[str, str] | None = None, clock: Callable[[], float] = time.time):
        self.db = db if isinstance(db, BoxDB) else BoxDB(db)
        self.vault_keys, self.holder_keys = vault_keys, holder_keys
        self.recovery_public_key = recovery_public_key
        self.open_ttl, self.clock = open_ttl, clock
        self.tiers = {"secret": "high", "protected": "normal", "normal": "normal", **(tiers or {})}
        self._open: dict[str, tuple[bytes, float]] = {}      # holder -> (private key, expires)
        self._lock = threading.Lock()

    # --------------------------------------------------------------- helpers
    def _mac(self, *parts: Any) -> str:
        msg = "\x00".join(str(p) for p in parts).encode()
        return hmac.new(self.vault_keys.data_key(), msg, hashlib.sha256).hexdigest()

    def _vault(self) -> AESGCM:
        return AESGCM(self.vault_keys.data_key())

    def box_id(self, holder: str, tier: str) -> str:
        return "box_" + self._mac("box", holder, tier)[:24]

    def _lock_vault(self, data: bytes, aad: str) -> bytes:
        n = os.urandom(12)
        return n + self._vault().encrypt(n, data, aad.encode())

    def _unlock_vault(self, blob: bytes, aad: str) -> bytes:
        try:
            return self._vault().decrypt(blob[:12], blob[12:], aad.encode())
        except Exception as e:  # noqa: BLE001 - InvalidTag
            raise KeyUnavailable("vault key can't open this box (wrong key or tampered data)") from e

    # ------------------------------------------------------------------ boxes
    def ensure_box(self, holder: str, tier: str) -> str:
        if tier not in TIERS:
            raise ValueError(f"tier must be one of {TIERS}")
        kind = holder.split(":", 1)[0]
        if kind not in HOLDER_TYPES and holder != "company":
            raise ValueError("holder must look like department:x, customer:x, client:x or 'company'")
        box = self.box_id(holder, tier)
        if self.db.execute("SELECT 1 FROM tv_boxes WHERE box_id=?", (box,)):
            return box
        if tier == "high":
            if self.holder_keys is None:
                raise BoxLocked("high-tier boxes need holder keys (holder_keys=...)")
            self.holder_keys.public_key(holder)            # fail early if the holder has no key
            dek = None
        else:
            dek = self._lock_vault(AESGCM.generate_key(bit_length=256), f"{box}|dek")
        label = self._lock_vault(holder.encode(), f"{box}|label")
        with self.db.transaction() as db:
            db.lock(box)
            if db.execute("SELECT 1 FROM tv_boxes WHERE box_id=?", (box,)):
                return box                # another writer created it first: keep ITS key, never replace it
            db.execute("INSERT INTO tv_boxes (box_id, holder_fp, holder_label, tier, wrapped_dek, created) "
                       "VALUES (?,?,?,?,?,?)", (box, self._mac("holder", holder), label, tier, dek, self.clock()))
            self._log(box, "created", {"tier": tier}, db=db)
        return box

    def _box_dek(self, box: str) -> bytes:
        rows = self.db.execute("SELECT wrapped_dek FROM tv_boxes WHERE box_id=?", (box,))
        if not rows:
            raise KeyError("no such box")
        return self._unlock_vault(rows[0][0], f"{box}|dek")

    def _holder_of(self, box: str) -> tuple[str, str]:
        rows = self.db.execute("SELECT holder_label, tier FROM tv_boxes WHERE box_id=?", (box,))
        if not rows:
            raise KeyError("no such box (it may have been forgotten)")
        return self._unlock_vault(rows[0][0], f"{box}|label").decode(), rows[0][1]

    # ------------------------------------------------------------- deposit
    def deposit(self, holder: str, tier: str, item: str, value: Any) -> str:
        """Put one value in a box. Returns the item id. High tier needs only the holder's PUBLIC key."""
        box = self.ensure_box(holder, tier)
        item_id = self._mac("item", box, item)[:24]
        plain = json.dumps(value).encode()
        aad = f"{box}|{item_id}"
        recovery = None
        if tier == "high":
            if self.holder_keys is None:
                raise BoxLocked("high-tier boxes need holder keys (holder_keys=...)")
            inner = _seal_to(self.holder_keys.public_key(holder), plain, aad.encode())
            blob = self._lock_vault(inner, aad)
            if self.recovery_public_key:
                recovery = self._lock_vault(_seal_to(self.recovery_public_key, plain, aad.encode()), aad + "|rec")
        else:
            n = os.urandom(12)
            blob = n + AESGCM(self._box_dek(box)).encrypt(n, plain, aad.encode())
        self.db.upsert("tv_items", ["box_id", "item", "blob", "recovery"], (box, item_id, blob, recovery),
                       ["box_id", "item"])
        self._log(box, "deposit", {"item": item_id})
        return item_id

    def store_record(self, source: str, key: Any, record: dict[str, Any], holder: str,
                     levels: dict[str, str]) -> dict[str, str]:
        """Split a record into the holder's normal and high boxes by each field's level."""
        record_fp = self._mac("record", source, key)
        placed = {}
        for f, v in record.items():
            tier = self.tiers.get(levels.get(f, "protected"), "normal")
            item_id = self.deposit(holder, tier, f"{source}\x00{key}\x00{f}", v)
            self.db.upsert("tv_index", ["record_fp", "field_fp", "box_id", "item"],
                           (record_fp, self._mac("field", f), self.box_id(holder, tier), item_id),
                           ["record_fp", "field_fp"])
            placed[f] = tier
        self._field_names(record_fp, list(record))
        return placed

    def _field_names(self, record_fp: str, fields: list[str]) -> None:
        # the list of field names is itself stored encrypted, so the index reveals no schema
        box = "box_index"
        blob = self._lock_vault(json.dumps(fields).encode(), f"{record_fp}|fields")
        self.db.upsert("tv_index", ["record_fp", "field_fp", "box_id", "item"],
                       (record_fp, "__fields__", box, base64.b64encode(blob).decode()), ["record_fp", "field_fp"])

    # ---------------------------------------------------------- withdraw
    def fetch_record(self, source: str, key: Any, task: Any = None) -> dict[str, Any] | None:
        """Normal-tier fields come back as values; high-tier fields as `tvbox:` references
        that can only be revealed later, with the holder's key."""
        record_fp = self._mac("record", source, key)
        rows = self.db.execute("SELECT item FROM tv_index WHERE record_fp=? AND field_fp='__fields__'",
                               (record_fp,))
        if not rows:
            return None
        fields = json.loads(self._unlock_vault(base64.b64decode(rows[0][0]), f"{record_fp}|fields"))
        out: dict[str, Any] = {}
        for f in fields:
            idx = self.db.execute("SELECT box_id, item FROM tv_index WHERE record_fp=? AND field_fp=?",
                                  (record_fp, self._mac("field", f)))
            if not idx:
                continue
            box, item = idx[0]
            _, tier = self._holder_of(box)
            if tier == "high":
                out[f] = f"tvbox:{box}:{item}"
            else:
                out[f] = self._read_normal(box, item, task)
        return out or None

    def _read_normal(self, box: str, item: str, task: Any) -> Any:
        rows = self.db.execute("SELECT blob FROM tv_items WHERE box_id=? AND item=?", (box, item))
        if not rows:
            raise KeyError("item not found")
        blob = rows[0][0]
        plain = AESGCM(self._box_dek(box)).decrypt(blob[:12], blob[12:], f"{box}|{item}".encode())
        self._log(box, "read", {"item": item, "task": task})
        return json.loads(plain)

    def reveal(self, ref: str, task: Any = None, reason: str = "") -> Any:
        """Open a high-tier item. Needs the vault key AND the holder's private key (maybe with approval)."""
        m = REF_RE.match(ref)
        if not m:
            raise ValueError("not a box reference")
        box, item = m.groups()
        holder, tier = self._holder_of(box)
        rows = self.db.execute("SELECT blob FROM tv_items WHERE box_id=? AND item=?", (box, item))
        if not rows:
            raise KeyError("item not found (it may have been forgotten)")
        aad = f"{box}|{item}"
        inner = self._unlock_vault(rows[0][0], aad)                  # key 1: the vault's
        private = self._holder_private(holder, box, task, reason)    # key 2: the holder's
        try:
            plain = _open_from(private, inner, aad.encode())
        except Exception as e:  # noqa: BLE001
            self._log(box, "open_failed", {"item": item, "task": task})
            raise BoxLocked("the holder's key didn't open this box") from e
        self._log(box, "reveal", {"item": item, "task": task, "reason": reason})
        return json.loads(plain)

    def _holder_private(self, holder: str, box: str, task: Any, reason: str) -> bytes:
        now = self.clock()
        with self._lock:
            cached = self._open.get(holder)
            if cached and cached[1] > now:
                return cached[0]
            self._open.pop(holder, None)
        if self.holder_keys is None:
            raise BoxLocked("no holder key service configured")
        try:
            key = self.holder_keys.private_key(OpenRequest(holder, box, task, reason))
        except KeyUnavailable as e:
            raise BoxLocked(str(e)) from e
        if not key:
            self._log(box, "open_denied", {"task": task, "reason": reason})
            raise BoxLocked(f"{holder.split(':')[0]} key holder did not allow this box to be opened")
        with self._lock:
            self._open[holder] = (key, now + self.open_ttl)
        self._log(box, "opened", {"task": task, "for_seconds": self.open_ttl})
        return key

    def close_all(self) -> None:
        """Forget every holder key held in memory (call at the end of a task or on shutdown)."""
        with self._lock:
            self._open.clear()

    def recover(self, ref: str, recovery_private_key: bytes) -> Any:
        """Company break-glass: read a high-tier item with the recovery key instead of the holder's."""
        m = REF_RE.match(ref) if isinstance(ref, str) else None
        if not m:
            raise ValueError("not a box reference")
        box, item = m.groups()
        rows = self.db.execute("SELECT recovery FROM tv_items WHERE box_id=? AND item=?", (box, item))
        if not rows or rows[0][0] is None:
            raise BoxLocked("no recovery copy for this item")
        aad = f"{box}|{item}"
        plain = _open_from(recovery_private_key, self._unlock_vault(rows[0][0], aad + "|rec"), aad.encode())
        self._log(box, "recovered", {"item": item})
        return json.loads(plain)

    # ------------------------------------------------------------- admin
    def forget_holder(self, holder: str) -> int:
        """Delete all of one holder's boxes and their contents. The per-box logs keep a 'forgotten' entry."""
        fp = self._mac("holder", holder)
        boxes = [r[0] for r in self.db.execute("SELECT box_id FROM tv_boxes WHERE holder_fp=?", (fp,))]
        with self._lock:
            self._open.pop(holder, None)
        n = 0
        for box in boxes:
            with self.db.transaction() as db:
                n += len(db.execute("SELECT item FROM tv_items WHERE box_id=?", (box,)))
                db.execute("DELETE FROM tv_items WHERE box_id=?", (box,))
                db.execute("DELETE FROM tv_index WHERE box_id=?", (box,))
                db.execute("DELETE FROM tv_boxes WHERE box_id=?", (box,))
            self._log(box, "forgotten", {})
        return n

    def boxes(self) -> list[BoxInfo]:
        out = []
        for box, label, tier, created in self.db.execute(
                "SELECT box_id, holder_label, tier, created FROM tv_boxes ORDER BY created"):
            n = self.db.execute("SELECT COUNT(*) FROM tv_items WHERE box_id=?", (box,))[0][0]
            out.append(BoxInfo(box, self._unlock_vault(label, f"{box}|label").decode(), tier, n, created))
        return out

    # --------------------------------------------------------------- logs
    def _log(self, box: str, event: str, detail: dict[str, Any], db: BoxDB | None = None) -> None:
        """Append to the box's hash-chained log (inside the caller's transaction, or a new one)."""
        if db is None:
            with self.db.transaction() as tx:
                self._log(box, event, detail, db=tx)
            return
        db.lock(box)
        last = db.execute("SELECT seq, hash FROM tv_box_log WHERE box_id=? ORDER BY seq DESC LIMIT 1", (box,))
        seq, prev = (last[0][0] + 1, last[0][1]) if last else (0, "0" * 64)
        ts = round(self.clock(), 3)
        body = json.dumps({"box": box, "seq": seq, "ts": ts, "event": event, "detail": detail, "prev": prev},
                          sort_keys=True, default=str)
        digest = hashlib.sha256(body.encode()).hexdigest()
        db.execute("INSERT INTO tv_box_log (box_id, seq, ts, event, detail, prev, hash) VALUES (?,?,?,?,?,?,?)",
                   (box, seq, ts, event, json.dumps(detail, sort_keys=True, default=str), prev, digest))

    def log(self, box: str) -> list[dict[str, Any]]:
        rows = self.db.execute("SELECT seq, ts, event, detail, prev, hash FROM tv_box_log WHERE box_id=? ORDER BY seq",
                               (box,))
        return [{"seq": s, "ts": t, "event": e, "detail": json.loads(d), "prev": p, "hash": h}
                for s, t, e, d, p, h in rows]

    def verify_log(self, box: str) -> bool:
        prev = "0" * 64
        for e in self.log(box):
            body = json.dumps({"box": box, "seq": e["seq"], "ts": e["ts"], "event": e["event"],
                               "detail": e["detail"], "prev": prev}, sort_keys=True, default=str)
            if e["prev"] != prev or hashlib.sha256(body.encode()).hexdigest() != e["hash"]:
                return False
            prev = e["hash"]
        return True


class BoxSource:
    """A vault source backed by deposit boxes: `Vault(sources={"crm.customer": BoxSource(store, "crm.customer")})`."""

    def __init__(self, store: BoxStore, source: str):
        self.store, self.source = store, source

    def __call__(self, key: Any) -> dict | None:
        return self.store.fetch_record(self.source, key)


def box_sources(policy: Any, store: BoxStore) -> dict[str, BoxSource]:
    """Sources for every policy source marked `storage: boxes`."""
    return {name: BoxSource(store, name) for name, src in policy.sources.items() if src.storage == "boxes"}
