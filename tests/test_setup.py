import importlib.util
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

from taskvault import Blocked, Policy
from taskvault.cli import main
from taskvault.detect import classify_column, classify_document, detect_value, redact
from taskvault.setup import classify_tool, run_setup, scan_mcp

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def company(tmp_path):
    db = tmp_path / "crm.db"
    c = sqlite3.connect(db)
    c.executescript("""
        CREATE TABLE customers (id INTEGER PRIMARY KEY, full_name TEXT, email TEXT, mobile TEXT, plan TEXT,
                                card_number TEXT, notes TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customers(id), total TEXT);
    """)
    c.executemany("INSERT INTO customers VALUES (?,?,?,?,?,?,?)", [
        (1, "Priya Shah", "priya@example.com", "0400 111 222", "Pro", "4111 1111 1111 1111", "vip"),
        (2, "Tom Nguyen", "tom@example.net", "0400 333 444", "Basic", "5555 5555 5555 4444", "call 0400 333 444")])
    c.executemany("INSERT INTO orders VALUES (?,?,?)", [(10, 1, "49.00"), (11, 2, "19.00")])
    c.commit()
    c.close()
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "refund_policy.md").write_text("Refunds within 30 days.")
    (docs / "pricing.md").write_text("CONFIDENTIAL: floor price $18")
    (tmp_path / "suppliers.csv").write_text("id,name,bsb_account,abn\nS1,Bolt,062-000 12345678,51 824 753 556\n")
    return tmp_path


# ---- detection -------------------------------------------------------------------

@pytest.mark.parametrize("value,kind", [
    ("4111 1111 1111 1111", "card_number"), ("4111 1111 1111 1112", None), ("123 456 782", "au_tfn"),
    ("51 824 753 556", "au_abn"), ("GB82 WEST 1234 5698 7654 32", "iban"), ("062-000 12345678", "bank_account"),
    ("AKIAABCDEFGHIJKLMNOP", "api_key"), ("priya@example.com", "email"), ("+61 400 111 222", "phone"),
    ("hello", None), ("12", None),
])
def test_detect_value(value, kind):
    assert detect_value(value) == kind


def test_classify_columns_and_documents():
    assert classify_column("card", ["4111 1111 1111 1111", "5555 5555 5555 4444"]).level == "secret"
    assert classify_column("plan", ["Pro", "Basic"]).level == "normal"
    assert classify_column("mystery", ["x", "y"]).level == "protected"          # unknown -> safe default
    notes = classify_column("notes", ["vip", "call 0400 333 444"])
    assert notes.kind == "free_text" and notes.level == "protected"
    assert classify_document("p", "CONFIDENTIAL pricing").level == "protected"
    assert classify_document("k", "key: AKIAABCDEFGHIJKLMNOP").level == "secret"
    assert redact("card 4111 1111 1111 1111") == "card [CARD_NUMBER]"


# ---- setup ---------------------------------------------------------------------------

def test_setup_writes_a_working_policy_without_copying_real_data(company):
    out = company / "out"
    assert run_setup(out, sqlite=[str(company / "crm.db")], files=[str(company / "suppliers.csv")],
                     docs=[str(company / "docs")], domain="acme.example", echo=lambda s: None) == 0
    policy = Policy.load(out / "taskvault.yaml")
    cust = policy.sources["db.customers"]
    assert cust.owner == "customer_id" and cust.owner_contact == "email"
    assert cust.fields["card_number"] == "secret" and cust.fields["email"] == "protected"
    assert set(cust.pseudonymize) == {"full_name", "email", "mobile"}
    assert policy.sources["db.orders"].owner_field == "customer_id"
    assert policy.sources["file.suppliers"].fields["bsb_account"] == "secret"
    assert policy.sources["docs.docs"].key_levels == {"pricing": "protected", "refund_policy": "normal"}
    for f in ("taskvault.yaml", "fixtures.yaml", "setup-report.md"):
        text = (out / f).read_text()
        assert "Priya" not in text and "priya@" not in text and "0400 111 222" not in text

    # the generated connector code works against the real database
    spec = importlib.util.spec_from_file_location("tv_app", out / "taskvault_app.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    sent = []
    cwd = os.getcwd()
    os.chdir(out)
    try:
        vault = app.build_vault({"email.send": lambda to, subject, body: sent.append((to, body))})
    finally:
        os.chdir(cwd)
    t = vault.start_task("customer_request", customer_id=1)
    c = t.read("db.customers")
    assert "Priya" not in json.dumps(c) and c["card_number"].startswith("[[vault:")
    t.act("email.send", to=c["email"], subject="Hi", body=f"Hi {c['full_name']}")
    assert sent == [("priya@example.com", "Hi Priya Shah")]
    with pytest.raises(Blocked):
        t.read("db.customers", 2)
    with pytest.raises(Blocked):
        t.act("email.send", to="exfil@attacker.example", subject="x", body=c["full_name"])


def test_setup_refuses_to_overwrite(company):
    out = company / "out"
    run_setup(out, sqlite=[str(company / "crm.db")], echo=lambda s: None)
    assert run_setup(out, sqlite=[str(company / "crm.db")], echo=lambda s: None) == 1


def test_setup_cli_and_mcp_scan(company, capsys):
    fake = [sys.executable, str(ROOT / "tests" / "fake_mcp_server.py")]
    tools = {t.name: t for t in scan_mcp(fake)}
    assert tools["get_customer"].role == "read"
    assert tools["refund"].role == "act" and tools["refund"].risk == "high"
    assert main(["setup", "--sqlite", str(company / "crm.db"), "--dir", str(company / "o2"), "--domain",
                 "acme.example", "--", *fake]) == 0
    policy = Policy.load(company / "o2" / "taskvault.yaml")
    assert policy.tasks["customer_request"].sinks["mcp.refund"].approval == "always"   # high risk -> approval
    assert "attack suite" in capsys.readouterr().out


def test_classify_tool():
    assert classify_tool("send_email", "", ["to", "subject", "body"]).recipient_arg == "to"
    assert classify_tool("deleteCustomer", "", ["id"]).risk == "high"
    assert classify_tool("update_ticket", "", ["id", "status"]).risk == "medium"
    assert classify_tool("get_order", "", ["order_id"]).role == "read"


def test_scan_cli(tmp_path, capsys):
    f = tmp_path / "notes.txt"
    f.write_text("hello\nkey AKIAABCDEFGHIJKLMNOP\n")
    assert main(["scan", str(f)]) == 1
    assert "notes.txt:2: API key or token" in capsys.readouterr().out
    f.write_text("nothing here")
    assert main(["scan", str(f)]) == 0


def test_setup_scans_a_real_postgres_database(tmp_path):
    pgserver = pytest.importorskip("pgserver")
    psycopg = pytest.importorskip("psycopg")
    uri = pgserver.get_server(str(tmp_path / "pg"), cleanup_mode="stop").get_uri()
    with psycopg.connect(uri, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS orders; DROP TABLE IF EXISTS customers")
        c.execute("CREATE TABLE customers (id INT PRIMARY KEY, full_name TEXT, email TEXT, card_number TEXT)")
        c.execute("CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT REFERENCES customers(id), total TEXT)")
        c.execute("INSERT INTO customers VALUES (1,'Priya Shah','priya@example.com','4111 1111 1111 1111'),"
                  "(2,'Tom Nguyen','tom@example.net','5555 5555 5555 4444')")
        c.execute("INSERT INTO orders VALUES (10,1,'49.00'),(11,2,'19.00')")
    out = tmp_path / "out"
    assert run_setup(out, postgres=[uri], domain="acme.example", echo=lambda s: None) == 0
    policy = Policy.load(out / "taskvault.yaml")
    assert policy.sources["db.customers"].fields["card_number"] == "secret"
    assert policy.sources["db.customers"].owner_contact == "email"
    assert policy.sources["db.orders"].owner_field == "customer_id"
    assert "Priya" not in (out / "taskvault.yaml").read_text()
