import json
import sqlite3
import urllib.parse

import pytest

from taskvault.connectors import (
    GoogleDriveConnector,
    HttpClient,
    HttpError,
    RESTConnector,
    RESTSink,
    SalesforceConnector,
    SalesforceSink,
    SharePointConnector,
    SMTPSink,
    SQLConnector,
    SQLSink,
)
from taskvault.connectors.base import Response


class FakeHTTP:
    """Records requests and answers from a {(method, path-prefix): (status, body)} table."""

    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        parsed = urllib.parse.urlparse(url)
        for (m, prefix), (status, payload) in self.routes.items():
            if m == method and parsed.path == prefix:
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                return Response(status, {}, raw)
        return Response(404, {}, b'{"error":"not found"}')


# ---- SQL ---------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    path = tmp_path / "crm.db"
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT, card TEXT, notes TEXT)")
    c.execute("INSERT INTO customers VALUES (12, 'Priya', 'p@example.com', '4111', 'vip')")
    c.commit()
    c.close()
    return lambda: sqlite3.connect(path)


def test_sql_reads_only_listed_columns(db):
    read = SQLConnector(db, "customers", "id", columns=["id", "name", "email"])
    assert read(12) == {"id": 12, "name": "Priya", "email": "p@example.com"}
    assert read(99) is None


def test_sql_key_is_a_bound_parameter_not_sql(db):
    read = SQLConnector(db, "customers", "id")
    assert read("12 OR 1=1") is None


def test_sql_rejects_unsafe_identifiers(db):
    with pytest.raises(ValueError):
        SQLConnector(db, "customers; DROP TABLE customers", "id")


def test_sql_sink_updates_only_writable_columns(db):
    write = SQLSink(db, "customers", "id", writable=["notes"])
    assert write(key=12, notes="refunded") == 1
    assert SQLConnector(db, "customers", "id", ["notes"])(12) == {"notes": "refunded"}
    with pytest.raises(ValueError):
        write(key=12, email="attacker@evil.example")


# ---- REST ----------------------------------------------------------------------

def test_rest_connector_escapes_keys_and_picks_fields():
    http = FakeHTTP({("GET", "/api/customers/12"): (200, {"name": "Priya", "email": "p@x", "ssn": "1"})})
    client = HttpClient("https://crm.example/api", token=lambda: "tok", transport=http)
    read = RESTConnector(client, "/customers/{key}", pick=["name", "email"])
    assert read(12) == {"name": "Priya", "email": "p@x"}
    assert http.calls[0][2]["Authorization"] == "Bearer tok"
    assert read("../admin") is None
    assert "/customers/..%2Fadmin" in http.calls[1][1]


def test_rest_sink_and_errors():
    http = FakeHTTP({("POST", "/api/refunds"): (201, {"ok": True}), ("POST", "/api/fail"): (500, {"e": 1})})
    client = HttpClient("https://pay.example/api", transport=http)
    assert RESTSink(client, "post", "/refunds", allowed_args=["card", "amount"])(card="4111", amount=5) == {"ok": True}
    with pytest.raises(ValueError):
        RESTSink(client, "post", "/refunds", allowed_args=["card"])(card="1", to="x")
    with pytest.raises(HttpError):
        RESTSink(client, "post", "/fail")(x=1)


def test_http_client_requires_https():
    with pytest.raises(ValueError):
        HttpClient("http://crm.example")


# ---- Salesforce ----------------------------------------------------------------

def test_salesforce_by_id_and_by_external_id():
    rec = {"Id": "0035g00000ABCDeAAF", "Name": "Priya", "Email": "p@x", "attributes": {}}
    http = FakeHTTP({
        ("GET", "/services/data/v61.0/sobjects/Contact/0035g00000ABCDeAAF"): (200, rec),
        ("GET", "/services/data/v61.0/query"): (200, {"records": [rec]}),
    })
    client = HttpClient("https://acme.my.salesforce.com", token="t", transport=http)
    by_id = SalesforceConnector(client, "Contact", ["Id", "Name", "Email"])
    assert by_id("0035g00000ABCDeAAF") == {"Id": "0035g00000ABCDeAAF", "Name": "Priya", "Email": "p@x"}
    assert by_id("not an id") is None
    by_ext = SalesforceConnector(client, "Contact", ["Id", "Email"], match_field="Customer_Id__c")
    assert by_ext("12' OR Name != '")["Email"] == "p@x"
    soql = urllib.parse.parse_qs(urllib.parse.urlparse(http.calls[-1][1]).query)["q"][0]
    assert "\\'" in soql   # quote escaped, so the key can't extend the query


def test_salesforce_sink_limits_fields():
    http = FakeHTTP({("PATCH", "/services/data/v61.0/sobjects/Case/5005g00000XYZabAAB"): (204, b"")})
    sink = SalesforceSink(HttpClient("https://acme.my.salesforce.com", transport=http), "Case", ["Status"])
    assert sink(Id="5005g00000XYZabAAB", Status="Closed")["updated"]
    with pytest.raises(ValueError):
        sink(Id="5005g00000XYZabAAB", OwnerId="005...")


# ---- Google Drive / SharePoint -----------------------------------------------

def test_google_drive_exports_docs_as_text():
    http = FakeHTTP({
        ("GET", "/drive/v3/files/abc"): (200, {"id": "abc", "name": "Refund policy",
                                               "mimeType": "application/vnd.google-apps.document"}),
        ("GET", "/drive/v3/files/abc/export"): (200, b"Refunds within 30 days."),
    })
    drive = GoogleDriveConnector(token="t", aliases={"refund_policy": "abc"}, transport=http)
    doc = drive("refund_policy")
    assert doc["name"] == "Refund policy" and doc["body"] == "Refunds within 30 days."
    assert drive("missing") is None


def test_sharepoint_by_path_and_traversal_guard():
    http = FakeHTTP({
        ("GET", "/v1.0/sites/site1/drive/root:/Policies/refunds.txt:"): (200, {"name": "refunds.txt", "size": 10}),
        ("GET", "/v1.0/sites/site1/drive/root:/Policies/refunds.txt:/content"): (200, b"30 days"),
    })
    sp = SharePointConnector("site1", token="t", transport=http)
    assert sp("Policies/refunds.txt")["body"] == "30 days"
    with pytest.raises(ValueError):
        sp("Policies/../HR/salaries.xlsx")


# ---- SMTP ------------------------------------------------------------------------

def test_smtp_sink_uses_starttls():
    sent = []

    class FakeSMTP:
        def __init__(self, host, port): self.tls = False
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): self.tls = True
        def login(self, u, p): pass
        def send_message(self, m): sent.append((self.tls, m["To"], m["Subject"]))

    SMTPSink("smtp.example", sender="support@acme.example", smtp_factory=FakeSMTP)(
        to="p@example.com", subject="Hi", body="Hello")
    assert sent == [(True, "p@example.com", "Hi")]


def test_sql_connector_on_real_postgres(tmp_path):
    pgserver = pytest.importorskip("pgserver")
    psycopg = pytest.importorskip("psycopg")
    uri = pgserver.get_server(str(tmp_path / "pg"), cleanup_mode="stop").get_uri()
    with psycopg.connect(uri, autocommit=True) as c:
        c.execute("DROP TABLE IF EXISTS customers")
        c.execute("CREATE TABLE customers (id INT PRIMARY KEY, name TEXT, email TEXT, notes TEXT)")
        c.execute("INSERT INTO customers VALUES (12, 'Priya', 'p@example.com', 'vip')")
    connect = lambda: psycopg.connect(uri)  # noqa: E731
    read = SQLConnector(connect, "customers", "id", columns=["name", "email"], paramstyle="format")
    assert read(12) == {"name": "Priya", "email": "p@example.com"}
    assert read(99) is None
    SQLSink(connect, "customers", "id", writable=["notes"], paramstyle="format")(key=12, notes="refunded")
    assert SQLConnector(connect, "customers", "id", ["notes"], paramstyle="format")(12) == {"notes": "refunded"}
