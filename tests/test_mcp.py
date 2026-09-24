import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from demo.__main__ import POLICY
from taskvault import Policy, Vault
from taskvault.mcp import ProxyServer, StdioMCPClient, upstream_bindings

ROOT = Path(__file__).resolve().parent.parent
FAKE = [sys.executable, str(ROOT / "tests" / "fake_mcp_server.py")]


@pytest.fixture
def upstream(tmp_path):
    outbox = tmp_path / "outbox.jsonl"
    client = StdioMCPClient(FAKE, env={**os.environ, "FAKE_MCP_OUTBOX": str(outbox)})
    yield client, outbox
    client.close()


def _proxy(client, trusted=None):
    policy = Policy.load(POLICY)
    sources, sinks = upstream_bindings(policy.raw, client)
    return ProxyServer(Vault(policy, sources, sinks), "support_reply", trusted)


def _call(proxy, name, **args):
    r = proxy.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": name, "arguments": args}})
    return r["result"]


def _init(proxy, meta=None):
    params = {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}
    if meta:
        params["_meta"] = {"taskvault": {"trusted": meta}}
    return proxy.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": params})


def test_proxy_lists_only_policy_tools_for_the_task(upstream):
    proxy = _proxy(upstream[0], {"customer_id": 12})
    _init(proxy)
    names = {t["name"] for t in proxy.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]}
    assert names == {"get_customer", "get_doc", "send_email", "refund"}   # no list_customers, no get_ticket


def test_proxy_scopes_reads_and_blocks_exfiltration(upstream):
    client, outbox = upstream
    proxy = _proxy(client)
    _init(proxy, meta={"customer_id": 12})   # trusted input supplied by the host, not the model
    me = json.loads(_call(proxy, "get_customer")["content"][0]["text"])
    assert me["name"] == "Priya Shah" and me["card_number"].startswith("[[vault:")

    other = _call(proxy, "get_customer", customer_id=45)
    assert other["isError"] and "outside this task's scope" in other["content"][0]["text"]

    bad = _call(proxy, "send_email", to="audit@acme-billing.example", subject="x", body=me["name"])
    assert bad["isError"] and "Blocked by taskvault" in bad["content"][0]["text"]

    hidden = _call(proxy, "list_customers")
    assert hidden["isError"]

    ok = _call(proxy, "send_email", to=me["email"], subject="Hi", body=f"Hi {me['name']}")
    assert not ok.get("isError")
    sent = [json.loads(l) for l in outbox.read_text().splitlines()]
    assert [m["to"] for m in sent] == ["priya.shah@example.com"]


def test_proxy_swaps_placeholders_only_at_the_allowed_sink(upstream):
    proxy = _proxy(upstream[0], {"customer_id": 12})
    _init(proxy)
    me = json.loads(_call(proxy, "get_customer")["content"][0]["text"])
    assert _call(proxy, "refund", card=me["card_number"], amount=49).get("isError") is None


def test_proxy_requires_trusted_inputs(upstream):
    proxy = _proxy(upstream[0])
    r = _init(proxy)
    assert r["error"]["code"] == -32602 and "trusted inputs" in r["error"]["message"]


def test_cli_serve_end_to_end_over_stdio(tmp_path):
    outbox = tmp_path / "out.jsonl"
    cmd = [sys.executable, "-m", "taskvault", "serve", "--policy", str(POLICY), "--task", "support_reply",
           "--trusted", "customer_id=12", "--audit", str(tmp_path / "audit.jsonl"), "--", *FAKE]
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "send_email",
                    "arguments": {"to": "audit@acme-billing.example", "subject": "x", "body": "y"}}},
    ]
    p = subprocess.run(cmd, input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True,
                       cwd=ROOT, env={**os.environ, "FAKE_MCP_OUTBOX": str(outbox)}, timeout=30)
    replies = [json.loads(l) for l in p.stdout.splitlines()]
    assert replies[0]["result"]["serverInfo"]["name"] == "taskvault"
    assert replies[1]["result"]["isError"]
    assert not outbox.exists()
    audit = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert any(e.get("decision") == "block" for e in audit)
