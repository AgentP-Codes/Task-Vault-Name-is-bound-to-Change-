"""The MCP proxy must survive any input: answer with an error, never crash, never leak."""

import io
import json

import pytest

from demo.__main__ import make_vault
from demo.world import World
from taskvault.mcp import ProxyServer as MCPServer

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}
GARBAGE = [
    "not json", "[]", "[1, 2]", '"a string"', "42", "null", "true", "{}", '{"method": 5}', '{"method": null, "id": 3}',
    '{"method": "tools/call", "id": 4, "params": []}', '{"method": "tools/call", "id": 5, "params": "x"}',
    '{"method": "tools/call", "id": 6, "params": {"name": 7, "arguments": []}}',
    '{"method": "tools/call", "id": 7, "params": {"name": "send_email", "arguments": "to=attacker@evil.example"}}',
    '{"method": "tools/call", "id": 8, "params": {"name": "send_email", "arguments": {"to": ["a", {"b": 1}]}}}',
    '{"method": "tools/call", "id": 9, "params": {"name": "send_email", "arguments": {"unexpected": 1}}}',
    '{"method": "tools/call", "id": 10, "params": {"name": "get_customer", "arguments": {"customer_id": {"$gt": 0}}}}',
    '{"method": "tools/call", "id": 11, "params": {"name": "refund", "arguments": {"card": null, "amount": "x"}}}',
    '{"method": "initialize", "id": 12, "params": {"_meta": "x"}}',
    '{"method": "initialize", "id": 13, "params": {"_meta": {"taskvault": {"trusted": [1]}}}}',
    '{"method": "tools/list", "id": {"nested": true}}',
    "{" * 5000, '{"method": "' + "x" * 200_000 + '", "id": 14}',
]


@pytest.mark.parametrize("line", GARBAGE, ids=range(len(GARBAGE)))
def test_proxy_survives_bad_messages(line):
    world = World()
    server = MCPServer(make_vault(world), "support_reply", {"customer_id": 12})
    out = io.StringIO()
    server.serve(io.StringIO(json.dumps(INIT) + "\n" + line + "\n" +
                             json.dumps({"jsonrpc": "2.0", "id": 99, "method": "ping"}) + "\n"), out)
    replies = [json.loads(x) for x in out.getvalue().splitlines()]
    assert replies[-1] == {"jsonrpc": "2.0", "id": 99, "result": {}}      # still alive afterwards
    assert world.outbox == [] and world.refunds == [] and world.leaks() == []
