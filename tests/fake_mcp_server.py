"""SIMULATED. A tiny stand-in MCP server with the demo company's data (used by the proxy tests).

Every email it "sends" is appended to the file named by $FAKE_MCP_OUTBOX.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demo.world import World  # noqa: E402

world = World()
OUTBOX = os.environ.get("FAKE_MCP_OUTBOX")

TOOLS = {
    "get_customer": lambda a: world.get_customer(a.get("customer_id")),
    "list_customers": lambda a: world.list_customers(),
    "get_doc": lambda a: world.get_doc(a.get("name")),
    "get_ticket": lambda a: world.get_ticket(a.get("ticket_id")),
    "send_email": lambda a: world.send_email(a["to"], a.get("subject", ""), a.get("body", "")),
    "refund": lambda a: world.refund(a["card"], a["amount"]),
}


def reply(rid, result):
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    msg = json.loads(line)
    method, rid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method == "initialize":
        reply(rid, {"protocolVersion": params.get("protocolVersion"), "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-acme", "version": "0"}})
    elif method == "tools/list":
        reply(rid, {"tools": [{"name": n, "inputSchema": {"type": "object"}} for n in TOOLS]})
    elif method == "tools/call":
        out = TOOLS[params["name"]](params.get("arguments") or {})
        if params["name"] == "send_email" and OUTBOX:
            with open(OUTBOX, "a") as f:
                f.write(json.dumps(world.outbox[-1]) + "\n")
        if out is None:
            reply(rid, {"isError": True, "content": [{"type": "text", "text": "not found"}]})
        else:
            reply(rid, {"content": [{"type": "text", "text": json.dumps(out)}]})
    elif rid is not None:
        reply(rid, {})
