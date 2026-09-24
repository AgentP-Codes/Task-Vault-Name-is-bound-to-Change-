"""Planner mode with real models: the strongest protection.

A privileged model writes the plan from the trusted request only. A quarantined
model (no tools) reads the untrusted ticket. The interpreter tracks where every
value came from, so rewording or encoding data can't get it past the checks.

    pip install "taskvault[anthropic]"
    python examples/planner_mode.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from demo.__main__ import make_vault  # noqa: E402  (fake company data for the example)
from demo.world import World  # noqa: E402
from taskvault.llm import AnthropicProvider, privileged_planner, quarantined_extractor  # noqa: E402
from taskvault.planner import Planner  # noqa: E402

world = World()
vault = make_vault(world)
task = vault.start_task("support_reply_planned", customer_id=12, ticket_id="T-101")   # the injected ticket

model = AnthropicProvider()
plan = privileged_planner(model, vault.policy, "support_reply_planned")(
    "Reply to the customer about their ticket. Refund $49 to their card only if they ask for a refund.")
print("plan:", plan)

Planner(task, quarantined_extractor(model)).run(plan)
print("sent:", [(m["to"], m["subject"]) for m in world.outbox])
print("leaks:", world.leaks())
