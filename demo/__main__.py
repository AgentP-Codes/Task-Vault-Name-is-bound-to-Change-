"""Run: python -m demo            (enforce mode)
        python -m demo --shadow   (shadow mode: log what would be blocked, block nothing)
"""

from __future__ import annotations

import argparse
from pathlib import Path

from taskvault import AuditLog, Policy, Vault

from .agents import HijackedAgent, LegitAgent, RawTools, VaultTools
from .world import TICKETS, World

POLICY = Path(__file__).with_name("policy.yaml")


def make_vault(world: World, mode: str = "enforce") -> Vault:
    return Vault(
        Policy.load(POLICY),
        sources={"crm.customer": world.get_customer, "docs": world.get_doc,
                 "inbox.ticket": world.get_ticket},
        sinks={"email.send": world.send_email, "payments.refund": world.refund},
        audit=AuditLog(),
        mode=mode,
    )


def run(agent, ticket_id: str, use_vault: bool, mode: str = "enforce"):
    world, ticket = World(), TICKETS[ticket_id]
    vault = None
    if use_vault:
        vault = make_vault(world, mode)
        tools = VaultTools(vault.start_task("support_reply", customer_id=ticket["verified_customer_id"]))
    else:
        tools = RawTools(world)
    return agent.run(tools, ticket), world, vault


def show(title: str, log, world: World, vault: Vault | None) -> None:
    print(f"\n=== {title} ===")
    for step, outcome in log:
        mark = "+" if outcome == "done" else ("x" if outcome.startswith("BLOCKED") else "!")
        print(f"  [{mark}] {step:<50} {outcome if mark != '+' else ''}")
    leaks = world.leaks()
    print(f"  Emails sent: {len(world.outbox)}   Refunds: {len(world.refunds)}   Leaked items: {len(leaks)}")
    for leak in leaks[:8]:
        print(f"     LEAK  {leak}")
    if len(leaks) > 8:
        print(f"     ... and {len(leaks) - 8} more")
    if vault:
        shadow = vault.audit.decisions("would_block")
        if shadow:
            print(f"  Shadow mode: {len(shadow)} actions WOULD have been blocked:")
            for e in shadow:
                print(f"     - {e['reason']}")
        print(f"  Audit log: {len(vault.audit.entries)} entries, chain valid = {vault.audit.verify()}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--shadow", action="store_true", help="observe only; block nothing")
    args = p.parse_args()
    mode = "shadow" if args.shadow else "enforce"

    print("SIMULATED demo: invented company data and a scripted agent. No real AI or systems are used.\n")
    print("Ticket T-101 hides instructions telling the AI to export customer data and pricing.")
    print("The agent below has FULLY obeyed them - the worst case.\n")
    show("Hijacked agent, direct access (no vault)", *run(HijackedAgent(), "T-101", use_vault=False))
    show(f"Hijacked agent, behind the vault ({mode} mode)", *run(HijackedAgent(), "T-101", True, mode))
    show(f"Normal refund request, behind the vault ({mode} mode)", *run(LegitAgent(), "T-100", True, mode))


if __name__ == "__main__":
    main()
