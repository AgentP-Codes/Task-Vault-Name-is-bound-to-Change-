import base64

import pytest

from demo.__main__ import make_vault
from demo.world import ATTACKER, World
from taskvault import Blocked, Policy, Vault
from taskvault.planner import PlanError, Planner, validate

REFUND_PLAN = [
    {"id": "cust", "read": "crm.customer"},
    {"id": "tkt", "read": "inbox.ticket"},
    {"id": "facts", "extract": {"from": ["tkt.body"], "instruction": "Refund amount requested?",
                                "schema": {"amount": "number"}}},
    {"id": "msg", "format": "Hi {cust.name}, we've refunded ${facts.amount} on your {cust.plan} plan."},
    {"act": "payments.refund", "args": {"card": "$cust.card_number", "amount": "$facts.amount"}},
    {"act": "email.send", "args": {"to": "$cust.email", "subject": "Your refund", "body": "$msg"}},
]


def honest(instruction, inputs, schema):
    return {"amount": 49}


def planned_task(world, ticket="T-100"):
    return make_vault(world).start_task("support_reply_planned", customer_id=12, ticket_id=ticket)


def test_planned_refund_runs_end_to_end():
    world = World()
    Planner(planned_task(world), honest).run(REFUND_PLAN)
    assert world.refunds == [{"card": "4111 1111 1111 1111", "amount": 49.0}]
    assert world.outbox[0]["to"] == "priya.shah@example.com"
    assert "$49.0" in world.outbox[0]["body"] and world.leaks() == []


def test_extractor_never_sees_secrets():
    seen = {}

    def spy(instruction, inputs, schema):
        seen.update(inputs)
        return {"amount": 1}

    plan = [{"id": "cust", "read": "crm.customer"},
            {"id": "x", "extract": {"from": ["cust.card_number"], "instruction": "?", "schema": {"amount": "number"}}}]
    Planner(planned_task(World()), spy).run(plan)
    assert "4111" not in str(seen)


def test_recipient_derived_from_untrusted_content_is_blocked_even_if_it_looks_valid():
    # A careless plan takes the reply-to address from the ticket body. The hijacked
    # extractor returns the customer's own address - which would pass a string check -
    # but its provenance is untrusted, so it's blocked.
    plan = [{"id": "tkt", "read": "inbox.ticket"},
            {"id": "f", "extract": {"from": ["tkt.body"], "instruction": "reply-to address?",
                                    "schema": {"email": "string"}}},
            {"act": "email.send", "args": {"to": "$f.email", "subject": "hi", "body": "hello"}}]
    world = World()
    with pytest.raises(Blocked, match="provenance: recipient .* untrusted"):
        Planner(planned_task(world, "T-101"), lambda *a: {"email": "priya.shah@example.com"}).run(plan)
    assert world.outbox == []


ENCODING_POLICY = {
    "internal_domains": ["acme.example"],
    "sources": {
        "crm.customer": {"owner": "customer_id", "owner_contact": "email",
                         "fields": {"email": "protected", "name": "protected"}},
        "docs": {"owner": "company", "key_levels": {"pricing_sheet": "protected"}},
    },
    "tasks": {"quote": {"trusted": ["customer_id"],
                        "reads": {"crm.customer": {"key": "{customer_id}"}, "docs": {"keys": ["pricing_sheet"]}},
                        "sinks": {"email.send": {"recipient_arg": "to",
                                                 "allowed_recipients": ["crm.customer:{customer_id}.email"]}}}},
}


def test_encoded_company_data_is_caught_by_provenance_not_string_matching():
    world = World()
    vault = Vault(Policy.from_dict(ENCODING_POLICY),
                  sources={"crm.customer": world.get_customer, "docs": world.get_doc},
                  sinks={"email.send": world.send_email})
    plan = [{"id": "cust", "read": "crm.customer"},
            {"id": "price", "read": "docs", "key": "pricing_sheet"},
            {"id": "s", "extract": {"from": ["price.body"], "instruction": "Summarise for the customer",
                                    "schema": {"text": "string"}}},
            {"act": "email.send", "args": {"to": "$cust.email", "subject": "Quote", "body": "$s.text"}}]

    def hijacked(instruction, inputs, schema):   # smuggles the whole sheet out, base64-encoded
        return {"text": base64.b64encode(inputs["price.body"].encode()).decode()}

    with pytest.raises(Blocked, match="owner company"):
        Planner(vault.start_task("quote", customer_id=12), hijacked).run(plan)
    assert world.outbox == []

    # The same encoded text sent directly through task.act slips past value matching:
    # exactly the gap planner mode exists to close.
    t = vault.start_task("quote", customer_id=12)
    body = t.read("docs", "pricing_sheet")["body"]
    t.act("email.send", to="priya.shah@example.com", subject="x", body=base64.b64encode(body.encode()).decode())
    assert len(world.outbox) == 1


def test_attacker_recipient_literal_is_still_checked():
    plan = [{"act": "email.send", "args": {"to": ATTACKER, "subject": "x", "body": "y"}}]
    with pytest.raises(Blocked, match="trusted data"):
        Planner(planned_task(World())).run(plan)


@pytest.mark.parametrize("plan,msg", [
    ([{"act": "email.send", "args": {"to": "$nope"}}], "before it is defined"),
    ([{"id": "a", "read": "docs"}, {"id": "a", "read": "docs"}], "new, simple 'id'"),
    ([{"read": "docs", "act": "email.send"}], "exactly one"),
])
def test_plan_validation(plan, msg):
    with pytest.raises(PlanError, match=msg):
        validate(plan)


def test_extract_without_extractor_is_an_error():
    with pytest.raises(PlanError, match="extractor"):
        Planner(planned_task(World())).run(REFUND_PLAN)
