"""Attempts to get around the vault. Every one of these must be blocked."""

import pytest

from demo.__main__ import make_vault
from demo.world import World
from taskvault import Blocked, Policy, Vault


@pytest.fixture
def world():
    return World()


@pytest.fixture
def task(world):
    return make_vault(world).start_task("support_reply", customer_id=12)


OK = ["priya.shah@example.com", "PRIYA.SHAH@EXAMPLE.COM", "  priya.shah@example.com  ",
      "Priya Shah <priya.shah@example.com>", ["priya.shah@example.com"]]

BAD = [
    "priya.shah@example.com <attacker@evil.example>",          # display name trick
    "priya.shah@example.com\nBcc: attacker@evil.example",      # header injection
    "priya.shah@example.com, attacker@evil.example",           # hidden second recipient
    "priya.shah@example.com; attacker@evil.example",
    ["priya.shah@example.com", "attacker@evil.example"],
    "priya.shah@exаmple.com",                                   # Cyrillic 'а'
    "ｐriya.shah@example.com",                                  # full-width letter
    "priya.shah@example.com.evil.example",
    "priya.shah@example.com%attacker@evil.example",
    "",
    None,
]


@pytest.mark.parametrize("to", OK, ids=str)
def test_legitimate_recipient_spellings_are_allowed(task, world, to):
    task.act("email.send", to=to, subject="Hi", body="Hello")
    assert len(world.outbox) == 1


@pytest.mark.parametrize("to", BAD, ids=repr)
def test_recipient_tricks_are_blocked(task, world, to):
    with pytest.raises(Blocked):
        task.act("email.send", to=to, subject="Hi", body="Hello")
    assert world.outbox == []


def test_forged_and_foreign_placeholders_are_blocked(world):
    vault = make_vault(world)
    a = vault.start_task("support_reply", customer_id=12)
    b = vault.start_task("support_reply", customer_id=12)
    token = a.read("crm.customer")["card_number"]
    with pytest.raises(Blocked, match="foreign"):
        b.act("payments.refund", card=token, amount=1)            # token from another task
    with pytest.raises(Blocked, match="foreign"):
        b.act("payments.refund", card="[[vault:card_number:deadbeef]]", amount=1)
    assert world.refunds == []


def test_secret_placeholder_as_recipient_or_nested_is_blocked(world):
    raw = Policy.load("demo/policy.yaml").raw
    raw["tasks"]["support_reply"]["sinks"]["payments.refund"]["secrets_allowed"] = {"card_number": "card"}
    base = make_vault(world)
    task = Vault(Policy.from_dict(raw), base.sources, base.sinks).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to=c["card_number"], subject="x", body="y")
    with pytest.raises(Blocked, match="only be passed as 'card'"):
        task.act("payments.refund", card="x", amount={"note": c["card_number"], "n": 1})
    task.act("payments.refund", card=c["card_number"], amount=1)
    assert world.outbox == [] and world.refunds == [{"card": "4111 1111 1111 1111", "amount": 1}]


def test_key_injection_is_out_of_scope(task):
    for key in ["12 OR 1=1", "12; DROP TABLE", " 12", "012", 12.0, ["12"], "*"]:
        with pytest.raises((Blocked, KeyError)):
            task.read("crm.customer", key)


def test_unexposed_tools_and_extra_args(task):
    with pytest.raises(Blocked):
        task.call_tool("list_customers", {})
    with pytest.raises(Blocked, match="does not accept"):
        task.act("payments.refund", card="x", amount=1, to="attacker@evil.example")


def test_protected_values_hidden_in_structures_or_case(task, world):
    c = task.read("crm.customer")
    for body in [c["name"].upper(), {"nested": [c["email"]]}, f"x{c['name']}x"]:
        with pytest.raises(Blocked):
            task.act("email.send", to="tom.nguyen@example.net", subject="x", body=body)
    assert world.outbox == []


def test_customer_data_may_go_to_internal_staff_but_not_secrets(world):
    raw = Policy.load("demo/policy.yaml").raw
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"].append("*@acme.example")
    vault = Vault(Policy.from_dict(raw), make_vault(world).sources, make_vault(world).sinks)
    t = vault.start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    t.act("email.send", to="escalations@acme.example", subject="VIP", body=f"{c['name']} {c['email']}")
    with pytest.raises(Blocked):
        t.act("email.send", to="escalations@acme.example", subject="card", body=c["card_number"])
    assert len(world.outbox) == 1


def test_shadow_mode_never_raises_but_logs_everything(world):
    vault = make_vault(world, mode="shadow")
    t = vault.start_task("support_reply", customer_id=12)
    t.act("email.send", to="attacker@evil.example\nBcc: x", subject="x", body="y")
    assert vault.audit.decisions("would_block") and vault.audit.decisions("block") == []
