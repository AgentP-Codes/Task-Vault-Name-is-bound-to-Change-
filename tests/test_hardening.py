"""Stress-test findings (September 2026): each test pins down one issue so it can't come back."""

import json

import pytest

from demo.__main__ import POLICY, make_vault
from demo.world import World
from taskvault import Blocked, Policy, SinkError, Vault

OWNER = "priya.shah@example.com"


def _vault_with_staff_glob(world, sinks=None):
    """Demo policy, but email.send may also go to anyone at the company (like the finance template)."""
    import copy
    data = copy.deepcopy(Policy.load(POLICY).raw)
    data["internal_domains"] = ["acme.example"]
    data["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"].append("*@acme.example")
    return Vault(Policy.from_dict(data),
                 {"crm.customer": world.get_customer, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                 sinks or {"email.send": world.send_email, "payments.refund": world.refund})


# ---- 1. one recipient string hiding a second address ------------------------------------

@pytest.mark.parametrize("to", [
    "attacker@evil.example staff@acme.example",
    "attacker@evil.example (staff@acme.example",
    "attacker@evil.example(x) staff@acme.example",
    '"attacker@evil.example" staff@acme.example',
    "attacker@evil.example\tstaff@acme.example",
])
def test_a_second_address_cannot_hide_behind_a_company_glob(to):
    world = World()
    task = _vault_with_staff_glob(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to=to, subject="x", body=c["name"])
    assert world.outbox == []


def test_a_real_company_address_still_works_with_the_glob():
    world = World()
    task = _vault_with_staff_glob(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    task.act("email.send", to="billing@acme.example", subject="x", body=c["name"])
    assert world.outbox[0]["to"] == "billing@acme.example"


# ---- 2. recipient edge cases -------------------------------------------------------------

@pytest.mark.parametrize("to", [
    OWNER + "\r\n", "\r\n" + OWNER, OWNER + "\nbcc: attacker@evil.example",
    "." + OWNER, OWNER.replace("@", "@."), OWNER + ".",
    f'"attacker@evil.example" <{OWNER}>', f"<@evil.example:{OWNER}>",
    f"{OWNER}(comment)", '"priya.shah"@example.com',
])
def test_odd_recipient_forms_are_blocked(to):
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Blocked):
        task.act("email.send", to=to, subject="x", body=c["name"])
    assert world.outbox == []


@pytest.mark.parametrize("to", [OWNER, OWNER.upper(), f"  {OWNER} ", f"Priya Shah <{OWNER}>"])
def test_ordinary_forms_of_the_owners_address_still_work(to):
    world = World()
    task = make_vault(world).start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    task.act("email.send", to=to, subject="x", body=f"Hi {c['name']}")
    assert len(world.outbox) == 1


# ---- 3. extra recipient arguments (cc / bcc) ---------------------------------------------

def test_cc_and_bcc_are_checked_like_the_main_recipient():
    world = World()
    got = []
    vault = make_vault(world)
    vault.sinks["email.send"] = lambda **kw: got.append(kw) or "sent"
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    for extra in ("cc", "bcc", "reply_to"):
        with pytest.raises(Blocked):
            task.act("email.send", to=c["email"], subject="x", body=c["name"], **{extra: "attacker@evil.example"})
    assert got == []


# ---- 4. what the sink sends back ---------------------------------------------------------

def test_secrets_in_a_sinks_reply_are_masked_before_the_agent_sees_them():
    world = World()
    vault = make_vault(world)
    vault.sinks["payments.refund"] = lambda card, amount: {"status": "ok", "card": card, "amount": amount}
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    out = task.act("payments.refund", card=c["card_number"], amount=49)
    assert "4111" not in json.dumps(out) and out["card"] == c["card_number"]


def test_secrets_in_a_sinks_error_are_masked_too():
    world = World()
    vault = make_vault(world)

    def failing_refund(card, amount):
        raise ValueError(f"card {card} was declined")
    vault.sinks["payments.refund"] = failing_refund
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    with pytest.raises(Exception) as e:
        task.act("payments.refund", card=c["card_number"], amount=49)
    assert "4111 1111 1111 1111" not in str(e.value)


def test_real_names_in_a_sinks_reply_are_shown_as_stand_ins():
    world = World()
    vault = make_vault(world)
    vault.sinks["email.send"] = lambda to, subject, body: f"sent to {to}: {body}"
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    if not c["name"].startswith("Name-"):
        pytest.skip("demo policy doesn't pseudonymise names")
    out = task.act("email.send", to=c["email"], subject="x", body=f"Hi {c['name']}")
    assert "Priya" not in out and OWNER not in out


# ---- 5. agent-chosen names in the audit log ----------------------------------------------

def test_agent_chosen_names_are_not_written_raw_to_the_audit_log():
    world = World()
    vault = make_vault(world)
    task = vault.start_task("support_reply", customer_id=12)
    task.read("crm.customer")
    for attempt in (lambda: task.act(OWNER, x=1), lambda: task.read(OWNER),
                    lambda: task.call_tool(OWNER, {}),
                    lambda: task.act("email.send", to=OWNER, subject="x", body="y", **{OWNER.replace("@", "_at_"): 1})):
        with pytest.raises((Blocked, KeyError, SinkError)):
            attempt()
    written = json.dumps(vault.audit.entries)
    assert OWNER not in written and "priya.shah_at_" not in written


# ---- 6. tampered deposit boxes fail as a normal block ------------------------------------

def test_tampered_box_data_is_a_logged_block_not_a_crash(tmp_path):
    from taskvault.crypto import LocalKeyProvider
    from tests.test_boxes import _vault_on_boxes
    vault, world = _vault_on_boxes(str(tmp_path / "b.db"), LocalKeyProvider(tmp_path / "v.key"))
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    vault.boxes.db.execute("UPDATE tv_items SET blob = substr(blob, 1, length(blob) - 4) || X'00000000'")
    with pytest.raises(Blocked):
        task.act("payments.refund", card=c["card_number"], amount=49)
    assert world.refunds == [] and vault.audit.decisions("block") and vault.audit.verify()


# ---- 7. damaged files: clear errors and a way back ---------------------------------------

def test_a_crash_mid_write_can_be_repaired_without_hiding_tampering(tmp_path, capsys):
    from taskvault.audit import AuditError, AuditLog
    from taskvault.cli import main
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.record("act", i=i)
    with path.open("a") as f:
        f.write('{"seq": 3, "ts": 1, "ev')                      # power cut mid-write
    with pytest.raises(AuditError, match="audit repair"):
        AuditLog(path)
    assert main(["audit", "repair", str(path)]) == 0
    assert "moved an unfinished last line" in capsys.readouterr().out
    fixed = AuditLog(path)
    assert len(fixed.entries) == 3 and fixed.verify()
    fixed.record("act", i=3)
    assert AuditLog(path).verify()

    lines = path.read_text().splitlines()                    # damage in the MIDDLE is not a crash
    lines[1] = lines[1][:-5]
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(AuditError):
        AuditLog.repair(path)


def test_damaged_key_file_gives_a_clear_error(tmp_path):
    from taskvault.crypto import KeyUnavailable, LocalKeyProvider
    for content in (b"not a key", b"", base64_of(b"short")):
        p = tmp_path / "k.key"
        p.write_bytes(content)
        with pytest.raises(KeyUnavailable, match="valid taskvault key"):
            LocalKeyProvider(p, create=False).data_key()


def base64_of(b):
    import base64
    return base64.b64encode(b)


@pytest.mark.parametrize("text", ["version: 1\nsources: 5", "- a\n- b", "tasks: [1]", "tools: {x: 5}",
                                  "internal_domains: acme.example"])
def test_policies_of_the_wrong_shape_give_a_policy_error(tmp_path, text):
    from taskvault import PolicyError
    p = tmp_path / "p.yaml"
    p.write_text(text)
    with pytest.raises(PolicyError):
        Policy.load(p)


def test_a_recipient_pattern_written_as_text_is_rejected_not_read_as_characters():
    import copy

    from taskvault import PolicyError
    data = copy.deepcopy(Policy.load(POLICY).raw)
    data["tasks"]["support_reply"]["sinks"]["email.send"]["allowed_recipients"] = "*@acme.example"
    with pytest.raises(PolicyError, match="must be a list"):
        Policy.from_dict(data)
