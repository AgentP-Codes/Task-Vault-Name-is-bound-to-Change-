import copy

import pytest

from demo.__main__ import POLICY
from demo.world import ATTACKER, World
from taskvault import AuditLog, Blocked, Policy, PolicyError, Vault
from taskvault.baseline import Baseline
from taskvault.crypto import Cipher, LocalKeyProvider
from taskvault.planner import Planner
from taskvault.store import SecretStore, VaultedSource, is_ref, tokenize_rows


def _vault(world, policy=None, **kw):
    return Vault(policy or Policy.load(POLICY),
                 {"crm.customer": world.get_customer, "docs": world.get_doc, "inbox.ticket": world.get_ticket},
                 {"email.send": world.send_email, "payments.refund": world.refund}, **kw)


@pytest.fixture
def cipher(tmp_path):
    return Cipher(LocalKeyProvider(tmp_path / "k.key"))


# ---- pseudonymisation ---------------------------------------------------------

def _pseudo_policy():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["sources"]["crm.customer"]["pseudonymize"] = ["name", "email"]
    return Policy.from_dict(raw)


def test_model_sees_stable_pseudonyms_not_real_values(cipher):
    world = World()
    vault = _vault(world, _pseudo_policy(), cipher=cipher)
    c1 = vault.start_task("support_reply", customer_id=12).read("crm.customer")
    c2 = vault.start_task("support_reply", customer_id=12).read("crm.customer")
    assert c1["name"].startswith("Name-") and c1["email"].endswith("@pseudonym.invalid")
    assert "Priya" not in str(c1) and "priya" not in str(c1)
    assert c1["name"] == c2["name"] and c1["email"] == c2["email"]     # consistent across tasks


def test_pseudonyms_are_swapped_back_only_at_the_sink():
    world = World()
    t = _vault(world, _pseudo_policy()).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    t.act("email.send", to=c["email"], subject="Hi", body=f"Hi {c['name']}, sorted!")
    assert world.outbox == [{"to": "priya.shah@example.com", "subject": "Hi", "body": "Hi Priya Shah, sorted!"}]


def test_pseudonymised_data_still_cant_go_to_an_attacker():
    world = World()
    t = _vault(world, _pseudo_policy()).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    with pytest.raises(Blocked):
        t.act("email.send", to=ATTACKER, subject="x", body=c["name"])
    assert world.outbox == []


def test_planner_mode_resolves_pseudonymous_recipients():
    world = World()
    t = _vault(world, _pseudo_policy()).start_task("support_reply_planned", customer_id=12, ticket_id="T-100")
    Planner(t).run([{"id": "c", "read": "crm.customer"},
                    {"id": "m", "format": "Hi {c.name}"},
                    {"act": "email.send", "args": {"to": "$c.email", "subject": "Hi", "body": "$m"}}])
    assert world.outbox[0]["to"] == "priya.shah@example.com" and world.outbox[0]["body"] == "Hi Priya Shah"


def test_secret_fields_cannot_be_pseudonymised():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["sources"]["crm.customer"]["pseudonymize"] = ["card_number"]
    with pytest.raises(PolicyError, match="placeholders"):
        Policy.from_dict(raw)


# ---- long-term secret store ---------------------------------------------------

def test_secrets_can_live_in_the_vault_instead_of_your_database(cipher, tmp_path):
    store = SecretStore(cipher, tmp_path / "secrets.db")
    world = World()
    rows = tokenize_rows(store, list(world.customers.values()), ["card_number"], "crm.customer",
                         owner_field="customer_id")
    for r in rows:
        world.customers[r["customer_id"]] = r               # the "database" now holds references only
    assert is_ref(world.customers[12]["card_number"]) and b"4111" not in (tmp_path / "secrets.db").read_bytes()

    t = _vault(world, cipher=cipher, store=store).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    assert c["card_number"].startswith("[[vault:")
    t.act("payments.refund", card=c["card_number"], amount=5)
    assert world.refunds[0]["card"] == "4111 1111 1111 1111"

    assert store.forget_owner("customer_id:12") == 1
    with pytest.raises(KeyError):
        store.get(world.customers[12]["card_number"])


def test_vaulted_source_moves_secrets_on_first_read(cipher):
    store = SecretStore(cipher)
    world = World()
    src = VaultedSource(world.get_customer, store, "crm.customer", ["card_number"], owner_name="customer_id")
    rec = src(12)
    assert is_ref(rec["card_number"]) and store.get(rec["card_number"]) == "4111 1111 1111 1111"
    assert src(12)["card_number"] == rec["card_number"]      # stable reference


# ---- imported labels ------------------------------------------------------------

def test_existing_labels_raise_the_level_of_a_document():
    world = World()
    world.docs["refund_policy"]["sensitivity"] = "Highly Confidential"
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["sources"]["docs"].update({"label_field": "sensitivity",
                                   "label_map": {"Public": "normal", "Highly Confidential": "protected"}})
    t = _vault(world, Policy.from_dict(raw)).start_task("support_reply", customer_id=12)
    body = t.read("docs", "refund_policy")["body"]
    with pytest.raises(Blocked, match="owner company"):
        t.act("email.send", to="priya.shah@example.com", subject="policy", body=body)


# ---- risk tiers, outbound detection -----------------------------------------------

def test_medium_risk_actions_are_allowed_but_flagged():
    world, flags = World(), []
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["risk"] = "medium"
    audit = AuditLog()
    t = _vault(world, Policy.from_dict(raw), audit=audit, on_flag=flags.append).start_task("support_reply",
                                                                                            customer_id=12)
    t.act("email.send", to="priya.shah@example.com", subject="Hi", body="Hello")
    assert world.outbox and flags[0].reasons == ["medium-risk action"]
    assert audit.decisions("flag")


def test_high_risk_means_human_approval():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["risk"] = "high"
    policy = Policy.from_dict(raw)
    assert policy.tasks["support_reply"].sinks["email.send"].approval == "always"
    raw["tasks"]["support_reply"]["sinks"]["email.send"]["approval"] = "never"
    with pytest.raises(PolicyError):
        Policy.from_dict(raw)


def test_outbound_detection_catches_secrets_the_vault_never_saw():
    raw = copy.deepcopy(Policy.load(POLICY).raw)
    raw["detect_outbound"] = True
    world = World()
    t = _vault(world, Policy.from_dict(raw)).start_task("support_reply", customer_id=12)
    with pytest.raises(Blocked, match="payment card number"):
        t.act("email.send", to="priya.shah@example.com", subject="x", body="Tom's card is 5555 5555 5555 4444")
    t.act("email.send", to="priya.shah@example.com", subject="x", body="Your order 12345 has shipped")
    assert len(world.outbox) == 1


# ---- behaviour baseline -------------------------------------------------------------

def _normal_history(n=25):
    world, audit = World(), AuditLog()
    vault = _vault(world, audit=audit)
    for _ in range(n):
        t = vault.start_task("support_reply", customer_id=12)
        c = t.read("crm.customer")
        t.act("email.send", to=c["email"], subject="Re: ticket", body="Thanks, all sorted." * 3)
    bad = vault.start_task("support_reply", customer_id=12)
    with pytest.raises(Blocked):
        bad.act("email.send", to=ATTACKER, subject="x", body="y")          # not learned from
    return audit


def test_baseline_learns_only_from_clean_tasks_and_flags_unusual_actions():
    base = Baseline.learn(_normal_history().entries)
    assert base.profiles["support_reply"]["tasks"] == 25
    world, flags = World(), []
    t = _vault(world, baseline=base, on_flag=flags.append).start_task("support_reply", customer_id=12)
    c = t.read("crm.customer")
    t.act("email.send", to=c["email"], subject="Re: ticket", body="Thanks!")
    assert flags == []
    t.act("email.send", to=c["email"], subject="Re: ticket", body="x" * 2000)
    reasons = flags[0].reasons
    assert any("called 2 times" in r for r in reasons) and any("characters" in r for r in reasons)
    t.act("payments.refund", card=c["card_number"], amount=1)
    assert any("first time" in r for r in flags[-1].reasons)
    assert len(world.outbox) == 2 and world.refunds            # flags never block


def test_baseline_stays_quiet_while_learning(tmp_path):
    base = Baseline.learn(_normal_history(3).entries)
    assert base.check("support_reply", "payments.refund", 1, ["card"], [], {}) == []
    base.save(tmp_path / "b.json")
    assert Baseline.load(tmp_path / "b.json").profiles == base.profiles


# ---- CLI for v0.3 ---------------------------------------------------------------------

def test_cli_baseline_review_and_store(tmp_path, capsys):
    from taskvault.cli import main
    audit = _normal_history()
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for e in audit.entries:
        log.record(e["event"], **{k: v for k, v in e.items() if k not in ("seq", "ts", "event", "prev", "hash")})
    log.record("flag", task=1, sink="email.send", reasons=["unusual"], decision="flag")
    assert main(["baseline", "learn", "--audit", str(path), "--out", str(tmp_path / "b.json")]) == 0
    assert "25 clean tasks" in capsys.readouterr().out
    assert main(["review", "--audit", str(path)]) == 0
    assert "unusual" in capsys.readouterr().out

    csv_in = tmp_path / "customers.csv"
    csv_in.write_text("id,card_number\n1,4111 1111 1111 1111\n")
    main(["keys", "init", str(tmp_path / "k.key")])
    assert main(["store", "tokenize", str(csv_in), "--fields", "card_number", "--source", "crm.customer",
                 "--owner-field", "id", "--owner-name", "customer_id", "--key", str(tmp_path / "k.key"),
                 "--store", str(tmp_path / "s.db"), "--out", str(tmp_path / "out.csv")]) == 0
    out = (tmp_path / "out.csv").read_text()
    assert "4111" not in out and "tvref_" in out
    assert oct((tmp_path / "s.db").stat().st_mode)[-3:] == "600"
