import json

import pytest

from demo.__main__ import POLICY
from demo.world import World
from taskvault import Blocked, Policy, Vault
from taskvault.cache import EncryptedCache
from taskvault.crypto import Cipher, KeyError_, KMSKeyProvider, LocalKeyProvider


class FakeKMS:
    """Stands in for a customer's cloud KMS: wraps keys with its own secret."""

    def __init__(self):
        self.master = Cipher(type("K", (), {"key_id": "m", "data_key": lambda s: b"k" * 32})())
        self.revoked = False

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.master.encrypt(plaintext.hex())

    def decrypt(self, blob: bytes) -> bytes:
        if self.revoked:
            raise PermissionError("key disabled by customer")
        return bytes.fromhex(self.master.decrypt(blob))


@pytest.fixture
def cipher(tmp_path):
    return Cipher(LocalKeyProvider(tmp_path / "customer.key"))


def test_key_file_is_private(tmp_path):
    LocalKeyProvider(tmp_path / "k.key")
    assert oct((tmp_path / "k.key").stat().st_mode)[-3:] == "600"


def test_round_trip_and_tamper_detection(cipher):
    blob = cipher.encrypt({"card": "4111"}, aad="ctx")
    assert cipher.decrypt(blob, aad="ctx") == {"card": "4111"}
    with pytest.raises(KeyError_):
        cipher.decrypt(blob, aad="other-context")
    with pytest.raises(KeyError_):
        cipher.decrypt(blob[:-1] + bytes([blob[-1] ^ 1]), aad="ctx")


def test_crypto_shredding_makes_data_unreadable(tmp_path):
    keys = LocalKeyProvider(tmp_path / "k.key")
    cipher = Cipher(keys)
    blob = cipher.encrypt("secret")
    keys.shred()
    with pytest.raises(KeyError_, match="destroyed"):
        cipher.decrypt(blob)


def test_kms_envelope_and_revocation(tmp_path):
    kms = FakeKMS()
    keys = KMSKeyProvider(kms, tmp_path / "wrapped.key", key_id="arn:aws:kms:demo")
    blob = Cipher(keys).encrypt("hello")
    assert b"hello" not in (tmp_path / "wrapped.key").read_bytes()
    kms.revoked = True
    keys.forget()
    with pytest.raises(KeyError_, match="KMS refused"):
        Cipher(keys).decrypt(blob)


def test_cache_expires_and_is_encrypted_at_rest(cipher, tmp_path):
    now = [1000.0]
    path = tmp_path / "cache.db"
    cache = EncryptedCache(cipher, ttl_seconds=60, path=path, clock=lambda: now[0])
    cache.put("crm.customer", 12, {"email": "priya.shah@example.com"})
    assert cache.get("crm.customer", 12) == {"email": "priya.shah@example.com"}
    assert b"priya" not in path.read_bytes()
    now[0] += 61
    assert cache.get("crm.customer", 12) is None


def _vault(world, **kw):
    return Vault(Policy.load(POLICY), sources={"crm.customer": world.get_customer, "docs": world.get_doc,
                          "inbox.ticket": world.get_ticket},
                 sinks={"email.send": world.send_email, "payments.refund": world.refund}, **kw)


def test_read_through_cache_serves_repeat_reads(cipher):
    world, calls = World(), []
    orig = world.get_customer
    world.get_customer = lambda k: (calls.append(k), orig(k))[1]
    vault = _vault(world, cipher=cipher, cache=EncryptedCache(cipher))
    for _ in range(3):
        vault.start_task("support_reply", customer_id=12).read("crm.customer")
    assert calls == [12]


def test_placeholders_are_sealed_and_audit_uses_keyed_fingerprints(cipher):
    world = World()
    vault = _vault(world, cipher=cipher)
    task = vault.start_task("support_reply", customer_id=12)
    c = task.read("crm.customer")
    sealed = task._tokens[c["card_number"]][0]
    assert isinstance(sealed, bytes) and b"4111 1111 1111 1111" not in sealed
    task.act("payments.refund", card=c["card_number"], amount=10)
    assert world.refunds[0]["card"] == "4111 1111 1111 1111"
    assert "4111 1111 1111 1111" not in json.dumps(vault.audit.entries)


# ---- approvals, limits, globs ----------------------------------------------

RAW = {
    "internal_domains": ["acme.example"],
    "sources": {"docs": {"owner": "company", "default_level": "normal"}},
    "tasks": {"t": {"trusted": [], "reads": {"docs": {"keys": ["faq"]}},
                    "sinks": {"email.send": {"recipient_arg": "to", "allowed_recipients": ["*@acme.example"],
                                             "max_calls": 2},
                              "payments.refund": {"approval": "always"}}}},
}


def _raw_vault(world, approver=None):
    world.docs["faq"] = {"body": "hello"}
    return Vault(Policy.from_dict(RAW), sources={"docs": world.get_doc},
                 sinks={"email.send": world.send_email, "payments.refund": world.refund}, approver=approver)


def test_recipient_globs_and_call_limits():
    world = World()
    t = _raw_vault(world).start_task("t")
    t.act("email.send", to="ops@acme.example", subject="a", body="b")
    t.act("email.send", to="SALES@acme.example", subject="a", body="b")
    with pytest.raises(Blocked, match="more than 2 times"):
        t.act("email.send", to="ops@acme.example", subject="a", body="b")
    with pytest.raises(Blocked):
        _raw_vault(World()).start_task("t").act("email.send", to="ops@acme.example.evil.com", subject="", body="")


def test_multiple_recipients_are_each_checked():
    t = _raw_vault(World()).start_task("t")
    with pytest.raises(Blocked, match="attacker"):
        t.act("email.send", to=["ops@acme.example", "attacker@evil.example"], subject="a", body="b")
    with pytest.raises(Blocked):
        t.act("email.send", to="ops@acme.example, attacker@evil.example", subject="a", body="b")


def test_approval_required_fails_closed_without_an_approver():
    world = World()
    with pytest.raises(Blocked, match="no approver"):
        _raw_vault(world).start_task("t").act("payments.refund", card="x", amount=1)
    seen = []
    ok = _raw_vault(world, approver=lambda req: seen.append(req) or True).start_task("t")
    ok.act("payments.refund", card="x", amount=1)
    assert seen[0].sink == "payments.refund" and world.refunds


def _audit_writer(path, n):
    from taskvault.audit import AuditLog
    log = AuditLog(path)
    for i in range(n):
        log.record("act", i=i, pid=__import__("os").getpid())


def test_several_processes_can_share_one_audit_file(tmp_path):
    """Found by the stress test: separate processes appending to one file must keep one valid chain."""
    import multiprocessing as mp

    from taskvault.audit import AuditLog
    path = str(tmp_path / "shared.jsonl")
    procs = [mp.get_context("spawn").Process(target=_audit_writer, args=(path, 150)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    log = AuditLog(path)
    assert len(log.entries) == 600 and log.verify(), log.first_bad_entry()
