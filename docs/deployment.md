# Deploying taskvault to production

A checklist for running taskvault in front of real agents and real data.

## 1. Install and pin

```bash
pip install "taskvault[all]==0.3.0"
```

Pin the version. Read the changelog before upgrading, and rerun `taskvault test` in CI on every upgrade.

## 2. Keys

The customer's key encrypts cached records, stored secrets, placeholders and traces.

- **Cloud (recommended):** use `KMSKeyProvider` with the customer's own KMS key (e.g. AWS KMS). Only a wrapped data key is stored on disk; revoking the KMS key revokes access.
- **Local:** `taskvault keys init /secure/volume/customer.key` creates a 256-bit key with owner-only permissions. Keep it out of version control, back it up separately from the data, and restrict who can read it.
- **Crypto-shredding:** `taskvault keys shred PATH`, or revoking the KMS key, makes everything encrypted under it unreadable. Test this in staging before relying on it.
- Use a **separate key per customer or tenant**, so pseudonyms and stored data can't be linked across tenants.

## 3. Write and test the policy

1. `taskvault setup ...` against a staging copy of your data (or `taskvault init`).
2. Review every comment in `taskvault.yaml`, especially low-confidence fields in `setup-report.md`.
3. Set `internal_domains` to your real domains.
4. Put `taskvault check` and `taskvault test` in CI; the build fails if any attack leaks.
5. Review policy changes in pull requests like any other code.

## 4. Trusted inputs

Everything depends on this: the values you pass to `start_task` (e.g. `customer_id`) must come from **your** system: an authenticated session, a verified email sender, a ticket's customer record. Never from text the model or the customer wrote.

## 5. Roll out in shadow mode first

1. Run with `mode="shadow"` (or `taskvault serve --shadow`) for one to two weeks. Nothing is blocked.
2. `taskvault plan --audit audit.jsonl --policy taskvault.yaml` shows what *would* have been blocked, and which paths were never exercised (month-end, refunds, rare cases).
3. Fix false alarms in the policy; declare rare paths up front.
4. Switch to enforce.

## 6. Audit log

- Use `AuditLog(path, fsync=True)` so each entry is on disk before the action runs.
- Ship the log to your SIEM or write-once storage (e.g. S3 Object Lock). The hash chain proves order and integrity; off-box copies protect against truncation.
- Check it regularly: `taskvault audit verify audit.jsonl` (exits 1 if the chain is broken).
- The log never contains raw sensitive values, only keyed fingerprints, field names and decisions.

## 7. Oversight

- Give high-risk sinks `risk: high` and pass an `approver` that asks a person (Slack, email, a queue). With no approver configured, high-risk actions fail closed.
- Use `risk: medium` and `on_flag` for actions worth a look but not worth blocking.
- After a few weeks of clean traffic, `taskvault baseline learn --audit audit.jsonl` and run with `--baseline baseline.json` to flag unusual behaviour. Review with `taskvault review`.

## 8. Secrets

For the sharpest values (cards, bank accounts, IDs), consider moving them into the vault entirely:

```bash
taskvault store tokenize customers.csv --fields card_number --source db.customers \
    --owner-field id --owner-name customer_id --key customer.key --store secrets.db --out customers.tokenized.csv
```

Load the tokenized file back into your database: it now holds `tvref_...` references instead of card numbers. `SecretStore.forget_owner()` deletes one customer's secrets for erasure requests.

## 9. Deposit boxes

- **Database:** SQLite is fine for one server; use Postgres (`postgresql://...`) when several vault processes share boxes. Back it up like any database: its contents are encrypted.
- **Holder keys:** for departments, `taskvault boxes holder` creates a key file; give it to the department and keep it off the vault server where possible. For customers or client companies, implement `HolderKeys` against *their* key service so their private key never sits with you.
- **Approvals:** pass an `approver` to the holder key service to require a person (e.g. an HR manager) to allow each opening of a high-security box.
- **Recovery:** create a company recovery key pair, keep the private half offline (e.g. in a safe), and pass its public key as `recovery_public_key`. It's the break-glass if a holder loses their key.
- **Erasure:** `taskvault boxes forget --holder customer:12` for a deletion request.

## 10. Logging

taskvault logs decisions to the standard `logging` module under the `taskvault` logger (blocks at INFO). It never logs raw sensitive values. Route it wherever your service logs go.

## 11. Incidents

1. `taskvault audit show audit.jsonl --decision block` to see what was stopped.
2. If you ran with `--record`, `taskvault replay <trace> --agent yourmodule:agent --remove "suspect text"` reruns the session with every tool stubbed, to find the likely cause. Results go to a separate investigation store; the audit log gets one entry per replay.
3. Pin traces you need to keep: `taskvault traces pin <id>`. Others expire after the retention period.
