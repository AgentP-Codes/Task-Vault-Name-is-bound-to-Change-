# Threat model

taskvault assumes the model **will** be fooled sometimes. It doesn't try to detect prompt injection. It limits what a fooled agent can reach and where data can go, using deterministic checks outside the model.

> The properties below are what taskvault is **designed** to enforce. They aren't a warranty or a promise of security: the software is experimental, hasn't been independently audited, and may contain bugs. See the [Disclaimer](../README.md#disclaimer).

## What we protect

| Asset | Example |
| --- | --- |
| Customer data | Names, emails, phone numbers, addresses, account records |
| Secrets | Card numbers, bank account numbers, government IDs, credentials |
| Company data | Pricing, contracts, internal documents |
| Actions | Refunds, payments, emails, record updates |

## Attacker

Anyone who can put text in front of the agent: a customer email, a support ticket, a web page, a document, a tool description. We assume the attacker **fully controls the model's output** once their text is read. They know how taskvault works (open design). They do not control the host application, the policy file, the vault process, the customer's key, or the source systems.

## Trust boundaries

```
 trusted                                  untrusted
 ───────                                  ─────────
 your app (decides trusted inputs)        ticket / email / web text
 policy file (reviewed in PRs)            everything the model says
 vault process + customer key             tool descriptions from third parties
 source systems (CRM, ERP, drive)
```

Trusted inputs (e.g. "this task is for customer 12") must come from your app, typically from a verified sender or an authenticated session. **If your app derives trusted inputs from untrusted text, every guarantee below is void.**

## Designed protections

Assuming the vault and key store aren't compromised and the policy is correct:

| # | Protection | Tool mode (`Task`, MCP proxy) | Planner mode |
| --- | --- | --- | --- |
| 1 | A task reads only the records and fields its template allows, keyed from trusted inputs | ✅ | ✅ |
| 2 | Secret fields never enter the model's context (placeholders only) | ✅ | ✅ (including the quarantined extractor) |
| 3 | Secrets are only turned back into real values at sinks listed in `secrets_allowed` | ✅ | ✅ |
| 4 | Recipients must match `allowed_recipients`, resolved by the vault from trusted data | ✅ | ✅ |
| 5 | Protected data only reaches its owner or internal domains | ⚠️ value matching: exact values and document lines | ✅ by provenance: survives rewording and encoding |
| 6 | A recipient derived from untrusted content is rejected, even if it looks valid | ⚠️ only via rule 4 | ✅ |
| 7 | Sinks reject arguments not in their `args` list and calls beyond `max_calls` | ✅ | ✅ |
| 8 | `approval: always` actions need a human yes; with no approver they fail closed | ✅ | ✅ |
| 9 | Every read, action, block and approval is in a hash-chained audit log with no raw sensitive values | ✅ | ✅ |
| 10 | Cached records, placeholder values, stored secrets and traces are encrypted with the customer's key; destroying the key makes them unreadable | ✅ when a cipher is configured | ✅ |
| 11 | Fields listed in `pseudonymize` reach the model only as stand-ins; recipients and data checks run on the real values | ✅ | ✅ |
| 12 | Recipients are compared after normalisation; display-name tricks, header injection, hidden second recipients and look-alike characters are rejected | ✅ | ✅ |
| 13 | Deposit boxes: a high-tier box can't be opened without both the vault's key and the holder's key; one holder's key can't open another holder's box; every opening is in that box's own tamper-evident log | ✅ | ✅ |

## Detection (helpful, never relied on)

These add oversight but aren't enforced protections: `detect_outbound` pattern matching, the behaviour baseline and `risk: medium` flags, and the classifications `taskvault setup` suggests. The baseline learns only from tasks with no blocks, so an attack can't teach it that exfiltration is normal, but a patient attacker could still behave "normally" for a long time.

## Not protected against (be honest with your users)

- **Content of allowed actions.** A fooled agent can still send the *right* customer a wrong, rude or misleading message. Review outbound content separately if that matters.
- **Tool mode, rule 5.** An agent that paraphrases, splits or encodes protected data can get it past value matching *to a recipient the task already allows*. Untrusted recipients are still blocked outright. Use planner mode where this matters.
- **Planner-mode conditions.** A `when:` condition derived from untrusted text lets that text decide *whether* a pre-approved action happens (one bit), not what it does. Conditions are logged.
- **Pseudonyms are consistent.** The same person gets the same stand-in across tasks, so a model (or its provider) can link activity to one pseudonymous person without learning who they are. Use a separate key per tenant to keep tenants unlinkable.
- **Deposit boxes while open.** Once a holder allows an opening, their key stays in the vault's memory for `open_ttl` seconds (default 300) so a task can finish. Keep it short, and call `close_all()` when a task ends.
- **Box metadata.** Box ids, tiers, item counts and timings are visible to anyone with database access; holder names, field names and values are encrypted.
- **Side channels.** Timing, error messages and whether an action happened can leak small amounts of information.
- **Sinks without a recipient.** For sinks like webhooks the vault can't know who receives the data. `taskvault check` warns about these; restrict them with `args` and don't send protected data to them.
- **A compromised host, policy, vault or key.** Out of scope.
- **Availability.** A hostile ticket can make an agent do nothing useful.

## Failure behaviour

| Situation | Behaviour |
| --- | --- |
| Rule violated (enforce mode) | Action blocked, `Blocked` raised, audit entry written |
| Rule violated (shadow mode) | Action allowed, `would_block` audit entry written |
| Approval needed, no approver | Blocked (fails closed) |
| Unknown source, sink or tool | Blocked |
| Key missing or revoked | Decryption fails; nothing is returned |
| Cache entry expired | Re-fetched from the source system |

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md).
