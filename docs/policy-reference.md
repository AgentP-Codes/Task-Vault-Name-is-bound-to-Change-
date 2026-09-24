# Policy reference

A policy is one YAML file, kept in your repo and reviewed like code. `taskvault init` creates a starter; `taskvault check` validates and lints it. Unknown keys are errors.

```yaml
version: 1
internal_domains: [yourcompany.com]
cache_ttl_seconds: 300
detect_outbound: true
sources:  {...}
tasks:    {...}
tools:    {...}     # optional: for the MCP proxy and LLM adapters
upstream: {...}     # optional: for the MCP proxy
```

## `internal_domains`

Your company's own email domains. Protected data (company-owned or a customer's) may be sent to these addresses, because the company already holds it. Secrets still only go where `secrets_allowed` says.

## `cache_ttl_seconds`

How long a fetched record stays in the encrypted read-through cache (when a cipher is configured). Default 300.

## `detect_outbound`

When `true`, any outbound action with a recipient is also scanned for things that look like secrets (card numbers, TFNs, Medicare numbers, bank accounts, IBANs, API keys, private keys), even if the vault never handed them out, and blocked. `taskvault setup` turns this on.

## `sources`

What the vault may read. Each source maps to a connector you pass to `Vault(sources=...)`.

| Key | Meaning | Default |
| --- | --- | --- |
| `owner` | `company`, or the name of a trusted input that identifies the record's owner (e.g. `customer_id`) | `company` |
| `owner_contact` | Field holding the owner's verified destination (e.g. `email`). Needed on at least one source per owner | – |
| `owner_field` | Field holding the owner's id when it isn't the record key (e.g. an invoice's `supplier_id`) | record key |
| `fields` | `field: level` for each field | – |
| `key_levels` | `record-key: level`, for document stores where sensitivity is per document | – |
| `default_level` | Level for anything not listed | `protected` |
| `trust` | `trusted`, or `untrusted` for inboxes, tickets, web pages | `trusted` |
| `pseudonymize` | Fields the model sees as stable stand-ins (e.g. `Name-7F3A2C`, `email-7f3a2c@pseudonym.invalid`). Real values are swapped back only at sinks, after every check. Not for secret fields | – |
| `storage` | `external` (read from your systems through a connector) or `boxes` (taskvault deposit boxes) | `external` |
| `label_field` | Field holding an existing sensitivity label (e.g. from Microsoft Purview) | – |
| `label_map` | That label's value → level, e.g. `{Public: normal, Confidential: protected, "Highly Confidential": secret}`. The most sensitive of the field level and the label wins | – |

**Levels**

| Level | Model sees it? | Where it can go |
| --- | --- | --- |
| `secret` | No, only a `[[vault:field:xxxx]]` placeholder | Only sinks listing it in `secrets_allowed`, and only to its owner |
| `protected` | Yes (or as a pseudonym, if listed in `pseudonymize`) | Only its owner's contact, or `internal_domains` |
| `normal` | Yes | Anywhere the task may send |

## `tasks`

A task template scopes one unit of agent work.

```yaml
tasks:
  support_reply:
    description: Answer one ticket for the customer who sent it.
    trusted: [customer_id]
    reads:
      crm.customer: {key: "{customer_id}", fields: [name, email, plan, card_number]}
      docs: {keys: [refund_policy], fields: [name, body]}
    sinks:
      email.send:
        recipient_arg: to
        allowed_recipients: ["crm.customer:{customer_id}.email"]
        max_calls: 3
      payments.refund:
        args: [card, amount]
        secrets_allowed: {card_number: card}
        risk: high
        max_calls: 1
        invalidates: [crm.customer]
```

| Key | Meaning |
| --- | --- |
| `trusted` | Inputs your app must supply to `start_task`. Never derive these from untrusted text |
| `reads.<source>.key` / `keys` | Which record(s) the task may read. `{name}` is filled from trusted inputs |
| `reads.<source>.fields` | Which fields are returned. Omit to return all (linter warns) |
| `sinks.<sink>.recipient_arg` | Argument naming the recipient(s). Lists and comma-separated strings are each checked. Each must be exactly one plain address (`a@b.com` or `Name <a@b.com>`) or one plain id; anything else is blocked. Arguments named `cc`, `bcc`, `reply_to` or `recipients` get the same checks. The sink receives the checked address |
| `sinks.<sink>.allowed_recipients` | `source:key.field` (looked up by the vault), a literal address, or a glob like `*@yourcompany.com` |
| `sinks.<sink>.secrets_allowed` | Secret fields whose placeholders are swapped for real values at this sink. As a mapping (`{card_number: card}`), each secret may only be passed as that one argument |
| `sinks.<sink>.args` | The only argument names this sink accepts. Recommended for every sink with a recipient (the linter warns otherwise) |
| `sinks.<sink>.risk` | `low` (default): allow. `medium`: allow, but flag for review (`on_flag` callback, `taskvault review`). `high`: a human must approve |
| `sinks.<sink>.approval` | `always` sends every call to your `approver`; `never` (default). Set automatically by `risk: high` |
| `sinks.<sink>.max_calls` | Per-task limit |
| `sinks.<sink>.invalidates` | Sources to drop from the cache after this action |

Any source or sink not listed in the task is blocked.

List settings (`allowed_recipients`, `args`, `fields`, `trusted`...) must be written as lists, e.g. `[a, b]`. A plain string is rejected, so a typo can't turn `"*@acme.example"` into "anyone".

## `tools`

Agent-facing tool names, used by the MCP proxy and `Task.call_tool` / `Task.tool_specs` (LLM adapters).

```yaml
tools:
  get_customer: {read: crm.customer, key_arg: customer_id, description: Look up the ticket's customer.}
  send_email:   {act: email.send, description: Email the customer., params: {to: string, subject: string, body: string}}
```

A tool is only offered to a task that can use its source or sink.

## `upstream`

For `taskvault serve`: which tools on the upstream MCP server back each source and sink.

```yaml
upstream:
  sources:
    crm.customer: {tool: get_customer, key_arg: customer_id}
  sinks:
    email.send: {tool: send_email}
```

The agent never sees upstream tools directly; unmapped upstream tools are unreachable.
