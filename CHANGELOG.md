# Changelog

## 0.4.2

Security and reliability fixes from a round of stress testing (with Claude Opus 5.5). Not an independent review.

**Security**
- Recipients must be exactly one plain address or id: a hidden second address could get past a glob rule like `*@yourcompany.com`
- Sink replies and error messages are masked (real values replaced with the placeholder or stand-in the agent saw); sink errors are raised as `SinkError`
- `cc` / `bcc` / `reply_to` / `recipients` arguments are checked like the main recipient; sinks receive the checked address
- Damaged or forged placeholders are blocked; tool arguments are type-checked against the policy's `params`
- Block reasons written to logs and the audit file contain no data values; agent-chosen names are fingerprinted
- List settings in policies must be lists (a string like `"*@acme.example"` was read as characters, including `*`); wrong shapes raise `PolicyError`
- A failure unlocking a stored secret is a logged block
- Requires `cryptography>=49` (older versions have known vulnerabilities)
- REST connector: only http(s) URLs; keys can't be `.` or `..`

**Reliability**
- Deposit boxes: a race could replace a box's data key (making earlier items unreadable); SQLite waits instead of failing with "database is locked"; Postgres setup is serialised
- Audit log: an OS-level file lock and chaining from the file's real last entry, so several processes can share one file; `taskvault audit repair` sets aside a torn last line
- MCP proxy: malformed JSON-RPC gets an error reply instead of crashing the proxy
- Clear errors for damaged key files and policies of the wrong shape
- Linter warns when a sink with a recipient has no `args` list; templates and demo policy now list them

**Testing**
- Fuzz tests (`tests/test_fuzz.py`, needs `hypothesis`), hardening tests, MCP proxy fuzz tests, multi-process audit test, concurrent deposit-box test
- `python -m demo.stress`: throughput, 32-thread and multi-writer checks, 10 MB inputs, 100,000-row setup scan
- Fixed a test that failed at random (short digit strings matching random hex)
- 231 tests

## 0.4.1

- First tests with live models (Claude Sonnet 5, Haiku 4.5, Opus 5.5; Gemini 3.5 Flash-Lite and 2.5 Flash on the free tier): with the vault, 0 of 43 attack runs leaked; without it, realistic attacks leaked data on several models. Chart, table and raw data in `docs/real-model-results.md`
- Planner mode: plans are checked against the policy (sources, sinks, required arguments, field references) before they run, and the model gets the errors back with up to two retries
- Planner prompt lists each sink's arguments and each source's keys, with a worked example
- The extractor may answer "unknown" (null); a `when` on it skips the action
- Gemini: waits out free-tier per-minute rate limits; the benchmark stops cleanly and keeps its results if a daily quota runs out
- README: fuller disclaimer and limitations; security features described as design goals, not guarantees
- Five harder, realistic attacks in the benchmark (new email address, shared account, staff impersonation, full card for records, forwarded internal request); `--scenarios` to run a subset
- 166 tests

## 0.4.0

- Deposit boxes: per-holder encrypted boxes for departments, customers and client companies, stored in SQLite or Postgres
- Two tiers: normal boxes open with the vault's key; high-security boxes need the vault's key and the holder's key (X25519 sealed per item), optionally with the holder's approval, for a limited time
- High-security values stay locked until an approved action needs them
- Per-box tamper-evident logs, `forget_holder`, and an optional company recovery key
- `storage: boxes` for policy sources; `taskvault boxes holder|put|list|log|forget`; `taskvault serve --boxes`
- Postgres support tested against a real Postgres 16 server (deposit boxes, setup scanner, SQL connector)
- 156 tests

## 0.3.0

- `taskvault setup`: scans SQLite, Postgres, CSV/JSON files, document folders and MCP servers, then writes a commented policy, synthetic fixtures, connector code and a report, and runs the attack suite
- Automatic detection of sensitive data (cards, TFN, Medicare, ABN, BSB/account, IBAN, API keys, private keys, emails, phones, names, addresses...) with checksums; `taskvault scan`
- Pseudonymisation: the model sees stable stand-ins for names, emails and phones; real values only at sinks
- Long-term secret store: move secrets into the vault, keep `tvref_` references in your data; `taskvault store tokenize`; per-owner erasure
- Risk tiers on sinks (`low` / `medium` flags for review / `high` needs approval) and `taskvault review`
- Behaviour baseline learned from clean tasks; flags unusual actions; `taskvault baseline`
- Import existing sensitivity labels (`label_field`, `label_map`)
- `detect_outbound`: block outbound text that looks like a secret
- `secrets_allowed` can bind each secret to one argument
- Protected data may go to internal domains
- Hardening: recipient normalisation (display names, header injection, hidden recipients, look-alike characters), owner-only file permissions, thread-safe audit log with optional fsync, `taskvault` logger, error hierarchy (`TaskvaultError`), typed package
- File connectors (`FolderDocuments`, `TableFile`)
- Tested on Python 3.10-3.13; 131 tests

## 0.2.0

- Planner mode: provenance-tracked plans with a quarantined extractor and conditional actions
- Customer-held keys (local file or cloud KMS envelope), AES-256-GCM, crypto-shredding
- Encrypted read-through cache with TTL and invalidation
- Connectors: SQL, REST, Salesforce, Google Drive, SharePoint/OneDrive, SMTP
- MCP proxy (`taskvault serve`) with host-supplied trusted inputs
- CLI: `init`, `check`, `test`, `plan`, `serve`, `replay`, `traces`, `audit`, `keys`
- Worst-case attack suite with an independent leak oracle, and a policy linter
- Encrypted session traces and replay investigations, kept separate from the audit log
- Anthropic and OpenAI adapters; benchmark harness (`python -m demo.bench`)
- Policy: `owner_field`, sink `args`, `approval`, `max_calls`, `invalidates`, recipient globs, `tools`, `upstream`
- Support and finance policy templates

## 0.1.0

- Task-scoped reads, secret placeholders, owner-bound outbound checks, shadow mode, hash-chained audit log
- Offline demo of a hijacked support agent
