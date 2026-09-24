# Security policy

taskvault is security software, so we take reports seriously.

## Reporting a vulnerability

Please **don't open a public issue**. Use GitHub's private reporting instead: go to the repository's **Security** tab and choose **Report a vulnerability**.

Include what you found, how to reproduce it, and which guarantee in [docs/threat-model.md](docs/threat-model.md) it breaks. We aim to acknowledge reports within 3 working days.

## In scope

- Any way for untrusted text to make the vault read outside a task's scope, reveal a secret to the model, or send protected data to someone who isn't its owner
- Audit log tampering that `taskvault audit verify` doesn't catch
- Cryptographic weaknesses in `taskvault.crypto`, the cache or trace storage
- Injection into connectors (SQL, SOQL, path traversal, URL manipulation)

## Out of scope

Items listed under "Not guaranteed" in the threat model, and attacks that need control of the host application, policy file, vault process or customer key.

## Supported versions

Only the latest release gets security fixes while the project is pre-1.0.
