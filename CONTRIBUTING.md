# Contributing

Thanks for helping. Issues, bug reports and pull requests are all welcome.

## Setup

```bash
pip install -e ".[dev]"
pytest
ruff check .
python -m demo && python -m demo.bench
```

## Guidelines

- **Every security rule needs a test that tries to break it.** Add attacks to `tests/` or to the attack suite in `taskvault/attacks.py`.
- **Fail closed.** When unsure, block and log.
- **Never log raw sensitive values.** Use `vault.fp(value)` for correlation.
- **Keep the core dependency-light.** Vendor SDKs go behind optional extras.
- **New connectors** take an injectable transport and ship with tests against fake responses. Validate every identifier and escape every key.
- If a change affects a guarantee, update [docs/threat-model.md](docs/threat-model.md) in the same PR.
