# Contributing

This project is built around conservative, authorized vulnerability research.
Changes should preserve the fail-closed posture: ambiguous scope, unsafe actions,
third-party data exposure, and missing approvals must block execution.

## Development

```bash
uv sync
uv run pytest
uv run ruff check .
uv run mypy
```

Tests must stay offline unless a test explicitly uses local fakes. Do not add
tests that make live network requests, create accounts, or spawn recon tools.

## License

By contributing, you agree that your contribution is licensed under
AGPL-3.0-or-later, the same license as the project.

## Safety Expectations

- Keep owned-account workflows manual unless the code is only modeling metadata.
- Store secret references, not secret values.
- Redact credentials, cookies, tokens, and third-party data from evidence.
- Keep live recon opt-in, budgeted, allowlisted, and operator-authorized.
- Update docs when CLI flags, safety behavior, or artifact formats change.

## Git Hygiene

Do not commit local secrets, `.env` files, `config/operator_policy.yaml`,
generated `artifacts/`, generated `planning/`, caches, coverage output, virtual
environments, or build output.
