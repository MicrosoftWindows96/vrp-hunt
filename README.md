# VRP Hunt

VRP Hunt is a Python toolkit for authorized vulnerability research workflows
against Google and Alphabet VRP scope. It focuses on guardrails, recon asset
modeling, triage, evidence handling, and report preparation. The project is
designed to fail closed: unsafe scope, ambiguous targets, missing owned-account
confirmation, third-party data exposure, and unapproved risky actions are
blocked before execution.

This repository does not contain exploit automation, account creation tooling,
or tests that make live network requests.

## What Is Included

- `vrp_hunt.guardrails`: scope normalization, policy checks, audit data, and
  conservative rate-limit contracts.
- `vrp_hunt.recon`: shared recon models, asset inventory storage, adapters,
  scheduling, and safe wrapper surfaces for HTTPX and nuclei command creation.
- `vrp_hunt.web_recon`: passive web recon parsing, guarded host filtering, polite
  probing, JavaScript URL extraction, endpoint extraction, technology notes, and
  redacted potential-secret notes.
- `vrp_hunt.mobile_recon`: Android/iOS artifact modeling, jadx/Frida/objection
  and emulator command builders, manifest parsing, endpoint extraction, deep-link
  extraction, and redacted potential-secret notes.
- `vrp_hunt.triage`: reward estimation and deterministic expected-value queues
  over recon assets and bug hypotheses.
- `vrp_hunt.playbooks`: manual testing playbooks and finding artifacts for
  owned-account, no-third-party-data validation.
- `vrp_hunt.reporting`: evidence, PoC metadata, report drafts, Markdown
  rendering, and quality linting for submission-ready artifacts.
- `vrp_hunt.tracking`: submission lifecycle logs, reward reconciliation,
  leaderboard notes, and appeal-window drafting.
- `vrp_hunt.agent`: constrained autonomous planning and execution with dry-run
  defaults, action budgets, approval gates, pluggable model providers, approved
  live-tool runners, and redacted workflow artifacts.

## Repository Layout

```text
src/vrp_hunt/          Python package
tests/                 Unit and property tests
config/                Shared rule data and local policy example
docs/                  Safety and agent workflow documentation
google-alphabet-vrp-rules.md
                       Local digest of the external Google/Alphabet VRP rules
pyproject.toml         Package metadata and tool configuration
uv.lock                Locked development environment
```

Generated planning notes, run artifacts, virtual environments, caches, local
operator policy, and secrets are intentionally ignored by Git.

## Requirements

- Python 3.11 or newer
- `uv`
- Optional live recon tools, only when explicitly used: `subfinder`,
  ProjectDiscovery `httpx`, and `jadx`

## Setup

```bash
uv sync
```

For live recon only, create a local operator policy from the committed example
and keep the real file out of source control:

```bash
cp config/operator_policy.example.yaml config/operator_policy.yaml
```

Edit `config/operator_policy.yaml` so `authorized_operator_id` and
`authorized_local_user` match the legally responsible local operator. The CLI
uses this file by default for `live-recon` unless `--operator-policy` is passed.

## Quality Checks

```bash
uv run pytest
uv run ruff check .
uv run mypy
```

The test suite is offline by design. It should not make live network requests or
spawn recon tools.

## CLI Quick Start

Build an offline plan:

```bash
uv run vrp-hunt agent-plan \
  --asset url:https://accounts.google.com/profile \
  --mode offline
```

Execute safe non-traffic handlers:

```bash
uv run vrp-hunt agent-run \
  --asset url:https://accounts.google.com/profile \
  --mode offline \
  --execute-safe
```

Build a testing-mode plan while keeping risky validation actions blocked unless
they are explicitly approved:

```bash
uv run vrp-hunt agent-run \
  --asset url:https://accounts.google.com/profile \
  --mode testing \
  --execute-safe \
  --max-live-requests 3
```

Approve a specific risky action by index or action id:

```bash
uv run vrp-hunt agent-run \
  --asset url:https://accounts.google.com/profile \
  --mode testing \
  --execute-safe \
  --approval-mode explicit \
  --approve-action 1 \
  --max-live-requests 3
```

Run the safe automation loop and write redacted artifacts:

```bash
uv run vrp-hunt agent-auto \
  --asset url:https://accounts.google.com/profile \
  --approval-mode explicit \
  --approve-action 1 \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --artifact-output-dir artifacts/accounts-profile
```

Artifacts written under `artifacts/` are ignored by Git.

Rank passive recon output and generate the next explicit live-approval queue:

```bash
uv run vrp-hunt recon-iterate \
  --run-json artifacts/live-subfinder-google/run.json \
  --httpx-dir artifacts/live-httpx-curated \
  --limit 10 \
  --output-dir artifacts/live-subfinder-google/iteration-01
```

`recon-iterate` does not send traffic. It filters noisy or already-failed hosts,
writes ranked URL assets, and emits approval lines such as
`APPROVE LIVE HTTPX https://example.google.com` for the next gated live step.
Pass `--httpx-dir` more than once to exclude failures from multiple prior
batches.

## Live Recon

Live recon is opt-in and additionally gated by:

- `config/google_vrp_rules.yaml`
- `config/operator_policy.yaml`
- `--operator-id`
- `--accept-legal-liability`
- tool-specific allowlisting for `subfinder`, ProjectDiscovery `httpx`, and
  `jadx`

Before any live traffic, re-check the canonical Google Bug Hunters rules page
and update `google-alphabet-vrp-rules.md` plus `config/google_vrp_rules.yaml` if
the rules changed.

Examples:

```bash
uv run vrp-hunt live-recon \
  --tool subfinder \
  --target google.com \
  --operator-id "$VRP_HUNT_OPERATOR_ID" \
  --accept-legal-liability

uv run vrp-hunt live-recon \
  --tool httpx \
  --target www.google.com \
  --rate-limit-per-minute 5 \
  --operator-id "$VRP_HUNT_OPERATOR_ID" \
  --accept-legal-liability

uv run vrp-hunt live-recon \
  --tool jadx \
  --target com.google.android.gm \
  --artifact-path /path/to/app.apk \
  --publisher "Google LLC" \
  --operator-id "$VRP_HUNT_OPERATOR_ID" \
  --accept-legal-liability
```

## Model-Assisted Planning

The default model provider is `heuristic`, which runs locally. Remote model
planning is opt-in and requires both credentials and an explicit acknowledgement
that redacted asset summaries may leave the machine:

```bash
OPENAI_API_KEY=... uv run vrp-hunt agent-plan \
  --asset url:https://accounts.google.com/profile \
  --model-provider openai \
  --allow-remote-model
```

The model path asks only for bounded hypothesis labels. It does not request
exploit payloads, credential material, browser actions, or live-test steps.

## Safety Boundaries

- Use only dedicated accounts owned by the researcher.
- Do not access, modify, store, or disclose third-party data.
- Do not automate account creation.
- Do not perform DoS, spam, social engineering, phishing, physical intrusion,
  black-hat SEO, broker disclosure, brute force, or disruptive testing.
- Stop immediately if unexpected third-party data appears, minimize exposure,
  redact evidence, and report through the VRP.
- Treat `google-alphabet-vrp-rules.md` and `config/google_vrp_rules.yaml` as a
  local digest that must be refreshed before live work.

See also:

- `docs/ethics-checklist.md`
- `docs/test-account-runbook.md`
- `docs/autonomous-agent.md`

## Git Hygiene

Commit source, tests, shared configuration, docs, `pyproject.toml`, and
`uv.lock`. Do not commit:

- `.env` files or credentials
- `config/operator_policy.yaml`
- `artifacts/`
- `planning/`
- virtual environments, caches, coverage output, or build output

## License

VRP Hunt is licensed under the GNU Affero General Public License v3.0 or later.
See `LICENSE`.
