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
- `vrp_hunt.programs`: bug bounty program registry loading, scope matching,
  reward metadata, safe-harbor summaries, exclusions, and rate-limit records.
- `vrp_hunt.recon`: shared recon models, asset inventory storage, adapters,
  scheduling, passive source readiness checks, and safe wrapper surfaces for
  HTTPX and nuclei command creation.
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

Check a target against the configured program registry:

```bash
uv run vrp-hunt program-match \
  --target https://accounts.google.com/
```

Compare two program registry snapshots and show fresh reward-eligible scope:

```bash
uv run vrp-hunt program-diff \
  --old-registry old-program-registry.yaml \
  --new-registry config/program_registry.yaml \
  --fresh-only
```

Run a declarative recon workflow:

```bash
uv run vrp-hunt recon-workflow \
  --workflow workflows/google-recon.yaml \
  --operator-id "$VRP_HUNT_OPERATOR_ID" \
  --accept-legal-liability
```

Check passive recon source readiness without printing secret values:

```bash
uv run vrp-hunt passive-sources
uv run vrp-hunt passive-sources-env-template --output .env.passive.example
```

Score existing recon assets by confidence, freshness, and priority:

```bash
uv run vrp-hunt asset-score \
  --asset-file artifacts/recon-depth/assets.jsonl \
  --output artifacts/recon-depth/asset-scores.json
```

Mine saved HTML or JavaScript content for scoped, redacted endpoint assets:

```bash
uv run vrp-hunt endpoint-mine \
  --document "https://www.google.com/=artifacts/pages/www-google.html" \
  --scope-domain google.com \
  --assets-output artifacts/endpoint-mine/assets.jsonl
```

Build safe validator actions from saved owned-account page snapshots:

```bash
uv run vrp-hunt owned-crawl-plan \
  --page "owned-a=https://docs.google.com/document/d/owned/edit=artifacts/owned/pages/doc.html" \
  --scope-domain google.com \
  --plan-output artifacts/owned/validation-plan.json
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

For low-friction owned-account automation, `--yolo` is available as an
approval shortcut. It approves approval-required actions for that run, but it
does not disable guardrails, budgets, local operator policy, owned-object URL
checks, legal acknowledgement requirements, or third-party-data stops.

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

Check one authenticated owned-object URL from an isolated browser profile:

```bash
uv run vrp-hunt owned-browser-check \
  --account-id owned-b \
  --profile-dir "$HOME/.vrp-hunt/browser-profiles/owned-b" \
  --url "https://drive.google.com/file/d/OWNED_TEST_OBJECT_ID/view" \
  --confirm-owned-object
```

This command refuses broad account pages and writes only a redacted access-state
classification. It does not export cookies, passwords, page text, or screenshots.
If a local Chrome session must stay open, launch it with
`--remote-debugging-port` and pass `--cdp-url http://127.0.0.1:<port>` instead
of `--profile-dir`.

Run a repeatable owned-object access matrix:

```yaml
scenario_id: docs-private-derived-deny
researcher_owned: true
accounts:
  - account_id: owned-b
    cdp_url: http://127.0.0.1:9223
steps:
  - name: private-doc-denied-to-owned-b
    account_id: owned-b
    url: https://docs.google.com/document/d/OWNED_TEST_OBJECT_ID/edit
    expected_state: access_denied
```

```bash
uv run vrp-hunt owned-browser-scenario \
  --scenario scenarios/docs-private-derived-deny.yaml \
  --expand-derived \
  --output-dir artifacts/owned-scenarios/docs-private-derived-deny
```

`owned-browser-scenario` runs exact owned-object assertions across already
authenticated test-account profiles or local CDP sessions. With
`--expand-derived`, it checks conservative view/edit/preview variants for the
same owned object and records only redacted URL hashes, access-state
classifications, and mismatch summaries.
Pass `--yolo` to continue through mismatches and collect the full matrix; safety
validation still runs before the browser opens any URL.

Generate scenario files from an owned-object catalog:

```yaml
catalog_id: docs-baseline
researcher_owned: true
accounts:
  - account_id: owned-a
    cdp_url: http://127.0.0.1:9222
  - account_id: owned-b
    cdp_url: http://127.0.0.1:9223
    cookie_env: OWNED_B_COOKIE
objects:
  - object_id: owned-a-private-doc
    product: docs
    owner_account_id: owned-a
    url: https://docs.google.com/document/d/OWNED_TEST_OBJECT_ID/edit
    expected_states:
      owned-a: access_granted
      owned-b: access_denied
```

```bash
uv run vrp-hunt scenario-generate \
  --object-catalog catalogs/docs-baseline.yaml \
  --output-dir scenarios/generated/docs-baseline
```

The generator writes one scenario per owned object plus `scenario-index.json`.
It is offline and fails closed unless the catalog confirms researcher ownership,
uses exact owned-object URLs, names known owned accounts, and marks every object
as non-sensitive and free of third-party data.

Convert high-signal scenario mismatches into draft report artifacts:

```bash
uv run vrp-hunt scenario-artifacts \
  --scenario scenarios/generated/docs-baseline/docs-baseline-owned-a-private-doc.yaml \
  --scenario-result artifacts/scenarios/docs-baseline/scenario-result.json \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --component "Docs private object" \
  --output-dir artifacts/findings/docs-baseline
```

`scenario-artifacts` creates `FindingArtifact` and `ReportDraft` records only
when an expected `access_denied` state is observed as `access_granted` with no
third-party data. Matching results, login-required states, timeouts, and other
low-signal mismatches are skipped with explicit reasons.

Run metadata-only checks for derived HTTP resources:

```bash
OWNED_B_COOKIE='SID=...; HSID=...' uv run vrp-hunt derived-http-check \
  --account-id owned-b \
  --url "https://docs.google.com/document/d/OWNED_TEST_OBJECT_ID/edit" \
  --cookie-env OWNED_B_COOKIE \
  --expected-state access_denied \
  --confirm-owned-object \
  --output-dir artifacts/derived/docs-private-owned-b
```

`derived-http-check` derives export/download/thumbnail-style endpoints for the
same exact owned object and stores only metadata: status code, final host, path
hashes, redirect count, selected redacted headers, and access-state
classification. It does not store response bodies, cookie values, downloaded
files, or raw redirect URLs. Cross-site redirects are classified but not
followed.

Convert high-signal derived HTTP metadata mismatches into draft reports:

```bash
uv run vrp-hunt derived-http-artifacts \
  --derived-http-result artifacts/derived/docs-private-owned-b/derived-http-result.json \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --component "Docs export endpoint" \
  --output-dir artifacts/findings/derived-docs
```

`derived-http-artifacts` drafts findings only for expected `access_denied`
results that observed `access_granted_metadata` while storing no response body
and reading zero response-body bytes.

Run the full owned-object workflow from one catalog:

```bash
OWNED_B_COOKIE='SID=...; HSID=...' uv run vrp-hunt owned-object-pipeline \
  --object-catalog catalogs/docs-baseline.yaml \
  --output-dir artifacts/pipeline/docs-baseline \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --component "Docs private object" \
  --yolo
```

`owned-object-pipeline` generates scenarios, runs browser access checks, drafts
scenario findings, runs metadata-only derived HTTP checks for denied accounts
with `cookie_env`, drafts derived findings, and writes `pipeline-summary.json`.
It keeps raw cookies out of output and uses local ignored artifact directories
for real object URLs.

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

Rank passive mobile hypotheses from JADX output:

```bash
uv run vrp-hunt mobile-hypotheses \
  --app-id com.google.android.gm \
  --artifact-path artifacts/jadx/com.google.android.gm \
  --output-dir artifacts/mobile/com.google.android.gm
```

Import APK fingerprints, JADX output, and MobSF static JSON into mobile assets:

```bash
uv run vrp-hunt mobile-import \
  --app-id com.google.android.gm \
  --apk-path artifacts/mobile/com.google.android.gm.apk \
  --jadx-output artifacts/jadx/com.google.android.gm \
  --mobsf-report artifacts/mobsf/com.google.android.gm.json \
  --output-dir artifacts/mobile/com.google.android.gm
```

Render a local static dashboard from generated artifacts:

```bash
uv run vrp-hunt dashboard \
  --asset-file artifacts/recon-depth/assets.jsonl \
  --approval-queue artifacts/recon-depth/approval-queue.txt \
  --artifact-bundle artifacts/pipeline/docs-baseline/findings/scenario/artifact-bundle.json \
  --summary-json artifacts/recon-depth/recon-depth-summary.json \
  --output artifacts/dashboard/index.html
```

`mobile-hypotheses` does not send traffic or run account-backed validation. It
turns decompiled artifacts into ranked manual-review leads such as OAuth
redirect handling, deep-link authorization boundaries, WebView bridge exposure,
API surfaces, and redacted secret-shape notes.

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
