# Autonomous Agent

`vrp_hunt.agent` adds a constrained autonomous workflow:

1. A brain suggests structured vulnerability hypotheses from recon assets.
2. The planner turns hypotheses into ranked test actions.
3. The policy gate checks dry-run mode, budgets, approval rules, and
   `GuardrailGate`.
4. A runner executes only actions that passed policy.
5. The controller stops when third-party data is observed.

## Default Posture

The default `AutonomyPolicy` is `dry_run=True`. Traffic-sending actions are
planned but blocked until dry-run is disabled. IDOR/authz and state-changing
tests require explicit human approval even outside dry-run.

## Model Integration

Model providers should implement the `StructuredModelClient` protocol and return
JSON-like dictionaries with:

- `bug_class`
- `category`
- `confidence`
- `reason`

The `ModelBrain` validates those suggestions into local Pydantic models before
the planner can use them. The package also includes `HeuristicBrain` as a safe
deterministic fallback for offline operation.

`OpenAIResponsesClient` is available as an optional real provider for the same
contract. It uses `OPENAI_API_KEY`, defaults to `VRP_HUNT_OPENAI_MODEL` or
`gpt-5.2`, requests structured JSON output, and redacts sensitive metadata keys
before sending asset summaries to the model.

The CLI now wires this provider into the existing planner path:

```bash
OPENAI_API_KEY=... uv run vrp-hunt agent-plan \
  --asset url:https://accounts.google.com/profile \
  --model-provider openai \
  --allow-remote-model
```

`--allow-remote-model` is required because even redacted recon asset summaries
leave the machine when a remote provider is selected. Without it, the CLI exits
before calling the provider. The default provider remains `heuristic`.

## Example

```python
from vrp_hunt.agent import (
    AutonomyPolicy,
    AutonomousAgent,
    HeuristicBrain,
    build_agent_plan,
)
from vrp_hunt.recon import Asset

assets = [
    Asset(kind="url", value="https://accounts.google.com/profile", source="manual")
]
plan = build_agent_plan(assets, brain=HeuristicBrain(), max_actions=5)
result = AutonomousAgent(policy=AutonomyPolicy(dry_run=True)).run_plan(plan)
```

## CLI

Build an offline autonomous plan:

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

Build a gated testing plan without executing traffic:

```bash
uv run vrp-hunt agent-plan \
  --asset url:https://accounts.google.com/profile \
  --mode testing
```

The CLI also accepts `--asset-file` with JSONL `Asset` records.

## Live Handlers

Live checks are opt-in. To execute one, register an action handler through
`RegisteredActionRunner`. The handler receives an already policy-approved
`AgentAction` and must return an `AgentObservation`.

```python
from vrp_hunt.agent import AgentObservation, RegisteredActionRunner

runner = RegisteredActionRunner(
    {
        "passive_recon": lambda action: AgentObservation(
            action_id=action.action_id,
            success=True,
            notes=["completed cached lookup"],
        )
    }
)
```

## Credential Metadata

`CredentialSet` models owned test accounts and objects without storing raw secret
material. Passwords, cookies, OAuth tokens, API tokens, TOTP seeds, and recovery
codes are represented by `SecretRef` locators. Cookie handling uses `CookieRef`
for name/domain/path/security metadata while keeping the value behind a
`SecretRef`.

Accounts have a primary role and optional secondary roles. `CredentialSet`
provides role lookups and validation-pair helpers for owned-account testing.
`OwnedTestObject` records the owner account, permitted owned-account access list,
target reference, resetability, and safety flags. Sensitive or third-party test
objects are rejected by model validation.

## Evidence Capture

`EvidenceCapture` can automatically write redacted evidence artifacts under a
per-finding directory. `capture_http_log()` accepts structured
`HttpEvidenceExchange` records, redacts sensitive headers, query/body fields, API
key shapes, bearer tokens, and cookie-like values, then writes JSONL evidence.

`capture_screenshot()` writes already-redacted PNG, JPEG, or WebP screenshot
bytes. `capture_video()` writes already-redacted WebM or MP4 video bytes.
Unsupported media signatures, empty files, oversized evidence, and unsafe
filenames are rejected. All generated `EvidenceItem` records are marked
redacted.

The built-in `LiveReconRunner` supports approved recon tools only:

- `passive_recon` with `metadata={"tool": "subfinder"}`
- `passive_recon` with `metadata={"tool": "jadx"}`
- `low_volume_probe` with `metadata={"tool": "httpx"}`

`ApprovedSubprocessRunner` executes only `subfinder`, `httpx`, and `jadx`
without shell expansion. Policy, guardrails, budgets, and approval checks should
still run before the live runner is called.

Live recon also requires a local operator policy. Copy
`config/operator_policy.example.yaml` to `config/operator_policy.yaml` and edit
the local file for the legally responsible operator before live work. The real
policy file is ignored by Git because it is machine/operator-specific.

The default local policy path binds execution to one operator id, one local OS
user, the approved tool allowlist, and an explicit legal-liability
acknowledgement. This is intentionally fail-closed: missing policy, wrong
operator id, wrong OS user, unapproved tool, or missing acknowledgement blocks
tool execution before any subprocess is started.

Run one approved tool directly:

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

`SafeValidationRunner` registers non-traffic handlers for IDOR, OAuth, XSLeak,
XSS, and CSRF-oriented actions. It prepares the matching playbook and records an
observation with `request_count=0`.

The named safe action types are:

- `idor_validation`
- `oauth_validation`
- `xsleak_validation`
- `xss_validation`
- `csrf_validation`

Each handler only prepares owned-account manual validation notes. Legacy
`owned_account_authz`, `state_change_test`, and `low_volume_probe` validation
actions are still accepted as compatibility aliases, but the safe validation
runner forces them to preparation-only observations.

## Approval Gates

Testing-mode CLI runs keep two separate gates:

```bash
uv run vrp-hunt agent-run \
  --asset url:https://accounts.google.com/profile \
  --mode testing \
  --execute-safe \
  --max-live-requests 3 \
  --approve-risky
```

`--max-live-requests` budgets the plan. The built-in safe validation runner still
does not send validation traffic.

Approval handling is explicit:

- `--approval-mode block` is the default. Risky actions are listed on stderr and
  then blocked by policy.
- `--approval-mode explicit --approve-action <index|action_id>` approves only
  named risky actions. `--approve-action all` approves every risky action.
- `--approval-mode prompt` renders a terminal approval prompt on stderr. Type
  `APPROVE <index>`, `APPROVE <action_id>`, or `APPROVE ALL`.
- `--approval-mode approve-all` approves every risky action.
- `--approve-risky` remains as a legacy shortcut for `approve-all`.

The CLI keeps machine-readable run results on stdout as JSON. Approval UI text is
written to stderr.

`agent-auto` runs the safe automation loop end to end:

```bash
uv run vrp-hunt agent-auto \
  --asset url:https://accounts.google.com/profile \
  --approval-mode explicit \
  --approve-action 1 \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --artifact-output-dir artifacts/accounts-profile
```

The command builds a plan, applies the same approval gate, executes the safe
offline or validation runner, and emits one JSON object containing the approved
plan, run result, and generated FindingArtifact/ReportDraft bundle. It does not
auto-approve risky actions, create accounts, store secrets, or send validation
traffic outside the configured request budget.

`recon-iterate` turns a passive recon artifact into the next approval queue
without sending traffic:

```bash
uv run vrp-hunt recon-iterate \
  --run-json artifacts/live-subfinder-google/run.json \
  --httpx-dir artifacts/live-httpx-curated \
  --limit 10 \
  --output-dir artifacts/live-subfinder-google/iteration-01
```

It ranks public-looking Google hosts, excludes noisy infrastructure and prior
failed `httpx` probes, writes `ranked-assets.jsonl`, and writes
`approval-queue.txt` with commands that still require explicit human approval.
Repeat `--httpx-dir` to exclude failures from multiple prior batches.

## Workflow Artifacts

The agent package also includes:

- owned-account browser workflow plans for login/session handling, UI driving,
  screenshots, short video capture notes, and Burp-assisted manual replay
- credential metadata models for secret references, cookies, account roles, and
  owned test objects without storing secret values in artifacts
- evidence helpers for redacted HTTP logs, screenshots, videos, Burp exports,
  and notes
- conversion from `AgentObservation` to structured `ObservationArtifact` records
  containing both `FindingArtifact` and `ReportDraft`
- batch conversion from an `AgentPlan` plus `AgentRunResult` into an
  `AgentArtifactBundle`, with unsafe or unmatched observations reported in
  `skipped`
- submission-assistance Markdown/checklists from report drafts
