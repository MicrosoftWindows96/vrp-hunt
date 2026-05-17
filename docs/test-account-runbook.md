# Manual Test-Account Runbook

Use a small number of dedicated Google test accounts that you create manually.
Do not use personal accounts or accounts belonging to anyone else.

Recommended manual workflow:

1. Create each dedicated account by hand through Google's normal UI.
2. Record the account purpose locally outside source control.
3. Keep credentials out of code, logs, screenshots, and fixtures.
4. Avoid storing real personal data in the account.
5. Isolate accounts by experiment when state separation matters.
6. Stop testing if an account triggers safety systems or exposes non-owned data.

Credential and object metadata:

- Store only secret references, such as environment variable names or external
  vault references. Do not store password, token, or cookie values in artifacts.
- Cookie metadata may record names, domains, paths, and security flags, but the
  cookie value must remain a `SecretRef`.
- Assign clear account roles such as owner, attacker, victim, admin, or viewer.
  Keep role-separated accounts distinct when validating authorization behavior.
- Owned test objects must be researcher-created, non-sensitive, and free of
  third-party data.
- Record which owned accounts may access each test object, and keep the owner
  account in that access list.

Forbidden:

- scripts for registration
- browser automation for account creation
- account farms or bulk registration
- SMS or phone quota bypass
- evasion of anti-abuse systems
- use of accounts not owned by the researcher

Narrow automation:

- Use `owned-browser-check` only for a single explicit Drive, Docs, or Sites
  object URL that you created in an owned test account.
- Use `owned-browser-scenario` when the same owned object needs to be checked
  across accounts, permission states, or derived view/edit/preview URLs.
- The command refuses broad pages such as Drive home and requires
  `--confirm-owned-object`.
- It records only a redacted URL hash and an access-state classification. It
  does not export cookies, tokens, raw page text, passwords, or screenshots.
- Avoid stealth, anti-bot bypass, proxy rotation, and generalized scraping for
  Google account workflows.

Example:

```bash
uv run vrp-hunt owned-browser-check \
  --account-id owned-b \
  --profile-dir "$HOME/.vrp-hunt/browser-profiles/owned-b" \
  --url "https://drive.google.com/file/d/OWNED_TEST_OBJECT_ID/view" \
  --confirm-owned-object \
  --output-path artifacts/owned-account-validation/evidence/drive/owned-b-before-share.json
```

If Chrome profile encryption prevents a persistent Playwright launch from seeing
the manual login, use a visible Chrome instance with local CDP instead:

```bash
open -na "Google Chrome" --args \
  --user-data-dir="$HOME/.vrp-hunt/browser-profiles/owned-b" \
  --profile-directory=Default \
  --remote-debugging-port=9223 \
  https://accounts.google.com/

uv run vrp-hunt owned-browser-check \
  --account-id owned-b \
  --cdp-url http://127.0.0.1:9223 \
  --url "https://drive.google.com/file/d/OWNED_TEST_OBJECT_ID/view" \
  --confirm-owned-object
```

Owned scenario example:

```yaml
scenario_id: drive-private-deny
researcher_owned: true
stop_on_mismatch: true
accounts:
  - account_id: owned-b
    cdp_url: http://127.0.0.1:9223
steps:
  - name: owned-b-denied
    account_id: owned-b
    url: https://drive.google.com/file/d/OWNED_TEST_OBJECT_ID/view
    expected_state: access_denied
```

```bash
uv run vrp-hunt owned-browser-scenario \
  --scenario scenarios/drive-private-deny.yaml \
  --expand-derived \
  --output-dir artifacts/owned-scenarios/drive-private-deny
```

Treat any mismatch as a lead, not a report by itself. Re-run the smallest
single check, confirm the object is owned and non-sensitive, then capture final
evidence for the submission draft.

Owned object catalog example:

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

Keep object catalogs out of Git when they contain real object URLs. Generated
scenarios under `scenarios/generated/` should be treated as local run material
unless they use placeholder object IDs only.

Convert scenario mismatches into draft report artifacts:

```bash
uv run vrp-hunt scenario-artifacts \
  --scenario scenarios/generated/docs-baseline/docs-baseline-owned-a-private-doc.yaml \
  --scenario-result artifacts/scenarios/docs-baseline/scenario-result.json \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --component "Docs private object" \
  --output-dir artifacts/findings/docs-baseline
```

Only denied-to-granted mismatches become draft findings. Treat generated drafts
as review material: manually re-run the smallest exact check before submission
and keep all third-party data out of evidence.

Metadata-only derived HTTP checks:

```bash
OWNED_B_COOKIE='SID=...; HSID=...' uv run vrp-hunt derived-http-check \
  --account-id owned-b \
  --url "https://docs.google.com/document/d/OWNED_TEST_OBJECT_ID/edit" \
  --cookie-env OWNED_B_COOKIE \
  --expected-state access_denied \
  --confirm-owned-object \
  --output-dir artifacts/derived/docs-private-owned-b
```

Use this only for exact owned objects. The command stores status/headers
metadata and redacted URL hashes only. It does not store cookie values, response
bodies, downloaded files, raw object content, or raw redirect URLs.

Convert a high-signal derived HTTP result into reviewable report drafts:

```bash
uv run vrp-hunt derived-http-artifacts \
  --derived-http-result artifacts/derived/docs-private-owned-b/derived-http-result.json \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --component "Docs export endpoint" \
  --output-dir artifacts/findings/derived-docs
```

Only metadata observations with denied-to-granted access drift become findings.
Review the generated report and manually reproduce the smallest exact check
before submission.

Full local pipeline:

```bash
OWNED_B_COOKIE='SID=...; HSID=...' uv run vrp-hunt owned-object-pipeline \
  --object-catalog catalogs/docs-baseline.yaml \
  --output-dir artifacts/pipeline/docs-baseline \
  --researcher-account owned-a \
  --researcher-account owned-b \
  --component "Docs private object" \
  --yolo
```

The pipeline uses `cookie_env` only as a local secret reference. Do not commit
real catalogs, generated scenarios, run artifacts, cookie values, or reports
containing real object URLs.
