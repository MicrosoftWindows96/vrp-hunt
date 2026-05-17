"""Owned-object scenario automation for authenticated browser checks."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

import yaml
from pydantic import Field, ValidationError, model_validator

from vrp_hunt.agent.artifacts import (
    AgentArtifactBundle,
    ObservationArtifact,
    report_draft_from_finding,
)
from vrp_hunt.agent.browser_check import (
    BrowserAccessState,
    BrowserCheckError,
    OwnedBrowserCheckResult,
    run_owned_browser_check,
    run_owned_browser_check_cdp,
    validate_owned_object_url,
)
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.playbooks import EvidenceItem, FindingArtifact, get_playbook
from vrp_hunt.recon import Asset
from vrp_hunt.reporting import Platform

MAX_SCENARIO_BYTES = 128_000
MAX_SCENARIO_STEPS = 50
MAX_CATALOG_BYTES = 256_000
MAX_CATALOG_OBJECTS = 200
MAX_SCENARIO_RESULT_BYTES = 2_000_000


class OwnedBrowserScenarioError(ValueError):
    """Raised when an owned-browser scenario is unsafe or malformed."""


class OwnedBrowserAccountConfig(StrictModel):
    """One already-authenticated owned test-account browser context."""

    account_id: str = Field(min_length=1)
    profile_dir: Path | None = None
    cdp_url: str | None = None
    cookie_env: str | None = Field(default=None, min_length=1, max_length=128)
    headless: bool = False
    timeout_ms: int = Field(default=15_000, ge=1_000, le=120_000)

    @model_validator(mode="after")
    def require_one_browser_attachment(self) -> "OwnedBrowserAccountConfig":
        if bool(self.profile_dir) == bool(self.cdp_url):
            raise ValueError("exactly one of profile_dir or cdp_url is required")
        return self


class OwnedBrowserScenarioStep(StrictModel):
    """One access-state assertion against an exact owned-object URL."""

    name: str = Field(min_length=1, max_length=128)
    account_id: str = Field(min_length=1)
    url: str = Field(min_length=1)
    expected_state: BrowserAccessState
    timeout_ms: int | None = Field(default=None, ge=1_000, le=120_000)
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_exact_owned_object_url(self) -> "OwnedBrowserScenarioStep":
        try:
            validate_owned_object_url(self.url)
        except BrowserCheckError as exc:
            raise ValueError(str(exc)) from exc
        return self


class OwnedBrowserScenario(StrictModel):
    """A bounded owned-object access matrix.

    Scenario files intentionally describe assertions only. They do not create
    accounts, mutate sharing state, scrape broad pages, or store raw page text.
    """

    scenario_id: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    researcher_owned: bool = False
    third_party_data_allowed: bool = False
    stop_on_mismatch: bool = True
    accounts: list[OwnedBrowserAccountConfig] = Field(min_length=1)
    steps: list[OwnedBrowserScenarioStep] = Field(min_length=1, max_length=MAX_SCENARIO_STEPS)

    @model_validator(mode="after")
    def enforce_safety_contract(self) -> "OwnedBrowserScenario":
        if not self.researcher_owned:
            raise ValueError("scenario must confirm researcher_owned=true")
        if self.third_party_data_allowed:
            raise ValueError("owned-browser scenarios must not allow third-party data")
        account_ids = [account.account_id for account in self.accounts]
        if len(account_ids) != len(set(account_ids)):
            raise ValueError("scenario account ids must be unique")
        missing = sorted({step.account_id for step in self.steps}.difference(account_ids))
        if missing:
            raise ValueError(f"scenario steps reference unknown accounts: {', '.join(missing)}")
        return self

    def account(self, account_id: str) -> OwnedBrowserAccountConfig:
        for account in self.accounts:
            if account.account_id == account_id:
                return account
        raise KeyError(account_id)


class OwnedBrowserScenarioStepResult(StrictModel):
    """Redacted result for one scenario step."""

    step_name: str = Field(min_length=1)
    account_id: str = Field(min_length=1)
    checked_url: str | None = None
    current_url_host: str | None = None
    current_url_path_hash: str | None = None
    expected_state: BrowserAccessState
    actual_state: BrowserAccessState | None = None
    matched: bool = False
    confidence: float | None = Field(default=None, ge=0, le=1)
    matched_signals: list[str] = Field(default_factory=list)
    request_count: int = Field(default=1, ge=0)
    error: str | None = None
    third_party_data_seen: bool = False
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OwnedBrowserScenarioResult(StrictModel):
    """Redacted scenario execution summary."""

    scenario_id: str = Field(min_length=1)
    completed_steps: int = Field(ge=0)
    mismatches: int = Field(ge=0)
    errors: int = Field(ge=0)
    stopped: bool = False
    stop_reason: str = ""
    results: list[OwnedBrowserScenarioStepResult] = Field(default_factory=list)


class OwnedObjectCatalogItem(StrictModel):
    """One researcher-owned test object and its expected account access states."""

    object_id: str = Field(min_length=1, max_length=128)
    product: str = Field(min_length=1, max_length=64)
    owner_account_id: str = Field(min_length=1)
    url: str = Field(min_length=1)
    expected_states: dict[str, BrowserAccessState] = Field(min_length=1)
    contains_sensitive_data: bool = False
    third_party_data: bool = False
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_owned_object_contract(self) -> "OwnedObjectCatalogItem":
        try:
            validate_owned_object_url(self.url)
        except BrowserCheckError as exc:
            raise ValueError(str(exc)) from exc
        if self.contains_sensitive_data:
            raise ValueError("catalog objects must not contain sensitive data")
        if self.third_party_data:
            raise ValueError("catalog objects must not contain third-party data")
        if self.owner_account_id not in self.expected_states:
            raise ValueError("catalog object expected_states must include owner_account_id")
        return self


class OwnedObjectCatalog(StrictModel):
    """Catalog of owned test objects that can be converted into scenarios."""

    catalog_id: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    researcher_owned: bool = False
    third_party_data_allowed: bool = False
    stop_on_mismatch: bool = True
    accounts: list[OwnedBrowserAccountConfig] = Field(min_length=1)
    objects: list[OwnedObjectCatalogItem] = Field(min_length=1, max_length=MAX_CATALOG_OBJECTS)

    @model_validator(mode="after")
    def enforce_catalog_contract(self) -> "OwnedObjectCatalog":
        if not self.researcher_owned:
            raise ValueError("catalog must confirm researcher_owned=true")
        if self.third_party_data_allowed:
            raise ValueError("owned-object catalogs must not allow third-party data")
        account_ids = [account.account_id for account in self.accounts]
        if len(account_ids) != len(set(account_ids)):
            raise ValueError("catalog account ids must be unique")
        known_accounts = set(account_ids)
        object_ids = [item.object_id for item in self.objects]
        if len(object_ids) != len(set(object_ids)):
            raise ValueError("catalog object ids must be unique")
        missing_owners = sorted(
            {item.owner_account_id for item in self.objects}.difference(known_accounts)
        )
        if missing_owners:
            raise ValueError(f"catalog objects reference unknown owners: {', '.join(missing_owners)}")
        missing_expected = sorted(
            {
                account_id
                for item in self.objects
                for account_id in item.expected_states
                if account_id not in known_accounts
            }
        )
        if missing_expected:
            raise ValueError(
                "catalog objects reference unknown expected-state accounts: "
                + ", ".join(missing_expected)
            )
        return self


class GeneratedOwnedBrowserScenario(StrictModel):
    """One generated scenario file record."""

    object_id: str = Field(min_length=1)
    scenario_id: str = Field(min_length=1)
    path: Path
    steps: int = Field(ge=1)


class OwnedObjectCatalogGenerationResult(StrictModel):
    """Summary returned after writing generated scenario files."""

    catalog_id: str = Field(min_length=1)
    output_dir: Path
    generated_count: int = Field(ge=0)
    scenarios: list[GeneratedOwnedBrowserScenario] = Field(default_factory=list)


ScenarioStepChecker = Callable[
    [OwnedBrowserAccountConfig, OwnedBrowserScenarioStep],
    OwnedBrowserCheckResult,
]


def load_owned_browser_scenario(path: Path) -> OwnedBrowserScenario:
    """Load an owned-browser scenario from YAML or JSON."""

    parsed = _load_mapping_file(path, max_bytes=MAX_SCENARIO_BYTES, noun="scenario")
    try:
        return OwnedBrowserScenario.model_validate(parsed)
    except ValidationError as exc:
        raise OwnedBrowserScenarioError("scenario validation failed") from exc


def load_owned_object_catalog(path: Path) -> OwnedObjectCatalog:
    """Load an owned-object catalog from YAML or JSON."""

    parsed = _load_mapping_file(path, max_bytes=MAX_CATALOG_BYTES, noun="catalog")
    try:
        return OwnedObjectCatalog.model_validate(parsed)
    except ValidationError as exc:
        raise OwnedBrowserScenarioError("catalog validation failed") from exc


def load_owned_browser_scenario_result(path: Path) -> OwnedBrowserScenarioResult:
    """Load a redacted owned-browser scenario result JSON file."""

    try:
        data = path.read_bytes()
    except OSError as exc:
        raise OwnedBrowserScenarioError(f"failed to read scenario result file: {path}") from exc
    if len(data) > MAX_SCENARIO_RESULT_BYTES:
        raise OwnedBrowserScenarioError(
            f"scenario result file exceeds {MAX_SCENARIO_RESULT_BYTES} bytes"
        )
    try:
        return OwnedBrowserScenarioResult.model_validate_json(data)
    except (ValueError, ValidationError) as exc:
        raise OwnedBrowserScenarioError("scenario result validation failed") from exc


def _load_mapping_file(path: Path, *, max_bytes: int, noun: str) -> dict[str, object]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise OwnedBrowserScenarioError(f"failed to read {noun} file: {path}") from exc
    if len(data) > max_bytes:
        raise OwnedBrowserScenarioError(f"{noun} file exceeds {max_bytes} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OwnedBrowserScenarioError(f"{noun} file must be UTF-8") from exc
    try:
        parsed = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise OwnedBrowserScenarioError(f"{noun} file is malformed") from exc
    if not isinstance(parsed, dict):
        raise OwnedBrowserScenarioError(f"{noun} root must be a mapping")
    return parsed


def run_owned_browser_scenario(
    scenario: OwnedBrowserScenario,
    *,
    checker: ScenarioStepChecker | None = None,
) -> OwnedBrowserScenarioResult:
    """Run a bounded owned-object access matrix."""

    active_checker = checker or _default_scenario_step_checker
    results: list[OwnedBrowserScenarioStepResult] = []
    mismatches = 0
    errors = 0
    stopped = False
    stop_reason = ""

    for step in scenario.steps:
        account = scenario.account(step.account_id)
        try:
            check = active_checker(account, step)
            matched = check.state == step.expected_state
            if not matched:
                mismatches += 1
            step_result = OwnedBrowserScenarioStepResult(
                step_name=step.name,
                account_id=step.account_id,
                checked_url=check.checked_url,
                current_url_host=check.current_url_host,
                current_url_path_hash=check.current_url_path_hash,
                expected_state=step.expected_state,
                actual_state=check.state,
                matched=matched,
                confidence=check.confidence,
                matched_signals=check.matched_signals,
                third_party_data_seen=check.third_party_data_seen,
                captured_at=check.captured_at,
            )
        except (BrowserCheckError, OSError, KeyError, ValueError) as exc:
            errors += 1
            step_result = OwnedBrowserScenarioStepResult(
                step_name=step.name,
                account_id=step.account_id,
                expected_state=step.expected_state,
                actual_state=None,
                matched=False,
                request_count=0,
                error=str(exc),
            )
        results.append(step_result)

        if step_result.third_party_data_seen:
            stopped = True
            stop_reason = "third-party data observed; stopping scenario"
            break
        if scenario.stop_on_mismatch and (step_result.error or not step_result.matched):
            stopped = True
            stop_reason = "scenario step failed expected access-state assertion"
            break

    return OwnedBrowserScenarioResult(
        scenario_id=scenario.scenario_id,
        completed_steps=len(results),
        mismatches=mismatches,
        errors=errors,
        stopped=stopped,
        stop_reason=stop_reason,
        results=results,
    )


def build_owned_browser_scenarios_from_catalog(
    catalog: OwnedObjectCatalog,
) -> list[OwnedBrowserScenario]:
    """Build one scenario per owned catalog object."""

    scenarios: list[OwnedBrowserScenario] = []
    accounts_by_id = {account.account_id: account for account in catalog.accounts}
    account_order = [account.account_id for account in catalog.accounts]
    for item in catalog.objects:
        ordered_expected_accounts = [
            account_id for account_id in account_order if account_id in item.expected_states
        ]
        selected_accounts = [accounts_by_id[account_id] for account_id in ordered_expected_accounts]
        steps = [
            OwnedBrowserScenarioStep(
                name=f"{_slug(item.object_id)}-{_slug(account_id)}-{state.replace('_', '-')}",
                account_id=account_id,
                url=item.url,
                expected_state=state,
                notes=[*item.notes, f"generated from catalog object {item.object_id}"],
            )
            for account_id in ordered_expected_accounts
            for state in [item.expected_states[account_id]]
        ]
        scenarios.append(
            OwnedBrowserScenario(
                scenario_id=_scenario_id(catalog.catalog_id, item.object_id),
                description=f"Generated {item.product} access matrix for owned object {item.object_id}.",
                researcher_owned=True,
                third_party_data_allowed=False,
                stop_on_mismatch=catalog.stop_on_mismatch,
                accounts=selected_accounts,
                steps=steps,
            )
        )
    return scenarios


def write_generated_owned_browser_scenarios(
    catalog: OwnedObjectCatalog,
    output_dir: Path,
) -> OwnedObjectCatalogGenerationResult:
    """Write generated scenario YAML files and a JSON index."""

    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[GeneratedOwnedBrowserScenario] = []
    for scenario, item in zip(
        build_owned_browser_scenarios_from_catalog(catalog),
        catalog.objects,
        strict=True,
    ):
        path = output_dir / f"{scenario.scenario_id}.yaml"
        payload = scenario.model_dump(mode="json", exclude_none=True)
        path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        records.append(
            GeneratedOwnedBrowserScenario(
                object_id=item.object_id,
                scenario_id=scenario.scenario_id,
                path=path,
                steps=len(scenario.steps),
            )
        )

    result = OwnedObjectCatalogGenerationResult(
        catalog_id=catalog.catalog_id,
        output_dir=output_dir,
        generated_count=len(records),
        scenarios=records,
    )
    (output_dir / "scenario-index.json").write_text(
        result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def artifact_bundle_from_owned_browser_scenario(
    scenario: OwnedBrowserScenario,
    result: OwnedBrowserScenarioResult,
    *,
    researcher_accounts: list[str],
    product: str = "Google",
    component: str = "VRP target",
    platform: Platform = "web",
    client: str = "Chrome stable with isolated owned-account profile",
    operating_system: str = "research workstation",
    observed_from: str = "owned-browser-scenario",
) -> AgentArtifactBundle:
    """Convert high-signal scenario mismatches into report-ready draft artifacts."""

    steps_by_key = _scenario_steps_by_key(scenario)
    artifacts: list[ObservationArtifact] = []
    skipped: list[str] = []

    for step_result in result.results:
        key = (step_result.step_name, step_result.account_id)
        step = steps_by_key.get(key)
        if step is None:
            skipped.append(f"{step_result.step_name}: no matching scenario step")
            continue
        skip_reason = _scenario_artifact_skip_reason(step_result)
        if skip_reason is not None:
            skipped.append(f"{step_result.step_name}: {skip_reason}")
            continue
        artifacts.append(
            _scenario_observation_artifact(
                scenario,
                step,
                step_result,
                researcher_accounts=researcher_accounts,
                product=product,
                component=component,
                platform=platform,
                client=client,
                operating_system=operating_system,
                observed_from=observed_from,
            )
        )

    return AgentArtifactBundle(artifacts=artifacts, skipped=skipped)


def expand_owned_browser_scenario_derived_urls(
    scenario: OwnedBrowserScenario,
    *,
    max_steps: int = MAX_SCENARIO_STEPS,
) -> OwnedBrowserScenario:
    """Expand each scenario step into safe derived-resource URL variants."""

    if max_steps < 1:
        raise OwnedBrowserScenarioError("max_steps must be at least 1")
    expanded: list[OwnedBrowserScenarioStep] = []
    for step in scenario.steps:
        variants = expand_owned_object_url_variants(step.url)
        for index, variant in enumerate(variants, start=1):
            if len(expanded) >= max_steps:
                raise OwnedBrowserScenarioError(f"derived expansion exceeds max_steps={max_steps}")
            name = step.name if len(variants) == 1 else f"{step.name}:variant-{index}"
            expanded.append(step.model_copy(update={"name": name, "url": variant}))
    return scenario.model_copy(update={"steps": expanded})


def expand_owned_object_url_variants(url: str) -> list[str]:
    """Return exact owned-object browser URL variants worth checking for authz drift."""

    validate_owned_object_url(url)
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    variants = [url]
    if host == "docs.google.com":
        variants.extend(_docs_variants(parsed))
    elif host == "drive.google.com":
        variants.extend(_drive_variants(parsed))
    return _unique_valid_variants(variants)


def _default_scenario_step_checker(
    account: OwnedBrowserAccountConfig,
    step: OwnedBrowserScenarioStep,
) -> OwnedBrowserCheckResult:
    timeout_ms = step.timeout_ms or account.timeout_ms
    if account.cdp_url:
        return run_owned_browser_check_cdp(
            account_id=account.account_id,
            cdp_url=account.cdp_url,
            url=step.url,
            confirm_owned_object=True,
            timeout_ms=timeout_ms,
        )
    if account.profile_dir is None:
        raise BrowserCheckError("scenario account has no browser attachment")
    return run_owned_browser_check(
        account_id=account.account_id,
        profile_dir=account.profile_dir,
        url=step.url,
        confirm_owned_object=True,
        headless=account.headless,
        timeout_ms=timeout_ms,
    )


def _docs_variants(parsed: SplitResult) -> list[str]:
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) < 3 or path_parts[1] != "d":
        return []
    doc_kind = path_parts[0]
    object_id = path_parts[2]
    base_path = f"/{doc_kind}/d/{object_id}"
    variants = [
        _replace_url(parsed, path=f"{base_path}/edit", query=""),
        _replace_url(parsed, path=f"{base_path}/preview", query=""),
    ]
    return variants


def _drive_variants(parsed: SplitResult) -> list[str]:
    parts = [part for part in parsed.path.split("/") if part]
    variants: list[str] = []
    if len(parts) >= 3 and parts[0] == "file" and parts[1] == "d":
        object_id = parts[2]
        variants.extend(
            [
                _replace_url(parsed, path=f"/file/d/{object_id}/view", query=""),
                _replace_url(parsed, path=f"/file/d/{object_id}/preview", query=""),
            ]
        )
    return variants


def _replace_url(parsed: SplitResult, *, path: str, query: str) -> str:
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            query,
            "",
        )
    )


def _unique_valid_variants(variants: list[str]) -> list[str]:
    seen: set[str] = set()
    valid: list[str] = []
    for variant in variants:
        if variant in seen:
            continue
        validate_owned_object_url(variant)
        seen.add(variant)
        valid.append(variant)
    return valid


def _scenario_steps_by_key(
    scenario: OwnedBrowserScenario,
) -> dict[tuple[str, str], OwnedBrowserScenarioStep]:
    steps_by_key: dict[tuple[str, str], OwnedBrowserScenarioStep] = {}
    for step in scenario.steps:
        key = (step.name, step.account_id)
        if key in steps_by_key:
            raise OwnedBrowserScenarioError(
                f"scenario has duplicate step/account pair: {step.name} {step.account_id}"
            )
        steps_by_key[key] = step
    return steps_by_key


def _scenario_artifact_skip_reason(step_result: OwnedBrowserScenarioStepResult) -> str | None:
    if step_result.third_party_data_seen:
        return "third-party data observed"
    if step_result.error:
        return f"step error: {step_result.error}"
    if step_result.actual_state is None:
        return "no actual state recorded"
    if step_result.matched:
        return "expected access state matched"
    if step_result.expected_state != "access_denied":
        return "mismatch is not a denied-to-granted authorization lead"
    if step_result.actual_state != "access_granted":
        return "mismatch did not grant access"
    return None


def _scenario_observation_artifact(
    scenario: OwnedBrowserScenario,
    step: OwnedBrowserScenarioStep,
    step_result: OwnedBrowserScenarioStepResult,
    *,
    researcher_accounts: list[str],
    product: str,
    component: str,
    platform: Platform,
    client: str,
    operating_system: str,
    observed_from: str,
) -> ObservationArtifact:
    playbook = get_playbook("idor")
    title = f"Potential IDOR in owned-object scenario {scenario.scenario_id}"
    evidence = [
        EvidenceItem(
            kind="note",
            description=(
                "Owned-browser scenario mismatch: expected access_denied but observed "
                f"access_granted for account {step.account_id}."
            ),
            path_or_ref=f"scenario:{scenario.scenario_id}:step:{step.name}:state",
            redacted=True,
        ),
        EvidenceItem(
            kind="note",
            description=f"Redacted checked URL: {step_result.checked_url or '[unavailable]'}",
            path_or_ref=f"scenario:{scenario.scenario_id}:step:{step.name}:checked-url",
            redacted=True,
        ),
    ]
    if step_result.current_url_host:
        evidence.append(
            EvidenceItem(
                kind="note",
                description=(
                    f"Observed host {step_result.current_url_host} with path hash "
                    f"{step_result.current_url_path_hash or '[unavailable]'}."
                ),
                path_or_ref=f"scenario:{scenario.scenario_id}:step:{step.name}:current-url",
                redacted=True,
            )
        )
    finding = FindingArtifact(
        title=title,
        bug_class="idor",
        reward_category=playbook.reward_category,
        status="needs_review",
        target=step.url,
        affected_assets=[
            Asset(
                kind="url",
                value=step.url,
                source="owned-browser-scenario",
                metadata={
                    "scenario_id": scenario.scenario_id,
                    "step_name": step.name,
                    "account_id": step.account_id,
                },
            )
        ],
        preconditions=[
            *playbook.preconditions,
            "The target object is researcher-owned and contains no sensitive or third-party data.",
            f"Scenario {scenario.scenario_id} expected account {step.account_id} to be denied.",
        ],
        impact=(
            "A researcher-owned account that was expected to be denied reached an owned test "
            "object. If reproduced, this indicates an authorization boundary failure for "
            "private object access."
        ),
        reproduction_steps=[
            f"Prepare the owned test object used by scenario {scenario.scenario_id}.",
            f"Authenticate as owned test account {step.account_id}.",
            f"Open the exact scenario step URL for {step.name}.",
            "Expected result: access_denied.",
            "Observed result: access_granted.",
            "Stop immediately if any non-owned data appears.",
        ],
        evidence=evidence,
        own_account_only=True,
        third_party_data_touched=False,
        notes=[
            "Generated from owned-browser-scenario mismatch.",
            f"confidence={step_result.confidence if step_result.confidence is not None else 'unknown'}",
            *[f"signal={signal}" for signal in step_result.matched_signals],
            *step.notes,
        ],
    )
    report = report_draft_from_finding(
        finding,
        researcher_accounts=researcher_accounts,
        product=product,
        component=component,
        platform=platform,
        client=client,
        operating_system=operating_system,
        observed_from=observed_from,
    )
    return ObservationArtifact(
        action_id=f"scenario:{scenario.scenario_id}:{step.name}:{step.account_id}",
        finding=finding,
        report=report,
    )


def _scenario_id(catalog_id: str, object_id: str) -> str:
    return f"{_slug(catalog_id)}-{_slug(object_id)}"[:128].strip("-") or "owned-object"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    slug = re.sub(r"-{2,}", "-", slug).strip("-._")
    return slug[:64] or "item"
