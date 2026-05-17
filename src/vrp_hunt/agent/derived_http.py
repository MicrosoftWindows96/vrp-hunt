"""Metadata-only HTTP checks for derived owned-object resources."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import SplitResult, parse_qs, urlencode, urljoin, urlsplit, urlunsplit

import httpx
from pydantic import Field, model_validator

from vrp_hunt.agent.artifacts import (
    AgentArtifactBundle,
    ObservationArtifact,
    report_draft_from_finding,
)
from vrp_hunt.agent.browser_check import (
    BrowserAccessState,
    BrowserCheckError,
    redact_object_url,
    validate_owned_object_url,
)
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.playbooks import EvidenceItem, FindingArtifact, get_playbook
from vrp_hunt.recon import Asset
from vrp_hunt.reporting import Platform

DerivedHttpAccessState = Literal[
    "access_denied",
    "access_granted_metadata",
    "login_required",
    "unknown",
]
DerivedHttpMethod = Literal["GET", "HEAD"]

MAX_DERIVED_HTTP_TARGETS = 25
MAX_DERIVED_HTTP_RESULT_BYTES = 2_000_000
HEADER_ALLOWLIST = {
    "content-type",
    "content-length",
    "content-disposition",
    "location",
    "x-frame-options",
}


class DerivedHttpCheckError(ValueError):
    """Raised when a metadata-only derived HTTP check is unsafe or malformed."""


class DerivedHttpTarget(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=4096)
    method: DerivedHttpMethod = "HEAD"

    @model_validator(mode="after")
    def require_exact_owned_object_url(self) -> "DerivedHttpTarget":
        try:
            validate_owned_object_url(self.url)
        except BrowserCheckError as exc:
            raise ValueError(str(exc)) from exc
        return self


class DerivedHttpObservation(StrictModel):
    target_name: str = Field(min_length=1)
    method: DerivedHttpMethod
    checked_url: str = Field(min_length=1)
    status_code: int | None = Field(default=None, ge=100, le=599)
    final_host: str | None = None
    final_path_hash: str | None = None
    redirect_count: int = Field(default=0, ge=0)
    redirect_location_host: str | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    state: DerivedHttpAccessState = "unknown"
    confidence: float = Field(default=0.2, ge=0, le=1)
    matched_signals: list[str] = Field(default_factory=list)
    error: str | None = None
    response_body_stored: bool = False
    response_body_bytes_read: int = 0
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DerivedHttpCheckResult(StrictModel):
    account_id: str = Field(min_length=1)
    source_url: str = Field(min_length=1)
    expected_state: BrowserAccessState
    target_count: int = Field(default=0, ge=0)
    observations: list[DerivedHttpObservation] = Field(default_factory=list)
    request_count: int = Field(default=0, ge=0)
    high_signal_mismatches: int = Field(default=0, ge=0)
    errors: int = Field(default=0, ge=0)
    third_party_data_seen: bool = False
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


def load_derived_http_check_result(path: str | os.PathLike[str]) -> DerivedHttpCheckResult:
    """Load a redacted derived HTTP result JSON file."""

    result_path = Path(path)
    try:
        raw = result_path.read_bytes()
    except OSError as exc:
        raise DerivedHttpCheckError(f"failed to read derived HTTP result file: {path}") from exc
    if len(raw) > MAX_DERIVED_HTTP_RESULT_BYTES:
        raise DerivedHttpCheckError(
            f"derived HTTP result file exceeds {MAX_DERIVED_HTTP_RESULT_BYTES} bytes"
        )
    try:
        return DerivedHttpCheckResult.model_validate_json(raw)
    except ValueError as exc:
        raise DerivedHttpCheckError("derived HTTP result validation failed") from exc


def build_derived_http_targets(
    owned_object_url: str,
    *,
    method: DerivedHttpMethod = "HEAD",
    max_targets: int = MAX_DERIVED_HTTP_TARGETS,
) -> list[DerivedHttpTarget]:
    """Build metadata-only derived endpoint candidates for one exact owned object."""

    if max_targets < 1:
        raise DerivedHttpCheckError("max_targets must be at least 1")
    if max_targets > MAX_DERIVED_HTTP_TARGETS:
        raise DerivedHttpCheckError(f"max_targets must be at most {MAX_DERIVED_HTTP_TARGETS}")
    validate_owned_object_url(owned_object_url)
    parsed = urlsplit(owned_object_url)
    host = parsed.hostname or ""
    targets: list[tuple[str, str]] = []
    if host == "docs.google.com":
        targets.extend(_docs_http_variants(parsed))
    elif host == "drive.google.com":
        targets.extend(_drive_http_variants(parsed))
    else:
        targets.append(("original", owned_object_url))

    unique: list[DerivedHttpTarget] = []
    seen: set[str] = set()
    for name, url in targets:
        if url in seen:
            continue
        seen.add(url)
        unique.append(DerivedHttpTarget(name=name, url=url, method=method))
        if len(unique) >= max_targets:
            break
    return unique


def run_derived_http_check(
    *,
    account_id: str,
    owned_object_url: str,
    expected_state: BrowserAccessState,
    cookie_header: str,
    confirm_owned_object: bool,
    method: DerivedHttpMethod = "HEAD",
    max_targets: int = MAX_DERIVED_HTTP_TARGETS,
    timeout_seconds: float = 10.0,
    max_redirects: int = 2,
    client: httpx.Client | None = None,
) -> DerivedHttpCheckResult:
    """Run metadata-only checks without reading or storing response bodies."""

    if not confirm_owned_object:
        raise DerivedHttpCheckError("--confirm-owned-object is required")
    if timeout_seconds <= 0:
        raise DerivedHttpCheckError("timeout_seconds must be positive")
    if max_redirects < 0:
        raise DerivedHttpCheckError("max_redirects must be non-negative")
    validate_owned_object_url(owned_object_url)
    sanitized_cookie = sanitize_cookie_header(cookie_header)
    targets = build_derived_http_targets(
        owned_object_url,
        method=method,
        max_targets=max_targets,
    )
    headers = {
        "Cookie": sanitized_cookie,
        "User-Agent": "vrp-hunt-owned-metadata-check/0.1",
        "Accept": "*/*",
    }
    active_client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False)
    close_client = client is None
    observations: list[DerivedHttpObservation] = []
    try:
        for target in targets:
            observations.append(
                _metadata_observation(
                    active_client,
                    target,
                    headers=headers,
                    max_redirects=max_redirects,
                )
            )
    finally:
        if close_client:
            active_client.close()

    return DerivedHttpCheckResult(
        account_id=account_id,
        source_url=redact_object_url(owned_object_url),
        expected_state=expected_state,
        target_count=len(targets),
        observations=observations,
        request_count=len([item for item in observations if item.error is None]),
        high_signal_mismatches=sum(
            1
            for item in observations
            if expected_state == "access_denied" and item.state == "access_granted_metadata"
        ),
        errors=sum(1 for item in observations if item.error is not None),
    )


def artifact_bundle_from_derived_http_check(
    result: DerivedHttpCheckResult,
    *,
    researcher_accounts: list[str],
    product: str = "Google",
    component: str = "VRP target",
    platform: Platform = "web",
    client: str = "metadata-only HTTP checker",
    operating_system: str = "research workstation",
    observed_from: str = "derived-http-check",
) -> AgentArtifactBundle:
    """Convert high-signal derived HTTP observations into draft artifacts."""

    artifacts: list[ObservationArtifact] = []
    skipped: list[str] = []
    for observation in result.observations:
        skip_reason = _derived_http_artifact_skip_reason(result, observation)
        if skip_reason is not None:
            skipped.append(f"{observation.target_name}: {skip_reason}")
            continue
        artifacts.append(
            _derived_http_observation_artifact(
                result,
                observation,
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


def cookie_header_from_env(name: str, env: Mapping[str, str] | None = None) -> str:
    env_name = name.strip()
    if not env_name:
        raise DerivedHttpCheckError("cookie env var name cannot be blank")
    values = env or os.environ
    value = values.get(env_name)
    if value is None:
        raise DerivedHttpCheckError(f"cookie env var is not set: {env_name}")
    return sanitize_cookie_header(value)


def cookie_header_from_cdp(cdp_url: str, *, owned_object_url: str) -> str:
    endpoint = cdp_url.strip()
    if not endpoint:
        raise DerivedHttpCheckError("cdp_url cannot be blank")
    try:
        validate_owned_object_url(owned_object_url)
    except BrowserCheckError as exc:
        raise DerivedHttpCheckError(str(exc)) from exc

    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise DerivedHttpCheckError("playwright is required to read cookies from CDP") from exc

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(endpoint)
            if not browser.contexts:
                raise DerivedHttpCheckError("cdp browser has no contexts; sign in to the owned account first")
            cookies = browser.contexts[0].cookies(_cdp_cookie_scope_urls(owned_object_url))
    except DerivedHttpCheckError:
        raise
    except PlaywrightError as exc:
        raise DerivedHttpCheckError("failed to read cookies from CDP browser") from exc

    return _cookie_header_from_browser_cookies(cookies)


def sanitize_cookie_header(value: str) -> str:
    stripped = value.strip()
    if stripped.lower().startswith("cookie:"):
        stripped = stripped.split(":", 1)[1].strip()
    if not stripped:
        raise DerivedHttpCheckError("cookie header cannot be blank")
    if "\r" in stripped or "\n" in stripped:
        raise DerivedHttpCheckError("cookie header must be a single line")
    return stripped


def _cdp_cookie_scope_urls(owned_object_url: str) -> list[str]:
    parsed = urlsplit(owned_object_url)
    urls = [owned_object_url]
    if parsed.scheme and parsed.netloc:
        urls.append(urlunsplit((parsed.scheme, parsed.netloc, "/", "", "")))
    urls.append("https://accounts.google.com/")

    unique: list[str] = []
    seen: set[str] = set()
    for url in urls:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def _cookie_header_from_browser_cookies(cookies: Sequence[Mapping[str, object]]) -> str:
    pairs: list[str] = []
    seen: set[str] = set()
    for cookie in cookies:
        raw_name = cookie.get("name")
        raw_value = cookie.get("value")
        if raw_name is None or raw_value is None:
            continue
        name = str(raw_name)
        if not name or name in seen:
            continue
        if any(char in name for char in "\r\n;="):
            raise DerivedHttpCheckError("CDP cookie name contains invalid characters")
        seen.add(name)
        pairs.append(f"{name}={raw_value}")
    if not pairs:
        raise DerivedHttpCheckError("cdp browser context has no cookies for the owned object URL")
    return sanitize_cookie_header("; ".join(pairs))


def _derived_http_artifact_skip_reason(
    result: DerivedHttpCheckResult,
    observation: DerivedHttpObservation,
) -> str | None:
    if result.third_party_data_seen:
        return "third-party data observed"
    if result.errors:
        return "derived HTTP result contains errors"
    if observation.error:
        return f"observation error: {observation.error}"
    if observation.response_body_stored:
        return "response body was stored"
    if observation.response_body_bytes_read != 0:
        return "response body bytes were read"
    if result.expected_state != "access_denied":
        return "expected state is not access_denied"
    if observation.state != "access_granted_metadata":
        return "metadata did not indicate granted access"
    return None


def _derived_http_observation_artifact(
    result: DerivedHttpCheckResult,
    observation: DerivedHttpObservation,
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
    title = f"Potential IDOR in derived HTTP resource {observation.target_name}"
    evidence = [
        EvidenceItem(
            kind="http",
            description=(
                "Metadata-only derived HTTP observation: expected access_denied but "
                f"observed {observation.state} for {observation.target_name}."
            ),
            path_or_ref=f"derived-http:{result.account_id}:{observation.target_name}:state",
            redacted=True,
        ),
        EvidenceItem(
            kind="note",
            description=f"Redacted derived URL: {observation.checked_url}",
            path_or_ref=f"derived-http:{result.account_id}:{observation.target_name}:checked-url",
            redacted=True,
        ),
    ]
    if observation.status_code is not None:
        evidence.append(
            EvidenceItem(
                kind="note",
                description=(
                    f"Status {observation.status_code}, final host {observation.final_host or '[unknown]'}, "
                    f"path hash {observation.final_path_hash or '[unknown]'}."
                ),
                path_or_ref=f"derived-http:{result.account_id}:{observation.target_name}:metadata",
                redacted=True,
            )
        )
    finding = FindingArtifact(
        title=title,
        bug_class="idor",
        reward_category=playbook.reward_category,
        status="needs_review",
        target=result.source_url,
        affected_assets=[
            Asset(
                kind="url",
                value=result.source_url,
                source="derived-http-check",
                metadata={
                    "account_id": result.account_id,
                    "target_name": observation.target_name,
                    "status_code": str(observation.status_code or ""),
                    "state": observation.state,
                },
            )
        ],
        preconditions=[
            *playbook.preconditions,
            "The source object is researcher-owned and contains no sensitive or third-party data.",
            f"Owned account {result.account_id} was expected to receive access_denied.",
            "The derived HTTP checker stored metadata only and did not read or persist response bodies.",
        ],
        impact=(
            "A derived resource returned metadata consistent with granted access where denied "
            "access was expected. If manually reproduced, this indicates authorization drift "
            "between the object ACL and derived HTTP resources."
        ),
        reproduction_steps=[
            "Prepare the exact researcher-owned source object.",
            f"Authenticate the owned test account {result.account_id} and export its Cookie header locally.",
            "Run derived-http-check with --confirm-owned-object and expected_state access_denied.",
            f"Review the metadata-only observation for target {observation.target_name}.",
            "Expected result: access_denied metadata such as 401, 403, or 404.",
            f"Observed result: {observation.state} without storing or reading the response body.",
            "Stop immediately if any non-owned data appears.",
        ],
        evidence=evidence,
        own_account_only=True,
        third_party_data_touched=False,
        notes=[
            "Generated from derived-http-check metadata mismatch.",
            f"confidence={observation.confidence}",
            f"redirect_count={observation.redirect_count}",
            f"response_body_stored={observation.response_body_stored}",
            f"response_body_bytes_read={observation.response_body_bytes_read}",
            *[f"signal={signal}" for signal in observation.matched_signals],
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
        action_id=f"derived-http:{result.account_id}:{observation.target_name}",
        finding=finding,
        report=report,
    )


def _metadata_observation(
    client: httpx.Client,
    target: DerivedHttpTarget,
    *,
    headers: dict[str, str],
    max_redirects: int,
) -> DerivedHttpObservation:
    current_url = target.url
    redirect_count = 0
    try:
        while True:
            parsed = urlsplit(current_url)
            if parsed.scheme != "https":
                raise DerivedHttpCheckError("derived HTTP checks require https URLs")
            with client.stream(
                target.method,
                current_url,
                headers=headers,
                follow_redirects=False,
            ) as response:
                sanitized_headers = _sanitized_response_headers(response.headers)
                location = response.headers.get("location")
                location_url = _absolute_location(current_url, location) if location else None
                location_host = urlsplit(location_url).hostname if location_url else None
                if _should_follow_same_host_redirect(
                    current_url,
                    location_url,
                    response.status_code,
                    redirect_count,
                    max_redirects,
                ):
                    redirect_count += 1
                    current_url = location_url or current_url
                    continue
                state, confidence, signals = _classify_metadata_response(
                    response.status_code,
                    response.headers,
                    location_host=location_host,
                )
                final = urlsplit(str(response.url))
                return DerivedHttpObservation(
                    target_name=target.name,
                    method=target.method,
                    checked_url=redact_object_url(target.url),
                    status_code=response.status_code,
                    final_host=final.hostname,
                    final_path_hash=_hash_text(final.path),
                    redirect_count=redirect_count,
                    redirect_location_host=location_host,
                    response_headers=sanitized_headers,
                    state=state,
                    confidence=confidence,
                    matched_signals=signals,
                    response_body_stored=False,
                    response_body_bytes_read=0,
                )
    except (httpx.HTTPError, DerivedHttpCheckError, ValueError) as exc:
        return DerivedHttpObservation(
            target_name=target.name,
            method=target.method,
            checked_url=redact_object_url(target.url),
            error=str(exc),
            response_body_stored=False,
            response_body_bytes_read=0,
        )


def _classify_metadata_response(
    status_code: int,
    headers: httpx.Headers,
    *,
    location_host: str | None,
) -> tuple[DerivedHttpAccessState, float, list[str]]:
    signals: list[str] = []
    if location_host == "accounts.google.com":
        return "login_required", 0.95, ["redirect:accounts.google.com"]
    if location_host and _is_googleusercontent_host(location_host):
        return "access_granted_metadata", 0.65, ["redirect:googleusercontent"]
    if status_code in {401, 403, 404}:
        return "access_denied", 0.8, [f"status:{status_code}"]
    if status_code in {200, 204, 206, 304}:
        content_type = headers.get("content-type", "").lower()
        content_disposition = headers.get("content-disposition")
        if content_disposition:
            signals.append("header:content-disposition")
        if status_code == 206:
            signals.append("status:206")
        if content_type and "text/html" not in content_type:
            signals.append(f"content-type:{content_type.split(';', 1)[0]}")
        if signals:
            return "access_granted_metadata", 0.7, signals[:5]
        return "unknown", 0.35, [f"status:{status_code}"]
    if 300 <= status_code < 400:
        return "unknown", 0.3, [f"redirect:{status_code}"]
    return "unknown", 0.2, [f"status:{status_code}"]


def _sanitized_response_headers(headers: httpx.Headers) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for key in sorted(HEADER_ALLOWLIST):
        value = headers.get(key)
        if value is None:
            continue
        if key == "content-disposition":
            sanitized[key] = "[PRESENT]"
        elif key == "location":
            sanitized[key] = _redacted_location(value)
        else:
            sanitized[key] = value[:200]
    return sanitized


def _absolute_location(current_url: str, location: str | None) -> str | None:
    if not location:
        return None
    return urljoin(current_url, location)


def _should_follow_same_host_redirect(
    current_url: str,
    location_url: str | None,
    status_code: int,
    redirect_count: int,
    max_redirects: int,
) -> bool:
    if not (300 <= status_code < 400) or not location_url:
        return False
    if redirect_count >= max_redirects:
        return False
    current = urlsplit(current_url)
    target = urlsplit(location_url)
    if target.scheme != "https":
        return False
    return current.hostname == target.hostname


def _docs_http_variants(parsed: SplitResult) -> list[tuple[str, str]]:
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 3 or parts[1] != "d":
        return [("original", urlunsplit(parsed))]
    doc_kind = parts[0]
    object_id = parts[2]
    base_path = f"/{doc_kind}/d/{object_id}"
    variants = [
        ("preview", _replace_url(parsed, path=f"{base_path}/preview", query="")),
    ]
    if doc_kind == "document":
        variants.extend(
            [
                (
                    "export-txt",
                    _replace_url(parsed, path=f"{base_path}/export", query=urlencode({"format": "txt"})),
                ),
                (
                    "export-pdf",
                    _replace_url(parsed, path=f"{base_path}/export", query=urlencode({"format": "pdf"})),
                ),
            ]
        )
    elif doc_kind == "spreadsheets":
        variants.extend(
            [
                (
                    "export-csv",
                    _replace_url(parsed, path=f"{base_path}/export", query=urlencode({"format": "csv"})),
                ),
                (
                    "export-xlsx",
                    _replace_url(parsed, path=f"{base_path}/export", query=urlencode({"format": "xlsx"})),
                ),
            ]
        )
    elif doc_kind == "presentation":
        variants.append(("export-pdf", _replace_url(parsed, path=f"{base_path}/export/pdf", query="")))
    return variants


def _drive_http_variants(parsed: SplitResult) -> list[tuple[str, str]]:
    parts = [part for part in parsed.path.split("/") if part]
    variants: list[tuple[str, str]] = []
    if len(parts) >= 3 and parts[0] == "file" and parts[1] == "d":
        object_id = parts[2]
        variants.extend(
            [
                ("preview", _replace_url(parsed, path=f"/file/d/{object_id}/preview", query="")),
                (
                    "download",
                    _replace_url(
                        parsed,
                        path="/uc",
                        query=urlencode({"id": object_id, "export": "download"}),
                    ),
                ),
                (
                    "thumbnail",
                    _replace_url(
                        parsed,
                        path="/thumbnail",
                        query=urlencode({"id": object_id, "sz": "w320"}),
                    ),
                ),
            ]
        )
    query = parse_qs(parsed.query)
    object_ids = query.get("id", [])
    if len(object_ids) == 1:
        object_id = object_ids[0]
        variants.extend(
            [
                ("open", _replace_url(parsed, path="/open", query=urlencode({"id": object_id}))),
                (
                    "download",
                    _replace_url(
                        parsed,
                        path="/uc",
                        query=urlencode({"id": object_id, "export": "download"}),
                    ),
                ),
                (
                    "thumbnail",
                    _replace_url(
                        parsed,
                        path="/thumbnail",
                        query=urlencode({"id": object_id, "sz": "w320"}),
                    ),
                ),
            ]
        )
    return variants or [("original", urlunsplit(parsed))]


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


def _redacted_location(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.hostname:
        return "[relative]"
    query_keys = sorted(parse_qs(parsed.query))
    query_label = f"?keys={','.join(query_keys)}" if query_keys else ""
    return f"{parsed.scheme}://{parsed.hostname}/[path:{_hash_text(parsed.path)}]{query_label}"


def _is_googleusercontent_host(host: str) -> bool:
    return host == "googleusercontent.com" or host.endswith(".googleusercontent.com")


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
