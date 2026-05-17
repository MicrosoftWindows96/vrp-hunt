"""Narrow owned-object browser checks for authenticated test profiles."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import parse_qs, urlsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel

BrowserAccessState = Literal["access_denied", "access_granted", "login_required", "unknown"]


class BrowserCheckError(ValueError):
    """Raised when a browser check is unsafe or cannot run."""


class OwnedBrowserCheckResult(StrictModel):
    account_id: str = Field(min_length=1)
    checked_url: str = Field(min_length=1)
    current_url_host: str | None = None
    current_url_path_hash: str | None = None
    state: BrowserAccessState
    confidence: float = Field(ge=0, le=1)
    matched_signals: list[str] = Field(default_factory=list)
    secrets_stored: bool = False
    third_party_data_seen: bool = False
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


ACCESS_DENIED_SIGNALS = (
    "you need access",
    "request access",
    "access denied",
    "you are not authorized",
    "you do not have access",
    "permission is required",
    "ask for access",
    "sorry, unable to open the file",
    "authorization is required",
)
LOGIN_REQUIRED_SIGNALS = (
    "sign in",
    "choose an account",
    "to continue to",
    "use your google account",
)
ACCESS_GRANTED_SIGNALS = (
    "vrp_script_ok",
    "vrp-owned-script-ok",
    "share",
    "file",
    "open with",
    "google docs",
    "google drive",
    "web app",
)
SAFE_OBJECT_HOSTS = {
    "docs.google.com",
    "drive.google.com",
    "script.google.com",
    "sites.google.com",
}
SAFE_RESULT_HOSTS = {
    *SAFE_OBJECT_HOSTS,
    "script.googleusercontent.com",
}


def run_owned_browser_check(
    *,
    account_id: str,
    profile_dir: Path,
    url: str,
    confirm_owned_object: bool,
    headless: bool = False,
    timeout_ms: int = 15_000,
) -> OwnedBrowserCheckResult:
    if not confirm_owned_object:
        raise BrowserCheckError("--confirm-owned-object is required")
    validate_owned_object_url(url)
    if not profile_dir.exists():
        raise BrowserCheckError(f"profile directory does not exist: {profile_dir}")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency is installed in normal envs.
        raise BrowserCheckError("Playwright is not installed; run `uv add playwright`") from exc

    try:
        with sync_playwright() as playwright:
            context = playwright.chromium.launch_persistent_context(
                str(profile_dir),
                channel="chrome",
                headless=headless,
                accept_downloads=False,
            )
            try:
                page = context.pages[0] if context.pages else context.new_page()
                text, current_url = _load_owned_object_page(page, url=url, timeout_ms=timeout_ms)
            finally:
                context.close()
    except PlaywrightTimeoutError as exc:
        raise BrowserCheckError(f"browser check timed out: {exc}") from exc
    except PlaywrightError as exc:
        raise BrowserCheckError(f"browser check failed: {exc}") from exc

    return _build_check_result(
        account_id=account_id,
        url=url,
        current_url=current_url,
        text=text,
    )


def run_owned_browser_check_cdp(
    *,
    account_id: str,
    cdp_url: str,
    url: str,
    confirm_owned_object: bool,
    timeout_ms: int = 15_000,
) -> OwnedBrowserCheckResult:
    if not confirm_owned_object:
        raise BrowserCheckError("--confirm-owned-object is required")
    validate_owned_object_url(url)
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency is installed in normal envs.
        raise BrowserCheckError("Playwright is not installed; run `uv add playwright`") from exc

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.connect_over_cdp(cdp_url, timeout=timeout_ms)
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.pages[0] if context.pages else context.new_page()
            text, current_url = _load_owned_object_page(page, url=url, timeout_ms=timeout_ms)
    except PlaywrightTimeoutError as exc:
        raise BrowserCheckError(f"browser check timed out: {exc}") from exc
    except PlaywrightError as exc:
        raise BrowserCheckError(f"browser check failed: {exc}") from exc

    return _build_check_result(
        account_id=account_id,
        url=url,
        current_url=current_url,
        text=text,
    )


def validate_owned_object_url(url: str) -> None:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https":
        raise BrowserCheckError("owned browser checks require https URLs")
    if host not in SAFE_OBJECT_HOSTS:
        raise BrowserCheckError("owned browser checks are limited to Drive, Docs, or Sites URLs")
    if host == "drive.google.com":
        if parsed.path in {"", "/", "/drive", "/drive/", "/drive/my-drive", "/drive/home"}:
            raise BrowserCheckError("refusing broad Drive pages; provide an exact owned object URL")
        query = parse_qs(parsed.query)
        if parsed.path.startswith(("/file/d/", "/drive/folders/")) or "id" in query:
            return
        raise BrowserCheckError("Drive URL must reference an exact file or folder object")
    if host == "docs.google.com":
        if "/d/" in parsed.path:
            return
        raise BrowserCheckError("Docs URL must contain an exact /d/<object-id> path")
    if host == "script.google.com":
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) == 4 and parts[0] == "macros" and parts[1] == "s" and parts[3] in {
            "dev",
            "exec",
        }:
            return
        raise BrowserCheckError("Apps Script URL must be an exact /macros/s/<deployment-id>/exec or /dev URL")
    if host == "sites.google.com":
        if parsed.path not in {"", "/"}:
            return
        raise BrowserCheckError("Sites URL must reference an exact site path")


def redact_object_url(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or "unknown"
    path_hash = _hash_text(parsed.path)
    query_keys = sorted(parse_qs(parsed.query))
    query_label = f"?keys={','.join(query_keys)}" if query_keys else ""
    return f"{parsed.scheme}://{host}/[path:{path_hash}]{query_label}"


def classify_access_text(text: str, *, current_url: str = "") -> tuple[BrowserAccessState, float, list[str]]:
    lowered = " ".join(text.lower().split())
    current_host = urlsplit(current_url).hostname or ""
    signals: list[str] = []
    if current_host == "accounts.google.com":
        return "login_required", 0.95, ["current_url:accounts.google.com"]
    for signal in ACCESS_DENIED_SIGNALS:
        if signal in lowered:
            signals.append(signal)
    if signals:
        return "access_denied", 0.9, signals[:5]
    for signal in LOGIN_REQUIRED_SIGNALS:
        if signal in lowered:
            signals.append(signal)
    if signals:
        return "login_required", 0.75, signals[:5]
    for signal in ACCESS_GRANTED_SIGNALS:
        if signal in lowered:
            signals.append(signal)
    if signals and current_host in SAFE_RESULT_HOSTS:
        return "access_granted", 0.55, signals[:5]
    return "unknown", 0.2, []


def _safe_body_text(page: Any, *, timeout_ms: int) -> str:
    body = page.locator("body")
    return cast(str, body.inner_text(timeout=timeout_ms))


def _load_owned_object_page(page: Any, *, url: str, timeout_ms: int) -> tuple[str, str]:
    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
    page.wait_for_timeout(1500)
    return _safe_body_text(page, timeout_ms=timeout_ms), cast(str, page.url)


def _build_check_result(
    *,
    account_id: str,
    url: str,
    current_url: str,
    text: str,
) -> OwnedBrowserCheckResult:
    state, confidence, signals = classify_access_text(text, current_url=current_url)
    parsed = urlsplit(current_url)
    return OwnedBrowserCheckResult(
        account_id=account_id,
        checked_url=redact_object_url(url),
        current_url_host=parsed.hostname,
        current_url_path_hash=_hash_text(parsed.path),
        state=state,
        confidence=confidence,
        matched_signals=signals,
    )


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
