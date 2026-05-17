"""Offline safe exposure checks for saved web content and URL assets."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit, urlunsplit
from typing import Literal

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

ExposureCategory = Literal["admin_panel", "debug_page", "config_leak", "directory_listing"]
ExposureConfidence = Literal["low", "medium", "high"]

ADMIN_PATH_MARKERS = (
    "/admin",
    "/administrator",
    "/console",
    "/dashboard",
    "/manage",
    "/management",
    "/phpmyadmin",
    "/wp-admin",
)
DEBUG_PATH_MARKERS = (
    "/actuator",
    "/debug",
    "/debug/pprof",
    "/metrics",
    "/phpinfo",
    "/server-status",
    "/trace",
    "/_profiler",
    "/__debugger__",
)
CONFIG_PATH_MARKERS = (
    "/.env",
    "/application.properties",
    "/application.yml",
    "/config.json",
    "/config.yml",
    "/credentials",
    "/firebase.json",
    "/secrets",
    "/service-account",
    "/settings.py",
)
ADMIN_BODY_MARKERS = (
    ("admin console", "admin-console"),
    ("sign in to admin", "admin-sign-in"),
    ("administrator login", "administrator-login"),
)
DEBUG_BODY_MARKERS = (
    ("traceback (most recent call last)", "python-traceback"),
    ("stack trace", "stack-trace"),
    ("phpinfo()", "phpinfo"),
    ("spring boot actuator", "spring-boot-actuator"),
    ("debug toolbar", "debug-toolbar"),
)
CONFIG_BODY_MARKERS = (
    ("db_password", "db-password"),
    ("database_url", "database-url"),
    ("aws_access_key_id", "aws-access-key-marker"),
    ("google_application_credentials", "google-credentials-marker"),
    ("client_secret", "client-secret-marker"),
    ("-----begin private key-----", "private-key-marker"),
)
DIRECTORY_BODY_MARKERS = (
    ("<title>index of /", "index-title"),
    ("index of /", "index-heading"),
    ("parent directory", "parent-directory"),
)


class ExposureDocument(StrictModel):
    url: str = Field(min_length=1)
    body: str = ""
    source: str = Field(min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        if _sanitize_url(value) is None:
            raise ValueError("exposure document URL must be absolute http(s)")
        return value.strip()


class ExposureSignal(StrictModel):
    url: str = Field(min_length=1)
    host: str = Field(min_length=1)
    category: ExposureCategory
    confidence: ExposureConfidence
    matched: str = Field(min_length=1)
    evidence: str = Field(min_length=1)
    parameter_names: list[str] = Field(default_factory=list)


class SafeExposureReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    total_signals: int = Field(ge=0)
    signals: list[ExposureSignal] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def check_safe_exposures(
    documents: list[ExposureDocument],
    *,
    scope_domains: list[str],
    assets: list[Asset] | None = None,
) -> SafeExposureReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    all_documents = [*documents, *_documents_from_assets(assets or [])]
    signals: list[ExposureSignal] = []
    warnings: list[str] = []
    for index, document in enumerate(all_documents, start=1):
        sanitized = _sanitize_url(document.url)
        if sanitized is None:
            warnings.append(f"{document.source}:{index}: invalid url")
            continue
        if not _host_allowed(sanitized.host, normalized_scope):
            warnings.append(f"{document.source}:{index}: skipped third-party host {sanitized.host}")
            continue
        signals.extend(_signals_for_document(document, sanitized=sanitized))
    deduped_signals = _dedupe_signals(signals)
    output_assets = safe_exposure_assets(deduped_signals)
    return SafeExposureReport(
        scope_domains=normalized_scope,
        total_inputs=len(all_documents),
        total_signals=len(deduped_signals),
        signals=deduped_signals,
        assets=output_assets,
        warnings=sorted(set(warnings)),
    )


def safe_exposure_assets(signals: list[ExposureSignal]) -> list[Asset]:
    assets: list[Asset] = []
    for signal in signals:
        assets.append(
            Asset(
                kind="note",
                value=f"safe-exposure:{signal.category}:{signal.url}",
                source="safe-exposure-check",
                parent=signal.url,
                metadata={
                    "category": signal.category,
                    "confidence": signal.confidence,
                    "matched": signal.matched,
                    "parameter_names": ",".join(signal.parameter_names),
                    "query_values_redacted": "true" if signal.parameter_names else "false",
                },
            )
        )
    return _dedupe_assets(assets)


def _signals_for_document(document: ExposureDocument, *, sanitized: "_SanitizedUrl") -> list[ExposureSignal]:
    signals: list[ExposureSignal] = []
    path = urlsplit(sanitized.url).path.lower()
    body = document.body.lower()
    metadata_text = " ".join(f"{key}={value}" for key, value in document.metadata.items()).lower()
    combined = f"{body}\n{metadata_text}"

    for marker in ADMIN_PATH_MARKERS:
        if _path_matches(path, marker):
            signals.append(_signal(document, sanitized=sanitized, category="admin_panel", matched=f"path:{marker}"))
    for marker in DEBUG_PATH_MARKERS:
        if _path_matches(path, marker):
            signals.append(_signal(document, sanitized=sanitized, category="debug_page", matched=f"path:{marker}"))
    for marker in CONFIG_PATH_MARKERS:
        if _path_matches(path, marker):
            signals.append(
                _signal(document, sanitized=sanitized, category="config_leak", matched=f"path:{marker}", confidence="high")
            )
    for needle, token in ADMIN_BODY_MARKERS:
        if needle in combined:
            signals.append(_signal(document, sanitized=sanitized, category="admin_panel", matched=f"body:{token}"))
    for needle, token in DEBUG_BODY_MARKERS:
        if needle in combined:
            signals.append(_signal(document, sanitized=sanitized, category="debug_page", matched=f"body:{token}"))
    for needle, token in CONFIG_BODY_MARKERS:
        if needle in combined:
            signals.append(
                _signal(document, sanitized=sanitized, category="config_leak", matched=f"body:{token}", confidence="high")
            )
    for needle, token in DIRECTORY_BODY_MARKERS:
        if needle in combined:
            signals.append(
                _signal(
                    document,
                    sanitized=sanitized,
                    category="directory_listing",
                    matched=f"body:{token}",
                    confidence="medium",
                )
            )
    return signals


def _signal(
    document: ExposureDocument,
    *,
    sanitized: "_SanitizedUrl",
    category: ExposureCategory,
    matched: str,
    confidence: ExposureConfidence = "medium",
) -> ExposureSignal:
    if category == "admin_panel" and matched.startswith("path:"):
        confidence = "low"
    return ExposureSignal(
        url=sanitized.url,
        host=sanitized.host,
        category=category,
        confidence=confidence,
        matched=matched,
        evidence=document.source,
        parameter_names=sanitized.parameter_names,
    )


def _documents_from_assets(assets: list[Asset]) -> list[ExposureDocument]:
    documents: list[ExposureDocument] = []
    for asset in assets:
        if asset.kind not in {"url", "endpoint"}:
            continue
        sanitized = _sanitize_url(asset.value)
        if sanitized is None:
            continue
        documents.append(
            ExposureDocument(
                url=asset.value,
                body="",
                source=f"asset:{asset.source}",
                metadata=asset.metadata,
            )
        )
    return documents


def _path_matches(path: str, marker: str) -> bool:
    return path == marker or path.startswith(f"{marker}/") or path.endswith(marker)


class _SanitizedUrl(StrictModel):
    url: str
    host: str
    parameter_names: list[str] = Field(default_factory=list)


def _sanitize_url(value: str) -> _SanitizedUrl | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = _normalize_host(parsed.hostname)
    if host is None:
        return None
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path or "/"
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return _SanitizedUrl(
        url=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        host=host,
        parameter_names=parameter_names,
    )


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in scope_domains:
        candidate = value.strip().lower().removeprefix("*.").rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        host = _normalize_host(candidate)
        if host is None:
            continue
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    if not normalized:
        raise ValueError("at least one scope domain is required")
    return normalized


def _normalize_host(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _dedupe_signals(signals: list[ExposureSignal]) -> list[ExposureSignal]:
    by_key = {(signal.url, signal.category, signal.matched): signal for signal in signals}
    return sorted(by_key.values(), key=lambda signal: (signal.url, signal.category, signal.matched))


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
