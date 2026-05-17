"""Offline security.txt parser."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

SecurityTxtField = Literal[
    "acknowledgments",
    "canonical",
    "contact",
    "encryption",
    "expires",
    "hiring",
    "policy",
    "preferred-languages",
    "unknown",
]

URL_FIELDS = {"acknowledgments", "canonical", "contact", "encryption", "hiring", "policy"}


class SecurityTxtRecord(StrictModel):
    field_name: SecurityTxtField
    raw_field_name: str = Field(min_length=1)
    value: str = Field(min_length=1)
    line_number: int = Field(ge=1)
    redacted: bool = False
    parameter_names: list[str] = Field(default_factory=list)

    @field_validator("parameter_names")
    @classmethod
    def clean_parameter_names(cls, value: list[str]) -> list[str]:
        names: list[str] = []
        seen: set[str] = set()
        for item in value:
            name = item.strip()
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        return names


class SecurityTxtParseReport(StrictModel):
    security_txt_url: str = Field(min_length=1)
    scope_domains: list[str] = Field(min_length=1)
    expires_at: str | None = None
    total_records: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    records: list[SecurityTxtRecord] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("security_txt_url")
    @classmethod
    def normalize_security_txt_url(cls, value: str) -> str:
        sanitized = _sanitize_http_url(value)
        if sanitized is None:
            raise ValueError("security.txt URL must be absolute http(s)")
        return sanitized.url


class SecurityTxtImportBundle(StrictModel):
    report_count: int = Field(ge=0)
    total_records: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    reports: list[SecurityTxtParseReport] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def parse_security_txt(
    security_txt_url: str,
    text: str,
    *,
    scope_domains: list[str] | None = None,
    now: datetime | None = None,
) -> SecurityTxtParseReport:
    normalized_url = SecurityTxtParseReport(
        security_txt_url=security_txt_url,
        scope_domains=_effective_scope_domains(security_txt_url, scope_domains),
        total_records=0,
        total_assets=0,
    ).security_txt_url
    normalized_scope = _effective_scope_domains(normalized_url, scope_domains)
    warnings: list[str] = []
    records: list[SecurityTxtRecord] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        key, separator, raw_value = line.partition(":")
        if not separator:
            warnings.append(f"line {line_number}: ignored malformed field")
            continue
        value = raw_value.strip()
        if not key.strip() or not value:
            warnings.append(f"line {line_number}: ignored empty field")
            continue
        records.append(_record_from_field(key.strip(), value, line_number))

    expires_at = _first_record_value(records, "expires")
    if expires_at:
        warnings.extend(_expires_warnings(expires_at, now=now or datetime.now(UTC)))
    assets, asset_warnings = _assets_and_warnings(
        records,
        security_txt_url=normalized_url,
        scope_domains=normalized_scope,
    )
    warnings.extend(asset_warnings)
    return SecurityTxtParseReport(
        security_txt_url=normalized_url,
        scope_domains=normalized_scope,
        expires_at=expires_at,
        total_records=len(records),
        total_assets=len(assets),
        records=records,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def build_security_txt_import_bundle(reports: list[SecurityTxtParseReport]) -> SecurityTxtImportBundle:
    assets = _dedupe_assets([asset for report in reports for asset in report.assets])
    warnings = sorted({warning for report in reports for warning in report.warnings})
    return SecurityTxtImportBundle(
        report_count=len(reports),
        total_records=sum(report.total_records for report in reports),
        total_assets=len(assets),
        reports=reports,
        assets=assets,
        warnings=warnings,
    )


def security_txt_assets(report: SecurityTxtParseReport) -> list[Asset]:
    assets, _warnings = _assets_and_warnings(
        report.records,
        security_txt_url=report.security_txt_url,
        scope_domains=report.scope_domains,
    )
    return assets


def _record_from_field(key: str, value: str, line_number: int) -> SecurityTxtRecord:
    field_name = _field_name(key)
    redacted_value, redacted, parameter_names = _redact_value(value)
    return SecurityTxtRecord(
        field_name=field_name,
        raw_field_name=key,
        value=redacted_value,
        line_number=line_number,
        redacted=redacted,
        parameter_names=parameter_names,
    )


def _assets_and_warnings(
    records: list[SecurityTxtRecord],
    *,
    security_txt_url: str,
    scope_domains: list[str],
) -> tuple[list[Asset], list[str]]:
    assets: list[Asset] = []
    warnings: list[str] = []
    for record in records:
        metadata = _metadata_for_record(record)
        if record.field_name == "contact" and record.value.startswith("mailto:"):
            domain = record.value.removeprefix("mailto:<redacted>@")
            assets.append(
                Asset(
                    kind="note",
                    value=f"security-contact:mailto:{domain}",
                    source="security-txt-contact",
                    parent=security_txt_url,
                    metadata=metadata | {"contact_domain": domain},
                )
            )
            continue
        if record.field_name == "contact" and record.value.startswith("tel:"):
            assets.append(
                Asset(
                    kind="note",
                    value="security-contact:tel",
                    source="security-txt-contact",
                    parent=security_txt_url,
                    metadata=metadata | {"redacted": "true"},
                )
            )
            continue
        if record.field_name == "expires":
            assets.append(
                Asset(
                    kind="note",
                    value=f"security-txt-expires:{security_txt_url}",
                    source="security-txt-expires",
                    parent=security_txt_url,
                    metadata=metadata | {"expires_at": record.value},
                )
            )
            continue
        if record.field_name in URL_FIELDS and record.value.startswith(("http://", "https://")):
            host = urlsplit(record.value).hostname or ""
            if not _host_allowed(host, scope_domains):
                warnings.append(f"line {record.line_number}: skipped third-party {record.field_name} host {host}")
                continue
            assets.append(
                Asset(
                    kind="url",
                    value=record.value,
                    source=f"security-txt-{record.field_name}",
                    parent=security_txt_url,
                    metadata=metadata,
                )
            )
    return _dedupe_assets(assets), sorted(set(warnings))


def _metadata_for_record(record: SecurityTxtRecord) -> dict[str, str]:
    metadata = {
        "security_txt_field": record.field_name,
        "raw_field_name": record.raw_field_name,
        "line_number": str(record.line_number),
    }
    if record.redacted:
        metadata["redacted"] = "true"
    if record.parameter_names:
        metadata["parameter_names"] = ",".join(record.parameter_names)
        metadata["query_values_redacted"] = "true"
    return metadata


class _SanitizedUrl(StrictModel):
    url: str
    parameter_names: list[str] = Field(default_factory=list)


def _redact_value(value: str) -> tuple[str, bool, list[str]]:
    stripped = value.strip()
    lower = stripped.lower()
    if lower.startswith("mailto:"):
        domain = stripped.removeprefix("mailto:").split("@", 1)[-1].strip().lower()
        if domain:
            return f"mailto:<redacted>@{domain}", True, []
        return "mailto:<redacted>", True, []
    if lower.startswith("tel:"):
        return "tel:<redacted>", True, []
    sanitized = _sanitize_http_url(stripped)
    if sanitized is not None:
        return sanitized.url, bool(sanitized.parameter_names), sanitized.parameter_names
    return stripped, False, []


def _sanitize_http_url(value: str) -> _SanitizedUrl | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        host = normalize_host(parsed.hostname.lower()).host
    except NormalizationError:
        return None
    path = parsed.path or "/"
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    port = f":{parsed.port}" if parsed.port is not None else ""
    return _SanitizedUrl(
        url=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        parameter_names=parameter_names,
    )


def _expires_warnings(expires_at: str, *, now: datetime) -> list[str]:
    try:
        parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError:
        return ["invalid Expires value"]
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    if parsed <= now:
        return ["security.txt is expired"]
    return []


def _field_name(value: str) -> SecurityTxtField:
    normalized = value.strip().lower()
    if normalized in {
        "acknowledgments",
        "canonical",
        "contact",
        "encryption",
        "expires",
        "hiring",
        "policy",
        "preferred-languages",
    }:
        return normalized  # type: ignore[return-value]
    return "unknown"


def _first_record_value(records: list[SecurityTxtRecord], field_name: SecurityTxtField) -> str | None:
    for record in records:
        if record.field_name == field_name:
            return record.value
    return None


def _effective_scope_domains(security_txt_url: str, scope_domains: list[str] | None) -> list[str]:
    normalized = _normalize_scope_domains(scope_domains or [])
    if normalized:
        return normalized
    sanitized = _sanitize_http_url(security_txt_url)
    if sanitized is None:
        raise ValueError("security.txt URL must be absolute http(s)")
    host = urlsplit(sanitized.url).hostname
    return [host] if host else []


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in scope_domains:
        candidate = value.strip().lower().removeprefix("*.").rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        if not candidate:
            continue
        try:
            host = normalize_host(candidate).host
        except NormalizationError as exc:
            raise ValueError(f"invalid scope domain: {value!r}") from exc
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    return normalized


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
