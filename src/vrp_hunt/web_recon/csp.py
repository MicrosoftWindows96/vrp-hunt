"""Offline Content-Security-Policy endpoint extraction."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Literal
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

CspSourceType = Literal["self", "host", "url"]

KEYWORD_SOURCES = {"'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", "'unsafe-hashes'"}
IGNORED_SCHEMES = {"data:", "blob:", "filesystem:", "mediastream:", "https:", "http:"}


class CspSourceRecord(StrictModel):
    directive: str = Field(min_length=1)
    source_type: CspSourceType
    value: str = Field(min_length=1)
    policy_index: int = Field(ge=1)
    parameter_names: list[str] = Field(default_factory=list)
    wildcard: bool = False

    @field_validator("directive")
    @classmethod
    def normalize_directive(cls, value: str) -> str:
        return value.strip().lower()

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


class CspExtractionReport(StrictModel):
    document_url: str = Field(min_length=1)
    scope_domains: list[str] = Field(min_length=1)
    policy_count: int = Field(ge=0)
    total_sources: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    sources: list[CspSourceRecord] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("document_url")
    @classmethod
    def normalize_document_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("document URL must be absolute http(s)")
        return sanitized.url


class CspImportBundle(StrictModel):
    report_count: int = Field(ge=0)
    policy_count: int = Field(ge=0)
    total_sources: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    reports: list[CspExtractionReport] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def extract_csp_from_text(
    document_url: str,
    text: str,
    *,
    scope_domains: list[str] | None = None,
) -> CspExtractionReport:
    normalized_url = CspExtractionReport(
        document_url=document_url,
        scope_domains=_effective_scope_domains(document_url, scope_domains),
        policy_count=0,
        total_sources=0,
        total_assets=0,
    ).document_url
    normalized_scope = _effective_scope_domains(normalized_url, scope_domains)
    policies = _policies_from_text(text)
    sources: list[CspSourceRecord] = []
    warnings: list[str] = []
    for policy_index, policy in enumerate(policies, start=1):
        parsed_sources, source_warnings = _sources_from_policy(
            policy,
            document_url=normalized_url,
            scope_domains=normalized_scope,
            policy_index=policy_index,
        )
        sources.extend(parsed_sources)
        warnings.extend(source_warnings)
    deduped_sources = _dedupe_sources(sources)
    assets = csp_assets(deduped_sources, document_url=normalized_url)
    return CspExtractionReport(
        document_url=normalized_url,
        scope_domains=normalized_scope,
        policy_count=len(policies),
        total_sources=len(deduped_sources),
        total_assets=len(assets),
        sources=deduped_sources,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def build_csp_import_bundle(reports: list[CspExtractionReport]) -> CspImportBundle:
    assets = _dedupe_assets([asset for report in reports for asset in report.assets])
    warnings = sorted({warning for report in reports for warning in report.warnings})
    return CspImportBundle(
        report_count=len(reports),
        policy_count=sum(report.policy_count for report in reports),
        total_sources=sum(report.total_sources for report in reports),
        total_assets=len(assets),
        reports=reports,
        assets=assets,
        warnings=warnings,
    )


def csp_assets(sources: list[CspSourceRecord], *, document_url: str) -> list[Asset]:
    assets: list[Asset] = []
    for source in sources:
        metadata = {
            "csp_directive": source.directive,
            "csp_source_type": source.source_type,
            "policy_index": str(source.policy_index),
        }
        if source.wildcard:
            metadata["wildcard_source"] = "true"
        if source.parameter_names:
            metadata["parameter_names"] = ",".join(source.parameter_names)
            metadata["query_values_redacted"] = "true"
        if source.source_type == "host":
            assets.append(
                Asset(
                    kind="host",
                    value=source.value,
                    source="csp-extract",
                    parent=document_url,
                    metadata=metadata,
                )
            )
        else:
            assets.append(
                Asset(
                    kind="endpoint" if _is_endpoint(source.value) else "url",
                    value=source.value,
                    source="csp-extract",
                    parent=document_url,
                    metadata=metadata,
                )
            )
    return _dedupe_assets(assets)


def _sources_from_policy(
    policy: str,
    *,
    document_url: str,
    scope_domains: list[str],
    policy_index: int,
) -> tuple[list[CspSourceRecord], list[str]]:
    records: list[CspSourceRecord] = []
    warnings: list[str] = []
    for directive, tokens in _directives(policy):
        for token in tokens:
            source = _record_from_token(
                token,
                directive=directive,
                document_url=document_url,
                policy_index=policy_index,
            )
            if source is None:
                continue
            host = _source_host(source)
            if host is not None and not _host_allowed(host, scope_domains):
                warnings.append(f"policy {policy_index} {directive}: skipped third-party host {host}")
                continue
            records.append(source)
    return records, warnings


def _record_from_token(
    token: str,
    *,
    directive: str,
    document_url: str,
    policy_index: int,
) -> CspSourceRecord | None:
    stripped = token.strip()
    if not stripped or stripped in KEYWORD_SOURCES or stripped.startswith(("'nonce-", "'sha")):
        return None
    if stripped == "'self'":
        origin = _origin_url(document_url)
        return CspSourceRecord(
            directive=directive,
            source_type="self",
            value=origin,
            policy_index=policy_index,
        )
    if stripped in IGNORED_SCHEMES:
        return None
    if stripped.startswith("/"):
        sanitized = _sanitize_url(urljoin(document_url, stripped))
        if sanitized is None:
            return None
        return CspSourceRecord(
            directive=directive,
            source_type="url",
            value=sanitized.url,
            policy_index=policy_index,
            parameter_names=sanitized.parameter_names,
        )
    candidate = _absolute_source_url(stripped, document_url)
    if candidate is not None:
        return CspSourceRecord(
            directive=directive,
            source_type="url",
            value=candidate.url,
            policy_index=policy_index,
            parameter_names=candidate.parameter_names,
            wildcard=candidate.wildcard,
        )
    host = _host_from_source(stripped)
    if host is None:
        return None
    return CspSourceRecord(
        directive=directive,
        source_type="host",
        value=host.host,
        policy_index=policy_index,
        wildcard=host.wildcard,
    )


class _SanitizedUrl(StrictModel):
    url: str
    parameter_names: list[str] = Field(default_factory=list)


class _SourceUrl(_SanitizedUrl):
    wildcard: bool = False


class _SourceHost(StrictModel):
    host: str
    wildcard: bool = False


def _absolute_source_url(token: str, document_url: str) -> _SourceUrl | None:
    if token.startswith("//"):
        token = f"{urlsplit(document_url).scheme}:{token}"
    parsed = urlsplit(token)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    wildcard = parsed.hostname is not None and parsed.hostname.startswith("*.")
    host = _normalize_host(parsed.hostname or "")
    if host is None:
        return None
    path = parsed.path or "/"
    port = f":{parsed.port}" if parsed.port is not None else ""
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return _SourceUrl(
        url=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        parameter_names=parameter_names,
        wildcard=wildcard,
    )


def _sanitize_url(value: str) -> _SanitizedUrl | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = _normalize_host(parsed.hostname)
    if host is None:
        return None
    path = parsed.path or "/"
    port = f":{parsed.port}" if parsed.port is not None else ""
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return _SanitizedUrl(
        url=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        parameter_names=parameter_names,
    )


def _host_from_source(token: str) -> _SourceHost | None:
    host_candidate = token.split("/", 1)[0]
    if ":" in host_candidate:
        host_candidate = host_candidate.split(":", 1)[0]
    wildcard = host_candidate.startswith("*.")
    normalized = _normalize_host(host_candidate)
    if normalized is None:
        return None
    return _SourceHost(host=normalized, wildcard=wildcard)


def _normalize_host(value: str) -> str | None:
    candidate = value.strip().lower().removeprefix("*.")
    if not candidate:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None


def _policies_from_text(text: str) -> list[str]:
    policies = _header_policies(text)
    policies.extend(_MetaCspParser.parse(text))
    if policies:
        return policies
    stripped = " ".join(line.strip() for line in text.splitlines() if line.strip())
    return [stripped] if stripped else []


def _header_policies(text: str) -> list[str]:
    policies: list[str] = []
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        if key.strip().lower() in {"content-security-policy", "content-security-policy-report-only"}:
            policies.append(value.strip())
    return policies


class _MetaCspParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.policies: list[str] = []

    @classmethod
    def parse(cls, text: str) -> list[str]:
        parser = cls()
        parser.feed(text)
        return parser.policies

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "meta":
            return
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if attr_map.get("http-equiv", "").lower() != "content-security-policy":
            return
        content = attr_map.get("content", "").strip()
        if content:
            self.policies.append(content)


def _directives(policy: str) -> list[tuple[str, list[str]]]:
    directives: list[tuple[str, list[str]]] = []
    for raw_directive in policy.split(";"):
        stripped = raw_directive.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if not parts:
            continue
        directive = parts[0].lower()
        directives.append((directive, parts[1:]))
    return directives


def _source_host(source: CspSourceRecord) -> str | None:
    if source.source_type == "host":
        return source.value
    return urlsplit(source.value).hostname


def _origin_url(document_url: str) -> str:
    parsed = urlsplit(document_url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _is_endpoint(url: str) -> bool:
    path = urlsplit(url).path
    return bool(path and path != "/")


def _effective_scope_domains(document_url: str, scope_domains: list[str] | None) -> list[str]:
    normalized = _normalize_scope_domains(scope_domains or [])
    if normalized:
        return normalized
    sanitized = _sanitize_url(document_url)
    if sanitized is None:
        raise ValueError("document URL must be absolute http(s)")
    host = urlsplit(sanitized.url).hostname
    return [host] if host else []


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
    return normalized


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _dedupe_sources(sources: list[CspSourceRecord]) -> list[CspSourceRecord]:
    by_key = {
        (
            source.directive,
            source.source_type,
            source.value,
            tuple(source.parameter_names),
            source.wildcard,
        ): source
        for source in sources
    }
    return sorted(by_key.values(), key=lambda source: (source.directive, source.source_type, source.value))


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
