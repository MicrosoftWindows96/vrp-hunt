"""Offline GraphQL endpoint discovery and safe introspection planning."""

from __future__ import annotations

import json
import re
from typing import Literal
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

GraphQLEvidenceType = Literal["document-url", "absolute-url", "relative-path", "graphql-marker", "introspection-response"]
GraphQLConfidence = Literal["low", "medium", "high"]

ABSOLUTE_URL_RE = re.compile(r"https?://[^\s\"'<>`{}\\]+", re.IGNORECASE)
QUOTED_PATH_RE = re.compile(r"(?P<quote>[\"'])(?P<path>/[A-Za-z0-9_./~%-]+(?:\?[^\"']*)?)(?P=quote)")
GRAPHQL_MARKERS = ("graphql", "__typename", "operationName", "query ", "mutation ", "subscription ")

INTROSPECTION_PROBE_QUERY = "query IntrospectionProbe { __schema { queryType { name } } }"


class GraphQLEndpointCandidate(StrictModel):
    url: str = Field(min_length=1)
    source_document: str = Field(min_length=1)
    evidence_type: GraphQLEvidenceType
    confidence: GraphQLConfidence
    parameter_names: list[str] = Field(default_factory=list)

    @field_validator("url", "source_document")
    @classmethod
    def normalize_urls(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("GraphQL candidate URL must be absolute http(s)")
        return sanitized.url

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


class GraphQLIntrospectionCheckPlan(StrictModel):
    endpoint_url: str = Field(min_length=1)
    method: str = "POST"
    content_type: str = "application/json"
    query: str = INTROSPECTION_PROBE_QUERY
    max_requests: int = Field(default=1, ge=1)
    approval_required: bool = True
    sends_traffic: bool = True

    @field_validator("endpoint_url")
    @classmethod
    def normalize_endpoint_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("GraphQL endpoint URL must be absolute http(s)")
        return sanitized.url


class GraphQLDiscoveryReport(StrictModel):
    document_url: str = Field(min_length=1)
    scope_domains: list[str] = Field(min_length=1)
    total_candidates: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    candidates: list[GraphQLEndpointCandidate] = Field(default_factory=list)
    introspection_plans: list[GraphQLIntrospectionCheckPlan] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("document_url")
    @classmethod
    def normalize_document_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("document URL must be absolute http(s)")
        return sanitized.url


class GraphQLImportBundle(StrictModel):
    report_count: int = Field(ge=0)
    total_candidates: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    reports: list[GraphQLDiscoveryReport] = Field(default_factory=list)
    introspection_plans: list[GraphQLIntrospectionCheckPlan] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def discover_graphql_endpoints(
    document_url: str,
    text: str,
    *,
    scope_domains: list[str] | None = None,
) -> GraphQLDiscoveryReport:
    normalized_url = GraphQLDiscoveryReport(
        document_url=document_url,
        scope_domains=_effective_scope_domains(document_url, scope_domains),
        total_candidates=0,
        total_assets=0,
    ).document_url
    normalized_scope = _effective_scope_domains(normalized_url, scope_domains)
    candidates, warnings = _candidate_records(
        normalized_url,
        text,
        scope_domains=normalized_scope,
    )
    deduped_candidates = _dedupe_candidates(candidates)
    plans = [GraphQLIntrospectionCheckPlan(endpoint_url=candidate.url) for candidate in deduped_candidates]
    assets = graphql_assets(deduped_candidates)
    return GraphQLDiscoveryReport(
        document_url=normalized_url,
        scope_domains=normalized_scope,
        total_candidates=len(deduped_candidates),
        total_assets=len(assets),
        candidates=deduped_candidates,
        introspection_plans=plans,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def build_graphql_import_bundle(reports: list[GraphQLDiscoveryReport]) -> GraphQLImportBundle:
    assets = _dedupe_assets([asset for report in reports for asset in report.assets])
    plans = _dedupe_plans([plan for report in reports for plan in report.introspection_plans])
    warnings = sorted({warning for report in reports for warning in report.warnings})
    return GraphQLImportBundle(
        report_count=len(reports),
        total_candidates=sum(report.total_candidates for report in reports),
        total_assets=len(assets),
        reports=reports,
        introspection_plans=plans,
        assets=assets,
        warnings=warnings,
    )


def graphql_assets(candidates: list[GraphQLEndpointCandidate]) -> list[Asset]:
    assets: list[Asset] = []
    for candidate in candidates:
        metadata = {
            "graphql_evidence_type": candidate.evidence_type,
            "confidence": candidate.confidence,
            "source_document": candidate.source_document,
            "introspection_plan_available": "true",
            "approval_required": "true",
        }
        if candidate.parameter_names:
            metadata["parameter_names"] = ",".join(candidate.parameter_names)
            metadata["query_values_redacted"] = "true"
        assets.append(
            Asset(
                kind="endpoint",
                value=candidate.url,
                source="graphql-discover",
                parent=candidate.source_document,
                metadata=metadata,
            )
        )
    return _dedupe_assets(assets)


def _candidate_records(
    document_url: str,
    text: str,
    *,
    scope_domains: list[str],
) -> tuple[list[GraphQLEndpointCandidate], list[str]]:
    records: list[GraphQLEndpointCandidate] = []
    warnings: list[str] = []
    has_marker = _has_graphql_marker(text)

    if _looks_like_graphql_url(document_url):
        record = _candidate_from_url(
            document_url,
            source_document=document_url,
            evidence_type="document-url",
            confidence="high",
            scope_domains=scope_domains,
        )
        if isinstance(record, GraphQLEndpointCandidate):
            records.append(record)

    if _looks_like_introspection_response(text):
        record = _candidate_from_url(
            document_url,
            source_document=document_url,
            evidence_type="introspection-response",
            confidence="high",
            scope_domains=scope_domains,
        )
        if isinstance(record, GraphQLEndpointCandidate):
            records.append(record)

    for raw_url in _absolute_urls(text):
        if not _looks_like_graphql_url(raw_url):
            continue
        record = _candidate_from_url(
            raw_url,
            source_document=document_url,
            evidence_type="absolute-url",
            confidence="high",
            scope_domains=scope_domains,
        )
        if isinstance(record, GraphQLEndpointCandidate):
            records.append(record)
        elif record:
            warnings.append(record)

    for path in _quoted_paths(text):
        if not _looks_like_graphql_path(path, require_marker=not has_marker):
            continue
        record = _candidate_from_url(
            urljoin(document_url, path),
            source_document=document_url,
            evidence_type="relative-path",
            confidence="high" if "graphql" in path.lower() else "medium",
            scope_domains=scope_domains,
        )
        if isinstance(record, GraphQLEndpointCandidate):
            records.append(record)
        elif record:
            warnings.append(record)

    if has_marker and not records and _looks_like_api_document(document_url):
        record = _candidate_from_url(
            document_url,
            source_document=document_url,
            evidence_type="graphql-marker",
            confidence="low",
            scope_domains=scope_domains,
        )
        if isinstance(record, GraphQLEndpointCandidate):
            records.append(record)
    return records, warnings


def _candidate_from_url(
    raw_url: str,
    *,
    source_document: str,
    evidence_type: GraphQLEvidenceType,
    confidence: GraphQLConfidence,
    scope_domains: list[str],
) -> GraphQLEndpointCandidate | str | None:
    sanitized = _sanitize_url(raw_url)
    if sanitized is None:
        return None
    host = urlsplit(sanitized.url).hostname or ""
    if not _host_allowed(host, scope_domains):
        return f"skipped third-party GraphQL host {host}"
    return GraphQLEndpointCandidate(
        url=sanitized.url,
        source_document=source_document,
        evidence_type=evidence_type,
        confidence=confidence,
        parameter_names=sanitized.parameter_names,
    )


class _SanitizedUrl(StrictModel):
    url: str
    parameter_names: list[str] = Field(default_factory=list)


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


def _absolute_urls(text: str) -> list[str]:
    return sorted({match.group(0).rstrip(").,;]") for match in ABSOLUTE_URL_RE.finditer(text)})


def _quoted_paths(text: str) -> list[str]:
    return sorted({match.group("path") for match in QUOTED_PATH_RE.finditer(text)})


def _looks_like_graphql_url(value: str) -> bool:
    parsed = urlsplit(value.strip())
    return _looks_like_graphql_path(parsed.path or "/", require_marker=False)


def _looks_like_graphql_path(path: str, *, require_marker: bool) -> bool:
    normalized = (urlsplit(path).path or "/").lower()
    if "graphql" in normalized:
        return True
    if require_marker:
        return False
    return normalized.endswith("/gql") or normalized.endswith("/query")


def _looks_like_api_document(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(marker in path for marker in ("/api/", "/graphql", "/gql", "/query"))


def _has_graphql_marker(text: str) -> bool:
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in GRAPHQL_MARKERS)


def _looks_like_introspection_response(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, dict):
        return False
    data = parsed.get("data")
    return isinstance(data, dict) and isinstance(data.get("__schema"), dict)


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


def _dedupe_candidates(candidates: list[GraphQLEndpointCandidate]) -> list[GraphQLEndpointCandidate]:
    by_url: dict[str, GraphQLEndpointCandidate] = {}
    rank: dict[GraphQLConfidence, int] = {"low": 0, "medium": 1, "high": 2}
    for candidate in candidates:
        existing = by_url.get(candidate.url)
        if existing is None or rank[candidate.confidence] > rank[existing.confidence]:
            by_url[candidate.url] = candidate
    return sorted(by_url.values(), key=lambda candidate: candidate.url)


def _dedupe_plans(plans: list[GraphQLIntrospectionCheckPlan]) -> list[GraphQLIntrospectionCheckPlan]:
    by_url = {plan.endpoint_url: plan for plan in plans}
    return sorted(by_url.values(), key=lambda plan: plan.endpoint_url)


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
