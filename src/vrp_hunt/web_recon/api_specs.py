"""Offline OpenAPI, Swagger, and Postman collection discovery."""

from __future__ import annotations

import json
from typing import Literal, cast
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import yaml
from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

ApiSpecKind = Literal["openapi", "swagger", "postman"]

HTTP_METHODS = {"delete", "get", "head", "options", "patch", "post", "put", "trace"}


class ApiSpecEndpoint(StrictModel):
    method: str = Field(min_length=1, max_length=16)
    url: str = Field(min_length=1)
    path: str = Field(min_length=1)
    spec_kind: ApiSpecKind
    source_spec: str = Field(min_length=1)
    operation_id: str | None = None
    tags: list[str] = Field(default_factory=list)
    parameter_names: list[str] = Field(default_factory=list)
    templated: bool = False

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("url", "source_spec")
    @classmethod
    def normalize_urls(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("spec endpoint URL must be absolute http(s)")
        return sanitized.url

    @field_validator("parameter_names", "tags")
    @classmethod
    def clean_string_list(cls, value: list[str]) -> list[str]:
        items: list[str] = []
        seen: set[str] = set()
        for item in value:
            candidate = item.strip()
            if candidate and candidate not in seen:
                seen.add(candidate)
                items.append(candidate)
        return items


class ApiSpecDiscoveryReport(StrictModel):
    spec_url: str = Field(min_length=1)
    spec_kind: ApiSpecKind
    scope_domains: list[str] = Field(min_length=1)
    total_endpoints: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    endpoints: list[ApiSpecEndpoint] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("spec_url")
    @classmethod
    def normalize_spec_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("spec URL must be absolute http(s)")
        return sanitized.url


class ApiSpecImportBundle(StrictModel):
    report_count: int = Field(ge=0)
    total_endpoints: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    reports: list[ApiSpecDiscoveryReport] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def discover_api_spec_assets(
    spec_url: str,
    text: str,
    *,
    scope_domains: list[str] | None = None,
) -> ApiSpecDiscoveryReport:
    normalized_url = ApiSpecDiscoveryReport(
        spec_url=spec_url,
        spec_kind="openapi",
        scope_domains=_effective_scope_domains(spec_url, scope_domains),
        total_endpoints=0,
        total_assets=0,
    ).spec_url
    normalized_scope = _effective_scope_domains(normalized_url, scope_domains)
    document = _load_spec_document(text)
    if not isinstance(document, dict):
        raise ValueError("API spec must be a JSON or YAML object")

    spec_kind = _detect_spec_kind(document)
    if spec_kind == "postman":
        endpoints, warnings = _postman_endpoints(document, spec_url=normalized_url, scope_domains=normalized_scope)
    elif spec_kind in {"openapi", "swagger"}:
        endpoints, warnings = _openapi_endpoints(
            document,
            spec_kind=spec_kind,
            spec_url=normalized_url,
            scope_domains=normalized_scope,
        )
    else:
        raise ValueError("unsupported API spec; expected OpenAPI, Swagger, or Postman collection")

    deduped_endpoints = _dedupe_endpoints(endpoints)
    assets = api_spec_assets(deduped_endpoints)
    return ApiSpecDiscoveryReport(
        spec_url=normalized_url,
        spec_kind=spec_kind,
        scope_domains=normalized_scope,
        total_endpoints=len(deduped_endpoints),
        total_assets=len(assets),
        endpoints=deduped_endpoints,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def build_api_spec_import_bundle(reports: list[ApiSpecDiscoveryReport]) -> ApiSpecImportBundle:
    assets = _dedupe_assets([asset for report in reports for asset in report.assets])
    warnings = sorted({warning for report in reports for warning in report.warnings})
    return ApiSpecImportBundle(
        report_count=len(reports),
        total_endpoints=sum(report.total_endpoints for report in reports),
        total_assets=len(assets),
        reports=reports,
        assets=assets,
        warnings=warnings,
    )


def api_spec_assets(endpoints: list[ApiSpecEndpoint]) -> list[Asset]:
    assets: list[Asset] = []
    for endpoint in endpoints:
        metadata = {
            "api_spec_kind": endpoint.spec_kind,
            "method": endpoint.method,
            "path": endpoint.path,
            "source_spec": endpoint.source_spec,
        }
        if endpoint.operation_id:
            metadata["operation_id"] = endpoint.operation_id
        if endpoint.tags:
            metadata["tags"] = ",".join(endpoint.tags)
        if endpoint.parameter_names:
            metadata["parameter_names"] = ",".join(endpoint.parameter_names)
            metadata["query_values_redacted"] = "true"
        if endpoint.templated:
            metadata["templated"] = "true"
        assets.append(
            Asset(
                kind="endpoint",
                value=endpoint.url,
                source="api-spec-import",
                parent=endpoint.source_spec,
                metadata=metadata,
            )
        )
        for parameter_name in endpoint.parameter_names:
            assets.append(
                Asset(
                    kind="parameter",
                    value=parameter_name,
                    source="api-spec-parameter",
                    parent=endpoint.url,
                    metadata={
                        "api_spec_kind": endpoint.spec_kind,
                        "method": endpoint.method,
                        "source_spec": endpoint.source_spec,
                    },
                )
            )
    return _dedupe_assets(assets)


def _openapi_endpoints(
    document: dict[object, object],
    *,
    spec_kind: ApiSpecKind,
    spec_url: str,
    scope_domains: list[str],
) -> tuple[list[ApiSpecEndpoint], list[str]]:
    warnings: list[str] = []
    endpoints: list[ApiSpecEndpoint] = []
    server_urls = _server_urls(document, spec_kind=spec_kind, spec_url=spec_url)
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return [], ["spec paths object missing"]

    for raw_path, path_item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(path_item, dict):
            continue
        path_parameters = _parameter_names(path_item.get("parameters"))
        for raw_method, operation in path_item.items():
            method = str(raw_method).lower()
            if method not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            operation_parameters = _parameter_names(operation.get("parameters"))
            parameter_names = [*path_parameters, *operation_parameters]
            operation_id = _optional_string(operation.get("operationId"))
            tags = _string_list(operation.get("tags"))
            for server_url in server_urls:
                endpoint_url = _join_url_path(server_url, raw_path)
                sanitized = _sanitize_url(endpoint_url)
                if sanitized is None:
                    warnings.append(f"{method.upper()} {raw_path}: skipped invalid endpoint URL")
                    continue
                host = urlsplit(sanitized.url).hostname or ""
                if not _host_allowed(host, scope_domains):
                    warnings.append(f"{method.upper()} {raw_path}: skipped third-party host {host}")
                    continue
                endpoints.append(
                    ApiSpecEndpoint(
                        method=method,
                        url=sanitized.url,
                        path=raw_path,
                        spec_kind=spec_kind,
                        source_spec=spec_url,
                        operation_id=operation_id,
                        tags=tags,
                        parameter_names=sorted({*parameter_names, *sanitized.parameter_names}),
                        templated="{" in raw_path,
                    )
                )
    return endpoints, warnings


def _postman_endpoints(
    document: dict[object, object],
    *,
    spec_url: str,
    scope_domains: list[str],
) -> tuple[list[ApiSpecEndpoint], list[str]]:
    endpoints: list[ApiSpecEndpoint] = []
    warnings: list[str] = []
    for index, request in enumerate(_postman_requests(document.get("item")), start=1):
        method = _optional_string(request.get("method")) or "GET"
        raw_url, explicit_parameters = _postman_request_url(request.get("url"), spec_url)
        if raw_url is None:
            warnings.append(f"request {index}: skipped missing URL")
            continue
        sanitized = _sanitize_url(raw_url)
        if sanitized is None:
            warnings.append(f"request {index}: skipped invalid URL")
            continue
        host = urlsplit(sanitized.url).hostname or ""
        if not _host_allowed(host, scope_domains):
            warnings.append(f"request {index}: skipped third-party host {host}")
            continue
        endpoints.append(
            ApiSpecEndpoint(
                method=method,
                url=sanitized.url,
                path=urlsplit(sanitized.url).path or "/",
                spec_kind="postman",
                source_spec=spec_url,
                parameter_names=sorted({*explicit_parameters, *sanitized.parameter_names}),
                templated="{" in sanitized.url or "{{" in raw_url,
            )
        )
    return endpoints, warnings


def _load_spec_document(text: str) -> object:
    stripped = text.strip()
    if not stripped:
        raise ValueError("API spec is empty")
    try:
        return cast(object, json.loads(stripped))
    except json.JSONDecodeError:
        try:
            return cast(object, yaml.safe_load(stripped))
        except yaml.YAMLError as exc:
            raise ValueError(f"invalid API spec JSON/YAML: {exc}") from exc


def _detect_spec_kind(document: dict[object, object]) -> ApiSpecKind | None:
    if isinstance(document.get("openapi"), str):
        return "openapi"
    if isinstance(document.get("swagger"), str):
        return "swagger"
    info = document.get("info")
    if isinstance(info, dict) and "postman" in str(info.get("schema", "")).lower():
        return "postman"
    if "item" in document and "info" in document:
        return "postman"
    return None


def _server_urls(document: dict[object, object], *, spec_kind: ApiSpecKind, spec_url: str) -> list[str]:
    if spec_kind == "swagger":
        return _swagger_server_urls(document, spec_url)
    servers = document.get("servers")
    urls: list[str] = []
    if isinstance(servers, list):
        for server in servers:
            if isinstance(server, dict):
                raw_url = server.get("url")
                if isinstance(raw_url, str) and raw_url.strip():
                    urls.append(_resolve_url(spec_url, raw_url))
    return urls or [_origin_url(spec_url)]


def _swagger_server_urls(document: dict[object, object], spec_url: str) -> list[str]:
    schemes = _string_list(document.get("schemes")) or [urlsplit(spec_url).scheme or "https"]
    raw_host = _optional_string(document.get("host")) or (urlsplit(spec_url).hostname or "")
    host = _normalize_host(raw_host)
    if host is None:
        return [_origin_url(spec_url)]
    base_path = _optional_string(document.get("basePath")) or "/"
    return [f"{scheme.lower()}://{host}{_ensure_leading_slash(base_path)}" for scheme in schemes]


def _postman_requests(item: object) -> list[dict[object, object]]:
    requests: list[dict[object, object]] = []
    if isinstance(item, list):
        for entry in item:
            requests.extend(_postman_requests(entry))
    elif isinstance(item, dict):
        request = item.get("request")
        if isinstance(request, dict):
            requests.append(request)
        elif isinstance(request, str):
            requests.append({"url": request, "method": "GET"})
        requests.extend(_postman_requests(item.get("item")))
    return requests


def _postman_request_url(value: object, spec_url: str) -> tuple[str | None, list[str]]:
    if isinstance(value, str):
        return _resolve_postman_url(value, spec_url), []
    if not isinstance(value, dict):
        return None, []
    raw = value.get("raw")
    parameter_names = _postman_query_names(value.get("query"))
    if isinstance(raw, str) and raw.strip():
        return _resolve_postman_url(raw, spec_url), parameter_names

    protocol = _optional_string(value.get("protocol")) or urlsplit(spec_url).scheme or "https"
    host = _postman_host(value.get("host"))
    path = _postman_path(value.get("path"))
    if host is None:
        if path is None:
            return None, parameter_names
        return _resolve_postman_url(path, spec_url), parameter_names
    return f"{protocol.lower()}://{host}{_ensure_leading_slash(path or '')}", parameter_names


def _postman_host(value: object) -> str | None:
    if isinstance(value, str):
        candidate = value
    elif isinstance(value, list):
        candidate = ".".join(str(part) for part in value if str(part).strip())
    else:
        return None
    if "{{" in candidate:
        return None
    return candidate.strip()


def _postman_path(value: object) -> str | None:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return "/".join(str(part).strip("/") for part in value if str(part).strip())
    return None


def _postman_query_names(value: object) -> list[str]:
    names: set[str] = set()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                key = item.get("key")
                if isinstance(key, str) and key.strip():
                    names.add(key.strip())
    return sorted(names)


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


def _resolve_postman_url(value: str, spec_url: str) -> str:
    stripped = value.strip()
    if stripped.startswith(("http://", "https://")):
        return stripped
    if stripped.startswith("//"):
        return f"{urlsplit(spec_url).scheme}:{stripped}"
    first_segment = stripped.lstrip("/").split("/", 1)[0]
    if "." in first_segment and not stripped.startswith("/"):
        return f"{urlsplit(spec_url).scheme or 'https'}://{stripped}"
    return urljoin(spec_url, stripped)


def _resolve_url(base_url: str, raw_url: str) -> str:
    stripped = raw_url.strip()
    if stripped.startswith(("http://", "https://")):
        return stripped
    return urljoin(base_url, stripped)


def _join_url_path(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def _origin_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


def _ensure_leading_slash(value: str) -> str:
    stripped = value.strip()
    if not stripped:
        return "/"
    return stripped if stripped.startswith("/") else f"/{stripped}"


def _parameter_names(value: object) -> list[str]:
    names: set[str] = set()
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                name = item.get("name")
                if isinstance(name, str) and name.strip():
                    names.add(name.strip())
    return sorted(names)


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _optional_string(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _effective_scope_domains(spec_url: str, scope_domains: list[str] | None) -> list[str]:
    normalized = _normalize_scope_domains(scope_domains or [])
    if normalized:
        return normalized
    sanitized = _sanitize_url(spec_url)
    if sanitized is None:
        raise ValueError("spec URL must be absolute http(s)")
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
    candidate = value.strip().lower().removeprefix("*.")
    if not candidate or "{" in candidate or "{{" in candidate:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _dedupe_endpoints(endpoints: list[ApiSpecEndpoint]) -> list[ApiSpecEndpoint]:
    by_key = {(endpoint.method, endpoint.url): endpoint for endpoint in endpoints}
    return sorted(by_key.values(), key=lambda endpoint: (endpoint.url, endpoint.method))


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
