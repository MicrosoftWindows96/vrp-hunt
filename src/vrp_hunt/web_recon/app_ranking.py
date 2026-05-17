"""Offline interesting-app ranking from recon assets."""

from __future__ import annotations

from collections import defaultdict
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

AppSignalCategory = Literal["auth", "api", "javascript", "cookie", "form", "technology", "change"]

AUTH_MARKERS = ("/login", "/signin", "/oauth", "/saml", "/account", "/session", "/admin", "authorize")
API_MARKERS = ("/api/", "/graphql", "/gql", "/v1/", "/v2/", "/v3/", "/rpc/")
COOKIE_KEYS = ("header:set-cookie", "set_cookie", "set-cookie", "cookie_names", "same_site", "samesite")
FORM_KEYS = ("form_count", "forms", "form_method", "csrf", "csrf_token", "method")


class AppSignal(StrictModel):
    category: AppSignalCategory
    weight: int = Field(ge=0)
    reason: str = Field(min_length=1)
    asset_kind: str = Field(min_length=1)
    asset_value: str = Field(min_length=1)


class RankedApp(StrictModel):
    app_id: str = Field(min_length=1)
    host: str = Field(min_length=1)
    base_url: str = Field(min_length=1)
    score: int = Field(ge=0)
    asset_count: int = Field(ge=0)
    technologies: list[str] = Field(default_factory=list)
    signal_categories: list[AppSignalCategory] = Field(default_factory=list)
    signals: list[AppSignal] = Field(default_factory=list)


class InterestingAppRankingReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_assets: int = Field(ge=0)
    total_apps: int = Field(ge=0)
    apps: list[RankedApp] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def rank_interesting_apps(
    assets: list[Asset],
    *,
    scope_domains: list[str],
    limit: int = 50,
) -> InterestingAppRankingReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    grouped: dict[str, list[Asset]] = defaultdict(list)
    warnings: list[str] = []
    for asset in assets:
        url = _url_for_asset(asset)
        if url is None:
            continue
        host = urlsplit(url).hostname or ""
        if not _host_allowed(host, normalized_scope):
            warnings.append(f"skipped third-party host {host}")
            continue
        grouped[_origin_url(url)].append(asset)

    ranked = [_rank_app(base_url, app_assets) for base_url, app_assets in grouped.items()]
    ranked.sort(key=lambda app: (-app.score, app.host, app.base_url))
    selected = ranked[: max(limit, 0)]
    output_assets = interesting_app_assets(selected)
    return InterestingAppRankingReport(
        scope_domains=normalized_scope,
        total_assets=len(assets),
        total_apps=len(selected),
        apps=selected,
        assets=output_assets,
        warnings=sorted(set(warnings)),
    )


def interesting_app_assets(apps: list[RankedApp]) -> list[Asset]:
    assets: list[Asset] = []
    for app in apps:
        assets.append(
            Asset(
                kind="note",
                value=f"interesting-app:{app.base_url}",
                source="interesting-app-rank",
                parent=app.base_url,
                metadata={
                    "score": str(app.score),
                    "host": app.host,
                    "asset_count": str(app.asset_count),
                    "signal_categories": ",".join(app.signal_categories),
                    "technologies": ",".join(app.technologies[:20]),
                },
            )
        )
    return _dedupe_assets(assets)


def _rank_app(base_url: str, assets: list[Asset]) -> RankedApp:
    signals: list[AppSignal] = []
    technologies: set[str] = set()
    for asset in assets:
        signals.extend(_signals_for_asset(asset))
        if asset.kind == "technology":
            technologies.add(asset.value)
    category_scores: dict[AppSignalCategory, int] = {}
    for signal in signals:
        category_scores[signal.category] = max(category_scores.get(signal.category, 0), signal.weight)
    score = min(100, sum(category_scores.values()) + min(len(assets), 10))
    selected_signals = sorted(signals, key=lambda signal: (-signal.weight, signal.category, signal.asset_value))[:20]
    parsed = urlsplit(base_url)
    host = parsed.hostname or base_url
    return RankedApp(
        app_id=host,
        host=host,
        base_url=base_url,
        score=score,
        asset_count=len(assets),
        technologies=sorted(technologies),
        signal_categories=sorted(category_scores),
        signals=selected_signals,
    )


def _signals_for_asset(asset: Asset) -> list[AppSignal]:
    signals: list[AppSignal] = []
    value = asset.value.lower()
    metadata_text = " ".join(f"{key}={item}" for key, item in asset.metadata.items()).lower()
    combined = f"{value} {metadata_text}"

    if any(marker in combined for marker in AUTH_MARKERS):
        signals.append(_signal("auth", 30, "auth or account path", asset))
    if asset.kind == "endpoint" and any(marker in value for marker in API_MARKERS):
        signals.append(_signal("api", 22, "API endpoint", asset))
    if asset.source in {"api-spec-import", "graphql-discover", "csp-extract"}:
        signals.append(_signal("api", 20, f"{asset.source} source", asset))
    if asset.kind == "javascript":
        signals.append(_signal("javascript", 12, "JavaScript asset", asset))
    if asset.kind == "technology":
        signals.append(_signal("technology", 10, "technology fingerprint", asset))
    if any(key in asset.metadata for key in COOKIE_KEYS) or "cookie" in metadata_text:
        signals.append(_signal("cookie", 14, "cookie metadata", asset))
    if any(key in asset.metadata for key in FORM_KEYS) or "form" in metadata_text:
        signals.append(_signal("form", 16, "form metadata", asset))
    if asset.source in {"screenshot-diff", "app-change-monitor"} or "screenshot-diff" in value or "app-change:" in value:
        signals.append(_signal("change", 8, "app or screenshot change", asset))
    return signals


def _signal(category: AppSignalCategory, weight: int, reason: str, asset: Asset) -> AppSignal:
    return AppSignal(
        category=category,
        weight=weight,
        reason=reason,
        asset_kind=asset.kind,
        asset_value=asset.value,
    )


def _url_for_asset(asset: Asset) -> str | None:
    for candidate in (asset.value, asset.parent):
        if not candidate:
            continue
        sanitized = _sanitize_url(candidate)
        if sanitized is not None:
            return sanitized
    return None


def _sanitize_url(value: str) -> str | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = _normalize_host(parsed.hostname)
    if host is None:
        return None
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", ""))


def _origin_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))


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


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
