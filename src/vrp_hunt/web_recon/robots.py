"""Offline robots.txt parser."""

from __future__ import annotations

from typing import Literal, cast
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset

RobotsDirective = Literal["allow", "disallow"]


class RobotsRule(StrictModel):
    user_agents: list[str] = Field(default_factory=list)
    directive: RobotsDirective
    path: str = Field(min_length=1)
    parameter_names: list[str] = Field(default_factory=list)
    line_number: int = Field(ge=1)


class RobotsSitemap(StrictModel):
    url: str = Field(min_length=1)
    line_number: int = Field(ge=1)

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        normalized = _sanitize_url(value)
        if normalized is None:
            raise ValueError("sitemap URL must be absolute http(s)")
        return normalized


class RobotsCrawlDelay(StrictModel):
    user_agents: list[str] = Field(default_factory=list)
    delay_seconds: float = Field(ge=0)
    line_number: int = Field(ge=1)


class RobotsHostDirective(StrictModel):
    host: str = Field(min_length=1)
    line_number: int = Field(ge=1)


class RobotsParseReport(StrictModel):
    robots_url: str = Field(min_length=1)
    rules: list[RobotsRule] = Field(default_factory=list)
    sitemaps: list[RobotsSitemap] = Field(default_factory=list)
    crawl_delays: list[RobotsCrawlDelay] = Field(default_factory=list)
    host_directives: list[RobotsHostDirective] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("robots_url")
    @classmethod
    def normalize_robots_url(cls, value: str) -> str:
        normalized = _sanitize_url(value)
        if normalized is None:
            raise ValueError("robots URL must be absolute http(s)")
        return normalized


class RobotsImportBundle(StrictModel):
    report_count: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    reports: list[RobotsParseReport] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def parse_robots_txt(
    robots_url: str,
    text: str,
    *,
    scope_domains: list[str] | None = None,
) -> RobotsParseReport:
    normalized_url = RobotsParseReport(
        robots_url=robots_url,
        rules=[],
        sitemaps=[],
        crawl_delays=[],
        host_directives=[],
    ).robots_url
    normalized_scope = _effective_scope_domains(normalized_url, scope_domains)
    current_agents: list[str] = []
    group_has_directives = False
    rules: list[RobotsRule] = []
    sitemaps: list[RobotsSitemap] = []
    crawl_delays: list[RobotsCrawlDelay] = []
    host_directives: list[RobotsHostDirective] = []
    warnings: list[str] = []

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        key, separator, value = line.partition(":")
        if not separator:
            warnings.append(f"line {line_number}: ignored malformed directive")
            continue
        directive = key.strip().lower()
        argument = value.strip()
        if directive == "user-agent":
            if argument:
                if group_has_directives:
                    current_agents = []
                    group_has_directives = False
                current_agents.append(argument.lower())
            continue
        if directive in {"allow", "disallow"}:
            if not argument:
                continue
            redacted_path, parameter_names = _redact_rule_path(argument)
            rules.append(
                RobotsRule(
                    user_agents=current_agents or ["*"],
                    directive=cast(RobotsDirective, directive),
                    path=redacted_path,
                    parameter_names=parameter_names,
                    line_number=line_number,
                )
            )
            group_has_directives = True
            continue
        if directive == "sitemap":
            sitemap_url = argument if argument.startswith(("http://", "https://")) else urljoin(normalized_url, argument)
            try:
                sitemaps.append(RobotsSitemap(url=sitemap_url, line_number=line_number))
            except ValueError as exc:
                warnings.append(f"line {line_number}: {exc}")
            continue
        if directive == "crawl-delay":
            try:
                crawl_delays.append(
                    RobotsCrawlDelay(
                        user_agents=current_agents or ["*"],
                        delay_seconds=float(argument),
                        line_number=line_number,
                    )
                )
            except ValueError:
                warnings.append(f"line {line_number}: invalid crawl-delay")
            group_has_directives = True
            continue
        if directive == "host" and argument:
            host = urlsplit(argument if "://" in argument else f"//{argument}").hostname
            if host:
                host_directives.append(RobotsHostDirective(host=host.lower(), line_number=line_number))
            continue

    report = RobotsParseReport(
        robots_url=normalized_url,
        rules=rules,
        sitemaps=sitemaps,
        crawl_delays=crawl_delays,
        host_directives=host_directives,
        warnings=warnings,
    )
    assets, asset_warnings = _robots_assets_and_warnings(report, scope_domains=normalized_scope)
    return report.model_copy(update={"assets": assets, "warnings": sorted({*warnings, *asset_warnings})})


def build_robots_import_bundle(reports: list[RobotsParseReport]) -> RobotsImportBundle:
    assets = _dedupe_assets([asset for report in reports for asset in report.assets])
    warnings = sorted({warning for report in reports for warning in report.warnings})
    return RobotsImportBundle(
        report_count=len(reports),
        total_assets=len(assets),
        reports=reports,
        assets=assets,
        warnings=warnings,
    )


def robots_assets(report: RobotsParseReport, *, scope_domains: list[str] | None = None) -> list[Asset]:
    normalized_scope = _effective_scope_domains(report.robots_url, scope_domains)
    assets, _warnings = _robots_assets_and_warnings(report, scope_domains=normalized_scope)
    return assets


def _robots_assets_and_warnings(
    report: RobotsParseReport,
    *,
    scope_domains: list[str],
) -> tuple[list[Asset], list[str]]:
    assets: list[Asset] = []
    warnings: list[str] = []
    for rule in report.rules:
        url = _url_for_path(report.robots_url, rule.path)
        if url is None:
            continue
        if not _url_allowed(url, scope_domains):
            host = urlsplit(url).hostname
            if host:
                warnings.append(f"skipped third-party robots rule host {host}")
            continue
        assets.append(
            Asset(
                kind="endpoint",
                value=url,
                source="robots-txt",
                parent=report.robots_url,
                metadata=_metadata_for_rule(rule, report.robots_url),
            )
        )
    for sitemap in report.sitemaps:
        if not _url_allowed(sitemap.url, scope_domains):
            host = urlsplit(sitemap.url).hostname
            if host:
                warnings.append(f"skipped third-party sitemap host {host}")
            continue
        assets.append(
            Asset(
                kind="url",
                value=sitemap.url,
                source="robots-txt-sitemap",
                parent=report.robots_url,
                metadata={"line_number": str(sitemap.line_number)},
            )
        )
    for crawl_delay in report.crawl_delays:
        if _url_allowed(report.robots_url, scope_domains):
            assets.append(
                Asset(
                    kind="note",
                    value=f"robots-crawl-delay:{report.robots_url}",
                    source="robots-txt-crawl-delay",
                    parent=report.robots_url,
                    metadata={
                        "delay_seconds": str(crawl_delay.delay_seconds),
                        "user_agents": ",".join(crawl_delay.user_agents),
                        "line_number": str(crawl_delay.line_number),
                    },
                )
            )
    for host_directive in report.host_directives:
        if _host_allowed(host_directive.host, scope_domains):
            assets.append(
                Asset(
                    kind="host",
                    value=host_directive.host,
                    source="robots-txt-host",
                    parent=report.robots_url,
                    metadata={"line_number": str(host_directive.line_number)},
                )
            )
        else:
            warnings.append(f"skipped third-party host directive {host_directive.host}")
    return _dedupe_assets(assets), sorted(set(warnings))


def _metadata_for_rule(rule: RobotsRule, robots_url: str) -> dict[str, str]:
    metadata = {
        "directive": rule.directive,
        "user_agents": ",".join(rule.user_agents),
        "line_number": str(rule.line_number),
    }
    if rule.parameter_names:
        metadata["parameter_names"] = ",".join(rule.parameter_names)
        metadata["query_values_redacted"] = "true"
    return metadata


def _url_for_path(robots_url: str, path: str) -> str | None:
    if path == "/":
        return None
    if path.startswith(("http://", "https://")):
        return _sanitize_url(path)
    return _sanitize_url(urljoin(robots_url, path))


def _sanitize_url(value: str) -> str | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    path = parsed.path or "/"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return urlunsplit((parsed.scheme.lower(), f"{parsed.hostname.lower()}{port}", path, "", ""))


def _redact_rule_path(value: str) -> tuple[str, list[str]]:
    parsed = urlsplit(value.strip())
    parameter_names = _query_parameter_names(value)
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        port = f":{parsed.port}" if parsed.port is not None else ""
        host = f"{parsed.hostname.lower()}{port}"
        redacted = urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", "", ""))
    else:
        redacted = parsed.path or "/"
    return redacted, parameter_names


def _url_allowed(url: str, scope_domains: list[str]) -> bool:
    host = urlsplit(url).hostname
    return host is not None and _host_allowed(host, scope_domains)


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for domain in scope_domains:
        candidate = domain.strip().lower().rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        if not candidate:
            continue
        if candidate not in seen:
            seen.add(candidate)
            normalized.append(candidate)
    return normalized


def _effective_scope_domains(robots_url: str, scope_domains: list[str] | None) -> list[str]:
    normalized = _normalize_scope_domains(scope_domains or [])
    if normalized:
        return normalized
    host = urlsplit(robots_url).hostname
    return [host.lower().rstrip(".")] if host else []


def _query_parameter_names(url: str) -> list[str]:
    names = {name for name, _value in parse_qsl(urlsplit(url).query, keep_blank_values=True) if name}
    return sorted(names)


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
