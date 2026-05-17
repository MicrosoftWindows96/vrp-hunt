"""Offline CDN and WAF fingerprinting from saved recon metadata."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon.dns_records import DnsRecord
from vrp_hunt.recon.models import Asset

CdnWafCategory = Literal["cdn", "waf", "cdn_waf", "edge"]
CdnWafSignalSource = Literal["http_metadata", "technology", "dns"]


@dataclass(frozen=True)
class _ProviderPattern:
    provider: str
    category: CdnWafCategory
    confidence: float
    terms: tuple[str, ...]
    reason: str


class CdnWafSignal(StrictModel):
    provider: str = Field(min_length=1)
    category: CdnWafCategory
    confidence: float = Field(ge=0, le=1)
    source: CdnWafSignalSource
    key: str = Field(min_length=1)
    value: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class CdnWafFingerprint(StrictModel):
    target: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    category: CdnWafCategory
    confidence: float = Field(ge=0, le=1)
    signals: list[CdnWafSignal] = Field(min_length=1)


class CdnWafFingerprintReport(StrictModel):
    total_targets: int = Field(ge=0)
    fingerprints: list[CdnWafFingerprint] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


HTTP_PATTERNS: tuple[_ProviderPattern, ...] = (
    _ProviderPattern("Cloudflare", "cdn_waf", 0.96, ("cf-ray", "cf-cache-status", "server=cloudflare", "cloudflare"), "Cloudflare HTTP header or server marker"),
    _ProviderPattern("Akamai", "cdn_waf", 0.9, ("akamai", "akamaighost", "x-akamai", "akamai-grn"), "Akamai HTTP or server marker"),
    _ProviderPattern("Fastly", "cdn", 0.9, ("fastly", "x-served-by", "x-cache-hits", "x-timer"), "Fastly HTTP cache marker"),
    _ProviderPattern("Amazon CloudFront", "cdn", 0.9, ("cloudfront", "x-amz-cf-id", "x-amz-cf-pop"), "CloudFront HTTP marker"),
    _ProviderPattern("Azure Front Door", "cdn_waf", 0.9, ("azurefrontdoor", "azurefd", "azureedge", "x-azure-ref"), "Azure edge HTTP marker"),
    _ProviderPattern("Imperva", "waf", 0.92, ("imperva", "incapsula", "x-iinfo", "visid_incap"), "Imperva or Incapsula WAF marker"),
    _ProviderPattern("F5 BIG-IP", "waf", 0.82, ("bigip", "big-ip", "f5"), "F5 BIG-IP marker"),
    _ProviderPattern("Google Front End", "edge", 0.82, ("google frontend", "google front end", "server=gfe", "server=gws", "gfe"), "Google edge server marker"),
)

DNS_PATTERNS: tuple[_ProviderPattern, ...] = (
    _ProviderPattern("Cloudflare", "cdn_waf", 0.9, ("cloudflare.net",), "Cloudflare CNAME target"),
    _ProviderPattern("Akamai", "cdn_waf", 0.86, ("akamai", "akadns.net", "edgesuite.net", "edgekey.net"), "Akamai DNS target"),
    _ProviderPattern("Fastly", "cdn", 0.86, ("fastly.net", "fastlylb.net"), "Fastly DNS target"),
    _ProviderPattern("Amazon CloudFront", "cdn", 0.88, ("cloudfront.net",), "CloudFront DNS target"),
    _ProviderPattern("Azure Front Door", "cdn_waf", 0.86, ("azurefd.net", "azureedge.net"), "Azure edge DNS target"),
    _ProviderPattern("Imperva", "waf", 0.88, ("impervadns.net", "incapdns.net"), "Imperva DNS target"),
    _ProviderPattern("Google Front End", "edge", 0.8, ("googlehosted.com", "ghs.google.com"), "Google edge DNS target"),
)


def fingerprint_cdn_waf(
    assets: list[Asset],
    *,
    dns_records: list[DnsRecord] | None = None,
) -> CdnWafFingerprintReport:
    signals_by_target_provider: dict[tuple[str, str], list[CdnWafSignal]] = defaultdict(list)
    warnings: list[str] = []
    targets: set[str] = set()

    for asset in assets:
        target = _asset_target(asset)
        if target is None:
            warnings.append(f"skipped {asset.kind} asset without hostname target: {asset.value}")
            continue
        targets.add(target)
        for signal in _signals_from_asset(asset):
            signals_by_target_provider[(target, signal.provider)].append(signal)

    for record in dns_records or []:
        targets.add(record.name)
        for signal in _signals_from_dns_record(record):
            signals_by_target_provider[(record.name, signal.provider)].append(signal)

    fingerprints = [
        _fingerprint_from_signals(target, provider, signals)
        for (target, provider), signals in signals_by_target_provider.items()
    ]
    fingerprints.sort(key=lambda item: (item.confidence, item.target, item.provider), reverse=True)
    return CdnWafFingerprintReport(
        total_targets=len(targets),
        fingerprints=fingerprints,
        warnings=warnings,
    )


def cdn_waf_fingerprint_assets(report: CdnWafFingerprintReport) -> list[Asset]:
    assets: list[Asset] = []
    for fingerprint in report.fingerprints:
        assets.append(
            Asset(
                kind="technology",
                value=fingerprint.provider,
                source="cdn-waf-fingerprint",
                parent=fingerprint.target,
                metadata={
                    "category": fingerprint.category,
                    "confidence": f"{fingerprint.confidence:.2f}",
                    "signal_count": str(len(fingerprint.signals)),
                },
            )
        )
    return assets


def _signals_from_asset(asset: Asset) -> list[CdnWafSignal]:
    source: CdnWafSignalSource = "technology" if asset.kind == "technology" else "http_metadata"
    signal_values = _asset_signal_values(asset)
    signals: list[CdnWafSignal] = []
    for key, value in signal_values:
        patterns = DNS_PATTERNS if key in {"cname", "cname_target"} else HTTP_PATTERNS
        signals.extend(
            _signals_for_text(
                key=key,
                value=value,
                patterns=patterns,
                source=source,
            )
        )
    return signals


def _signals_from_dns_record(record: DnsRecord) -> list[CdnWafSignal]:
    if record.record_type != "CNAME":
        return []
    return _signals_for_text(
        key="cname",
        value=record.value,
        patterns=DNS_PATTERNS,
        source="dns",
    )


def _signals_for_text(
    *,
    key: str,
    value: str,
    patterns: tuple[_ProviderPattern, ...],
    source: CdnWafSignalSource,
) -> list[CdnWafSignal]:
    searchable = f"{key}={value}".lower()
    signals: list[CdnWafSignal] = []
    for pattern in patterns:
        if any(term in searchable for term in pattern.terms):
            signals.append(
                CdnWafSignal(
                    provider=pattern.provider,
                    category=pattern.category,
                    confidence=pattern.confidence,
                    source=source,
                    key=key,
                    value=value,
                    reason=pattern.reason,
                )
            )
    return signals


def _fingerprint_from_signals(
    target: str,
    provider: str,
    signals: list[CdnWafSignal],
) -> CdnWafFingerprint:
    confidence = min(max(signal.confidence for signal in signals) + (0.03 * (len(signals) - 1)), 0.99)
    category = _combined_category(signals)
    signals.sort(key=lambda signal: (signal.confidence, signal.key), reverse=True)
    return CdnWafFingerprint(
        target=target,
        provider=provider,
        category=category,
        confidence=confidence,
        signals=signals,
    )


def _combined_category(signals: list[CdnWafSignal]) -> CdnWafCategory:
    categories = {signal.category for signal in signals}
    if "cdn_waf" in categories or {"cdn", "waf"}.issubset(categories):
        return "cdn_waf"
    if "waf" in categories:
        return "waf"
    if "cdn" in categories:
        return "cdn"
    return "edge"


def _asset_target(asset: Asset) -> str | None:
    if asset.kind == "host":
        return _host_from_value(asset.value)
    if asset.kind in {"url", "endpoint", "javascript"}:
        return _host_from_value(asset.value)
    if asset.parent:
        return _host_from_value(asset.parent)
    return None


def _asset_signal_values(asset: Asset) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    if asset.kind == "technology":
        values.append(("technology", asset.value))
    for key, value in asset.metadata.items():
        if value:
            values.append((key.lower(), value))
    return values


def _host_from_value(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None
    if "://" in candidate:
        return urlsplit(candidate).hostname
    if "/" in candidate or " " in candidate:
        return None
    return candidate.rstrip(".")
