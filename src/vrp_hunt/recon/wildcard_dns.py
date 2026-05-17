"""Offline wildcard DNS detection and asset elimination."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon.models import Asset


class WildcardDnsProbe(StrictModel):
    probe_host: str = Field(min_length=1)
    domain: str = Field(min_length=1)
    addresses: list[str] = Field(min_length=1)

    @field_validator("probe_host", "domain")
    @classmethod
    def normalize_host(cls, value: str) -> str:
        return value.strip().lower().rstrip(".")

    @field_validator("addresses")
    @classmethod
    def normalize_addresses(cls, value: list[str]) -> list[str]:
        normalized = sorted({item.strip().lower() for item in value if item.strip()})
        if not normalized:
            raise ValueError("wildcard DNS probe addresses cannot be empty")
        return normalized


class WildcardDnsPattern(StrictModel):
    domain: str = Field(min_length=1)
    addresses: list[str] = Field(min_length=1)
    probe_hosts: list[str] = Field(min_length=1)


class WildcardDnsAssetDecision(StrictModel):
    asset: Asset
    eliminated: bool
    reason: str = Field(min_length=1)
    matched_domain: str | None = None


class WildcardDnsFilterReport(StrictModel):
    total_assets: int = Field(ge=0)
    kept_assets: list[Asset] = Field(default_factory=list)
    eliminated_assets: list[Asset] = Field(default_factory=list)
    patterns: list[WildcardDnsPattern] = Field(default_factory=list)
    decisions: list[WildcardDnsAssetDecision] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def filter_wildcard_dns_assets(
    assets: list[Asset],
    probes: list[WildcardDnsProbe],
    *,
    min_probes: int = 2,
) -> WildcardDnsFilterReport:
    if min_probes < 1:
        raise ValueError("min_probes must be at least 1")
    patterns, warnings = detect_wildcard_dns_patterns(probes, min_probes=min_probes)
    decisions = [
        _asset_decision(asset, patterns)
        for asset in assets
    ]
    kept_assets = [decision.asset for decision in decisions if not decision.eliminated]
    eliminated_assets = [decision.asset for decision in decisions if decision.eliminated]
    return WildcardDnsFilterReport(
        total_assets=len(assets),
        kept_assets=kept_assets,
        eliminated_assets=eliminated_assets,
        patterns=patterns,
        decisions=decisions,
        warnings=warnings,
    )


def detect_wildcard_dns_patterns(
    probes: list[WildcardDnsProbe],
    *,
    min_probes: int = 2,
) -> tuple[list[WildcardDnsPattern], list[str]]:
    if min_probes < 1:
        raise ValueError("min_probes must be at least 1")
    grouped: dict[tuple[str, tuple[str, ...]], list[WildcardDnsProbe]] = defaultdict(list)
    for probe in probes:
        grouped[(probe.domain, tuple(probe.addresses))].append(probe)

    patterns: list[WildcardDnsPattern] = []
    warnings: list[str] = []
    for (domain, addresses), matching_probes in sorted(grouped.items()):
        if len(matching_probes) < min_probes:
            warnings.append(
                f"{domain}: only {len(matching_probes)} matching wildcard probe(s); "
                f"need {min_probes}"
            )
            continue
        patterns.append(
            WildcardDnsPattern(
                domain=domain,
                addresses=list(addresses),
                probe_hosts=sorted(probe.probe_host for probe in matching_probes),
            )
        )
    return patterns, warnings


def wildcard_probe_from_spec(spec: str) -> WildcardDnsProbe:
    host, separator, addresses_text = spec.partition("=")
    if not separator or not host.strip() or not addresses_text.strip():
        raise ValueError(f"invalid wildcard probe spec: {spec!r}; expected HOST=ADDR[,ADDR]")
    normalized_host = host.strip().lower().rstrip(".")
    domain = ".".join(normalized_host.split(".")[1:])
    if not domain:
        raise ValueError(f"invalid wildcard probe host: {host!r}")
    addresses = [item.strip() for item in addresses_text.replace(";", ",").split(",")]
    return WildcardDnsProbe(probe_host=normalized_host, domain=domain, addresses=addresses)


def wildcard_probe_from_asset(asset: Asset) -> WildcardDnsProbe | None:
    if asset.kind != "host":
        return None
    addresses = _asset_addresses(asset)
    if not addresses:
        return None
    domain = asset.metadata.get("wildcard_domain") or ".".join(asset.value.split(".")[1:])
    if not domain:
        return None
    return WildcardDnsProbe(probe_host=asset.value, domain=domain, addresses=addresses)


def _asset_decision(asset: Asset, patterns: list[WildcardDnsPattern]) -> WildcardDnsAssetDecision:
    host = _asset_host(asset)
    if host is None:
        return WildcardDnsAssetDecision(
            asset=asset,
            eliminated=False,
            reason="asset has no hostname",
        )
    addresses = _asset_addresses(asset)
    if not addresses:
        return WildcardDnsAssetDecision(
            asset=asset,
            eliminated=False,
            reason="asset has no DNS address metadata",
        )
    address_tuple = tuple(addresses)
    for pattern in patterns:
        if host == pattern.domain:
            continue
        if host.endswith(f".{pattern.domain}") and address_tuple == tuple(pattern.addresses):
            return WildcardDnsAssetDecision(
                asset=asset,
                eliminated=True,
                reason="host address set matched confirmed wildcard DNS probe set",
                matched_domain=pattern.domain,
            )
    return WildcardDnsAssetDecision(
        asset=asset,
        eliminated=False,
        reason="host did not match a confirmed wildcard DNS pattern",
    )


def _asset_host(asset: Asset) -> str | None:
    if asset.kind == "host":
        return asset.value.strip().lower().rstrip(".")
    if asset.kind in {"url", "endpoint", "javascript"}:
        return urlsplit(asset.value).hostname
    if asset.parent and "://" in asset.parent:
        return urlsplit(asset.parent).hostname
    return None


def _asset_addresses(asset: Asset) -> list[str]:
    values: list[str] = []
    for key in ("addresses", "a_records", "aaaa_records", "ips", "ip"):
        raw_value = asset.metadata.get(key)
        if raw_value:
            values.extend(raw_value.replace(";", ",").split(","))
    return sorted({value.strip().lower() for value in values if value.strip()})
