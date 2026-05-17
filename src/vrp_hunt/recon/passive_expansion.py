"""Offline reverse-IP and certificate-transparency expansion."""

from __future__ import annotations

import json
from collections import defaultdict
from ipaddress import ip_address
from pathlib import Path
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

PassiveExpansionSource = Literal["reverse_ip", "certificate_transparency"]


class _RecordParser(Protocol):
    def __call__(
        self,
        text: str,
        *,
        source: str,
        scope_domains: list[str],
    ) -> tuple[list["PassiveExpansionRecord"], list[str], int]: ...


class PassiveExpansionRecord(StrictModel):
    host: str = Field(min_length=1)
    source: PassiveExpansionSource
    parent: str = Field(min_length=1)
    scope_domain: str = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    evidence: str = Field(min_length=1)


class PassiveExpansionReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    total_records: int = Field(ge=0)
    total_assets: int = Field(ge=0)
    records: list[PassiveExpansionRecord] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def build_passive_expansion_report(
    records: list[PassiveExpansionRecord],
    *,
    scope_domains: list[str],
    total_inputs: int = 0,
    warnings: list[str] | None = None,
) -> PassiveExpansionReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    scoped_records = [
        record for record in records if record.scope_domain in normalized_scope
    ]
    deduped_records = _dedupe_records(scoped_records)
    assets = passive_expansion_assets(deduped_records)
    return PassiveExpansionReport(
        scope_domains=normalized_scope,
        total_inputs=total_inputs,
        total_records=len(deduped_records),
        total_assets=len(assets),
        records=deduped_records,
        assets=assets,
        warnings=warnings or [],
    )


def passive_expansion_assets(records: list[PassiveExpansionRecord]) -> list[Asset]:
    grouped: dict[str, list[PassiveExpansionRecord]] = defaultdict(list)
    for record in records:
        grouped[record.host].append(record)

    assets: list[Asset] = []
    for host, host_records in sorted(grouped.items()):
        sources = sorted({record.source for record in host_records})
        parents = sorted({record.parent for record in host_records})
        scope_domains = sorted({record.scope_domain for record in host_records})
        confidence = max(record.confidence for record in host_records)
        assets.append(
            Asset(
                kind="host",
                value=host,
                source="passive-expansion",
                metadata={
                    "expansion_sources": ",".join(sources),
                    "parents": ",".join(parents[:10]),
                    "scope_domains": ",".join(scope_domains),
                    "confidence": f"{confidence:.2f}",
                    "record_count": str(len(host_records)),
                },
            )
        )
    return assets


def load_reverse_ip_records(
    path: Path,
    *,
    scope_domains: list[str],
) -> tuple[list[PassiveExpansionRecord], list[str], int]:
    return _load_records(
        path,
        scope_domains=scope_domains,
        parser=_records_from_reverse_ip_text,
    )


def load_certificate_transparency_records(
    path: Path,
    *,
    scope_domains: list[str],
) -> tuple[list[PassiveExpansionRecord], list[str], int]:
    return _load_records(
        path,
        scope_domains=scope_domains,
        parser=_records_from_ct_text,
    )


def build_reverse_ct_expansion_report(
    *,
    reverse_ip_files: list[Path],
    certificate_transparency_files: list[Path],
    scope_domains: list[str],
) -> PassiveExpansionReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    records: list[PassiveExpansionRecord] = []
    warnings: list[str] = []
    total_inputs = 0
    for path in reverse_ip_files:
        loaded, load_warnings, input_count = load_reverse_ip_records(
            path,
            scope_domains=normalized_scope,
        )
        records.extend(loaded)
        warnings.extend(load_warnings)
        total_inputs += input_count
    for path in certificate_transparency_files:
        loaded, load_warnings, input_count = load_certificate_transparency_records(
            path,
            scope_domains=normalized_scope,
        )
        records.extend(loaded)
        warnings.extend(load_warnings)
        total_inputs += input_count
    return build_passive_expansion_report(
        records,
        scope_domains=normalized_scope,
        total_inputs=total_inputs,
        warnings=warnings,
    )


def _load_records(
    path: Path,
    *,
    scope_domains: list[str],
    parser: _RecordParser,
) -> tuple[list[PassiveExpansionRecord], list[str], int]:
    try:
        return parser(path.read_text(encoding="utf-8"), source=str(path), scope_domains=scope_domains)
    except OSError:
        raise
    except ValueError as exc:
        return [], [f"{path}: {exc}"], 0


def _records_from_reverse_ip_text(
    text: str,
    *,
    source: str,
    scope_domains: list[str],
) -> tuple[list[PassiveExpansionRecord], list[str], int]:
    raw_items = _json_items(text)
    if raw_items is None:
        raw_items = _reverse_ip_items_from_lines(text)
    records: list[PassiveExpansionRecord] = []
    warnings: list[str] = []
    for index, item in enumerate(raw_items, start=1):
        try:
            parent, hosts = _reverse_ip_parent_hosts(item)
        except ValueError as exc:
            warnings.append(f"{source}:{index}: {exc}")
            continue
        records.extend(
            _records_from_hosts(
                hosts,
                parent=parent,
                source_type="reverse_ip",
                evidence=source,
                confidence=0.65,
                scope_domains=scope_domains,
                warning_prefix=f"{source}:{index}",
                warnings=warnings,
            )
        )
    return records, warnings, len(raw_items)


def _records_from_ct_text(
    text: str,
    *,
    source: str,
    scope_domains: list[str],
) -> tuple[list[PassiveExpansionRecord], list[str], int]:
    raw_items = _json_items(text)
    if raw_items is None:
        raw_items = [{"name_value": line.strip()} for line in text.splitlines() if line.strip()]
    records: list[PassiveExpansionRecord] = []
    warnings: list[str] = []
    for index, item in enumerate(raw_items, start=1):
        hosts = _ct_hosts(item)
        records.extend(
            _records_from_hosts(
                hosts,
                parent="certificate-transparency",
                source_type="certificate_transparency",
                evidence=source,
                confidence=0.75,
                scope_domains=scope_domains,
                warning_prefix=f"{source}:{index}",
                warnings=warnings,
            )
        )
    return records, warnings, len(raw_items)


def _records_from_hosts(
    hosts: list[str],
    *,
    parent: str,
    source_type: PassiveExpansionSource,
    evidence: str,
    confidence: float,
    scope_domains: list[str],
    warning_prefix: str,
    warnings: list[str],
) -> list[PassiveExpansionRecord]:
    records: list[PassiveExpansionRecord] = []
    for raw_host in hosts:
        candidate = _coarse_hostname(raw_host)
        if candidate is None:
            warnings.append(f"{warning_prefix}: skipped invalid host {raw_host!r}")
            continue
        scope_domain = _matching_scope_domain(candidate, scope_domains)
        if scope_domain is None:
            continue
        host = _normalize_hostname(candidate)
        if host is None:
            warnings.append(f"{warning_prefix}: skipped invalid host {raw_host!r}")
            continue
        records.append(
            PassiveExpansionRecord(
                host=host,
                source=source_type,
                parent=parent,
                scope_domain=scope_domain,
                confidence=confidence,
                evidence=evidence,
            )
        )
    return records


def _json_items(text: str) -> list[object] | None:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        items: list[object] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                return None
        return items
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("records", "results", "data", "items"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    return None


def _reverse_ip_items_from_lines(text: str) -> list[object]:
    items: list[object] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parent, _, hosts_text = stripped.partition(" ")
        hosts = [item.strip() for item in hosts_text.replace(",", " ").split() if item.strip()]
        items.append({"ip": parent, "hosts": hosts})
    return items


def _reverse_ip_parent_hosts(item: object) -> tuple[str, list[str]]:
    if isinstance(item, dict):
        parent = _first_string(item, ("ip", "address", "query", "parent"))
        if parent is None:
            raise ValueError("reverse IP record is missing ip/address/query")
        try:
            ip_address(parent)
        except ValueError as exc:
            raise ValueError(f"reverse IP parent is not an IP address: {parent}") from exc
        hosts = _host_list(item, ("hosts", "hostnames", "domains", "names", "results"))
        single_host = _first_string(item, ("host", "hostname", "domain", "name"))
        if single_host is not None:
            hosts.append(single_host)
        if not hosts:
            raise ValueError("reverse IP record has no hosts")
        return parent, hosts
    raise ValueError("reverse IP record must be an object")


def _ct_hosts(item: object) -> list[str]:
    if isinstance(item, str):
        return [item]
    if not isinstance(item, dict):
        return []
    hosts = _host_list(item, ("dns_names", "names", "hosts", "hostnames", "domains"))
    for key in ("name_value", "common_name", "host", "hostname", "domain", "name"):
        value = item.get(key)
        if isinstance(value, str):
            hosts.extend(value.splitlines())
    return hosts


def _host_list(mapping: dict[object, object], keys: tuple[str, ...]) -> list[str]:
    hosts: list[str] = []
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, list):
            hosts.extend(str(item) for item in value)
        elif isinstance(value, str):
            hosts.extend(value.splitlines())
    return hosts


def _first_string(mapping: dict[object, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _normalize_hostname(value: str) -> str | None:
    candidate = _coarse_hostname(value)
    if candidate is None:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None


def _coarse_hostname(value: str) -> str | None:
    candidate = value.strip().lower().removeprefix("*.").rstrip(".")
    if not candidate:
        return None
    if "://" in candidate:
        candidate = urlsplit(candidate).hostname or ""
    if not candidate or "/" in candidate or " " in candidate or "@" in candidate:
        return None
    return candidate


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for domain in scope_domains:
        host = _normalize_hostname(domain)
        if host is None:
            raise ValueError(f"invalid scope domain: {domain!r}")
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    if not normalized:
        raise ValueError("at least one scope domain is required")
    return normalized


def _matching_scope_domain(host: str, scope_domains: list[str]) -> str | None:
    for domain in scope_domains:
        if host == domain or host.endswith(f".{domain}"):
            return domain
    return None


def _dedupe_records(records: list[PassiveExpansionRecord]) -> list[PassiveExpansionRecord]:
    by_key: dict[tuple[str, PassiveExpansionSource, str], PassiveExpansionRecord] = {}
    for record in records:
        key = (record.host, record.source, record.parent)
        existing = by_key.get(key)
        if existing is None or record.confidence > existing.confidence:
            by_key[key] = record
    return sorted(by_key.values(), key=lambda record: (record.host, record.source, record.parent))
