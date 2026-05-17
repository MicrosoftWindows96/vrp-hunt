"""Offline ASN and owned netblock expansion."""

from __future__ import annotations

import json
from collections import defaultdict
from ipaddress import ip_network
from pathlib import Path

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon.models import Asset


class AsnNetblockRecord(StrictModel):
    asn: int = Field(gt=0)
    organization: str = Field(min_length=1)
    cidr: str = Field(min_length=1)
    source: str = Field(min_length=1)
    confidence: float = Field(default=0.8, ge=0, le=1)
    notes: str = Field(default="", max_length=1000)

    @field_validator("asn", mode="before")
    @classmethod
    def parse_asn(cls, value: object) -> object:
        if isinstance(value, str):
            return int(value.strip().upper().removeprefix("AS"))
        return value

    @field_validator("organization", "source")
    @classmethod
    def strip_required_strings(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("value cannot be blank")
        return stripped

    @field_validator("cidr")
    @classmethod
    def normalize_cidr(cls, value: str) -> str:
        return str(ip_network(value.strip(), strict=False))


class AsnNetblockSummary(StrictModel):
    asn: int = Field(gt=0)
    organization: str = Field(min_length=1)
    netblock_count: int = Field(ge=0)
    ipv4_count: int = Field(ge=0)
    ipv6_count: int = Field(ge=0)
    total_addresses: int = Field(ge=0)


class AsnNetblockReport(StrictModel):
    total_asns: int = Field(ge=0)
    total_netblocks: int = Field(ge=0)
    records: list[AsnNetblockRecord] = Field(default_factory=list)
    summaries: list[AsnNetblockSummary] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def build_asn_netblock_report(records: list[AsnNetblockRecord]) -> AsnNetblockReport:
    deduped = _dedupe_records(records)
    summaries = _summaries(deduped)
    return AsnNetblockReport(
        total_asns=len(summaries),
        total_netblocks=len(deduped),
        records=deduped,
        summaries=summaries,
    )


def asn_netblock_assets(report: AsnNetblockReport) -> list[Asset]:
    assets: list[Asset] = []
    for record in report.records:
        network = ip_network(record.cidr)
        assets.append(
            Asset(
                kind="note",
                value=f"asn-netblock:AS{record.asn}:{record.cidr}",
                source="asn-netblock-import",
                metadata={
                    "asn": f"AS{record.asn}",
                    "organization": record.organization,
                    "cidr": record.cidr,
                    "ip_version": str(network.version),
                    "prefixlen": str(network.prefixlen),
                    "confidence": f"{record.confidence:.2f}",
                    "record_source": record.source,
                },
            )
        )
    return assets


def asn_netblock_record_from_spec(spec: str, *, source: str = "cli") -> AsnNetblockRecord:
    left, separator, cidr = spec.partition("=")
    if not separator or not left.strip() or not cidr.strip():
        raise ValueError(f"invalid netblock spec: {spec!r}; expected ASNNN:ORG=CIDR")
    asn, org_separator, organization = left.partition(":")
    if not org_separator or not asn.strip() or not organization.strip():
        raise ValueError(f"invalid netblock spec: {spec!r}; expected ASNNN:ORG=CIDR")
    return AsnNetblockRecord.model_validate(
        {
            "asn": asn,
            "organization": organization,
            "cidr": cidr,
            "source": source,
        }
    )


def load_asn_netblock_records(path: Path) -> tuple[list[AsnNetblockRecord], list[str]]:
    warnings: list[str] = []
    parsed = json.loads(path.read_text(encoding="utf-8"))
    raw_records = _raw_records(parsed)
    records: list[AsnNetblockRecord] = []
    for index, raw_record in enumerate(raw_records, start=1):
        try:
            records.append(AsnNetblockRecord.model_validate(raw_record))
        except ValueError as exc:
            warnings.append(f"{path}:{index}: {exc}")
    return records, warnings


def _raw_records(parsed: object) -> list[object]:
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        records = parsed.get("records") or parsed.get("netblocks") or parsed.get("prefixes")
        if isinstance(records, list):
            return records
    raise ValueError("ASN netblock input must be a list or object with records/netblocks/prefixes")


def _dedupe_records(records: list[AsnNetblockRecord]) -> list[AsnNetblockRecord]:
    by_key: dict[tuple[int, str], AsnNetblockRecord] = {}
    for record in records:
        key = (record.asn, record.cidr)
        existing = by_key.get(key)
        if existing is None or record.confidence > existing.confidence:
            by_key[key] = record
    return sorted(by_key.values(), key=_record_sort_key)


def _record_sort_key(record: AsnNetblockRecord) -> tuple[int, int, int, int]:
    network = ip_network(record.cidr)
    return (record.asn, network.version, int(network.network_address), network.prefixlen)


def _summaries(records: list[AsnNetblockRecord]) -> list[AsnNetblockSummary]:
    grouped: dict[int, list[AsnNetblockRecord]] = defaultdict(list)
    for record in records:
        grouped[record.asn].append(record)
    summaries: list[AsnNetblockSummary] = []
    for asn, asn_records in sorted(grouped.items()):
        networks = [ip_network(record.cidr) for record in asn_records]
        summaries.append(
            AsnNetblockSummary(
                asn=asn,
                organization=asn_records[0].organization,
                netblock_count=len(asn_records),
                ipv4_count=sum(1 for network in networks if network.version == 4),
                ipv6_count=sum(1 for network in networks if network.version == 6),
                total_addresses=sum(network.num_addresses for network in networks),
            )
        )
    return summaries
