"""Offline DNS record collection plans and parsers."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel

DnsRecordType = Literal["CNAME", "MX", "TXT", "NS", "CAA", "DMARC", "SPF"]
DigQueryType = Literal["CNAME", "MX", "TXT", "NS", "CAA"]


class DnsRecordQuery(StrictModel):
    name: str = Field(min_length=1)
    record_type: DigQueryType
    command: list[str] = Field(min_length=1)


class DnsRecordPlan(StrictModel):
    domain: str = Field(min_length=1)
    queries: list[DnsRecordQuery] = Field(min_length=1)


class DnsRecord(StrictModel):
    name: str = Field(min_length=1)
    record_type: DnsRecordType
    value: str = Field(min_length=1)
    source: str = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return _normalize_name(value)

    @field_validator("record_type", mode="before")
    @classmethod
    def normalize_record_type(cls, value: object) -> object:
        return value.upper() if isinstance(value, str) else value


class DnsRecordCollection(StrictModel):
    domain: str = Field(min_length=1)
    records: list[DnsRecord] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        return _normalize_name(value)


def build_dns_record_plan(domain: str) -> DnsRecordPlan:
    normalized_domain = _normalize_name(domain)
    queries = [
        _query(normalized_domain, "CNAME"),
        _query(normalized_domain, "MX"),
        _query(normalized_domain, "TXT"),
        _query(normalized_domain, "NS"),
        _query(normalized_domain, "CAA"),
        _query(f"_dmarc.{normalized_domain}", "TXT"),
    ]
    return DnsRecordPlan(domain=normalized_domain, queries=queries)


def parse_dig_records(
    name: str,
    record_type: DigQueryType,
    output: str,
    *,
    source: str = "dig",
) -> list[DnsRecord]:
    normalized_name = _normalize_name(name)
    normalized_type = record_type.upper()
    records: list[DnsRecord] = []
    for line in output.splitlines():
        value = _parse_dig_value(normalized_type, line)
        if value is None:
            continue
        records.append(
            DnsRecord(
                name=normalized_name,
                record_type=_semantic_record_type(normalized_name, normalized_type, value),
                value=value,
                source=source,
            )
        )
    return records


def import_dns_record_files(domain: str, specs: list[str]) -> DnsRecordCollection:
    records: list[DnsRecord] = []
    warnings: list[str] = []
    for spec in specs:
        try:
            name, record_type, path = _parse_record_file_spec(spec)
            records.extend(
                parse_dig_records(
                    name,
                    record_type,
                    path.read_text(encoding="utf-8"),
                    source=str(path),
                )
            )
        except (OSError, ValueError) as exc:
            warnings.append(f"{spec}: {exc}")
    return DnsRecordCollection(domain=domain, records=records, warnings=warnings)


def _query(name: str, record_type: DigQueryType) -> DnsRecordQuery:
    return DnsRecordQuery(
        name=name,
        record_type=record_type,
        command=["dig", "+short", record_type, name],
    )


def _parse_record_file_spec(spec: str) -> tuple[str, DigQueryType, Path]:
    name_and_type, separator, path_text = spec.partition("=")
    if not separator or not name_and_type.strip() or not path_text.strip():
        raise ValueError(f"invalid record spec: {spec!r}; expected NAME:TYPE=PATH")
    name, type_separator, record_type_text = name_and_type.rpartition(":")
    if not type_separator or not name.strip() or not record_type_text.strip():
        raise ValueError(f"invalid record spec: {spec!r}; expected NAME:TYPE=PATH")
    record_type = record_type_text.strip().upper()
    if record_type not in {"CNAME", "MX", "TXT", "NS", "CAA"}:
        raise ValueError(f"unsupported DNS record type: {record_type}")
    return name, cast(DigQueryType, record_type), Path(path_text).expanduser()


def _parse_dig_value(record_type: str, line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith(";"):
        return None
    if record_type == "TXT":
        tokens = shlex.split(stripped)
        value = "".join(tokens) if tokens else stripped.strip('"')
        return value.strip() or None
    if record_type == "CAA":
        tokens = shlex.split(stripped)
        value = " ".join(tokens) if tokens else stripped
        return _strip_trailing_dot(value)
    return _strip_trailing_dot(" ".join(stripped.split()))


def _semantic_record_type(name: str, record_type: str, value: str) -> DnsRecordType:
    lowered = value.lower()
    if record_type == "TXT" and name.startswith("_dmarc.") and "v=dmarc1" in lowered:
        return "DMARC"
    if record_type == "TXT" and "v=spf1" in lowered:
        return "SPF"
    return cast(DnsRecordType, record_type)


def _normalize_name(value: str) -> str:
    normalized = value.strip().lower().rstrip(".")
    if not normalized or "/" in normalized or " " in normalized:
        raise ValueError("DNS name must be a hostname")
    return normalized


def _strip_trailing_dot(value: str) -> str:
    return " ".join(part.rstrip(".") for part in value.split())
