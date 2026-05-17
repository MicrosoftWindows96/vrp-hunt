"""Offline host availability and dead-host suppression from saved probe metadata."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, model_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

HostProbeSource = Literal["httpx", "live_run", "generic"]
ProbeOutcome = Literal["success", "failure", "retryable", "unknown"]
HostAvailabilityStatus = Literal["alive", "backoff", "dead", "flaky", "unknown"]

RETRYABLE_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


class HostProbeDocument(StrictModel):
    source: HostProbeSource = "httpx"
    evidence: str = Field(min_length=1)
    text: str = ""


class DeadHostSuppressionConfig(StrictModel):
    min_failures: int = Field(default=2, ge=1)
    suppress_after_failures: int = Field(default=2, ge=1)
    retry_budget: int = Field(default=3, ge=0)
    backoff_base_seconds: float = Field(default=60.0, gt=0)
    backoff_cap_seconds: float = Field(default=3600.0, gt=0)

    @model_validator(mode="after")
    def cap_must_not_be_less_than_base(self) -> "DeadHostSuppressionConfig":
        if self.backoff_cap_seconds < self.backoff_base_seconds:
            raise ValueError("backoff cap must be >= base")
        return self


class HostProbeRecord(StrictModel):
    host: str = Field(min_length=1)
    url: str = Field(min_length=1)
    source: HostProbeSource
    evidence: str = Field(min_length=1)
    outcome: ProbeOutcome
    status_code: int | None = Field(default=None, ge=100, le=599)
    error: str | None = None
    retry_after_seconds: float | None = Field(default=None, ge=0)
    observed_at: str | None = None


class HostAvailability(StrictModel):
    host: str = Field(min_length=1)
    status: HostAvailabilityStatus
    success_count: int = Field(ge=0)
    failure_count: int = Field(ge=0)
    retryable_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    latest_outcome: ProbeOutcome
    failure_streak: int = Field(ge=0)
    suppressed: bool = False
    retry_allowed: bool = False
    next_retry_delay_seconds: float = Field(ge=0)
    reasons: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)


class DeadHostSuppressionReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    total_records: int = Field(ge=0)
    total_hosts: int = Field(ge=0)
    suppressed_hosts: list[str] = Field(default_factory=list)
    records: list[HostProbeRecord] = Field(default_factory=list)
    hosts: list[HostAvailability] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def analyze_host_availability(
    documents: list[HostProbeDocument],
    *,
    scope_domains: list[str],
    config: DeadHostSuppressionConfig | None = None,
) -> DeadHostSuppressionReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    active_config = config or DeadHostSuppressionConfig()
    records: list[HostProbeRecord] = []
    warnings: list[str] = []
    total_inputs = 0

    for document in documents:
        parsed_records, document_warnings, input_count = _records_from_document(document, normalized_scope)
        records.extend(parsed_records)
        warnings.extend(document_warnings)
        total_inputs += input_count

    hosts = [_availability_for_host(host, host_records, config=active_config) for host, host_records in _group_records(records)]
    suppressed_hosts = sorted(host.host for host in hosts if host.suppressed)
    assets = dead_host_suppression_assets(hosts)
    return DeadHostSuppressionReport(
        scope_domains=normalized_scope,
        total_inputs=total_inputs,
        total_records=len(records),
        total_hosts=len(hosts),
        suppressed_hosts=suppressed_hosts,
        records=records,
        hosts=hosts,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def load_host_probe_documents(
    *,
    httpx_files: list[Path] | None = None,
    live_run_files: list[Path] | None = None,
    live_run_dirs: list[Path] | None = None,
) -> list[HostProbeDocument]:
    documents: list[HostProbeDocument] = []
    for path in httpx_files or []:
        documents.append(HostProbeDocument(source="httpx", evidence=str(path), text=path.read_text(encoding="utf-8")))
    for path in live_run_files or []:
        documents.append(HostProbeDocument(source="live_run", evidence=str(path), text=path.read_text(encoding="utf-8")))
    for directory in live_run_dirs or []:
        for path in sorted(directory.glob("*.json")):
            documents.append(
                HostProbeDocument(source="live_run", evidence=str(path), text=path.read_text(encoding="utf-8"))
            )
    return documents


def dead_host_suppression_assets(hosts: list[HostAvailability]) -> list[Asset]:
    assets: list[Asset] = []
    for host in hosts:
        if not host.suppressed:
            continue
        assets.append(
            Asset(
                kind="note",
                value=f"dead-host:{host.host}",
                source="dead-host-suppress",
                parent=f"https://{host.host}/",
                metadata={
                    "status": host.status,
                    "failure_count": str(host.failure_count),
                    "failure_streak": str(host.failure_streak),
                    "retry_allowed": str(host.retry_allowed).lower(),
                    "next_retry_delay_seconds": f"{host.next_retry_delay_seconds:.0f}",
                    "reasons": ",".join(host.reasons),
                },
            )
        )
    return _dedupe_assets(assets)


def _records_from_document(
    document: HostProbeDocument,
    scope_domains: list[str],
) -> tuple[list[HostProbeRecord], list[str], int]:
    if document.source == "live_run":
        return _records_from_live_run(document, scope_domains)
    return _records_from_probe_items(document, scope_domains)


def _records_from_probe_items(
    document: HostProbeDocument,
    scope_domains: list[str],
) -> tuple[list[HostProbeRecord], list[str], int]:
    items = _items_from_text(document.text)
    records: list[HostProbeRecord] = []
    warnings: list[str] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, Mapping):
            warnings.append(f"{document.evidence}:{index}: skipped non-object record")
            continue
        record, warning = _probe_record_from_mapping(
            cast(Mapping[str, object], item),
            document=document,
            index=index,
            scope_domains=scope_domains,
        )
        if record is not None:
            records.append(record)
        if warning is not None:
            warnings.append(warning)
    return records, warnings, len(items)


def _records_from_live_run(
    document: HostProbeDocument,
    scope_domains: list[str],
) -> tuple[list[HostProbeRecord], list[str], int]:
    parsed = _json_mapping(document.text)
    observations = _mapping_list(parsed.get("observations"))
    records: list[HostProbeRecord] = []
    warnings: list[str] = []
    for index, observation in enumerate(observations, start=1):
        raw_url = _live_run_observation_url(parsed, observation)
        sanitized = _sanitize_url_or_host(raw_url or "")
        if sanitized is None:
            warnings.append(f"{document.evidence}:{index}: missing target host")
            continue
        if not _host_allowed(sanitized.host, scope_domains):
            warnings.append(f"{document.evidence}:{index}: skipped third-party host {sanitized.host}")
            continue
        records.append(
            HostProbeRecord(
                host=sanitized.host,
                url=sanitized.url,
                source=document.source,
                evidence=document.evidence,
                outcome=_live_run_outcome(observation),
                status_code=_status_code(observation.get("status_code")),
                error=_first_string(observation, ("error", "notes")),
                observed_at=_first_string(observation, ("observed_at", "timestamp", "time")),
            )
        )
    return records, warnings, len(observations)


def _probe_record_from_mapping(
    item: Mapping[str, object],
    *,
    document: HostProbeDocument,
    index: int,
    scope_domains: list[str],
) -> tuple[HostProbeRecord | None, str | None]:
    raw_url = _first_string(item, ("url", "final_url", "input", "target", "host"))
    if raw_url is None:
        return None, f"{document.evidence}:{index}: missing url"
    sanitized = _sanitize_url_or_host(raw_url)
    if sanitized is None:
        return None, f"{document.evidence}:{index}: invalid url"
    if not _host_allowed(sanitized.host, scope_domains):
        return None, f"{document.evidence}:{index}: skipped third-party host {sanitized.host}"
    headers = item.get("headers") or item.get("header")
    return (
        HostProbeRecord(
            host=sanitized.host,
            url=sanitized.url,
            source=document.source,
            evidence=document.evidence,
            outcome=_probe_outcome(item),
            status_code=_status_code(item.get("status_code") or item.get("status")),
            error=_first_string(item, ("error", "err", "failed_reason", "message")),
            retry_after_seconds=_retry_after_seconds(headers),
            observed_at=_first_string(item, ("observed_at", "timestamp", "captured_at", "time")),
        ),
        None,
    )


def _availability_for_host(
    host: str,
    records: list[HostProbeRecord],
    *,
    config: DeadHostSuppressionConfig,
) -> HostAvailability:
    success_count = sum(1 for record in records if record.outcome == "success")
    failure_count = sum(1 for record in records if record.outcome == "failure")
    retryable_count = sum(1 for record in records if record.outcome == "retryable")
    unknown_count = sum(1 for record in records if record.outcome == "unknown")
    latest = records[-1]
    failure_streak = _failure_streak(records)
    retry_after = latest.retry_after_seconds if latest.outcome == "retryable" else None
    next_retry_delay = _next_retry_delay(failure_streak, retry_after=retry_after, config=config)
    suppressed = (
        latest.outcome == "failure"
        and failure_count >= config.min_failures
        and failure_streak >= config.suppress_after_failures
    )
    retry_allowed = failure_streak > 0 and failure_streak <= config.retry_budget and not suppressed
    status = _host_status(latest.outcome, success_count=success_count, suppressed=suppressed)
    reasons = _availability_reasons(
        latest,
        failure_count=failure_count,
        failure_streak=failure_streak,
        suppressed=suppressed,
        retryable_count=retryable_count,
    )
    urls = sorted({record.url for record in records})
    return HostAvailability(
        host=host,
        status=status,
        success_count=success_count,
        failure_count=failure_count,
        retryable_count=retryable_count,
        unknown_count=unknown_count,
        latest_outcome=latest.outcome,
        failure_streak=failure_streak,
        suppressed=suppressed,
        retry_allowed=retry_allowed,
        next_retry_delay_seconds=next_retry_delay,
        reasons=reasons,
        urls=urls,
    )


def _host_status(
    latest_outcome: ProbeOutcome,
    *,
    success_count: int,
    suppressed: bool,
) -> HostAvailabilityStatus:
    if latest_outcome == "success":
        return "alive"
    if latest_outcome == "retryable":
        return "backoff"
    if suppressed and success_count == 0:
        return "dead"
    if latest_outcome == "failure" and success_count > 0:
        return "flaky"
    return "unknown"


def _availability_reasons(
    latest: HostProbeRecord,
    *,
    failure_count: int,
    failure_streak: int,
    suppressed: bool,
    retryable_count: int,
) -> list[str]:
    reasons = [f"latest:{latest.outcome}"]
    if latest.status_code is not None:
        reasons.append(f"status:{latest.status_code}")
    if latest.error:
        reasons.append(f"error:{_safe_reason_token(latest.error)}")
    if failure_count:
        reasons.append(f"failures:{failure_count}")
    if failure_streak:
        reasons.append(f"failure_streak:{failure_streak}")
    if retryable_count:
        reasons.append(f"retryable:{retryable_count}")
    if suppressed:
        reasons.append("suppressed")
    return reasons


def _failure_streak(records: list[HostProbeRecord]) -> int:
    count = 0
    for record in reversed(records):
        if record.outcome not in {"failure", "retryable"}:
            break
        count += 1
    return count


def _next_retry_delay(
    failure_streak: int,
    *,
    retry_after: float | None,
    config: DeadHostSuppressionConfig,
) -> float:
    if retry_after is not None:
        return float(min(config.backoff_cap_seconds, retry_after))
    if failure_streak <= 0:
        return 0.0
    delay = config.backoff_base_seconds * (2 ** max(failure_streak - 1, 0))
    return float(min(config.backoff_cap_seconds, delay))


def _probe_outcome(item: Mapping[str, object]) -> ProbeOutcome:
    status_code = _status_code(item.get("status_code") or item.get("status"))
    if status_code in RETRYABLE_STATUS_CODES:
        return "retryable"
    if status_code is not None:
        return "success"
    if _truthy(item.get("failed")) or _first_string(item, ("error", "err", "failed_reason", "message")):
        return "failure"
    return "unknown"


def _live_run_outcome(observation: Mapping[str, object]) -> ProbeOutcome:
    status_code = _status_code(observation.get("status_code"))
    if status_code in RETRYABLE_STATUS_CODES:
        return "retryable"
    if status_code is not None:
        return "success"
    success = observation.get("success")
    assets = _mapping_list(observation.get("assets"))
    if success is True or assets:
        return "success"
    if success is False:
        return "failure"
    return "unknown"


def _live_run_observation_url(parsed: Mapping[str, object], observation: Mapping[str, object]) -> str | None:
    for candidate in (
        _first_string(observation, ("url", "target", "normalized_target")),
        _target_host_from_run(parsed),
    ):
        if candidate:
            return candidate
    return None


def _target_host_from_run(data: Mapping[str, object]) -> str | None:
    decisions = _mapping_list(data.get("decisions"))
    if not decisions:
        return None
    gate_decision = decisions[0].get("gate_decision")
    if not isinstance(gate_decision, Mapping):
        return None
    normalized = gate_decision.get("normalized_target")
    return normalized if isinstance(normalized, str) else None


class _SanitizedTarget(StrictModel):
    host: str
    url: str


def _sanitize_url_or_host(value: str) -> _SanitizedTarget | None:
    candidate = value.strip()
    if not candidate:
        return None
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = _normalize_host(parsed.hostname)
    if host is None:
        return None
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path or "/"
    url = urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", ""))
    return _SanitizedTarget(host=host, url=url)


def _items_from_text(text: str) -> list[object]:
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
                continue
        return items
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("results", "items", "data", "records", "probes"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    return []


def _json_mapping(text: str) -> Mapping[str, object]:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, Mapping):
        return {}
    return cast(Mapping[str, object], parsed)


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [cast(Mapping[str, object], item) for item in value if isinstance(item, Mapping)]


def _group_records(records: list[HostProbeRecord]) -> list[tuple[str, list[HostProbeRecord]]]:
    grouped: dict[str, list[HostProbeRecord]] = {}
    for record in records:
        grouped.setdefault(record.host, []).append(record)
    return sorted(grouped.items(), key=lambda item: item[0])


def _status_code(value: object) -> int | None:
    if isinstance(value, int) and 100 <= value <= 599:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        parsed = int(value.strip())
        return parsed if 100 <= parsed <= 599 else None
    return None


def _retry_after_seconds(headers: object) -> float | None:
    if not isinstance(headers, Mapping):
        return None
    for key, value in headers.items():
        if not isinstance(key, str) or key.lower() != "retry-after":
            continue
        try:
            return max(float(str(value).strip()), 0.0)
        except ValueError:
            return None
    return None


def _truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes", "y"}
    return False


def _first_string(item: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _safe_reason_token(value: str) -> str:
    return value.strip().lower().replace(",", " ").replace(":", " ")[:80]


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
