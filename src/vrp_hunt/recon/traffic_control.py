"""Offline traffic-control planning for request budgets, robots, and run cache."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.guardrails.rate_limits import RateLimitPolicy
from vrp_hunt.recon.models import Asset

CacheDecisionValue = Literal["hit", "miss", "duplicate"]


class TrafficRequestRecord(StrictModel):
    method: str = Field(default="GET", min_length=1, max_length=16)
    target: str = Field(min_length=1)
    normalized_target: str = Field(min_length=1)
    host: str = Field(min_length=1)
    source: str = Field(min_length=1)
    request_count: int = Field(default=1, ge=1)
    parameter_names: list[str] = Field(default_factory=list)


class HostRequestBudgetPolicy(StrictModel):
    global_request_budget: int = Field(default=100, ge=0)
    per_host_request_budget: int = Field(default=10, ge=0)
    max_repeat_target_count: int = Field(default=1, ge=1)


class HostBudgetUsage(StrictModel):
    host: str = Field(min_length=1)
    request_count: int = Field(ge=0)
    remaining_requests: int = Field(ge=0)
    target_count: int = Field(ge=0)
    repeated_targets: list[str] = Field(default_factory=list)
    over_budget: bool = False


class RequestBudgetLedgerReport(StrictModel):
    policy: HostRequestBudgetPolicy
    total_request_count: int = Field(ge=0)
    remaining_global_requests: int = Field(ge=0)
    global_over_budget: bool = False
    hosts: list[HostBudgetUsage] = Field(default_factory=list)
    violations: list[str] = Field(default_factory=list)


class RunCacheEntry(StrictModel):
    fingerprint: str = Field(min_length=64, max_length=64)
    method: str = Field(min_length=1, max_length=16)
    normalized_target: str = Field(min_length=1)
    host: str = Field(min_length=1)
    source: str = Field(min_length=1)
    status: str = Field(default="planned", min_length=1)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RunCacheDecision(StrictModel):
    fingerprint: str = Field(min_length=64, max_length=64)
    normalized_target: str = Field(min_length=1)
    host: str = Field(min_length=1)
    decision: CacheDecisionValue
    reason: str = Field(min_length=1)


class RunCacheReport(StrictModel):
    existing_entry_count: int = Field(ge=0)
    new_entry_count: int = Field(ge=0)
    hit_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    miss_count: int = Field(ge=0)
    decisions: list[RunCacheDecision] = Field(default_factory=list)
    new_entries: list[RunCacheEntry] = Field(default_factory=list)


class RobotsTrafficPolicy(StrictModel):
    host: str = Field(min_length=1)
    crawl_delay_seconds: float = Field(default=0.0, ge=0)
    disallowed_paths: list[str] = Field(default_factory=list)


class ScheduledTrafficRequest(StrictModel):
    method: str = Field(min_length=1, max_length=16)
    normalized_target: str = Field(min_length=1)
    host: str = Field(min_length=1)
    source: str = Field(min_length=1)
    request_count: int = Field(ge=1)
    scheduled_after_seconds: float = Field(ge=0)
    cache_decision: CacheDecisionValue
    blocked: bool = False
    block_reason: str = ""


class TrafficScheduleReport(StrictModel):
    rate_policy: RateLimitPolicy
    robots_policies: list[RobotsTrafficPolicy] = Field(default_factory=list)
    scheduled: list[ScheduledTrafficRequest] = Field(default_factory=list)
    blocked_count: int = Field(ge=0)
    cache_hit_count: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)


class TrafficControlPlanReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    requests: list[TrafficRequestRecord] = Field(default_factory=list)
    budget_ledger: RequestBudgetLedgerReport
    run_cache: RunCacheReport
    schedule: TrafficScheduleReport
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def build_traffic_control_plan(
    records: list[TrafficRequestRecord],
    *,
    scope_domains: list[str],
    budget_policy: HostRequestBudgetPolicy | None = None,
    rate_policy: RateLimitPolicy | None = None,
    existing_cache: list[RunCacheEntry] | None = None,
    robots_assets: list[Asset] | None = None,
) -> TrafficControlPlanReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    scoped_records, warnings = _filter_scope(records, normalized_scope)
    active_budget = budget_policy or HostRequestBudgetPolicy()
    active_rate = rate_policy or RateLimitPolicy()
    robots_policies = robots_policies_from_assets(robots_assets or [])
    cache_report = build_run_cache_report(scoped_records, existing_entries=existing_cache or [])
    ledger = build_request_budget_ledger(scoped_records, policy=active_budget)
    schedule = build_traffic_schedule(
        scoped_records,
        rate_policy=active_rate,
        cache_report=cache_report,
        robots_policies=robots_policies,
    )
    assets = traffic_control_assets(ledger, cache_report, schedule)
    return TrafficControlPlanReport(
        scope_domains=normalized_scope,
        total_inputs=len(records),
        requests=scoped_records,
        budget_ledger=ledger,
        run_cache=cache_report,
        schedule=schedule,
        assets=assets,
        warnings=sorted({*warnings, *schedule.warnings}),
    )


def build_request_budget_ledger(
    records: list[TrafficRequestRecord],
    *,
    policy: HostRequestBudgetPolicy | None = None,
) -> RequestBudgetLedgerReport:
    active_policy = policy or HostRequestBudgetPolicy()
    total = sum(record.request_count for record in records)
    by_host: dict[str, list[TrafficRequestRecord]] = {}
    for record in records:
        by_host.setdefault(record.host, []).append(record)
    host_usages: list[HostBudgetUsage] = []
    violations: list[str] = []
    for host, host_records in sorted(by_host.items()):
        request_count = sum(record.request_count for record in host_records)
        target_counts: dict[str, int] = {}
        for record in host_records:
            target_counts[record.normalized_target] = target_counts.get(record.normalized_target, 0) + 1
        repeated = sorted(
            target for target, count in target_counts.items() if count > active_policy.max_repeat_target_count
        )
        over_budget = request_count > active_policy.per_host_request_budget
        if over_budget:
            violations.append(f"host budget exceeded: {host}")
        for target in repeated:
            violations.append(f"repeat target exceeded: {target}")
        host_usages.append(
            HostBudgetUsage(
                host=host,
                request_count=request_count,
                remaining_requests=max(active_policy.per_host_request_budget - request_count, 0),
                target_count=len(target_counts),
                repeated_targets=repeated,
                over_budget=over_budget,
            )
        )
    global_over_budget = total > active_policy.global_request_budget
    if global_over_budget:
        violations.append("global request budget exceeded")
    return RequestBudgetLedgerReport(
        policy=active_policy,
        total_request_count=total,
        remaining_global_requests=max(active_policy.global_request_budget - total, 0),
        global_over_budget=global_over_budget,
        hosts=host_usages,
        violations=sorted(set(violations)),
    )


def build_run_cache_report(
    records: list[TrafficRequestRecord],
    *,
    existing_entries: list[RunCacheEntry] | None = None,
) -> RunCacheReport:
    existing = {entry.fingerprint: entry for entry in existing_entries or []}
    seen: set[str] = set()
    decisions: list[RunCacheDecision] = []
    new_entries: list[RunCacheEntry] = []
    for record in records:
        fingerprint = request_fingerprint(record)
        decision: CacheDecisionValue
        if fingerprint in existing:
            decision = "hit"
            reason = "existing cache entry"
        elif fingerprint in seen:
            decision = "duplicate"
            reason = "duplicate in current run"
        else:
            decision = "miss"
            reason = "new target"
            seen.add(fingerprint)
            new_entries.append(
                RunCacheEntry(
                    fingerprint=fingerprint,
                    method=record.method,
                    normalized_target=record.normalized_target,
                    host=record.host,
                    source=record.source,
                )
            )
        decisions.append(
            RunCacheDecision(
                fingerprint=fingerprint,
                normalized_target=record.normalized_target,
                host=record.host,
                decision=decision,
                reason=reason,
            )
        )
    return RunCacheReport(
        existing_entry_count=len(existing),
        new_entry_count=len(new_entries),
        hit_count=sum(1 for decision in decisions if decision.decision == "hit"),
        duplicate_count=sum(1 for decision in decisions if decision.decision == "duplicate"),
        miss_count=sum(1 for decision in decisions if decision.decision == "miss"),
        decisions=decisions,
        new_entries=new_entries,
    )


def build_traffic_schedule(
    records: list[TrafficRequestRecord],
    *,
    rate_policy: RateLimitPolicy | None = None,
    cache_report: RunCacheReport | None = None,
    robots_policies: list[RobotsTrafficPolicy] | None = None,
) -> TrafficScheduleReport:
    active_rate = rate_policy or RateLimitPolicy()
    robots_by_host = {policy.host: policy for policy in robots_policies or []}
    cache_by_fingerprint = {
        decision.fingerprint: decision
        for decision in cache_report.decisions
    } if cache_report is not None else {}
    global_next = 0.0
    host_next: dict[str, float] = {}
    scheduled: list[ScheduledTrafficRequest] = []
    warnings: list[str] = []
    for record in records:
        fingerprint = request_fingerprint(record)
        cache_decision = cache_by_fingerprint.get(fingerprint)
        cache_value: CacheDecisionValue = cache_decision.decision if cache_decision else "miss"
        robots_policy = robots_by_host.get(record.host)
        blocked_reason = _robots_block_reason(record, robots_policy)
        if cache_value in {"hit", "duplicate"} and not blocked_reason:
            blocked_reason = cache_value
        blocked = bool(blocked_reason)
        scheduled_after = 0.0
        if not blocked:
            scheduled_after = max(global_next, host_next.get(record.host, 0.0))
            global_next = scheduled_after + (1.0 / active_rate.global_max_rps)
            per_host_delay = 1.0 / active_rate.per_host_max_rps
            if robots_policy is not None:
                per_host_delay = max(per_host_delay, robots_policy.crawl_delay_seconds)
            host_next[record.host] = scheduled_after + per_host_delay
        elif blocked_reason.startswith("robots"):
            warnings.append(f"{record.normalized_target}: {blocked_reason}")
        scheduled.append(
            ScheduledTrafficRequest(
                method=record.method,
                normalized_target=record.normalized_target,
                host=record.host,
                source=record.source,
                request_count=record.request_count,
                scheduled_after_seconds=scheduled_after,
                cache_decision=cache_value,
                blocked=blocked,
                block_reason=blocked_reason,
            )
        )
    return TrafficScheduleReport(
        rate_policy=active_rate,
        robots_policies=sorted(robots_by_host.values(), key=lambda policy: policy.host),
        scheduled=scheduled,
        blocked_count=sum(1 for item in scheduled if item.blocked),
        cache_hit_count=sum(1 for item in scheduled if item.cache_decision in {"hit", "duplicate"}),
        warnings=sorted(set(warnings)),
    )


def traffic_control_assets(
    ledger: RequestBudgetLedgerReport,
    cache: RunCacheReport,
    schedule: TrafficScheduleReport,
) -> list[Asset]:
    assets: list[Asset] = []
    for host in ledger.hosts:
        assets.append(
            Asset(
                kind="note",
                value=f"traffic-budget:{host.host}",
                source="traffic-control",
                parent=f"https://{host.host}/",
                metadata={
                    "request_count": str(host.request_count),
                    "remaining_requests": str(host.remaining_requests),
                    "target_count": str(host.target_count),
                    "over_budget": str(host.over_budget).lower(),
                },
            )
        )
    for entry in cache.new_entries:
        assets.append(
            Asset(
                kind="note",
                value=f"run-cache:{entry.fingerprint}",
                source="run-cache",
                parent=entry.normalized_target,
                metadata={"host": entry.host, "method": entry.method, "status": entry.status},
            )
        )
    for item in schedule.scheduled:
        if item.blocked:
            continue
        assets.append(
            Asset(
                kind="note",
                value=f"traffic-schedule:{item.normalized_target}",
                source="traffic-scheduler",
                parent=item.normalized_target,
                metadata={
                    "host": item.host,
                    "scheduled_after_seconds": f"{item.scheduled_after_seconds:.2f}",
                },
            )
        )
    return _dedupe_assets(assets)


def robots_policies_from_assets(assets: list[Asset]) -> list[RobotsTrafficPolicy]:
    crawl_delays: dict[str, float] = {}
    disallowed: dict[str, set[str]] = {}
    for asset in assets:
        if asset.source == "robots-txt-crawl-delay" and asset.parent:
            host = _host_from_target(asset.parent)
            delay = _float_from_string(asset.metadata.get("delay_seconds"))
            if host and delay is not None:
                crawl_delays[host] = max(crawl_delays.get(host, 0.0), delay)
        if asset.source == "robots-txt" and asset.metadata.get("directive") == "disallow":
            sanitized = _sanitize_target(asset.value)
            if sanitized is not None:
                disallowed.setdefault(sanitized.host, set()).add(urlsplit(sanitized.normalized).path or "/")
    hosts = sorted(set(crawl_delays) | set(disallowed))
    return [
        RobotsTrafficPolicy(
            host=host,
            crawl_delay_seconds=crawl_delays.get(host, 0.0),
            disallowed_paths=sorted(disallowed.get(host, set())),
        )
        for host in hosts
    ]


def traffic_requests_from_assets(assets: list[Asset], *, source: str = "asset") -> list[TrafficRequestRecord]:
    records: list[TrafficRequestRecord] = []
    for asset in assets:
        if asset.kind not in {"host", "url", "endpoint", "javascript"}:
            continue
        record = traffic_request_from_target(asset.value, source=f"{source}:{asset.source}")
        if record is not None:
            records.append(record)
    return records


def traffic_request_from_target(
    target: str,
    *,
    source: str = "cli",
    method: str = "GET",
    request_count: int = 1,
) -> TrafficRequestRecord | None:
    sanitized = _sanitize_target(target)
    if sanitized is None:
        return None
    return TrafficRequestRecord(
        method=method.strip().upper(),
        target=sanitized.normalized,
        normalized_target=sanitized.normalized,
        host=sanitized.host,
        source=source,
        request_count=request_count,
        parameter_names=sanitized.parameter_names,
    )


def request_fingerprint(record: TrafficRequestRecord) -> str:
    raw = "\x1f".join([record.method.upper(), record.normalized_target.lower()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_run_cache_entries(path: Path) -> list[RunCacheEntry]:
    text = path.read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        entries: list[RunCacheEntry] = []
        for line in text.splitlines():
            if line.strip():
                entries.append(RunCacheEntry.model_validate_json(line))
        return entries
    if isinstance(parsed, list):
        return [RunCacheEntry.model_validate(item) for item in parsed]
    if isinstance(parsed, Mapping):
        value = parsed.get("new_entries") or parsed.get("entries") or parsed.get("cache")
        if isinstance(value, list):
            return [RunCacheEntry.model_validate(item) for item in value]
    return []


def write_run_cache_entries(path: Path, entries: list[RunCacheEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(entry.model_dump_json() + "\n")


class _SanitizedTarget(StrictModel):
    normalized: str
    host: str
    parameter_names: list[str] = Field(default_factory=list)


def _sanitize_target(value: str) -> _SanitizedTarget | None:
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
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return _SanitizedTarget(
        normalized=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        host=host,
        parameter_names=parameter_names,
    )


def _filter_scope(
    records: list[TrafficRequestRecord],
    scope_domains: list[str],
) -> tuple[list[TrafficRequestRecord], list[str]]:
    scoped: list[TrafficRequestRecord] = []
    warnings: list[str] = []
    for record in records:
        if _host_allowed(record.host, scope_domains):
            scoped.append(record)
        else:
            warnings.append(f"skipped third-party host {record.host}")
    return scoped, warnings


def _robots_block_reason(record: TrafficRequestRecord, policy: RobotsTrafficPolicy | None) -> str:
    if policy is None:
        return ""
    path = urlsplit(record.normalized_target).path or "/"
    for disallowed in policy.disallowed_paths:
        if path == disallowed or path.startswith(f"{disallowed.rstrip('/')}/"):
            return f"robots disallow:{disallowed}"
    return ""


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


def _host_from_target(value: str) -> str | None:
    sanitized = _sanitize_target(value)
    return sanitized.host if sanitized is not None else None


def _float_from_string(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
