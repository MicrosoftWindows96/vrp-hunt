"""Offline recursive passive subdomain discovery planning."""

from __future__ import annotations

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset


class RecursivePassiveCandidate(StrictModel):
    zone: str = Field(min_length=1)
    seed_domain: str = Field(min_length=1)
    discovered_host_count: int = Field(ge=1)
    depth: int = Field(ge=1)
    command: list[str] = Field(min_length=1)


class RecursivePassivePlan(StrictModel):
    seed_domains: list[str] = Field(min_length=1)
    total_hosts: int = Field(ge=0)
    candidates: list[RecursivePassiveCandidate] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    truncated: bool = False


class RecursivePassiveConfig(StrictModel):
    seed_domains: list[str] = Field(min_length=1)
    max_depth: int = Field(default=2, ge=1, le=5)
    max_queries: int = Field(default=25, ge=1, le=200)
    min_hosts_per_zone: int = Field(default=2, ge=1, le=100)

    @field_validator("seed_domains")
    @classmethod
    def normalize_seed_domains(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for domain in value:
            host = _normalize_host(domain)
            if host is None:
                raise ValueError(f"invalid seed domain: {domain!r}")
            if host not in seen:
                seen.add(host)
                normalized.append(host)
        return normalized


def build_recursive_passive_plan(
    hosts: list[str],
    *,
    config: RecursivePassiveConfig,
) -> RecursivePassivePlan:
    normalized_hosts, warnings = _normalize_hosts(hosts)
    zone_hosts: dict[tuple[str, str], set[str]] = {}
    for host in normalized_hosts:
        for seed_domain in config.seed_domains:
            if host == seed_domain or not host.endswith(f".{seed_domain}"):
                continue
            for zone, depth in _candidate_zones(host, seed_domain, max_depth=config.max_depth):
                zone_hosts.setdefault((zone, seed_domain), set()).add(host)

    candidates: list[RecursivePassiveCandidate] = []
    for (zone, seed_domain), discovered_hosts in sorted(
        zone_hosts.items(),
        key=lambda item: (-len(item[1]), item[0][0]),
    ):
        if len(discovered_hosts) < config.min_hosts_per_zone:
            continue
        depth = _zone_depth(zone, seed_domain)
        candidates.append(
            RecursivePassiveCandidate(
                zone=zone,
                seed_domain=seed_domain,
                discovered_host_count=len(discovered_hosts),
                depth=depth,
                command=["subfinder", "-d", zone, "-oJ", "-silent"],
            )
        )
        if len(candidates) >= config.max_queries:
            return RecursivePassivePlan(
                seed_domains=config.seed_domains,
                total_hosts=len(normalized_hosts),
                candidates=candidates,
                warnings=warnings,
                truncated=True,
            )

    return RecursivePassivePlan(
        seed_domains=config.seed_domains,
        total_hosts=len(normalized_hosts),
        candidates=candidates,
        warnings=warnings,
    )


def recursive_passive_assets(plan: RecursivePassivePlan) -> list[Asset]:
    return [
        Asset(
            kind="note",
            value=f"recursive-passive:{candidate.zone}",
            source="recursive-passive-plan",
            metadata={
                "zone": candidate.zone,
                "seed_domain": candidate.seed_domain,
                "depth": str(candidate.depth),
                "discovered_host_count": str(candidate.discovered_host_count),
                "command": " ".join(candidate.command),
            },
        )
        for candidate in plan.candidates
    ]


def _candidate_zones(host: str, seed_domain: str, *, max_depth: int) -> list[tuple[str, int]]:
    relative = host.removesuffix(f".{seed_domain}")
    labels = [label for label in relative.split(".") if label]
    zones: list[tuple[str, int]] = []
    for start in range(1, len(labels)):
        zone_labels = labels[start:]
        depth = len(zone_labels)
        if depth > max_depth:
            continue
        zones.append((".".join([*zone_labels, seed_domain]), depth))
    return zones


def _zone_depth(zone: str, seed_domain: str) -> int:
    relative = zone.removesuffix(f".{seed_domain}")
    return len([label for label in relative.split(".") if label])


def _normalize_hosts(hosts: list[str]) -> tuple[list[str], list[str]]:
    normalized: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        normalized_host = _normalize_host(host)
        if normalized_host is None:
            warnings.append(f"skipped invalid host: {host!r}")
            continue
        if normalized_host not in seen:
            seen.add(normalized_host)
            normalized.append(normalized_host)
    return normalized, warnings


def _normalize_host(value: str) -> str | None:
    candidate = value.strip().lower().removeprefix("*.").rstrip(".")
    if not candidate or "/" in candidate or " " in candidate or "@" in candidate:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None
