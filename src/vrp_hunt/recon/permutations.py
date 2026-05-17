"""Strict-capped offline subdomain permutation generation."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

PermutationStrategy = Literal["prefix", "replace-leftmost", "append-leftmost", "prepend-leftmost"]

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class SubdomainPermutationConfig(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    words: list[str] = Field(min_length=1)
    max_candidates: int = Field(default=100, ge=1, le=1000)
    max_per_seed: int = Field(default=20, ge=1, le=100)

    @field_validator("scope_domains")
    @classmethod
    def normalize_scope_domains(cls, value: list[str]) -> list[str]:
        return _normalize_unique_hosts(value, "scope domain")

    @field_validator("words")
    @classmethod
    def normalize_words(cls, value: list[str]) -> list[str]:
        words: list[str] = []
        seen: set[str] = set()
        for raw_word in value:
            word = raw_word.strip().lower()
            if not word:
                continue
            if not _LABEL_RE.fullmatch(word):
                raise ValueError(f"invalid permutation word: {raw_word!r}")
            if word not in seen:
                seen.add(word)
                words.append(word)
        if not words:
            raise ValueError("at least one permutation word is required")
        return words

    @model_validator(mode="after")
    def global_cap_must_cover_seed_cap(self) -> "SubdomainPermutationConfig":
        if self.max_candidates < self.max_per_seed:
            raise ValueError("max_candidates must be greater than or equal to max_per_seed")
        return self


class SubdomainPermutationCandidate(StrictModel):
    host: str = Field(min_length=1)
    seed: str = Field(min_length=1)
    scope_domain: str = Field(min_length=1)
    strategy: PermutationStrategy
    word: str = Field(min_length=1)


class SubdomainPermutationReport(StrictModel):
    total_seeds: int = Field(ge=0)
    total_candidates: int = Field(ge=0)
    truncated: bool = False
    candidates: list[SubdomainPermutationCandidate] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def generate_subdomain_permutations(
    seeds: list[str],
    *,
    config: SubdomainPermutationConfig,
) -> SubdomainPermutationReport:
    normalized_seeds, warnings = _normalize_scoped_seeds(seeds, config.scope_domains)
    candidates: list[SubdomainPermutationCandidate] = []
    seen_hosts: set[str] = set()
    truncated = False

    for seed in normalized_seeds:
        seed_count = 0
        for candidate in _candidates_for_seed(seed, config):
            if candidate.host in seen_hosts:
                continue
            seen_hosts.add(candidate.host)
            candidates.append(candidate)
            seed_count += 1
            if len(candidates) >= config.max_candidates:
                truncated = True
                break
            if seed_count >= config.max_per_seed:
                break
        if truncated:
            break

    assets = subdomain_permutation_assets(candidates)
    return SubdomainPermutationReport(
        total_seeds=len(normalized_seeds),
        total_candidates=len(candidates),
        truncated=truncated,
        candidates=candidates,
        assets=assets,
        warnings=warnings,
    )


def subdomain_permutation_assets(candidates: list[SubdomainPermutationCandidate]) -> list[Asset]:
    return [
        Asset(
            kind="host",
            value=candidate.host,
            source="subdomain-permutation",
            parent=candidate.seed,
            metadata={
                "scope_domain": candidate.scope_domain,
                "strategy": candidate.strategy,
                "word": candidate.word,
            },
        )
        for candidate in candidates
    ]


def load_words(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _candidates_for_seed(
    seed: str,
    config: SubdomainPermutationConfig,
) -> list[SubdomainPermutationCandidate]:
    scope_domain = _matching_scope_domain(seed, config.scope_domains)
    if scope_domain is None:
        return []
    relative = "" if seed == scope_domain else seed.removesuffix(f".{scope_domain}")
    labels = relative.split(".") if relative else []
    leftmost = labels[0] if labels and labels[0] else ""
    candidates: list[SubdomainPermutationCandidate] = []
    for word in config.words:
        candidates.extend(
            _candidate(seed, scope_domain, "prefix", word, f"{word}.{scope_domain}"),
        )
        if leftmost:
            candidates.extend(
                [
                    *_candidate(
                        seed,
                        scope_domain,
                        "replace-leftmost",
                        word,
                        f"{word}.{scope_domain}",
                    ),
                    *_candidate(
                        seed,
                        scope_domain,
                        "append-leftmost",
                        word,
                        f"{leftmost}-{word}.{scope_domain}",
                    ),
                    *_candidate(
                        seed,
                        scope_domain,
                        "prepend-leftmost",
                        word,
                        f"{word}-{leftmost}.{scope_domain}",
                    ),
                ]
            )
    return candidates


def _candidate(
    seed: str,
    scope_domain: str,
    strategy: PermutationStrategy,
    word: str,
    host: str,
) -> list[SubdomainPermutationCandidate]:
    normalized = _normalize_host(host)
    if normalized is None:
        return []
    return [
        SubdomainPermutationCandidate(
            host=normalized,
            seed=seed,
            scope_domain=scope_domain,
            strategy=strategy,
            word=word,
        )
    ]


def _normalize_scoped_seeds(
    seeds: list[str],
    scope_domains: list[str],
) -> tuple[list[str], list[str]]:
    normalized: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for seed in seeds:
        host = _normalize_host(seed)
        if host is None:
            warnings.append(f"skipped invalid seed: {seed!r}")
            continue
        if _matching_scope_domain(host, scope_domains) is None:
            warnings.append(f"skipped out-of-scope seed: {host}")
            continue
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    return normalized, warnings


def _normalize_unique_hosts(values: list[str], label: str) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        host = _normalize_host(value)
        if host is None:
            raise ValueError(f"invalid {label}: {value!r}")
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    return normalized


def _normalize_host(value: str) -> str | None:
    candidate = value.strip().lower().removeprefix("*.").rstrip(".")
    if not candidate or "/" in candidate or " " in candidate or "@" in candidate:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None


def _matching_scope_domain(host: str, scope_domains: list[str]) -> str | None:
    for domain in scope_domains:
        if host == domain or host.endswith(f".{domain}"):
            return domain
    return None
