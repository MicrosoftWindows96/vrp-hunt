"""Safe iteration helpers for recon-to-approval loops."""

from __future__ import annotations

import json
from collections.abc import Mapping
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset


class RankedReconTarget(StrictModel):
    index: int = Field(ge=1)
    host: str = Field(min_length=1)
    url: str = Field(min_length=1)
    score: int
    reasons: list[str] = Field(default_factory=list)


class ReconIterationSummary(StrictModel):
    source_host_count: int = Field(ge=0)
    unique_host_count: int = Field(ge=0)
    excluded_dead_hosts: list[str] = Field(default_factory=list)
    candidates: list[RankedReconTarget] = Field(default_factory=list)
    approval_queue: list[str] = Field(default_factory=list)


NOISE_SUFFIXES = (
    ".mx-verification.google.com",
    ".ghs.google.com",
    ".corp.google.com",
    ".cache.google.com",
    ".l.google.com",
    ".pack.google.com",
)
NOISE_TERMS = (
    "feedproxy",
    "googleproxy",
    "ratelimited-proxy",
    "rate-limited-proxy",
    "mx-verification",
)
PUBLIC_PRODUCT_HOSTS = {
    "accounts.google.com",
    "adssettings.google.com",
    "admob.google.com",
    "admin.google.com",
    "calendar.google.com",
    "chat.google.com",
    "cloud.google.com",
    "console.cloud.google.com",
    "drive.google.com",
    "mail.google.com",
    "meet.google.com",
    "myaccount.google.com",
    "pay.google.com",
    "photos.google.com",
    "script.google.com",
    "sites.google.com",
    "wallet.google.com",
}
KEYWORD_BOOSTS = (
    ("account", 80),
    ("admin", 70),
    ("settings", 65),
    ("security", 65),
    ("login", 45),
    ("signin", 45),
    ("oauth", 45),
    ("wallet", 45),
    ("pay", 45),
    ("ads", 35),
    ("script", 35),
    ("cloud", 30),
    ("drive", 30),
    ("mail", 30),
    ("calendar", 30),
    ("photos", 30),
    ("sites", 25),
)


def build_recon_iteration_summary(
    run_json_path: Path,
    *,
    httpx_dir: Path | None = None,
    httpx_dirs: Sequence[Path] | None = None,
    limit: int = 10,
) -> ReconIterationSummary:
    hosts = _hosts_from_live_run(run_json_path)
    dead_hosts = _dead_hosts_from_httpx_dirs(httpx_dir=httpx_dir, httpx_dirs=httpx_dirs)
    ranked: list[tuple[int, str, list[str]]] = []
    for host in sorted(set(hosts)):
        if host in dead_hosts:
            continue
        score = _score_host(host)
        if score is None:
            continue
        ranked.append(score)

    ranked_targets = [
        RankedReconTarget(
            index=index,
            host=host,
            url=f"https://{host}",
            score=score,
            reasons=reasons,
        )
        for index, (score, host, reasons) in enumerate(
            sorted(ranked, key=lambda item: (-item[0], item[1]))[:limit],
            start=1,
        )
    ]
    approval_queue = [
        f"APPROVE LIVE HTTPX {target.url}"
        for target in ranked_targets
    ]
    return ReconIterationSummary(
        source_host_count=len(hosts),
        unique_host_count=len(set(hosts)),
        excluded_dead_hosts=sorted(dead_hosts),
        candidates=ranked_targets,
        approval_queue=approval_queue,
    )


def write_recon_iteration_outputs(summary: ReconIterationSummary, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "ranked-targets.json").write_text(
        summary.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    with (output_dir / "ranked-assets.jsonl").open("w", encoding="utf-8") as handle:
        for target in summary.candidates:
            asset = Asset(kind="url", value=target.url, source="recon-rank")
            handle.write(asset.model_dump_json() + "\n")
    (output_dir / "approval-queue.txt").write_text(
        "\n".join(summary.approval_queue) + ("\n" if summary.approval_queue else ""),
        encoding="utf-8",
    )


def _hosts_from_live_run(path: Path) -> list[str]:
    data = _json_mapping(path)
    observations = _mapping_list(data.get("observations"))
    hosts: list[str] = []
    for observation in observations:
        for asset in _mapping_list(observation.get("assets")):
            if asset.get("kind") != "host":
                continue
            value = asset.get("value")
            if isinstance(value, str) and _looks_like_hostname(value):
                hosts.append(value.strip().lower())
    return hosts


def _dead_hosts_from_httpx_dir(path: Path) -> set[str]:
    dead_hosts: set[str] = set()
    if not path.exists():
        return dead_hosts
    for file_path in sorted(path.glob("*.json")):
        data = _json_mapping(file_path)
        observations = _mapping_list(data.get("observations"))
        if not observations:
            continue
        observation = observations[0]
        if observation.get("success") is not False:
            continue
        if _mapping_list(observation.get("assets")):
            continue
        host = _target_host_from_run(data)
        if host is not None:
            dead_hosts.add(host)
    return dead_hosts


def _dead_hosts_from_httpx_dirs(
    *,
    httpx_dir: Path | None,
    httpx_dirs: Sequence[Path] | None,
) -> set[str]:
    dead_hosts: set[str] = set()
    if httpx_dir is not None:
        dead_hosts.update(_dead_hosts_from_httpx_dir(httpx_dir))
    for path in httpx_dirs or []:
        dead_hosts.update(_dead_hosts_from_httpx_dir(path))
    return dead_hosts


def _target_host_from_run(data: Mapping[str, object]) -> str | None:
    decisions = _mapping_list(data.get("decisions"))
    if decisions:
        gate_decision = decisions[0].get("gate_decision")
        if isinstance(gate_decision, Mapping):
            normalized = gate_decision.get("normalized_target")
            if isinstance(normalized, str):
                return _hostname_from_string(normalized)
    return None


def _score_host(host: str) -> tuple[int, str, list[str]] | None:
    if any(host.endswith(suffix) for suffix in NOISE_SUFFIXES):
        return None
    if any(term in host for term in NOISE_TERMS):
        return None
    if not host.endswith(".google.com") and host != "google.com":
        return None

    score = 0
    reasons: list[str] = []
    if host in PUBLIC_PRODUCT_HOSTS:
        score += 160
        reasons.append("known public product host")
    for keyword, boost in KEYWORD_BOOSTS:
        if keyword in host:
            score += boost
            reasons.append(f"keyword:{keyword}")

    label_count = host.count(".") + 1
    if label_count <= 3:
        score += 35
        reasons.append("short hostname")
    elif label_count <= 4:
        score += 10
    else:
        score -= 55
        reasons.append("deep infrastructure-like hostname")

    if ".clients" in host or ".sandbox." in host or ".usercontent." in host:
        score -= 80
        reasons.append("likely infrastructure or sandbox")
    if ".docs.google.com" in host:
        score -= 45
        reasons.append("numbered docs host noise")

    if score < 45:
        return None
    return score, host, reasons


def _json_mapping(path: Path) -> Mapping[str, object]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, Mapping):
        return {}
    return cast(Mapping[str, object], parsed)


def _mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [cast(Mapping[str, object], item) for item in value if isinstance(item, Mapping)]


def _looks_like_hostname(value: str) -> bool:
    if "/" in value or " " in value or "{" in value:
        return False
    hostname = _hostname_from_string(value)
    return hostname is not None and "." in hostname


def _hostname_from_string(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    return parsed.hostname
