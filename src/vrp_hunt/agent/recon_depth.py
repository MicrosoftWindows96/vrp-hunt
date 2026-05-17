"""Depth-oriented approved recon pipeline orchestration."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field

from vrp_hunt.agent.models import AgentAction, AgentPlan, AgentRunResult
from vrp_hunt.agent.planner import HeuristicBrain, build_agent_plan
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset

ReconDepthProfile = Literal["passive", "balanced", "deep", "owned-auth"]
ReconDepthPhase = Literal["subfinder", "httpx", "katana", "nuclei"]
ReconDepthActionExecutor = Callable[[AgentAction], AgentRunResult]
ReconDepthAssetFilter = Callable[[Asset], bool]


class ReconDepthError(ValueError):
    """Raised when a recon-depth pipeline cannot run safely."""


class ReconDepthPhaseRun(StrictModel):
    phase: ReconDepthPhase
    action_id: str = Field(min_length=1)
    target: str = Field(min_length=1)
    target_count: int = Field(ge=0)
    result_path: Path
    asset_path: Path
    success: bool
    request_count: int = Field(ge=0)
    asset_count: int = Field(ge=0)
    notes: list[str] = Field(default_factory=list)


class ReconDepthResult(StrictModel):
    domain: str = Field(min_length=1)
    profile: ReconDepthProfile
    output_dir: Path
    phase_runs: list[ReconDepthPhaseRun] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    total_assets: int = Field(ge=0)
    total_requests: int = Field(ge=0)
    assets_path: Path
    validation_plan_path: Path | None = None
    approval_queue_path: Path | None = None
    summary_path: Path | None = None


def run_recon_depth(
    *,
    domain: str,
    output_dir: Path,
    profile: ReconDepthProfile,
    action_executor: ReconDepthActionExecutor,
    max_hosts: int = 25,
    max_urls: int = 25,
    rate_limit_per_minute: int = 5,
    katana_depth: int = 1,
    katana_js_crawl: bool = False,
    katana_known_files: str | None = None,
    katana_crawl_duration_seconds: int = 30,
    nuclei_templates: list[str] | None = None,
    nuclei_tags: list[str] | None = None,
    nuclei_severity: list[str] | None = None,
    nuclei_rate_limit_per_second: int = 1,
    max_validation_actions: int = 20,
) -> ReconDepthResult:
    """Run approved recon phases and persist structured phase outputs."""

    normalized_domain = _normalize_domain(domain)
    _validate_limits(
        max_hosts=max_hosts,
        max_urls=max_urls,
        rate_limit_per_minute=rate_limit_per_minute,
        katana_depth=katana_depth,
        katana_crawl_duration_seconds=katana_crawl_duration_seconds,
        nuclei_rate_limit_per_second=nuclei_rate_limit_per_second,
        max_validation_actions=max_validation_actions,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    phase_runs: list[ReconDepthPhaseRun] = []
    warnings: list[str] = []
    errors: list[str] = []
    all_assets: list[Asset] = []

    subfinder_run, subfinder_assets = _execute_phase(
        phase="subfinder",
        action=_subfinder_action(normalized_domain),
        output_dir=output_dir,
        target_count=1,
        action_executor=action_executor,
        asset_filter=lambda asset: _asset_in_domain(asset, normalized_domain),
    )
    phase_runs.append(subfinder_run)
    all_assets.extend(subfinder_assets)
    if not subfinder_run.success:
        errors.append("subfinder phase did not complete successfully")

    hosts = _scoped_hosts(
        [*subfinder_assets, Asset(kind="host", value=normalized_domain, source="seed")],
        normalized_domain,
    )
    hosts = hosts[:max_hosts]
    if profile == "passive":
        return _finalize_depth_result(
            domain=normalized_domain,
            profile=profile,
            output_dir=output_dir,
            phase_runs=phase_runs,
            warnings=warnings,
            errors=errors,
            assets=all_assets,
            max_validation_actions=max_validation_actions,
            build_validation_plan=False,
        )
    if not hosts:
        errors.append("no in-scope hosts available for httpx")
        return _finalize_depth_result(
            domain=normalized_domain,
            profile=profile,
            output_dir=output_dir,
            phase_runs=phase_runs,
            warnings=warnings,
            errors=errors,
            assets=all_assets,
            max_validation_actions=max_validation_actions,
            build_validation_plan=profile == "owned-auth",
        )

    hosts_file = _write_lines(output_dir / "inputs" / "httpx-hosts.txt", hosts)
    httpx_run, httpx_assets = _execute_phase(
        phase="httpx",
        action=_httpx_action(
            target=normalized_domain,
            targets_file=hosts_file,
            target_count=len(hosts),
            rate_limit_per_minute=rate_limit_per_minute,
        ),
        output_dir=output_dir,
        target_count=len(hosts),
        action_executor=action_executor,
        asset_filter=lambda asset: _asset_in_domain(asset, normalized_domain),
    )
    phase_runs.append(httpx_run)
    all_assets.extend(httpx_assets)
    if not httpx_run.success:
        errors.append("httpx phase did not complete successfully")

    urls = _scoped_urls(httpx_assets, normalized_domain)[:max_urls]
    if profile not in {"balanced", "deep", "owned-auth"}:
        return _finalize_depth_result(
            domain=normalized_domain,
            profile=profile,
            output_dir=output_dir,
            phase_runs=phase_runs,
            warnings=warnings,
            errors=errors,
            assets=all_assets,
            max_validation_actions=max_validation_actions,
            build_validation_plan=False,
        )
    if not urls:
        errors.append("no in-scope live URLs available for katana")
        return _finalize_depth_result(
            domain=normalized_domain,
            profile=profile,
            output_dir=output_dir,
            phase_runs=phase_runs,
            warnings=warnings,
            errors=errors,
            assets=all_assets,
            max_validation_actions=max_validation_actions,
            build_validation_plan=profile == "owned-auth",
        )

    urls_file = _write_lines(output_dir / "inputs" / "katana-urls.txt", urls)
    crawl_depth = max(katana_depth, 2 if profile in {"deep", "owned-auth"} else 1)
    katana_run, katana_assets = _execute_phase(
        phase="katana",
        action=_katana_action(
            target=urls[0],
            targets_file=urls_file,
            target_count=len(urls),
            rate_limit_per_minute=rate_limit_per_minute,
            depth=crawl_depth,
            js_crawl=katana_js_crawl or profile in {"deep", "owned-auth"},
            known_files=katana_known_files,
            crawl_duration_seconds=katana_crawl_duration_seconds,
        ),
        output_dir=output_dir,
        target_count=len(urls),
        action_executor=action_executor,
        asset_filter=lambda asset: _asset_in_domain(asset, normalized_domain),
    )
    phase_runs.append(katana_run)
    all_assets.extend(katana_assets)
    if not katana_run.success:
        errors.append("katana phase did not complete successfully")

    nuclei_targets = _scoped_urls([*httpx_assets, *katana_assets], normalized_domain)[:max_urls]
    if profile in {"deep", "owned-auth"}:
        templates = nuclei_templates or []
        if templates and nuclei_targets:
            nuclei_file = _write_lines(output_dir / "inputs" / "nuclei-urls.txt", nuclei_targets)
            nuclei_run, nuclei_assets = _execute_phase(
                phase="nuclei",
                action=_nuclei_action(
                    target=nuclei_targets[0],
                    targets_file=nuclei_file,
                    target_count=len(nuclei_targets),
                    templates=templates,
                    tags=nuclei_tags or [],
                    severity=nuclei_severity or [],
                    rate_limit_per_second=nuclei_rate_limit_per_second,
                ),
                output_dir=output_dir,
                target_count=len(nuclei_targets),
                action_executor=action_executor,
                asset_filter=lambda asset: _asset_in_domain(asset, normalized_domain),
            )
            phase_runs.append(nuclei_run)
            all_assets.extend(nuclei_assets)
            if not nuclei_run.success:
                errors.append("nuclei phase did not complete successfully")
        elif not templates:
            warnings.append("nuclei phase skipped: no explicit templates configured")
        else:
            warnings.append("nuclei phase skipped: no in-scope URLs available")

    return _finalize_depth_result(
        domain=normalized_domain,
        profile=profile,
        output_dir=output_dir,
        phase_runs=phase_runs,
        warnings=warnings,
        errors=errors,
        assets=all_assets,
        max_validation_actions=max_validation_actions,
        build_validation_plan=profile == "owned-auth",
    )


def _execute_phase(
    *,
    phase: ReconDepthPhase,
    action: AgentAction,
    output_dir: Path,
    target_count: int,
    action_executor: ReconDepthActionExecutor,
    asset_filter: ReconDepthAssetFilter | None = None,
) -> tuple[ReconDepthPhaseRun, list[Asset]]:
    result = action_executor(action)
    observations = result.observations
    if asset_filter is not None:
        observations = [
            observation.model_copy(
                update={
                    "assets": [asset for asset in observation.assets if asset_filter(asset)]
                }
            )
            for observation in result.observations
        ]
        result = result.model_copy(update={"observations": observations})
    phase_dir = output_dir / "phases" / phase
    phase_dir.mkdir(parents=True, exist_ok=True)
    result_path = phase_dir / "run.json"
    result_path.write_text(result.model_dump_json(indent=2) + "\n", encoding="utf-8")
    assets = [asset for observation in observations for asset in observation.assets]
    asset_path = phase_dir / "assets.jsonl"
    _write_assets(asset_path, assets)
    notes = [note for observation in observations for note in observation.notes]
    success = (
        bool(observations)
        and result.blocked_actions == 0
        and not result.stopped
        and all(observation.success for observation in observations)
    )
    return (
        ReconDepthPhaseRun(
            phase=phase,
            action_id=action.action_id,
            target=action.target,
            target_count=target_count,
            result_path=result_path,
            asset_path=asset_path,
            success=success,
            request_count=sum(observation.request_count for observation in observations),
            asset_count=len(assets),
            notes=notes,
        ),
        assets,
    )


def _finalize_depth_result(
    *,
    domain: str,
    profile: ReconDepthProfile,
    output_dir: Path,
    phase_runs: list[ReconDepthPhaseRun],
    warnings: list[str],
    errors: list[str],
    assets: list[Asset],
    max_validation_actions: int,
    build_validation_plan: bool,
) -> ReconDepthResult:
    deduped = _dedupe_assets(assets)
    assets_path = output_dir / "assets.jsonl"
    _write_assets(assets_path, deduped)
    validation_plan_path = None
    approval_queue_path = None
    if build_validation_plan:
        validation_plan = build_agent_plan(
            deduped,
            brain=HeuristicBrain(),
            max_actions=max_validation_actions,
        )
        validation_plan_path = output_dir / "validation-plan.json"
        validation_plan_path.write_text(
            validation_plan.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        approval_queue_path = output_dir / "approval-queue.txt"
        approval_queue_path.write_text(_approval_queue_text(validation_plan), encoding="utf-8")

    result = ReconDepthResult(
        domain=domain,
        profile=profile,
        output_dir=output_dir,
        phase_runs=phase_runs,
        warnings=warnings,
        errors=errors,
        total_assets=len(deduped),
        total_requests=sum(phase.request_count for phase in phase_runs),
        assets_path=assets_path,
        validation_plan_path=validation_plan_path,
        approval_queue_path=approval_queue_path,
        summary_path=output_dir / "recon-depth-summary.json",
    )
    (output_dir / "recon-depth-summary.json").write_text(
        result.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def _subfinder_action(domain: str) -> AgentAction:
    return AgentAction(
        action_type="passive_recon",
        target_kind="host",
        target=domain,
        intended_action="passive_recon",
        description=f"Run approved passive subfinder recon for {domain}.",
        metadata={"tool": "subfinder"},
    )


def _httpx_action(
    *,
    target: str,
    targets_file: Path,
    target_count: int,
    rate_limit_per_minute: int,
) -> AgentAction:
    return AgentAction(
        action_type="low_volume_probe",
        target_kind="host",
        target=target,
        intended_action="recon",
        description=f"Run approved httpx probing for {target_count} scoped hosts.",
        sends_traffic=True,
        request_budget=max(1, target_count),
        metadata={
            "tool": "httpx",
            "targets_file": str(targets_file),
            "rate_limit_per_minute": str(rate_limit_per_minute),
        },
    )


def _katana_action(
    *,
    target: str,
    targets_file: Path,
    target_count: int,
    rate_limit_per_minute: int,
    depth: int,
    js_crawl: bool,
    known_files: str | None,
    crawl_duration_seconds: int,
) -> AgentAction:
    metadata = {
        "tool": "katana",
        "targets_file": str(targets_file),
        "rate_limit_per_minute": str(rate_limit_per_minute),
        "depth": str(depth),
        "field_scope": "fqdn",
        "js_crawl": str(js_crawl).lower(),
        "crawl_duration_seconds": str(crawl_duration_seconds),
    }
    if known_files:
        metadata["known_files"] = known_files
    return AgentAction(
        action_type="low_volume_probe",
        target_kind="url",
        target=target,
        intended_action="recon",
        description=f"Run approved scoped katana crawl for {target_count} live URLs.",
        sends_traffic=True,
        request_budget=max(1, target_count),
        metadata=metadata,
    )


def _nuclei_action(
    *,
    target: str,
    targets_file: Path,
    target_count: int,
    templates: list[str],
    tags: list[str],
    severity: list[str],
    rate_limit_per_second: int,
) -> AgentAction:
    return AgentAction(
        action_type="low_volume_probe",
        target_kind="url",
        target=target,
        intended_action="recon",
        description=f"Run approved explicit-template nuclei checks for {target_count} URLs.",
        sends_traffic=True,
        request_budget=max(1, target_count),
        metadata={
            "tool": "nuclei",
            "targets_file": str(targets_file),
            "nuclei_templates": ",".join(templates),
            "nuclei_tags": ",".join(tags),
            "nuclei_severity": ",".join(severity),
            "rate_limit_per_second": str(rate_limit_per_second),
        },
    )


def _normalize_domain(domain: str) -> str:
    candidate = domain.strip().lower()
    if "://" in candidate:
        parsed = urlsplit(candidate)
        candidate = parsed.hostname or ""
    if not candidate or "/" in candidate or " " in candidate or "." not in candidate:
        raise ReconDepthError("domain must be a hostname")
    return candidate


def _validate_limits(
    *,
    max_hosts: int,
    max_urls: int,
    rate_limit_per_minute: int,
    katana_depth: int,
    katana_crawl_duration_seconds: int,
    nuclei_rate_limit_per_second: int,
    max_validation_actions: int,
) -> None:
    if max_hosts < 1:
        raise ReconDepthError("max_hosts must be at least 1")
    if max_urls < 1:
        raise ReconDepthError("max_urls must be at least 1")
    if rate_limit_per_minute < 1:
        raise ReconDepthError("rate_limit_per_minute must be at least 1")
    if katana_depth < 1:
        raise ReconDepthError("katana_depth must be at least 1")
    if katana_crawl_duration_seconds < 1:
        raise ReconDepthError("katana_crawl_duration_seconds must be at least 1")
    if nuclei_rate_limit_per_second < 1:
        raise ReconDepthError("nuclei_rate_limit_per_second must be at least 1")
    if max_validation_actions < 0:
        raise ReconDepthError("max_validation_actions must be at least 0")


def _scoped_hosts(assets: list[Asset], domain: str) -> list[str]:
    hosts = []
    for asset in assets:
        host = _asset_host(asset)
        if host is not None and _host_in_domain(host, domain):
            hosts.append(host)
    return sorted(set(hosts))


def _scoped_urls(assets: list[Asset], domain: str) -> list[str]:
    urls = []
    for asset in assets:
        if asset.kind not in {"url", "endpoint", "javascript"} or not asset.value.startswith("http"):
            continue
        host = urlsplit(asset.value).hostname
        if host is not None and _host_in_domain(host, domain):
            urls.append(asset.value)
    return sorted(set(urls))


def _asset_host(asset: Asset) -> str | None:
    if asset.kind == "host":
        return asset.value.lower()
    if asset.value.startswith("http"):
        return urlsplit(asset.value).hostname
    if asset.parent and asset.parent.startswith("http"):
        return urlsplit(asset.parent).hostname
    return None


def _asset_in_domain(asset: Asset, domain: str) -> bool:
    host = _asset_host(asset)
    return host is not None and _host_in_domain(host, domain)


def _host_in_domain(host: str, domain: str) -> bool:
    normalized = host.lower().strip(".")
    return normalized == domain or normalized.endswith(f".{domain}")


def _write_lines(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_assets(path: Path, assets: list[Asset]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for asset in assets:
            handle.write(asset.model_dump_json() + "\n")


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint: dict[str, Asset] = {}
    for asset in assets:
        by_fingerprint.setdefault(asset.fingerprint, asset)
    return list(by_fingerprint.values())


def _approval_queue_text(plan: AgentPlan) -> str:
    lines = [
        f"APPROVE ACTION {index} {action.action_id} {action.intended_action} {action.target}"
        for index, action in enumerate(plan.actions, start=1)
        if action.requires_human_approval
    ]
    return "\n".join(lines) + ("\n" if lines else "")
