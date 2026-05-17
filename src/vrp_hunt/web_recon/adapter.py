"""Web recon adapter implementation."""

from __future__ import annotations

from datetime import date
from urllib.parse import urlsplit

from vrp_hunt.guardrails import TargetCandidate
from vrp_hunt.recon import (
    AdapterCapability,
    AdapterResult,
    Asset,
    HttpRequest,
    ReconContext,
    ReconScope,
)
from vrp_hunt.recon.scheduler import GateDeniedError
from vrp_hunt.web_recon.endpoint_mining import (
    EndpointMiningConfig,
    WebContentDocument,
    mine_javascript_and_api_endpoints,
)
from vrp_hunt.web_recon.models import CommandRunner, WebReconConfig
from vrp_hunt.web_recon.parsers import parse_amass_text, parse_httpx_jsonl, parse_subfinder_jsonl
from vrp_hunt.web_recon.tools import build_amass_command, build_subfinder_command


class WebReconAdapter:
    name = "web-recon"
    capabilities = [
        AdapterCapability(name="passive-subdomains", asset_kinds=["host"], sends_traffic=False),
        AdapterCapability(
            name="live-web-probe",
            asset_kinds=["url", "technology", "javascript", "endpoint", "parameter", "note"],
            sends_traffic=True,
        ),
    ]

    def __init__(self, *, runner: CommandRunner | None = None, config: WebReconConfig | None = None) -> None:
        self.runner = runner
        self.config = config or WebReconConfig()

    async def discover(self, scope: ReconScope, context: ReconContext) -> AdapterResult:
        assets: list[Asset] = []
        warnings: list[str] = []
        errors: list[str] = []

        allowed_seeds = self._allowed_seeds(scope, context, warnings)
        if self.config.passive_tools_enabled and self.runner is not None:
            for seed in allowed_seeds:
                tool_assets, tool_errors = await self._run_passive_tools(seed)
                assets.extend(self._filter_allowed_hosts(tool_assets, scope, context, warnings))
                errors.extend(tool_errors)
        else:
            assets.extend(Asset(kind="host", value=seed, source=self.name) for seed in allowed_seeds)

        host_values = [asset.value for asset in assets if asset.kind == "host"]
        if self.config.live_probe_enabled:
            for host in sorted(set(host_values))[: self.config.max_live_hosts]:
                probe_assets, probe_warning = await self._probe_host(host, scope, context)
                assets.extend(probe_assets)
                if probe_warning:
                    warnings.append(probe_warning)

        return AdapterResult(assets=assets, warnings=warnings, errors=errors)

    def _allowed_seeds(
        self, scope: ReconScope, context: ReconContext, warnings: list[str]
    ) -> list[str]:
        allowed: list[str] = []
        for seed in scope.seeds:
            decision = context.scheduler.gate.decide(self._candidate(seed, scope, kind="host"))
            if decision.allowed:
                allowed.append(seed.lower())
            else:
                warnings.append(f"skipped seed {seed}: {decision.rule_id}")
        return allowed

    async def _run_passive_tools(self, seed: str) -> tuple[list[Asset], list[str]]:
        assert self.runner is not None
        assets: list[Asset] = []
        errors: list[str] = []
        if self.config.subfinder_enabled:
            result = await self.runner.run(build_subfinder_command(seed))
            if result.returncode == 0:
                assets.extend(parse_subfinder_jsonl(result.stdout))
            else:
                errors.append(f"subfinder failed for {seed}: {result.stderr}")
        if self.config.amass_enabled:
            result = await self.runner.run(build_amass_command(seed))
            if result.returncode == 0:
                assets.extend(parse_amass_text(result.stdout))
            else:
                errors.append(f"amass failed for {seed}: {result.stderr}")
        return assets, errors

    def _filter_allowed_hosts(
        self,
        assets: list[Asset],
        scope: ReconScope,
        context: ReconContext,
        warnings: list[str],
    ) -> list[Asset]:
        allowed: list[Asset] = []
        for asset in assets:
            if asset.kind != "host":
                allowed.append(asset)
                continue
            decision = context.scheduler.gate.decide(self._candidate(asset.value, scope, kind="host"))
            if decision.allowed:
                allowed.append(asset)
            else:
                warnings.append(f"skipped host {asset.value}: {decision.rule_id}")
        return allowed

    async def _probe_host(
        self, host: str, scope: ReconScope, context: ReconContext
    ) -> tuple[list[Asset], str | None]:
        url = f"https://{host}/"
        request = HttpRequest(
            url=url,
            headers={"User-Agent": self.config.user_agent},
            timeout_seconds=self.config.http_timeout_seconds,
        )
        try:
            response = await context.scheduler.request(
                request,
                scope=self._candidate(url, scope, kind="url"),
            )
        except GateDeniedError as exc:
            return [], f"skipped probe {url}: {exc}"

        assets = parse_httpx_jsonl(
            _http_response_as_jsonl(url, response.status_code, response.headers),
            source="web-probe",
        )
        assets.extend(self._extract_response_assets(url, response.text, scope))
        return assets, None

    def _extract_response_assets(self, url: str, text: str, scope: ReconScope) -> list[Asset]:
        report = mine_javascript_and_api_endpoints(
            [WebContentDocument(url=url, body=text, source="web-probe")],
            config=EndpointMiningConfig(scope_domains=scope.seeds),
        )
        return report.assets

    def _candidate(self, raw_target: str, scope: ReconScope, *, kind: str) -> TargetCandidate:
        acquisition_date = self._acquisition_date(raw_target, scope)
        return TargetCandidate(
            kind=kind,  # type: ignore[arg-type]
            raw_target=raw_target,
            intended_action="recon",
            researcher_owned_account=scope.researcher_owned_account,
            will_access_third_party_data=scope.will_access_third_party_data,
            legal_acknowledged=scope.legal_acknowledged,
            acquisition_date=acquisition_date,
        )

    def _acquisition_date(self, raw_target: str, scope: ReconScope) -> date | None:
        host = urlsplit(raw_target).hostname or raw_target
        for domain, acquired_at in self.config.acquisition_dates.items():
            if host == domain or host.endswith(f".{domain}"):
                return acquired_at
        scoped = scope.metadata.get("acquisition_date")
        if scoped:
            return date.fromisoformat(scoped)
        return None


def _http_response_as_jsonl(url: str, status_code: int, headers: dict[str, str]) -> str:
    import json

    server = ""
    for key, value in headers.items():
        if key.lower() == "server":
            server = value
            break
    return json.dumps({"url": url, "status_code": status_code, "webserver": server}) + "\n"
