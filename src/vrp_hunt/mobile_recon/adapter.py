"""Mobile recon adapter implementation."""

from __future__ import annotations

from pathlib import Path

from vrp_hunt.guardrails import GateDecision, TargetCandidate
from vrp_hunt.recon import AdapterCapability, AdapterResult, Asset, ReconContext, ReconScope
from vrp_hunt.mobile_recon.extractors import (
    extract_certificate_pinning_indicators,
    extract_mobile_endpoints,
    extract_mobile_risk_notes,
    extract_mobile_secret_notes,
    parse_android_manifest,
    parse_dynamic_messages,
)
from vrp_hunt.mobile_recon.models import MobileAppTarget, MobileReconConfig
from vrp_hunt.mobile_recon.tools import build_frida_script_command, build_jadx_command


class MobileReconAdapter:
    name = "mobile-recon"
    capabilities = [
        AdapterCapability(
            name="mobile-static-analysis",
            asset_kinds=["url", "endpoint", "mobile_component", "note"],
            sends_traffic=False,
        ),
        AdapterCapability(
            name="mobile-dynamic-observation",
            asset_kinds=["url", "endpoint", "mobile_component"],
            sends_traffic=True,
        ),
    ]

    def __init__(self, *, config: MobileReconConfig | None = None) -> None:
        self.config = config or MobileReconConfig()

    async def discover(self, scope: ReconScope, context: ReconContext) -> AdapterResult:
        assets: list[Asset] = []
        warnings: list[str] = []
        errors: list[str] = []

        targets = self._targets_for_scope(scope)
        for target in targets:
            decision = self._gate_target(context, scope, target)
            if not decision.allowed:
                warnings.append(f"skipped app {target.app_id}: {decision.rule_id}")
                continue
            if target.publisher not in self.config.allowed_publishers:
                warnings.append(f"skipped app {target.app_id}: publisher-not-allowed")
                continue

            assets.append(
                Asset(
                    kind="mobile_component",
                    value=target.app_id,
                    source=self.name,
                    metadata={"platform": target.platform, "publisher": target.publisher},
                )
            )
            static_assets, static_errors = await self._static_analysis(target)
            assets.extend(static_assets)
            errors.extend(static_errors)

            if self.config.dynamic_enabled:
                dynamic_assets, dynamic_errors = await self._dynamic_observation(target)
                assets.extend(dynamic_assets)
                errors.extend(dynamic_errors)

        return AdapterResult(assets=assets, warnings=warnings, errors=errors)

    def _targets_for_scope(self, scope: ReconScope) -> list[MobileAppTarget]:
        configured = {target.app_id: target for target in self.config.targets}
        targets: list[MobileAppTarget] = []
        for seed in scope.seeds:
            target = configured.get(seed)
            if target is not None:
                targets.append(target)
        if not targets and len(self.config.targets) == 1:
            return self.config.targets
        return targets

    def _gate_target(
        self, context: ReconContext, scope: ReconScope, target: MobileAppTarget
    ) -> GateDecision:
        return context.scheduler.gate.decide(
            TargetCandidate(
                kind="mobile_app",
                raw_target=target.app_id,
                intended_action="recon",
                researcher_owned_account=scope.researcher_owned_account,
                will_access_third_party_data=scope.will_access_third_party_data,
                legal_acknowledged=scope.legal_acknowledged,
                context={"publisher": target.publisher},
            )
        )

    async def _static_analysis(self, target: MobileAppTarget) -> tuple[list[Asset], list[str]]:
        assets: list[Asset] = []
        errors: list[str] = []
        if target.platform != "android":
            errors.append(f"{target.app_id}: iOS static artifact parsing is documented but not automated")
            return assets, errors
        if target.artifact_path is None:
            errors.append(f"{target.app_id}: no APK artifact path configured")
            return assets, errors

        runner = self.config.runner
        if runner is not None:
            command = build_jadx_command(target.artifact_path, self.config.jadx_output_dir / target.app_id)
            result = await runner.run(command)
            if result.returncode != 0:
                errors.append(f"jadx failed for {target.app_id}: {result.stderr}")
                return assets, errors

        assets.extend(self._scan_artifact_texts(target))
        return assets, errors

    async def _dynamic_observation(self, target: MobileAppTarget) -> tuple[list[Asset], list[str]]:
        runner = self.config.runner
        if runner is None:
            return [], [f"{target.app_id}: dynamic runner not configured"]
        script = self.config.frida_scripts_dir / "observe-network.js"
        result = await runner.run(build_frida_script_command(target.app_id, script))
        if result.returncode != 0:
            return [], [f"frida failed for {target.app_id}: {result.stderr}"]
        return parse_dynamic_messages(result.stdout, parent=target.app_id), []

    def _scan_artifact_texts(self, target: MobileAppTarget) -> list[Asset]:
        assert target.artifact_path is not None
        return self._scan_artifact_texts_from_path(target.artifact_path, parent=target.app_id)

    @staticmethod
    def _scan_artifact_texts_from_path(path: Path, *, parent: str) -> list[Asset]:
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            return MobileReconAdapter._assets_from_text(text, parent=parent)
        if not path.exists():
            return []

        assets: list[Asset] = []
        for file_path in path.rglob("*"):
            if not file_path.is_file() or file_path.stat().st_size > 1_000_000:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            if file_path.name == "AndroidManifest.xml":
                assets.extend(parse_android_manifest(text))
            assets.extend(MobileReconAdapter._assets_from_text(text, parent=parent))
        return assets

    @staticmethod
    def _assets_from_text(text: str, *, parent: str) -> list[Asset]:
        return [
            *extract_certificate_pinning_indicators(text, parent=parent),
            *extract_mobile_endpoints(text, parent=parent),
            *extract_mobile_secret_notes(text, parent=parent),
            *extract_mobile_risk_notes(text, parent=parent),
        ]
