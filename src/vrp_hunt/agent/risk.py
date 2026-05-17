"""Risk taxonomy for agent modules and approval policy."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel

ModuleRiskLevel = Literal["passive", "safe", "active", "aggressive"]

RISK_ORDER: dict[ModuleRiskLevel, int] = {
    "passive": 0,
    "safe": 1,
    "active": 2,
    "aggressive": 3,
}


class ModuleRiskProfile(StrictModel):
    module: str = Field(min_length=1)
    risk_level: ModuleRiskLevel
    sends_traffic: bool
    approval_required: bool
    default_request_budget: int = Field(ge=0)
    reason: str = Field(min_length=1)


DEFAULT_MODULE_RISK_PROFILES: dict[str, ModuleRiskProfile] = {
    "analyze_assets": ModuleRiskProfile(
        module="analyze_assets",
        risk_level="passive",
        sends_traffic=False,
        approval_required=False,
        default_request_budget=0,
        reason="offline asset analysis",
    ),
    "report_draft": ModuleRiskProfile(
        module="report_draft",
        risk_level="passive",
        sends_traffic=False,
        approval_required=False,
        default_request_budget=0,
        reason="offline reporting",
    ),
    "plan_test": ModuleRiskProfile(
        module="plan_test",
        risk_level="passive",
        sends_traffic=False,
        approval_required=False,
        default_request_budget=0,
        reason="offline planning",
    ),
    "passive_recon": ModuleRiskProfile(
        module="passive_recon",
        risk_level="passive",
        sends_traffic=False,
        approval_required=False,
        default_request_budget=0,
        reason="saved or passive recon artifacts",
    ),
    "low_volume_probe": ModuleRiskProfile(
        module="low_volume_probe",
        risk_level="safe",
        sends_traffic=True,
        approval_required=False,
        default_request_budget=1,
        reason="bounded metadata probe",
    ),
    "owned_account_authz": ModuleRiskProfile(
        module="owned_account_authz",
        risk_level="active",
        sends_traffic=True,
        approval_required=True,
        default_request_budget=1,
        reason="authenticated owned-account validation",
    ),
    "idor_validation": ModuleRiskProfile(
        module="idor_validation",
        risk_level="active",
        sends_traffic=True,
        approval_required=True,
        default_request_budget=1,
        reason="authorization boundary validation",
    ),
    "oauth_validation": ModuleRiskProfile(
        module="oauth_validation",
        risk_level="active",
        sends_traffic=True,
        approval_required=True,
        default_request_budget=1,
        reason="OAuth flow validation",
    ),
    "xsleak_validation": ModuleRiskProfile(
        module="xsleak_validation",
        risk_level="active",
        sends_traffic=True,
        approval_required=True,
        default_request_budget=1,
        reason="browser-side auth-boundary validation",
    ),
    "xss_validation": ModuleRiskProfile(
        module="xss_validation",
        risk_level="active",
        sends_traffic=True,
        approval_required=True,
        default_request_budget=1,
        reason="input reflection validation",
    ),
    "csrf_validation": ModuleRiskProfile(
        module="csrf_validation",
        risk_level="aggressive",
        sends_traffic=True,
        approval_required=True,
        default_request_budget=1,
        reason="state-changing request validation",
    ),
    "state_change_test": ModuleRiskProfile(
        module="state_change_test",
        risk_level="aggressive",
        sends_traffic=True,
        approval_required=True,
        default_request_budget=1,
        reason="explicit state-changing action",
    ),
}


def module_risk_profile(module: str, *, sends_traffic: bool | None = None) -> ModuleRiskProfile:
    profile = DEFAULT_MODULE_RISK_PROFILES.get(module)
    if profile is not None:
        if sends_traffic is None or sends_traffic == profile.sends_traffic:
            return profile
        if sends_traffic:
            return profile.model_copy(
                update={
                    "risk_level": max_risk(profile.risk_level, "safe"),
                    "sends_traffic": True,
                    "approval_required": profile.approval_required,
                    "default_request_budget": max(profile.default_request_budget, 1),
                    "reason": f"{profile.reason}; sends traffic",
                }
            )
        return profile.model_copy(
            update={
                "sends_traffic": False,
                "default_request_budget": 0,
                "reason": f"{profile.reason}; planned without traffic",
            }
        )
    risk_level: ModuleRiskLevel = "safe" if sends_traffic else "passive"
    return ModuleRiskProfile(
        module=module,
        risk_level=risk_level,
        sends_traffic=bool(sends_traffic),
        approval_required=False,
        default_request_budget=1 if sends_traffic else 0,
        reason="unregistered module default",
    )


def risk_at_least(level: ModuleRiskLevel, minimum: ModuleRiskLevel) -> bool:
    return RISK_ORDER[level] >= RISK_ORDER[minimum]


def max_risk(left: ModuleRiskLevel, right: ModuleRiskLevel) -> ModuleRiskLevel:
    return left if RISK_ORDER[left] >= RISK_ORDER[right] else right
