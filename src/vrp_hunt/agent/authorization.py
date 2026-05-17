"""Operator authorization for live recon execution."""

from __future__ import annotations

import getpass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field, ValidationError, field_validator

from vrp_hunt.guardrails.models import StrictModel

ApprovedLiveTool = Literal["subfinder", "httpx", "katana", "nuclei", "jadx"]
APPROVED_LIVE_TOOLS: tuple[ApprovedLiveTool, ...] = (
    "subfinder",
    "httpx",
    "katana",
    "nuclei",
    "jadx",
)
MAX_OPERATOR_POLICY_BYTES = 32_000
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OPERATOR_POLICY_PATH = REPO_ROOT / "config" / "operator_policy.yaml"


class LiveReconAuthorizationError(ValueError):
    """Raised when live recon is not authorized for the local operator."""


class LiveReconOperatorPolicy(StrictModel):
    """Local policy binding live recon to one legally liable operator."""

    authorized_operator_id: str = Field(min_length=1, max_length=128)
    authorized_local_user: str = Field(min_length=1, max_length=128)
    allowed_tools: list[ApprovedLiveTool] = Field(default_factory=lambda: list(APPROVED_LIVE_TOOLS))
    require_liability_ack: bool = True

    @field_validator("allowed_tools")
    @classmethod
    def allowed_tools_must_be_unique(cls, value: list[ApprovedLiveTool]) -> list[ApprovedLiveTool]:
        if len(value) != len(set(value)):
            raise ValueError("allowed tools must be unique")
        return value


class LiveReconAuthorization(StrictModel):
    """Auditable authorization decision for one live recon tool invocation."""

    operator_id: str = Field(min_length=1)
    local_user: str = Field(min_length=1)
    tool: ApprovedLiveTool
    legal_liability_accepted: bool


def load_operator_policy(path: str | Path = DEFAULT_OPERATOR_POLICY_PATH) -> LiveReconOperatorPolicy:
    policy_path = Path(path)
    try:
        data = policy_path.read_bytes()
    except OSError as exc:
        raise LiveReconAuthorizationError(f"failed to read operator policy: {policy_path}") from exc
    if len(data) > MAX_OPERATOR_POLICY_BYTES:
        raise LiveReconAuthorizationError(f"operator policy exceeds size limit: {policy_path}")
    try:
        parsed = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise LiveReconAuthorizationError("operator policy is malformed") from exc
    if not isinstance(parsed, dict):
        raise LiveReconAuthorizationError("operator policy root must be a mapping")
    try:
        return LiveReconOperatorPolicy.model_validate(parsed)
    except ValidationError as exc:
        raise LiveReconAuthorizationError("operator policy validation failed") from exc


def authorize_live_recon(
    *,
    tool: str,
    operator_id: str | None,
    legal_liability_accepted: bool,
    policy: LiveReconOperatorPolicy,
    local_user: str | None = None,
) -> LiveReconAuthorization:
    approved_tool = _approved_live_tool(tool)
    effective_operator = (operator_id or "").strip()
    effective_user = (local_user or getpass.getuser()).strip()

    if effective_operator != policy.authorized_operator_id:
        raise LiveReconAuthorizationError("live recon operator is not authorized")
    if effective_user != policy.authorized_local_user:
        raise LiveReconAuthorizationError("local OS user is not authorized for live recon")
    if approved_tool not in policy.allowed_tools:
        raise LiveReconAuthorizationError(f"tool is not allowed by operator policy: {approved_tool}")
    if policy.require_liability_ack and not legal_liability_accepted:
        raise LiveReconAuthorizationError("legal liability acknowledgement is required")

    return LiveReconAuthorization(
        operator_id=effective_operator,
        local_user=effective_user,
        tool=approved_tool,
        legal_liability_accepted=legal_liability_accepted,
    )


def _approved_live_tool(tool: str) -> ApprovedLiveTool:
    normalized = tool.strip().lower()
    if normalized not in APPROVED_LIVE_TOOLS:
        raise LiveReconAuthorizationError(f"tool is not approved for live recon: {tool}")
    return normalized
