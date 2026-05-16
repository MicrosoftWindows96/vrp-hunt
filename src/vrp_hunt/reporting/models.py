"""Submission artifact models for evidence, PoC, and reports."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, model_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.playbooks.models import EvidenceItem, FindingArtifact

Platform = Literal["web", "api", "android", "ios", "browser_extension", "other"]
QualityDimension = Literal[
    "vulnerability_description",
    "attack_preconditions",
    "impact_analysis",
    "reproduction_steps_poc",
    "target_info",
    "reproduction_output",
    "researcher_responsiveness",
    "evidence",
    "conciseness_precision",
]
LintSeverity = Literal["error", "warning"]


class TargetInfo(StrictModel):
    product: str = Field(min_length=1)
    component: str = Field(min_length=1)
    hostnames: list[str] = Field(default_factory=list)
    platform: Platform
    version: str | None = None


class EnvironmentInfo(StrictModel):
    researcher_accounts: list[str] = Field(min_length=1)
    client: str = Field(min_length=1)
    operating_system: str = Field(min_length=1)
    observed_from: str = Field(min_length=1)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class EvidenceBundle(StrictModel):
    finding_id: str = Field(min_length=1)
    target_info: TargetInfo
    environment: EnvironmentInfo
    items: list[EvidenceItem] = Field(default_factory=list)
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def all_redacted(self) -> bool:
        return all(item.redacted for item in self.items)


class PocArtifact(StrictModel):
    title: str = Field(min_length=1)
    automated: bool
    command: str | None = None
    steps: list[str] = Field(min_length=1)
    expected_output: str = Field(min_length=1)
    automated_poc_feasible: bool = True
    clean_state_reproducible: bool = True
    own_account_only: bool = True
    third_party_data_touched: bool = False
    infeasible_reason: str | None = None

    @model_validator(mode="after")
    def enforce_poc_boundary(self) -> "PocArtifact":
        if self.automated and not self.command:
            raise ValueError("automated PoC requires a reproducibility command")
        if not self.own_account_only:
            raise ValueError("PoC must be limited to owned test accounts")
        if self.third_party_data_touched:
            raise ValueError("PoC must not touch third-party data")
        return self


class ReportDraft(StrictModel):
    finding: FindingArtifact
    target_info: TargetInfo
    environment: EnvironmentInfo
    evidence: EvidenceBundle
    poc: PocArtifact
    vulnerability_description: str = Field(min_length=1)
    attack_preconditions: list[str] = Field(default_factory=list)
    impact_analysis: str = Field(min_length=1)
    reproduction_steps: list[str] = Field(default_factory=list)
    reproduction_output: str = Field(min_length=1)
    researcher_response_plan: str = Field(min_length=1)
    response_sla_business_days: int = Field(default=3, ge=1)

    @model_validator(mode="after")
    def keep_bundle_attached_to_finding(self) -> "ReportDraft":
        if self.evidence.finding_id != self.finding.finding_id:
            raise ValueError("evidence bundle must reference the same finding")
        return self


class ReportLintIssue(StrictModel):
    dimension: QualityDimension
    message: str = Field(min_length=1)
    severity: LintSeverity = "error"


class QualityDimensionResult(StrictModel):
    dimension: QualityDimension
    passed: bool
    message: str = Field(min_length=1)


class ReportLintResult(StrictModel):
    dimension_results: list[QualityDimensionResult]
    issues: list[ReportLintIssue] = Field(default_factory=list)
    quality_multiplier: Literal["0.8", "1.2"]

    @property
    def passed(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)
