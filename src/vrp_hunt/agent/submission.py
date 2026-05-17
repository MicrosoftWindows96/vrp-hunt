"""Submission-assistance helpers."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel, TargetKind
from vrp_hunt.programs import ProgramRegistry, ProgramScopeDecision, match_program_scope
from vrp_hunt.reporting import ReportDraft, lint_report, render_markdown_report


@dataclass(frozen=True)
class _SubmissionTarget:
    value: str
    target_kind: TargetKind | None
    publisher: str | None = None


class SubmissionChecklistItem(StrictModel):
    name: str = Field(min_length=1)
    passed: bool
    detail: str = Field(min_length=1)


class SubmissionAssistance(StrictModel):
    markdown: str = Field(min_length=1)
    checklist: list[SubmissionChecklistItem] = Field(min_length=1)
    ready: bool
    program_decisions: list[ProgramScopeDecision] = Field(default_factory=list)


def build_submission_assistance(
    report: ReportDraft,
    *,
    registry: ProgramRegistry | None = None,
) -> SubmissionAssistance:
    lint = lint_report(report)
    checklist = [
        SubmissionChecklistItem(
            name="report-lint",
            passed=lint.passed,
            detail="Report lint passed." if lint.passed else "Report lint has blocking issues.",
        ),
        SubmissionChecklistItem(
            name="owned-accounts",
            passed=report.finding.own_account_only and report.poc.own_account_only,
            detail="Evidence and PoC are limited to owned accounts.",
        ),
        SubmissionChecklistItem(
            name="third-party-data",
            passed=not report.finding.third_party_data_touched and not report.poc.third_party_data_touched,
            detail="No third-party data is recorded in the report artifacts.",
        ),
        SubmissionChecklistItem(
            name="redacted-evidence",
            passed=report.evidence.all_redacted,
            detail="All evidence items are marked redacted.",
        ),
    ]
    program_decisions: list[ProgramScopeDecision] = []
    if registry is not None:
        program_decisions = _program_scope_decisions(report, registry)
        checklist.extend(_program_checklist(report, program_decisions))
    return SubmissionAssistance(
        markdown=render_markdown_report(report),
        checklist=checklist,
        ready=all(item.passed for item in checklist),
        program_decisions=program_decisions,
    )


def _program_scope_decisions(
    report: ReportDraft,
    registry: ProgramRegistry,
) -> list[ProgramScopeDecision]:
    decisions: list[ProgramScopeDecision] = []
    seen: set[tuple[str, TargetKind | None, str | None]] = set()
    for target in _submission_targets(report):
        key = (target.value, target.target_kind, target.publisher)
        if key in seen:
            continue
        seen.add(key)
        decisions.append(
            match_program_scope(
                registry,
                target=target.value,
                target_kind=target.target_kind,
                publisher=target.publisher,
            )
        )
    return decisions


def _program_checklist(
    report: ReportDraft,
    decisions: list[ProgramScopeDecision],
) -> list[SubmissionChecklistItem]:
    if not decisions:
        return [
            SubmissionChecklistItem(
                name="program-scope",
                passed=False,
                detail="No target was available for program scope matching.",
            )
        ]

    primary = decisions[0]
    out_of_scope = [decision for decision in decisions if decision.decision == "OUT_OF_SCOPE"]
    unknown = [decision for decision in decisions if decision.decision == "UNKNOWN"]
    safe_evidence = (
        report.finding.own_account_only
        and report.poc.own_account_only
        and not report.finding.third_party_data_touched
        and not report.poc.third_party_data_touched
    )
    return [
        SubmissionChecklistItem(
            name="program-scope",
            passed=primary.decision == "IN_SCOPE",
            detail=_decision_detail(primary),
        ),
        SubmissionChecklistItem(
            name="reward-eligible",
            passed=primary.decision == "IN_SCOPE" and primary.reward_eligible,
            detail=(
                f"Primary target matched reward-eligible scope entry {primary.matched_entry_id}."
                if primary.reward_eligible
                else "Primary target is not confirmed reward-eligible."
            ),
        ),
        SubmissionChecklistItem(
            name="program-exclusions",
            passed=not out_of_scope,
            detail=(
                "No referenced report target matched an out-of-scope exclusion."
                if not out_of_scope
                else "; ".join(_decision_detail(decision) for decision in out_of_scope)
            ),
        ),
        SubmissionChecklistItem(
            name="referenced-assets-in-scope",
            passed=not out_of_scope and not unknown,
            detail=(
                "All referenced report targets matched in-scope program entries."
                if not out_of_scope and not unknown
                else "; ".join(_decision_detail(decision) for decision in out_of_scope + unknown)
            ),
        ),
        SubmissionChecklistItem(
            name="program-safe-harbor",
            passed=bool(primary.safe_harbor_summary) and safe_evidence,
            detail=(
                primary.safe_harbor_summary
                if primary.safe_harbor_summary and safe_evidence
                else "Safe-harbor confirmation requires in-scope, owned-account-only evidence."
            ),
        ),
        SubmissionChecklistItem(
            name="rate-limit-policy",
            passed=primary.rate_limit is not None,
            detail=(
                "Matched program rate-limit policy is attached to the checklist."
                if primary.rate_limit is not None
                else "No program rate-limit policy was attached for the primary target."
            ),
        ),
    ]


def _submission_targets(report: ReportDraft) -> list[_SubmissionTarget]:
    publisher = _publisher_from_report(report)
    targets = [
        _SubmissionTarget(
            value=report.finding.target,
            target_kind=_target_kind_for_value(report.finding.target, platform=report.target_info.platform),
            publisher=publisher,
        )
    ]
    targets.extend(
        _SubmissionTarget(value=hostname, target_kind="host")
        for hostname in report.target_info.hostnames
    )
    for asset in report.finding.affected_assets:
        target_kind = _target_kind_for_asset(asset.kind, asset.value, report.target_info.platform)
        if target_kind is not None:
            targets.append(
                _SubmissionTarget(
                    value=asset.value,
                    target_kind=target_kind,
                    publisher=asset.metadata.get("publisher") or publisher,
                )
            )
    return targets


def _target_kind_for_asset(
    asset_kind: str,
    value: str,
    platform: str,
) -> TargetKind | None:
    if asset_kind == "host":
        return "host"
    if asset_kind in {"url", "endpoint", "javascript"} and "://" in value:
        return "url"
    if platform in {"android", "ios"} and asset_kind == "mobile_component":
        return "mobile_app"
    return None


def _target_kind_for_value(value: str, *, platform: str) -> TargetKind:
    if platform in {"android", "ios"} and "://" not in value and "/" not in value:
        return "mobile_app"
    if "://" in value:
        return "url"
    return "host"


def _publisher_from_report(report: ReportDraft) -> str | None:
    for asset in report.finding.affected_assets:
        publisher = asset.metadata.get("publisher")
        if publisher:
            return publisher
    return None


def _decision_detail(decision: ProgramScopeDecision) -> str:
    program = decision.program_name or decision.program_id or "unmatched program"
    entry = f" entry {decision.matched_entry_id}" if decision.matched_entry_id else ""
    return f"{decision.target}: {decision.decision} for {program}{entry}: {decision.reason}"
