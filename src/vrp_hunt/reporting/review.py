"""Finding review, dedupe, impact, and export helpers."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.playbooks import BugClass, FindingArtifact, get_playbook
from vrp_hunt.reporting.models import ReportDraft
from vrp_hunt.reporting.renderer import render_markdown_report

FindingReviewState = Literal["needs_manual_proof", "ready_for_review", "likely_false_positive"]
ReportExportFormat = Literal["markdown", "json", "sarif", "faraday"]

IMPACT_HELPERS: dict[BugClass, list[str]] = {
    "idor": [
        "Explain the exact owned object or record that crossed an authorization boundary.",
        "State the least-privileged owned role that could access or modify it.",
        "Avoid claiming broader data exposure without owned-account proof.",
    ],
    "oauth": [
        "List affected redirect URI, client, response type, and scope class.",
        "Tie impact to account takeover, token disclosure, or consent confusion only when proven.",
        "Mention whether state, PKCE, and consent prompts were present.",
    ],
    "csrf": [
        "Describe the meaningful state change and why it matters to the victim account.",
        "Document token, SameSite, origin, and referer controls before claiming exploitability.",
        "Avoid logout-only or low-impact settings changes.",
    ],
    "xss": [
        "Identify the rendering context and affected owned-account surface.",
        "Use benign marker evidence; do not describe credential theft or persistence unless proven.",
        "Explain whether CSP, sanitization, or sandboxing changes practical impact.",
    ],
    "xsleak": [
        "Describe the observable side channel without exposing private content.",
        "State the attacker/victim owned-account setup and measurement volume.",
        "Separate theoretical timing ideas from reproducible account-state leakage.",
    ],
    "server_side": [
        "Tie impact to a concrete owned-resource effect or server-side trust boundary.",
        "Document non-destructive validation and rollback.",
        "Avoid availability or destructive impact unless explicitly authorized.",
    ],
}


class FindingConfidenceAssessment(StrictModel):
    finding_id: str = Field(min_length=1)
    score: float = Field(ge=0.0, le=1.0)
    state: FindingReviewState
    reasons: list[str] = Field(default_factory=list)
    needs_manual_proof: bool = True


class FindingDedupeGroup(StrictModel):
    canonical_finding_id: str = Field(min_length=1)
    duplicate_finding_ids: list[str] = Field(default_factory=list)
    dedupe_key: str = Field(min_length=1)
    confidence: FindingConfidenceAssessment


class FindingDeduplicationReport(StrictModel):
    input_count: int = Field(ge=0)
    unique_count: int = Field(ge=0)
    duplicate_count: int = Field(ge=0)
    canonical_findings: list[FindingArtifact] = Field(default_factory=list)
    groups: list[FindingDedupeGroup] = Field(default_factory=list)


class FalsePositiveReviewItem(StrictModel):
    finding_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    priority: Literal["low", "medium", "high"]
    reasons: list[str] = Field(default_factory=list)
    suggested_next_step: str = Field(min_length=1)


class FalsePositiveReviewQueue(StrictModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    items: list[FalsePositiveReviewItem] = Field(default_factory=list)


class ImpactHelper(StrictModel):
    bug_class: BugClass
    reward_category: str
    prompts: list[str] = Field(min_length=1)
    non_qualifying_pitfalls: list[str] = Field(min_length=1)


class ReportExportBundle(StrictModel):
    report_id: str = Field(min_length=1)
    exports: dict[ReportExportFormat, str] = Field(default_factory=dict)


def score_finding_confidence(finding: FindingArtifact) -> FindingConfidenceAssessment:
    reasons: list[str] = []
    score = 0.2
    if finding.status == "ready_for_report":
        score += 0.2
        reasons.append("finding marked ready for report")
    elif finding.status == "needs_review":
        score += 0.1
        reasons.append("finding needs review")
    if finding.evidence:
        score += min(len(finding.evidence) * 0.08, 0.24)
        reasons.append(f"{len(finding.evidence)} evidence item(s) attached")
    if any(item.kind == "http" for item in finding.evidence):
        score += 0.14
        reasons.append("HTTP evidence attached")
    if any(item.kind in {"screenshot", "video", "har"} for item in finding.evidence):
        score += 0.12
        reasons.append("visual or HAR evidence attached")
    if finding.affected_assets:
        score += 0.08
        reasons.append("affected assets attached")
    if finding.own_account_only and not finding.third_party_data_touched:
        score += 0.08
        reasons.append("owned-account boundary preserved")
    needs_manual_proof = not _has_manual_proof(finding)
    if needs_manual_proof:
        reasons.append("manual proof still required")
    final_score = min(score, 1.0)
    if final_score < 0.45:
        state: FindingReviewState = "likely_false_positive"
    elif needs_manual_proof:
        state = "needs_manual_proof"
    else:
        state = "ready_for_review"
    return FindingConfidenceAssessment(
        finding_id=finding.finding_id,
        score=round(final_score, 2),
        state=state,
        reasons=reasons,
        needs_manual_proof=needs_manual_proof,
    )


def dedupe_findings_across_runs(findings: list[FindingArtifact]) -> FindingDeduplicationReport:
    groups: dict[str, list[FindingArtifact]] = {}
    for finding in findings:
        groups.setdefault(_dedupe_key(finding), []).append(finding)
    canonical_findings: list[FindingArtifact] = []
    dedupe_groups: list[FindingDedupeGroup] = []
    for key, grouped in sorted(groups.items()):
        ordered = sorted(
            grouped,
            key=lambda item: (score_finding_confidence(item).score, item.created_at),
            reverse=True,
        )
        canonical = ordered[0]
        canonical_findings.append(canonical)
        dedupe_groups.append(
            FindingDedupeGroup(
                canonical_finding_id=canonical.finding_id,
                duplicate_finding_ids=[item.finding_id for item in ordered[1:]],
                dedupe_key=key,
                confidence=score_finding_confidence(canonical),
            )
        )
    duplicate_count = sum(len(group.duplicate_finding_ids) for group in dedupe_groups)
    return FindingDeduplicationReport(
        input_count=len(findings),
        unique_count=len(canonical_findings),
        duplicate_count=duplicate_count,
        canonical_findings=canonical_findings,
        groups=dedupe_groups,
    )


def build_false_positive_review_queue(findings: list[FindingArtifact]) -> FalsePositiveReviewQueue:
    items: list[FalsePositiveReviewItem] = []
    for finding in findings:
        assessment = score_finding_confidence(finding)
        reasons = list(assessment.reasons)
        if finding.status == "invalid":
            reasons.append("finding already marked invalid")
        if not finding.evidence:
            reasons.append("missing evidence")
        if not any(item.kind == "http" for item in finding.evidence):
            reasons.append("missing HTTP evidence")
        if assessment.state == "ready_for_review" and finding.status != "invalid":
            continue
        items.append(
            FalsePositiveReviewItem(
                finding_id=finding.finding_id,
                title=finding.title,
                priority=_review_priority(assessment),
                reasons=sorted(set(reasons)),
                suggested_next_step=_suggested_next_step(assessment),
            )
        )
    return FalsePositiveReviewQueue(items=items)


def impact_helper_for_bug_class(bug_class: BugClass) -> ImpactHelper:
    playbook = get_playbook(bug_class)
    return ImpactHelper(
        bug_class=bug_class,
        reward_category=playbook.reward_category,
        prompts=IMPACT_HELPERS[bug_class],
        non_qualifying_pitfalls=playbook.non_qualifying_pitfalls,
    )


def impact_helper_for_finding(finding: FindingArtifact) -> ImpactHelper:
    return impact_helper_for_bug_class(finding.bug_class)


def export_report_draft(
    report: ReportDraft,
    *,
    formats: list[ReportExportFormat] | None = None,
) -> ReportExportBundle:
    selected_formats = formats or ["markdown", "json", "sarif", "faraday"]
    exports: dict[ReportExportFormat, str] = {}
    for export_format in selected_formats:
        if export_format == "markdown":
            exports[export_format] = render_markdown_report(report)
        elif export_format == "json":
            exports[export_format] = report.model_dump_json(indent=2)
        elif export_format == "sarif":
            exports[export_format] = json.dumps(_sarif_report(report), indent=2)
        elif export_format == "faraday":
            exports[export_format] = json.dumps(_faraday_report(report), indent=2)
    return ReportExportBundle(report_id=report.finding.finding_id, exports=exports)


def _has_manual_proof(finding: FindingArtifact) -> bool:
    evidence_kinds = {item.kind for item in finding.evidence}
    return "http" in evidence_kinds and bool(evidence_kinds.intersection({"screenshot", "video", "har"}))


def _dedupe_key(finding: FindingArtifact) -> str:
    host = urlsplit(finding.target).hostname or finding.target.lower()
    title = " ".join(finding.title.lower().split())
    return f"{finding.bug_class}:{host}:{title}"


def _review_priority(assessment: FindingConfidenceAssessment) -> Literal["low", "medium", "high"]:
    if assessment.state == "likely_false_positive":
        return "high"
    if assessment.needs_manual_proof:
        return "medium"
    return "low"


def _suggested_next_step(assessment: FindingConfidenceAssessment) -> str:
    if assessment.state == "likely_false_positive":
        return "Reproduce manually with owned accounts or close as false positive."
    if assessment.needs_manual_proof:
        return "Attach redacted HTTP plus screenshot/HAR proof before submission review."
    return "Review impact wording and program fit."


def _sarif_report(report: ReportDraft) -> dict[str, object]:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "vrp-hunt", "rules": [_sarif_rule(report)]}},
                "results": [
                    {
                        "ruleId": report.finding.bug_class,
                        "level": "warning",
                        "message": {"text": report.vulnerability_description},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": report.finding.target}
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _sarif_rule(report: ReportDraft) -> dict[str, object]:
    return {
        "id": report.finding.bug_class,
        "name": report.finding.title,
        "shortDescription": {"text": report.finding.title},
        "help": {"text": report.impact_analysis},
    }


def _faraday_report(report: ReportDraft) -> dict[str, object]:
    return {
        "hosts": report.target_info.hostnames,
        "vulnerabilities": [
            {
                "name": report.finding.title,
                "description": report.vulnerability_description,
                "target": report.finding.target,
                "severity": _faraday_severity(report.finding.bug_class),
                "impact": report.impact_analysis,
                "evidence": [
                    {
                        "type": item.kind,
                        "description": item.description,
                        "path": item.path_or_ref,
                        "redacted": item.redacted,
                    }
                    for item in report.evidence.items
                ],
            }
        ],
    }


def _faraday_severity(bug_class: BugClass) -> str:
    if bug_class in {"idor", "server_side"}:
        return "high"
    if bug_class in {"csrf", "oauth", "xsleak", "xss"}:
        return "medium"
    return "low"
