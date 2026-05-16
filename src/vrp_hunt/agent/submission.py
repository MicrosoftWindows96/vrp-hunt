"""Submission-assistance helpers."""

from __future__ import annotations

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.reporting import ReportDraft, lint_report, render_markdown_report


class SubmissionChecklistItem(StrictModel):
    name: str = Field(min_length=1)
    passed: bool
    detail: str = Field(min_length=1)


class SubmissionAssistance(StrictModel):
    markdown: str = Field(min_length=1)
    checklist: list[SubmissionChecklistItem] = Field(min_length=1)
    ready: bool


def build_submission_assistance(report: ReportDraft) -> SubmissionAssistance:
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
    return SubmissionAssistance(
        markdown=render_markdown_report(report),
        checklist=checklist,
        ready=all(item.passed for item in checklist),
    )
