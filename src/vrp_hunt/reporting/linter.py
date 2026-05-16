"""Quality gate for VRP report drafts."""

from __future__ import annotations

import re
from collections.abc import Iterable

from vrp_hunt.reporting.models import (
    QualityDimension,
    QualityDimensionResult,
    ReportDraft,
    ReportLintIssue,
    ReportLintResult,
)

QUALITY_DIMENSIONS: tuple[QualityDimension, ...] = (
    "vulnerability_description",
    "attack_preconditions",
    "impact_analysis",
    "reproduction_steps_poc",
    "target_info",
    "reproduction_output",
    "researcher_responsiveness",
    "evidence",
    "conciseness_precision",
)

PLACEHOLDER_PATTERNS = (
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bas an ai\b",
        r"\btodo\b",
        r"\btbd\b",
        r"\blorem\b",
        r"\bmaybe\b",
        r"\bnot sure\b",
        r"\bplaceholder\b",
        r"\bincomplete\b",
    )
)


def lint_report(report: ReportDraft, *, max_words: int = 1200) -> ReportLintResult:
    issues: list[ReportLintIssue] = []
    results: list[QualityDimensionResult] = []

    _check(
        results,
        issues,
        "vulnerability_description",
        _meaningful(report.vulnerability_description, min_chars=60),
        "vulnerability description is complete",
        "vulnerability description is incomplete or contains placeholder language",
    )
    _check(
        results,
        issues,
        "attack_preconditions",
        bool(report.attack_preconditions)
        and all(_meaningful(item, min_chars=12) for item in report.attack_preconditions),
        "attack preconditions are explicit",
        "attack preconditions are missing or too vague",
    )
    _check(
        results,
        issues,
        "impact_analysis",
        _meaningful(report.impact_analysis, min_chars=60)
        and "theoretical" not in report.impact_analysis.lower(),
        "impact analysis is concrete",
        "impact analysis is missing, theoretical, or contains placeholder language",
    )
    _check(
        results,
        issues,
        "reproduction_steps_poc",
        _reproduction_and_poc_pass(report),
        "reproduction steps and PoC are clean-state reproducible",
        _reproduction_issue_message(report),
    )
    _check(
        results,
        issues,
        "target_info",
        _target_info_pass(report),
        "target information is complete",
        "target information is missing product, component, host, or platform details",
    )
    _check(
        results,
        issues,
        "reproduction_output",
        _meaningful(report.reproduction_output, min_chars=40),
        "reproduction output is concrete",
        "reproduction output is missing or incomplete",
    )
    _check(
        results,
        issues,
        "researcher_responsiveness",
        report.response_sla_business_days <= 3
        and _meaningful(report.researcher_response_plan, min_chars=20),
        "researcher responsiveness plan meets the three-business-day bar",
        "researcher responsiveness plan misses the three-business-day quality bar",
    )
    _check(
        results,
        issues,
        "evidence",
        bool(report.evidence.items) and report.evidence.all_redacted,
        "evidence is present and redacted",
        "evidence is missing or not marked redacted",
    )
    _check(
        results,
        issues,
        "conciseness_precision",
        _concise_and_precise(report, max_words=max_words),
        "report is concise and technically precise",
        "report contains placeholder language or exceeds the concision limit",
    )

    return ReportLintResult(
        dimension_results=results,
        issues=issues,
        quality_multiplier="1.2" if not issues else "0.8",
    )


def _check(
    results: list[QualityDimensionResult],
    issues: list[ReportLintIssue],
    dimension: QualityDimension,
    passed: bool,
    pass_message: str,
    fail_message: str,
) -> None:
    results.append(
        QualityDimensionResult(
            dimension=dimension,
            passed=passed,
            message=pass_message if passed else fail_message,
        )
    )
    if not passed:
        issues.append(ReportLintIssue(dimension=dimension, message=fail_message))


def _meaningful(value: str, *, min_chars: int) -> bool:
    text = value.strip()
    if len(text) < min_chars:
        return False
    return not _contains_placeholder(text)


def _contains_placeholder(value: str) -> bool:
    return any(pattern.search(value) for pattern in PLACEHOLDER_PATTERNS)


def _target_info_pass(report: ReportDraft) -> bool:
    return all(
        (
            report.target_info.product.strip(),
            report.target_info.component.strip(),
            report.target_info.hostnames,
            report.target_info.platform.strip(),
        )
    )


def _reproduction_and_poc_pass(report: ReportDraft) -> bool:
    if len(report.reproduction_steps) < 2:
        return False
    if any(not _meaningful(step, min_chars=12) for step in report.reproduction_steps):
        return False
    if report.poc.automated_poc_feasible and not report.poc.automated:
        return False
    if report.poc.automated and not report.poc.command:
        return False
    return (
        report.poc.clean_state_reproducible
        and report.poc.own_account_only
        and not report.poc.third_party_data_touched
        and _meaningful(report.poc.expected_output, min_chars=30)
    )


def _reproduction_issue_message(report: ReportDraft) -> str:
    if report.poc.automated_poc_feasible and not report.poc.automated:
        return "automated PoC is missing even though the report marks it feasible"
    return "reproduction steps or PoC are incomplete, unsafe, or not clean-state reproducible"


def _concise_and_precise(report: ReportDraft, *, max_words: int) -> bool:
    fields = (
        report.vulnerability_description,
        report.impact_analysis,
        report.reproduction_output,
        report.researcher_response_plan,
        *report.attack_preconditions,
        *report.reproduction_steps,
        *report.poc.steps,
        report.poc.expected_output,
    )
    if any(_contains_placeholder(field) for field in fields):
        return False
    return _word_count(fields) <= max_words


def _word_count(values: Iterable[str]) -> int:
    return sum(len(value.split()) for value in values)
