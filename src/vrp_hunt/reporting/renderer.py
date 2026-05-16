"""Markdown report rendering."""

from __future__ import annotations

from vrp_hunt.reporting.models import EvidenceBundle, ReportDraft


def render_markdown_report(report: ReportDraft) -> str:
    sections = [
        f"# {report.finding.title}",
        "## Vulnerability Description",
        report.vulnerability_description,
        "## Attack Preconditions",
        _bullet_list(report.attack_preconditions),
        "## Impact Analysis",
        report.impact_analysis,
        "## Reproduction Steps",
        _numbered_list(report.reproduction_steps),
        "## Proof of Concept",
        _render_poc(report),
        "## Target Information",
        _render_target(report),
        "## Evidence",
        _render_evidence(report.evidence),
        "## Reproduction Output",
        report.reproduction_output,
        "## Researcher Responsiveness",
        report.researcher_response_plan,
    ]
    return "\n\n".join(sections) + "\n"


def _render_poc(report: ReportDraft) -> str:
    command = report.poc.command if report.poc.command else "Manual PoC only"
    return "\n".join(
        [
            f"Title: {report.poc.title}",
            f"Automated: {'yes' if report.poc.automated else 'no'}",
            f"Command: `{command}`",
            "Steps:",
            _numbered_list(report.poc.steps),
            f"Expected output: {report.poc.expected_output}",
        ]
    )


def _render_target(report: ReportDraft) -> str:
    target = report.target_info
    lines = [
        f"- Product: {target.product}",
        f"- Component: {target.component}",
        f"- Platform: {target.platform}",
        f"- Hostnames: {', '.join(target.hostnames)}",
    ]
    if target.version:
        lines.append(f"- Version: {target.version}")
    return "\n".join(lines)


def _render_evidence(evidence: EvidenceBundle) -> str:
    if not evidence.items:
        return "- No evidence attached"
    return "\n".join(
        f"- {item.kind}: {item.description} ({item.path_or_ref})"
        for item in evidence.items
    )


def _bullet_list(items: list[str]) -> str:
    return "\n".join(f"- {item}" for item in items)


def _numbered_list(items: list[str]) -> str:
    return "\n".join(f"{index}. {item}" for index, item in enumerate(items, start=1))
