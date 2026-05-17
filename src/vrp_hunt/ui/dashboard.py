"""Render a static local dashboard from redacted VRP Hunt artifacts."""

from __future__ import annotations

import html
import json
import re
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field

from vrp_hunt.agent.artifacts import AgentArtifactBundle
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.playbooks import EvidenceItem, FindingArtifact
from vrp_hunt.programs import ProgramRegistryLoadError, load_program_registry
from vrp_hunt.recon import Asset
from vrp_hunt.reporting import ReportDraft

TOKEN_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{12,}\b"),
    re.compile(r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)=([^&\s]+)"),
)
TEXT_PREVIEW_KINDS = {"http", "note", "burp", "har", "tool_versions"}
MAX_ARTIFACT_PREVIEW_BYTES = 4096
ModelT = TypeVar("ModelT", bound=StrictModel)


class DashboardWarning(StrictModel):
    source: str = Field(min_length=1)
    message: str = Field(min_length=1)


class DashboardApproval(StrictModel):
    source: str = Field(min_length=1)
    command: str = Field(min_length=1)
    approval_id: str = Field(min_length=1)
    risk: str = Field(default="review")


class DashboardEvidence(StrictModel):
    finding_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    description: str = Field(min_length=1)
    path_or_ref: str = Field(min_length=1)
    redacted: bool


class DashboardArtifactPreview(StrictModel):
    finding_id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    path_or_ref: str = Field(min_length=1)
    preview: str = Field(min_length=1)
    redacted: bool = True
    source_exists: bool = False


class DashboardFinding(StrictModel):
    finding_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    bug_class: str = Field(min_length=1)
    status: str = Field(min_length=1)
    target: str = Field(min_length=1)
    evidence_count: int = Field(ge=0)
    third_party_data_touched: bool = False


class DashboardSummary(StrictModel):
    source: str = Field(min_length=1)
    label: str = Field(min_length=1)
    values: dict[str, str] = Field(default_factory=dict)


class DashboardTimelineEntry(StrictModel):
    source: str = Field(min_length=1)
    phase: str = Field(min_length=1)
    status: str = Field(min_length=1)
    detail: str = ""


class DashboardProgramOverview(StrictModel):
    program_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    scope_count: int = Field(ge=0)
    reward_eligible_scope_count: int = Field(ge=0)
    exclusion_count: int = Field(ge=0)
    safe_harbor: str = Field(min_length=1)


class DashboardData(StrictModel):
    title: str = Field(min_length=1)
    generated_at: datetime
    assets: list[Asset] = Field(default_factory=list)
    approvals: list[DashboardApproval] = Field(default_factory=list)
    findings: list[DashboardFinding] = Field(default_factory=list)
    evidence: list[DashboardEvidence] = Field(default_factory=list)
    artifacts: list[DashboardArtifactPreview] = Field(default_factory=list)
    summaries: list[DashboardSummary] = Field(default_factory=list)
    timeline: list[DashboardTimelineEntry] = Field(default_factory=list)
    programs: list[DashboardProgramOverview] = Field(default_factory=list)
    warnings: list[DashboardWarning] = Field(default_factory=list)


def build_dashboard_data(
    *,
    title: str = "VRP Hunt Dashboard",
    asset_files: list[Path] | None = None,
    approval_queues: list[Path] | None = None,
    artifact_bundles: list[Path] | None = None,
    findings: list[Path] | None = None,
    reports: list[Path] | None = None,
    summary_json: list[Path] | None = None,
    program_registries: list[Path] | None = None,
    now: datetime | None = None,
) -> DashboardData:
    warnings: list[DashboardWarning] = []
    loaded_assets: list[Asset] = []
    loaded_approvals: list[DashboardApproval] = []
    loaded_findings: list[FindingArtifact] = []
    loaded_reports: list[ReportDraft] = []
    loaded_summaries: list[DashboardSummary] = []
    loaded_timeline: list[DashboardTimelineEntry] = []
    loaded_programs: list[DashboardProgramOverview] = []

    for path in asset_files or []:
        loaded_assets.extend(_load_assets(path, warnings))
    for path in approval_queues or []:
        loaded_approvals.extend(_load_approvals(path, warnings))
    for path in artifact_bundles or []:
        bundle = _load_model(path, AgentArtifactBundle, "artifact bundle", warnings)
        if bundle is not None:
            loaded_findings.extend(bundle.findings)
            loaded_reports.extend(bundle.reports)
    for path in findings or []:
        finding = _load_model(path, FindingArtifact, "finding", warnings)
        if finding is not None:
            loaded_findings.append(finding)
    for path in reports or []:
        report = _load_model(path, ReportDraft, "report", warnings)
        if report is not None:
            loaded_reports.append(report)
            loaded_findings.append(report.finding)
    for path in summary_json or []:
        summary, timeline = _load_summary(path, warnings)
        if summary is not None:
            loaded_summaries.append(summary)
        loaded_timeline.extend(timeline)
    for path in program_registries or []:
        loaded_programs.extend(_load_program_overviews(path, warnings))

    deduped_findings = _dedupe_findings(loaded_findings)
    evidence = _evidence_rows(deduped_findings, loaded_reports)

    return DashboardData(
        title=title,
        generated_at=now or datetime.now(UTC),
        assets=_dedupe_assets(loaded_assets),
        approvals=loaded_approvals,
        findings=_finding_rows(deduped_findings),
        evidence=evidence,
        artifacts=_artifact_previews(evidence),
        summaries=loaded_summaries,
        timeline=loaded_timeline,
        programs=loaded_programs,
        warnings=warnings,
    )


def write_dashboard(data: DashboardData, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_dashboard_html(data), encoding="utf-8")
    return output_path


def render_dashboard_html(data: DashboardData) -> str:
    counts = _asset_counts(data.assets)
    finding_counts = Counter(finding.bug_class for finding in data.findings)
    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_e(data.title)}</title>",
            "<style>",
            _css(),
            "</style>",
            "</head>",
            "<body>",
            '<header class="top">',
            f"<h1>{_e(data.title)}</h1>",
            f"<p>Generated {_e(data.generated_at.isoformat())}. Local static view; no network actions.</p>",
            "</header>",
            '<nav class="tabs" aria-label="Dashboard sections">',
            '<a href="#assets">Assets</a>',
            '<a href="#approval-review">Approvals</a>',
            '<a href="#findings">Findings</a>',
            '<a href="#triage">Triage</a>',
            '<a href="#evidence">Evidence</a>',
            '<a href="#artifact-browser">Artifacts</a>',
            '<a href="#timeline">Timeline</a>',
            '<a href="#programs">Programs</a>',
            '<a href="#runs">Runs</a>',
            "</nav>",
            '<main class="layout">',
            _summary_html(data, counts, finding_counts),
            _assets_html(data.assets),
            _approvals_html(data.approvals),
            _findings_html(data.findings),
            _triage_html(data.findings),
            _evidence_html(data.evidence),
            _artifacts_html(data.artifacts),
            _timeline_html(data.timeline),
            _programs_html(data.programs),
            _runs_html(data.summaries, data.warnings),
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


def _summary_html(
    data: DashboardData,
    asset_counts: Counter[str],
    finding_counts: Counter[str],
) -> str:
    asset_detail = ", ".join(f"{kind}: {count}" for kind, count in sorted(asset_counts.items())) or "none"
    finding_detail = ", ".join(
        f"{bug_class}: {count}" for bug_class, count in sorted(finding_counts.items())
    ) or "none"
    stats = [
        ("Assets", str(len(data.assets)), asset_detail),
        ("Approval Lines", str(len(data.approvals)), "explicit review queue entries"),
        ("Findings", str(len(data.findings)), finding_detail),
        ("Evidence Items", str(len(data.evidence)), "redaction-aware references"),
        ("Artifacts", str(len(data.artifacts)), "local redacted previews"),
        ("Timeline", str(len(data.timeline)), "phase and step status records"),
        ("Programs", str(len(data.programs)), "scope overview entries"),
        ("Run Summaries", str(len(data.summaries)), "loaded JSON summaries"),
        ("Warnings", str(len(data.warnings)), "file load or parse issues"),
    ]
    rows = [
        f'<div class="stat"><span>{_e(label)}</span><strong>{_e(value)}</strong><small>{_e(detail)}</small></div>'
        for label, value, detail in stats
    ]
    return f'<section class="band" id="overview"><h2>Overview</h2><div class="stats">{"".join(rows)}</div></section>'


def _assets_html(assets: list[Asset]) -> str:
    rows = [
        "<tr>"
        f"<td>{_e(asset.kind)}</td>"
        f"<td>{_e(_redact_text(asset.value))}</td>"
        f"<td>{_e(asset.source)}</td>"
        f"<td>{_e(_redact_text(asset.parent or ''))}</td>"
        f"<td>{_e(_metadata_summary(asset.metadata))}</td>"
        "</tr>"
        for asset in assets
    ]
    return _table_section(
        section_id="assets",
        title="Assets",
        headers=["Kind", "Value", "Source", "Parent", "Metadata"],
        rows=rows,
    )


def _approvals_html(approvals: list[DashboardApproval]) -> str:
    rows = [
        "<tr>"
        f"<td>{_e(approval.approval_id)}</td>"
        f"<td>{_e(approval.risk)}</td>"
        f"<td>{_e(approval.source)}</td>"
        f"<td><code>{_e(_redact_text(approval.command))}</code></td>"
        f'<td><button type="button" data-command="{_e(approval.approval_id)}">Approve</button></td>'
        f'<td><button type="button" data-command="{_e(approval.approval_id)}">Block</button></td>'
        "</tr>"
        for approval in approvals
    ]
    return _table_section(
        section_id="approval-review",
        title="Approval Review",
        headers=["ID", "Risk", "Source", "Command", "Approve", "Block"],
        rows=rows,
    )


def _findings_html(findings: list[DashboardFinding]) -> str:
    rows = [
        "<tr>"
        f"<td>{_e(finding.status)}</td>"
        f"<td>{_e(finding.bug_class)}</td>"
        f"<td>{_e(finding.title)}</td>"
        f"<td>{_e(_redact_text(finding.target))}</td>"
        f"<td>{finding.evidence_count}</td>"
        f"<td>{_e('yes' if finding.third_party_data_touched else 'no')}</td>"
        "</tr>"
        for finding in findings
    ]
    return _table_section(
        section_id="findings",
        title="Findings",
        headers=["Status", "Class", "Title", "Target", "Evidence", "Third Party Data"],
        rows=rows,
    )


def _triage_html(findings: list[DashboardFinding]) -> str:
    statuses = ["draft", "needs_review", "ready_for_report", "invalid"]
    columns = []
    for status in statuses:
        cards = [
            "<article class=\"triage-card\">"
            f"<strong>{_e(finding.title)}</strong>"
            f"<span>{_e(finding.bug_class)} / evidence {finding.evidence_count}</span>"
            f"<small>{_e(_redact_text(finding.target))}</small>"
            "</article>"
            for finding in findings
            if finding.status == status
        ]
        body = "".join(cards) if cards else '<p class="empty">No records loaded</p>'
        columns.append(
            f'<section class="triage-column"><h3>{_e(status)}</h3>{body}</section>'
        )
    return f'<section class="band" id="triage"><h2>Finding Triage</h2><div class="triage">{"".join(columns)}</div></section>'


def _evidence_html(evidence: list[DashboardEvidence]) -> str:
    rows = [
        "<tr>"
        f"<td>{_e(item.kind)}</td>"
        f"<td>{_e(item.finding_id)}</td>"
        f"<td>{_e(_redact_text(item.description))}</td>"
        f"<td>{_e(_redact_text(item.path_or_ref))}</td>"
        f"<td>{_e('yes' if item.redacted else 'no')}</td>"
        "</tr>"
        for item in evidence
    ]
    return _table_section(
        section_id="evidence",
        title="Evidence",
        headers=["Kind", "Finding", "Description", "Path Or Ref", "Redacted"],
        rows=rows,
    )


def _artifacts_html(artifacts: list[DashboardArtifactPreview]) -> str:
    rows = [
        "<tr>"
        f"<td>{_e(item.kind)}</td>"
        f"<td>{_e(item.finding_id)}</td>"
        f"<td>{_e(_redact_text(item.path_or_ref))}</td>"
        f"<td><pre>{_e(item.preview)}</pre></td>"
        f"<td>{_e('yes' if item.redacted else 'no')}</td>"
        f"<td>{_e('yes' if item.source_exists else 'no')}</td>"
        "</tr>"
        for item in artifacts
    ]
    return _table_section(
        section_id="artifact-browser",
        title="Artifact Browser",
        headers=["Kind", "Finding", "Path Or Ref", "Preview", "Redacted", "Local File"],
        rows=rows,
    )


def _timeline_html(timeline: list[DashboardTimelineEntry]) -> str:
    rows = [
        "<tr>"
        f"<td>{_e(entry.phase)}</td>"
        f"<td>{_e(entry.status)}</td>"
        f"<td>{_e(entry.source)}</td>"
        f"<td>{_e(_redact_text(entry.detail))}</td>"
        "</tr>"
        for entry in timeline
    ]
    return _table_section(
        section_id="timeline",
        title="Run Timeline",
        headers=["Phase", "Status", "Source", "Detail"],
        rows=rows,
    )


def _programs_html(programs: list[DashboardProgramOverview]) -> str:
    rows = [
        "<tr>"
        f"<td>{_e(program.program_id)}</td>"
        f"<td>{_e(program.name)}</td>"
        f"<td>{_e(program.platform)}</td>"
        f"<td>{program.scope_count}</td>"
        f"<td>{program.reward_eligible_scope_count}</td>"
        f"<td>{program.exclusion_count}</td>"
        f"<td>{_e(program.safe_harbor)}</td>"
        "</tr>"
        for program in programs
    ]
    return _table_section(
        section_id="programs",
        title="Program Scope",
        headers=["Program", "Name", "Platform", "Scope", "Reward Eligible", "Exclusions", "Safe Harbor"],
        rows=rows,
    )


def _runs_html(summaries: list[DashboardSummary], warnings: list[DashboardWarning]) -> str:
    summary_rows = [
        "<tr>"
        f"<td>{_e(summary.label)}</td>"
        f"<td>{_e(summary.source)}</td>"
        f"<td>{_e(_metadata_summary(summary.values))}</td>"
        "</tr>"
        for summary in summaries
    ]
    warning_rows = [
        "<tr>"
        f"<td>{_e(warning.source)}</td>"
        f"<td>{_e(warning.message)}</td>"
        "</tr>"
        for warning in warnings
    ]
    return "\n".join(
        [
            _table_section(
                section_id="runs",
                title="Run Summaries",
                headers=["Label", "Source", "Values"],
                rows=summary_rows,
            ),
            _table_section(
                section_id="warnings",
                title="Warnings",
                headers=["Source", "Message"],
                rows=warning_rows,
            ),
        ]
    )


def _table_section(
    *,
    section_id: str,
    title: str,
    headers: list[str],
    rows: list[str],
) -> str:
    header_html = "".join(f"<th>{_e(header)}</th>" for header in headers)
    body = "".join(rows) if rows else f'<tr><td colspan="{len(headers)}" class="empty">No records loaded</td></tr>'
    return "\n".join(
        [
            f'<section class="band" id="{section_id}">',
            f"<h2>{_e(title)}</h2>",
            '<div class="table-wrap">',
            "<table>",
            f"<thead><tr>{header_html}</tr></thead>",
            f"<tbody>{body}</tbody>",
            "</table>",
            "</div>",
            "</section>",
        ]
    )


def _load_assets(path: Path, warnings: list[DashboardWarning]) -> list[Asset]:
    assets: list[Asset] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        warnings.append(DashboardWarning(source=str(path), message=f"failed to read asset file: {exc}"))
        return assets
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            assets.append(Asset.model_validate_json(line))
        except ValueError as exc:
            warnings.append(
                DashboardWarning(source=str(path), message=f"asset line {index} ignored: {exc}")
            )
    return assets


def _load_approvals(path: Path, warnings: list[DashboardWarning]) -> list[DashboardApproval]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        warnings.append(DashboardWarning(source=str(path), message=f"failed to read approval queue: {exc}"))
        return []
    approvals: list[DashboardApproval] = []
    for index, line in enumerate(lines, start=1):
        command = line.strip()
        if not command:
            continue
        approvals.append(
            DashboardApproval(
                source=str(path),
                command=command,
                approval_id=_approval_id(path, index),
                risk=_approval_risk(command),
            )
        )
    return approvals


def _approval_id(path: Path, index: int) -> str:
    return f"{path.stem or 'approval'}-{index:04d}"


def _approval_risk(command: str) -> str:
    normalized = command.upper()
    padded = f" {normalized} "
    if " YOLO" in padded:
        return "high"
    if " LIVE " in padded:
        return "live"
    if any(token in padded for token in (" DELETE ", " POST ", " PUT ", " PATCH ")):
        return "state-change"
    return "review"


def _load_model(
    path: Path,
    model: type[ModelT],
    noun: str,
    warnings: list[DashboardWarning],
) -> ModelT | None:
    try:
        return model.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        warnings.append(DashboardWarning(source=str(path), message=f"failed to load {noun}: {exc}"))
        return None


def _load_summary(
    path: Path,
    warnings: list[DashboardWarning],
) -> tuple[DashboardSummary | None, list[DashboardTimelineEntry]]:
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append(DashboardWarning(source=str(path), message=f"failed to load summary: {exc}"))
        return None, []
    if not isinstance(parsed, dict):
        warnings.append(DashboardWarning(source=str(path), message="summary root is not an object"))
        return None, []
    return (
        DashboardSummary(
            source=str(path),
            label=_summary_label(parsed, path),
            values=_summary_values(parsed),
        ),
        _timeline_entries(parsed, path),
    )


def _load_program_overviews(
    path: Path,
    warnings: list[DashboardWarning],
) -> list[DashboardProgramOverview]:
    try:
        registry = load_program_registry(path)
    except ProgramRegistryLoadError as exc:
        warnings.append(DashboardWarning(source=str(path), message=f"failed to load program registry: {exc}"))
        return []
    return [
        DashboardProgramOverview(
            program_id=program.id,
            name=program.name,
            platform=program.platform,
            scope_count=len(program.scope),
            reward_eligible_scope_count=sum(1 for scope in program.scope if scope.reward_eligible),
            exclusion_count=len(program.exclusions),
            safe_harbor=program.safe_harbor.summary,
        )
        for program in registry.programs
    ]


def _timeline_entries(parsed: dict[str, object], path: Path) -> list[DashboardTimelineEntry]:
    entries: list[DashboardTimelineEntry] = []
    source = str(path)
    entries.extend(_phase_run_entries(parsed.get("phase_runs"), source))
    entries.extend(_scenario_run_entries(parsed.get("scenario_runs"), source))
    entries.extend(_derived_run_entries(parsed.get("derived_runs"), source))
    if not entries:
        entries.extend(_single_summary_entry(parsed, source))
    return entries


def _phase_run_entries(value: object, source: str) -> list[DashboardTimelineEntry]:
    if not isinstance(value, list):
        return []
    entries: list[DashboardTimelineEntry] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            continue
        phase = _first_string(item, ("phase", "phase_id", "action_id")) or f"phase-{index}"
        entries.append(
            DashboardTimelineEntry(
                source=source,
                phase=phase,
                status=_run_status(item),
                detail=_timeline_detail(
                    item,
                    (
                        "target",
                        "target_count",
                        "request_count",
                        "asset_count",
                        "artifact_count",
                        "error_count",
                        "skipped_derived_count",
                    ),
                ),
            )
        )
    return entries


def _scenario_run_entries(value: object, source: str) -> list[DashboardTimelineEntry]:
    if not isinstance(value, list):
        return []
    entries: list[DashboardTimelineEntry] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            continue
        scenario_id = _first_string(item, ("scenario_id", "object_id")) or f"scenario-{index}"
        entries.append(
            DashboardTimelineEntry(
                source=source,
                phase=f"scenario:{scenario_id}",
                status=_run_status(item),
                detail=_timeline_detail(
                    item,
                    ("completed_steps", "mismatches", "errors", "artifact_count", "skipped_count"),
                ),
            )
        )
    return entries


def _derived_run_entries(value: object, source: str) -> list[DashboardTimelineEntry]:
    if not isinstance(value, list):
        return []
    entries: list[DashboardTimelineEntry] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            continue
        object_id = _first_string(item, ("object_id",)) or f"object-{index}"
        account_id = _first_string(item, ("account_id",)) or "account"
        entries.append(
            DashboardTimelineEntry(
                source=source,
                phase=f"derived:{object_id}:{account_id}",
                status=_run_status(item),
                detail=_timeline_detail(
                    item,
                    ("request_count", "high_signal_mismatches", "errors", "artifact_count", "skipped_count"),
                ),
            )
        )
    return entries


def _single_summary_entry(parsed: dict[str, object], source: str) -> list[DashboardTimelineEntry]:
    label = _first_string(parsed, ("scenario_id", "matrix_id", "catalog_id", "domain", "app_id", "program_id"))
    if label is None:
        return []
    return [
        DashboardTimelineEntry(
            source=source,
            phase=label,
            status=_run_status(parsed),
            detail=_timeline_detail(
                parsed,
                ("completed_steps", "mismatches", "errors", "warnings", "total_assets", "total_requests"),
            ),
        )
    ]


def _run_status(item: Mapping[str, object]) -> str:
    errors = item.get("errors")
    if errors:
        if isinstance(errors, int) and errors > 0:
            return "failed"
        if isinstance(errors, list) and errors:
            return "failed"
        if isinstance(errors, str) and errors.strip():
            return "failed"
    error_count = item.get("error_count")
    if isinstance(error_count, int) and error_count > 0:
        return "failed"
    success = item.get("success")
    if isinstance(success, bool):
        return "ok" if success else "failed"
    if item.get("stopped") is True:
        return "stopped"
    mismatches = item.get("mismatches") or item.get("high_signal_mismatches")
    if isinstance(mismatches, int) and mismatches > 0:
        return "needs_review"
    return "ok"


def _timeline_detail(item: Mapping[str, object], keys: tuple[str, ...]) -> str:
    details: list[str] = []
    for key in keys:
        value = item.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            details.append(f"{key}={len(value)}")
        else:
            details.append(f"{key}={value}")
    return ", ".join(details)


def _first_string(item: Mapping[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _summary_label(parsed: dict[str, object], path: Path) -> str:
    for key in ("scenario_id", "matrix_id", "catalog_id", "domain", "app_id", "program_id"):
        value = parsed.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return path.stem


def _summary_values(parsed: dict[str, object]) -> dict[str, str]:
    keys = (
        "profile",
        "total_assets",
        "total_requests",
        "total_artifacts",
        "asset_count",
        "hypothesis_count",
        "completed_steps",
        "mismatches",
        "errors",
        "warnings",
    )
    values: dict[str, str] = {}
    for key in keys:
        value = parsed.get(key)
        if value is None:
            continue
        if isinstance(value, list):
            values[key] = str(len(value))
        else:
            values[key] = str(value)
    phase_runs = parsed.get("phase_runs")
    if isinstance(phase_runs, list):
        values["phase_runs"] = str(len(phase_runs))
    return values


def _finding_rows(findings: list[FindingArtifact]) -> list[DashboardFinding]:
    return [
        DashboardFinding(
            finding_id=finding.finding_id,
            title=finding.title,
            bug_class=finding.bug_class,
            status=finding.status,
            target=finding.target,
            evidence_count=len(finding.evidence),
            third_party_data_touched=finding.third_party_data_touched,
        )
        for finding in findings
    ]


def _evidence_rows(
    findings: list[FindingArtifact],
    reports: list[ReportDraft],
) -> list[DashboardEvidence]:
    evidence: list[DashboardEvidence] = []
    for finding in findings:
        evidence.extend(_evidence_item_rows(finding.finding_id, finding.evidence))
    for report in reports:
        evidence.extend(_evidence_item_rows(report.finding.finding_id, report.evidence.items))
    return _dedupe_evidence(evidence)


def _evidence_item_rows(finding_id: str, items: list[EvidenceItem]) -> list[DashboardEvidence]:
    return [
        DashboardEvidence(
            finding_id=finding_id,
            kind=item.kind,
            description=item.description,
            path_or_ref=item.path_or_ref,
            redacted=item.redacted,
        )
        for item in items
    ]


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_key: dict[tuple[str, str, str], Asset] = {}
    for asset in assets:
        key = (asset.kind, asset.value, asset.parent or "")
        by_key.setdefault(key, asset)
    return list(by_key.values())


def _dedupe_findings(findings: list[FindingArtifact]) -> list[FindingArtifact]:
    by_id: dict[str, FindingArtifact] = {}
    for finding in findings:
        by_id.setdefault(finding.finding_id, finding)
    return list(by_id.values())


def _dedupe_evidence(evidence: list[DashboardEvidence]) -> list[DashboardEvidence]:
    by_key: dict[tuple[str, str, str, str], DashboardEvidence] = {}
    for item in evidence:
        key = (item.finding_id, item.kind, item.description, item.path_or_ref)
        by_key.setdefault(key, item)
    return list(by_key.values())


def _artifact_previews(evidence: list[DashboardEvidence]) -> list[DashboardArtifactPreview]:
    return [
        DashboardArtifactPreview(
            finding_id=item.finding_id,
            kind=item.kind,
            path_or_ref=item.path_or_ref,
            preview=preview,
            redacted=True,
            source_exists=source_exists,
        )
        for item in evidence
        for preview, source_exists in [_artifact_preview(item)]
    ]


def _artifact_preview(item: DashboardEvidence) -> tuple[str, bool]:
    path = Path(item.path_or_ref)
    source_exists = path.is_file()
    if item.kind not in TEXT_PREVIEW_KINDS:
        return f"{item.kind} preview suppressed; inspect the local artifact directly.", source_exists
    if not source_exists:
        return "reference only; local file not found", False
    try:
        raw = path.read_bytes()
        size = len(raw)
        preview_raw = raw[:MAX_ARTIFACT_PREVIEW_BYTES]
    except OSError as exc:
        return f"preview unavailable: {exc}", False
    if b"\x00" in preview_raw:
        return "binary artifact preview suppressed", True
    preview = preview_raw.decode("utf-8", errors="replace")
    if size > MAX_ARTIFACT_PREVIEW_BYTES:
        preview = f"{preview}\n[truncated after {MAX_ARTIFACT_PREVIEW_BYTES} bytes]"
    return _redact_text(preview), True


def _asset_counts(assets: list[Asset]) -> Counter[str]:
    return Counter(asset.kind for asset in assets)


def _metadata_summary(metadata: dict[str, str]) -> str:
    if not metadata:
        return ""
    return ", ".join(f"{key}={_redact_text(value)}" for key, value in sorted(metadata.items()))


def _redact_text(value: str) -> str:
    if not value:
        return value
    redacted = _redact_url(value)
    for pattern in TOKEN_PATTERNS:
        redacted = pattern.sub(_redacted_match, redacted)
    return redacted


def _redacted_match(match: re.Match[str]) -> str:
    if match.lastindex:
        return f"{match.group(1)}=[redacted]"
    return "[redacted]"


def _redact_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.query:
        return value
    keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    suffix = f" [query keys: {', '.join(keys)}]" if keys else ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", "")) + suffix


def _e(value: str) -> str:
    return html.escape(value, quote=True)


def _css() -> str:
    return """
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --text: #1f2933;
  --muted: #52606d;
  --line: #d9e2ec;
  --panel: #ffffff;
  --header: #102a43;
  --accent: #0f766e;
  --accent-2: #7c3aed;
  --warn: #b45309;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-size: 14px;
  line-height: 1.45;
}
.top {
  background: var(--header);
  color: #f8fafc;
  padding: 24px clamp(16px, 4vw, 48px);
  border-bottom: 4px solid var(--accent);
}
.top h1 {
  margin: 0 0 6px;
  font-size: 26px;
  font-weight: 700;
  letter-spacing: 0;
}
.top p { margin: 0; color: #cbd5e1; }
.tabs {
  position: sticky;
  top: 0;
  z-index: 2;
  display: flex;
  gap: 2px;
  overflow-x: auto;
  padding: 0 clamp(16px, 4vw, 48px);
  background: #e5eaf0;
  border-bottom: 1px solid var(--line);
}
.tabs a {
  display: inline-flex;
  align-items: center;
  min-height: 42px;
  padding: 0 14px;
  color: var(--header);
  text-decoration: none;
  border-bottom: 3px solid transparent;
  white-space: nowrap;
}
.tabs a:focus, .tabs a:hover {
  border-bottom-color: var(--accent-2);
  background: #f8fafc;
}
.layout {
  width: min(1440px, 100%);
  margin: 0 auto;
  padding: 18px clamp(12px, 3vw, 32px) 40px;
}
.band {
  background: var(--panel);
  border: 1px solid var(--line);
  margin: 0 0 16px;
  padding: 16px;
}
.band h2 {
  margin: 0 0 12px;
  font-size: 17px;
  letter-spacing: 0;
}
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
}
.stat {
  min-height: 92px;
  border-left: 4px solid var(--accent);
  background: #f8fafc;
  padding: 10px 12px;
}
.stat span, .stat small {
  display: block;
  color: var(--muted);
}
.stat strong {
  display: block;
  font-size: 26px;
  line-height: 1.1;
  margin: 6px 0;
}
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--line);
}
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}
th, td {
  padding: 9px 10px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
  text-align: left;
  overflow-wrap: anywhere;
}
th {
  background: #edf2f7;
  color: var(--header);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0;
}
td { color: var(--text); }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
button {
  min-height: 32px;
  border: 1px solid var(--accent);
  background: #ffffff;
  color: var(--accent);
  font: inherit;
  font-weight: 600;
  padding: 4px 10px;
  cursor: default;
}
button:hover, button:focus {
  background: #ecfdf5;
  outline: 2px solid #99f6e4;
  outline-offset: 1px;
}
pre {
  max-height: 180px;
  margin: 0;
  white-space: pre-wrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.triage {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 10px;
}
.triage-column {
  border: 1px solid var(--line);
  background: #f8fafc;
  padding: 10px;
}
.triage-column h3 {
  margin: 0 0 8px;
  color: var(--header);
  font-size: 13px;
  letter-spacing: 0;
  text-transform: uppercase;
}
.triage-card {
  border: 1px solid var(--line);
  background: #ffffff;
  margin: 0 0 8px;
  padding: 9px;
}
.triage-card strong,
.triage-card span,
.triage-card small {
  display: block;
}
.triage-card span,
.triage-card small {
  color: var(--muted);
  margin-top: 4px;
}
.empty {
  color: var(--muted);
  text-align: center;
}
@media (max-width: 720px) {
  .top h1 { font-size: 22px; }
  th, td { min-width: 140px; }
  .band { padding: 12px; }
}
""".strip()
