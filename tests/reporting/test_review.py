from vrp_hunt.agent import report_draft_from_finding
from vrp_hunt.playbooks import EvidenceItem, FindingArtifact
from vrp_hunt.reporting import (
    build_false_positive_review_queue,
    dedupe_findings_across_runs,
    export_report_draft,
    impact_helper_for_finding,
    score_finding_confidence,
)


def _finding(*, title: str = "Owned object authorization bypass") -> FindingArtifact:
    return FindingArtifact(
        title=title,
        bug_class="idor",
        reward_category="S2b",
        status="needs_review",
        target="https://docs.google.com/document/d/owned/edit",
        preconditions=["owned accounts"],
        impact="Owned account B can access owned account A test object.",
        reproduction_steps=["Open owned account A object as owned account B."],
        evidence=[
            EvidenceItem(kind="http", description="redacted HTTP", path_or_ref="evidence/http.jsonl"),
            EvidenceItem(
                kind="screenshot",
                description="redacted screenshot",
                path_or_ref="evidence/screen.png",
            ),
        ],
    )


def test_score_finding_confidence_marks_manual_proof_ready() -> None:
    assessment = score_finding_confidence(_finding())

    assert assessment.score >= 0.7
    assert assessment.state == "ready_for_review"
    assert not assessment.needs_manual_proof


def test_dedupe_findings_across_runs_groups_duplicate_targets() -> None:
    first = _finding()
    second = _finding()

    report = dedupe_findings_across_runs([first, second])

    assert report.input_count == 2
    assert report.unique_count == 1
    assert report.duplicate_count == 1
    assert report.groups[0].duplicate_finding_ids


def test_false_positive_review_queue_prioritizes_weak_findings() -> None:
    weak = _finding(title="Theoretical issue")
    weak = weak.model_copy(update={"evidence": [], "status": "draft"})

    queue = build_false_positive_review_queue([weak])

    assert queue.items[0].priority == "high"
    assert "missing evidence" in queue.items[0].reasons


def test_impact_helper_and_exports_cover_submission_formats() -> None:
    finding = _finding()
    helper = impact_helper_for_finding(finding)
    report = report_draft_from_finding(finding, researcher_accounts=["owned-a", "owned-b"])
    bundle = export_report_draft(report)

    assert helper.bug_class == "idor"
    assert {"markdown", "json", "sarif", "faraday"} == set(bundle.exports)
    assert "# Owned object authorization bypass" in bundle.exports["markdown"]
    assert '"version": "2.1.0"' in bundle.exports["sarif"]
    assert '"vulnerabilities"' in bundle.exports["faraday"]
