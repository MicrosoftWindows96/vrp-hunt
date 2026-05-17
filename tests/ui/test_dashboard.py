from datetime import UTC, datetime
from pathlib import Path

from vrp_hunt.playbooks import EvidenceItem, FindingArtifact
from vrp_hunt.recon import Asset
from vrp_hunt.ui import build_dashboard_data, render_dashboard_html, write_dashboard


def _finding() -> FindingArtifact:
    return FindingArtifact(
        finding_id="finding-1",
        title="Potential IDOR in owned object",
        bug_class="idor",
        reward_category="S2b",
        status="needs_review",
        target="https://docs.google.com/document/d/owned/edit?token=secret",
        preconditions=["owned test object"],
        impact="Owned actor reached a denied object.",
        reproduction_steps=["Open the owned object as owned-b."],
        evidence=[
            EvidenceItem(
                kind="http",
                description="Redacted HTTP log",
                path_or_ref="artifacts/http.jsonl",
                redacted=True,
            )
        ],
    )


def test_dashboard_loads_assets_approvals_findings_and_summaries(tmp_path: Path) -> None:
    assets_path = tmp_path / "assets.jsonl"
    assets_path.write_text(
        Asset(
            kind="url",
            value="https://accounts.google.com/o/oauth2/v2/auth?client_id=owned",
            source="test",
        ).model_dump_json()
        + "\n",
        encoding="utf-8",
    )
    approvals_path = tmp_path / "approval-queue.txt"
    approvals_path.write_text("APPROVE LIVE HTTPX https://www.google.com\n", encoding="utf-8")
    finding_path = tmp_path / "finding.json"
    finding_path.write_text(_finding().model_dump_json(), encoding="utf-8")
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        '{"domain":"google.com","total_assets":3,"phase_runs":[{"phase":"subfinder"}]}',
        encoding="utf-8",
    )

    data = build_dashboard_data(
        asset_files=[assets_path],
        approval_queues=[approvals_path],
        findings=[finding_path],
        summary_json=[summary_path],
        now=datetime(2026, 5, 16, tzinfo=UTC),
    )

    assert len(data.assets) == 1
    assert len(data.approvals) == 1
    assert len(data.findings) == 1
    assert len(data.evidence) == 1
    assert data.summaries[0].values["phase_runs"] == "1"


def test_dashboard_html_redacts_query_values_and_tokens(tmp_path: Path) -> None:
    data = build_dashboard_data(
        title="Owned Dashboard",
        findings=[],
        now=datetime(2026, 5, 16, tzinfo=UTC),
    )
    data = data.model_copy(
        update={
            "assets": [
                Asset(
                    kind="url",
                    value="https://example.com/path?access_token=secret",
                    source="test",
                    metadata={"auth": "Bearer abcdefghijklmnopqrstuvwxyz"},
                )
            ]
        }
    )

    html = render_dashboard_html(data)
    output_path = write_dashboard(data, tmp_path / "dashboard.html")

    assert "access_token=secret" not in html
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in html
    assert "[query keys: access_token]" in html
    assert output_path.exists()
