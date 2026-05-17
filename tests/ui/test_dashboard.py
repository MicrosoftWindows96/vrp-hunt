import json
from datetime import UTC, datetime
from pathlib import Path

from vrp_hunt.playbooks import EvidenceItem, FindingArtifact
from vrp_hunt.recon import Asset
from vrp_hunt.ui import build_dashboard_data, render_dashboard_html, write_dashboard


def _finding(path_or_ref: str = "artifacts/http.jsonl") -> FindingArtifact:
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
                path_or_ref=path_or_ref,
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
    evidence_path = tmp_path / "http.jsonl"
    evidence_path.write_text(
        '{"url":"https://docs.google.com/document/d/owned/edit?access_token=secret","authorization":"Bearer abcdefghijklmnopqrstuvwxyz"}\n',
        encoding="utf-8",
    )
    finding_path = tmp_path / "finding.json"
    finding_path.write_text(_finding(str(evidence_path)).model_dump_json(), encoding="utf-8")
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        '{"domain":"google.com","total_assets":3,"phase_runs":[{"phase":"subfinder","success":true},{"phase":"httpx","success":false,"errors":["timeout"]}]}',
        encoding="utf-8",
    )
    registry_path = tmp_path / "program-registry.json"
    registry_path.write_text(
        json.dumps(
            {
                "version": "test",
                "programs": [
                    {
                        "id": "google-vrp",
                        "name": "Google VRP",
                        "platform": "Google Bug Hunters",
                        "policy_url": "https://bughunters.google.com/",
                        "captured_date": "2026-05-16",
                        "safe_harbor": {
                            "summary": "Owned-account testing only.",
                            "source_reference": "test",
                        },
                        "scope": [
                            {
                                "id": "google-web",
                                "kind": "domain",
                                "value": "google.com",
                                "reward_eligible": True,
                                "source_reference": "test",
                            }
                        ],
                        "exclusions": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    data = build_dashboard_data(
        asset_files=[assets_path],
        approval_queues=[approvals_path],
        findings=[finding_path],
        summary_json=[summary_path],
        program_registries=[registry_path],
        now=datetime(2026, 5, 16, tzinfo=UTC),
    )

    assert len(data.assets) == 1
    assert len(data.approvals) == 1
    assert len(data.findings) == 1
    assert len(data.evidence) == 1
    assert len(data.artifacts) == 1
    assert data.artifacts[0].source_exists is True
    assert "access_token=secret" not in data.artifacts[0].preview
    assert "Bearer abcdefghijklmnopqrstuvwxyz" not in data.artifacts[0].preview
    assert data.summaries[0].values["phase_runs"] == "2"
    assert [entry.status for entry in data.timeline] == ["ok", "failed"]
    assert data.programs[0].reward_eligible_scope_count == 1


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
    assert 'id="approval-review"' in html
    assert 'id="artifact-browser"' in html
    assert 'id="triage"' in html
    assert 'id="timeline"' in html
    assert 'id="programs"' in html
    assert "Approve" in html
    assert "Block" in html
    assert output_path.exists()
