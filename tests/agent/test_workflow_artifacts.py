import pytest

from vrp_hunt.agent import (
    AgentAction,
    AgentPlan,
    AgentRunResult,
    AgentObservation,
    ObservationConversionError,
    BrowserWorkflow,
    CredentialSet,
    EvidenceCapture,
    OwnedAccount,
    OwnedTestObject,
    SecretRef,
    build_owned_account_browser_workflow,
    build_submission_assistance,
    artifact_bundle_from_agent_run,
    finding_from_observation,
    finding_report_from_observation,
    report_draft_from_finding,
)
from vrp_hunt.recon import Asset


def test_credential_set_redacts_secret_material() -> None:
    credentials = CredentialSet(
        accounts=[
            OwnedAccount(
                account_id="acct-a",
                role="owner",
                username="vrp-test-a@example.com",
                password=SecretRef(name="password-a", env_var="VRP_TEST_A_PASSWORD"),
                cookies={"SID": SecretRef(name="sid-a", env_var="VRP_TEST_A_SID")},
            )
        ],
        test_objects=[
            OwnedTestObject(
                object_id="obj-a",
                owner_account_id="acct-a",
                object_type="profile",
                target_ref="https://accounts.google.com/profile",
            )
        ],
    )

    summary = credentials.redacted_summary()

    assert "VRP_TEST_A_PASSWORD" in str(summary)
    assert "secret" not in str(summary).lower()
    assert "[REDACTED]" in str(summary)


def test_browser_workflow_forbids_account_creation() -> None:
    workflow = build_owned_account_browser_workflow(
        target="https://accounts.google.com/profile",
        account_id="acct-a",
    )

    assert workflow.burp_proxy == "http://127.0.0.1:8080"
    assert any(step.kind == "screenshot" for step in workflow.steps)

    with pytest.raises(ValueError, match="account creation"):
        BrowserWorkflow(
            target="https://accounts.google.com/profile",
            account_id="acct-a",
            steps=workflow.steps,
            allows_account_creation=True,
        )


def test_evidence_capture_records_redacted_items() -> None:
    capture = EvidenceCapture(finding_id="finding-1")

    capture.record_http_log("evidence/http.txt")
    capture.record_screenshot("evidence/screenshot.png")
    capture.record_video("evidence/repro.webm")

    assert [item.kind for item in capture.items] == ["http", "screenshot", "video"]
    assert all(item.redacted for item in capture.items)


def test_observation_converts_to_finding_report_and_submission_assistance() -> None:
    action = AgentAction(
        action_type="owned_account_authz",
        target_kind="url",
        target="https://accounts.google.com/profile",
        intended_action="idor_testing",
        description="Compare owned account A and B profile requests.",
        sends_traffic=True,
        request_budget=1,
        requires_human_approval=True,
        human_approved=True,
    )
    observation = AgentObservation(
        action_id=action.action_id,
        success=True,
        notes=["redacted Burp request/response pair captured"],
        assets=[
            Asset(
                kind="url",
                value="https://accounts.google.com/profile",
                source="burp",
            )
        ],
        request_count=1,
    )

    finding = finding_from_observation(action, observation)
    report = report_draft_from_finding(finding, researcher_accounts=["acct-a", "acct-b"])
    assistance = build_submission_assistance(report)

    assert finding.bug_class == "idor"
    assert finding.evidence
    assert report.evidence.finding_id == finding.finding_id
    assert finding.title in assistance.markdown
    assert any(item.name == "owned-accounts" and item.passed for item in assistance.checklist)


def test_observation_converts_to_structured_artifact_record() -> None:
    action = AgentAction(
        action_type="idor_validation",
        target_kind="url",
        target="https://accounts.google.com/profile",
        intended_action="idor_testing",
        description="Prepare owned-account IDOR validation.",
        requires_human_approval=True,
        human_approved=True,
    )
    observation = AgentObservation(
        action_id=action.action_id,
        success=True,
        notes=["redacted HTTP evidence captured"],
        assets=[Asset(kind="url", value=action.target, source="burp")],
    )

    artifact = finding_report_from_observation(
        action,
        observation,
        researcher_accounts=["acct-owner", "acct-actor"],
        component="Accounts profile",
    )

    assert artifact.action_id == action.action_id
    assert artifact.finding.bug_class == "idor"
    assert artifact.finding.evidence
    assert artifact.report.finding.finding_id == artifact.finding.finding_id
    assert artifact.report.target_info.component == "Accounts profile"
    assert artifact.report.evidence.items == artifact.finding.evidence


def test_agent_run_converts_to_artifact_bundle_and_skips_unsafe_observations() -> None:
    safe_action = AgentAction(
        action_type="xss_validation",
        target_kind="url",
        target="https://accounts.google.com/profile?q=test",
        intended_action="xss_testing",
        description="Prepare owned-account XSS validation.",
    )
    unsafe_action = AgentAction(
        action_type="oauth_validation",
        target_kind="url",
        target="https://accounts.google.com/o/oauth2/v2/auth",
        intended_action="oauth_testing",
        description="Prepare OAuth validation.",
    )
    plan = AgentPlan(actions=[safe_action, unsafe_action])
    result = AgentRunResult(
        observations=[
            AgentObservation(
                action_id=safe_action.action_id,
                success=True,
                notes=["redacted screenshot captured"],
            ),
            AgentObservation(
                action_id=unsafe_action.action_id,
                success=True,
                notes=["unexpected data appeared"],
                third_party_data_seen=True,
            ),
            AgentObservation(
                action_id="missing-action",
                success=True,
                notes=["orphan observation"],
            ),
        ]
    )

    bundle = artifact_bundle_from_agent_run(
        plan,
        result,
        researcher_accounts=["acct-a"],
    )

    assert len(bundle.artifacts) == 1
    assert bundle.findings[0].bug_class == "xss"
    assert bundle.reports[0].finding.finding_id == bundle.findings[0].finding_id
    assert len(bundle.skipped) == 2
    assert any("third-party data" in item for item in bundle.skipped)
    assert any("no matching action" in item for item in bundle.skipped)


def test_observations_with_third_party_data_are_rejected() -> None:
    action = AgentAction(
        action_type="oauth_validation",
        target_kind="url",
        target="https://accounts.google.com/o/oauth2/v2/auth",
        intended_action="oauth_testing",
        description="Prepare OAuth validation.",
    )
    observation = AgentObservation(
        action_id=action.action_id,
        success=True,
        third_party_data_seen=True,
    )

    with pytest.raises(ObservationConversionError, match="third-party data"):
        finding_from_observation(action, observation)
