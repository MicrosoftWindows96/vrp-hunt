from vrp_hunt.playbooks import EvidenceItem, FindingArtifact
from vrp_hunt.reporting import (
    EnvironmentInfo,
    EvidenceBundle,
    PocArtifact,
    ReportDraft,
    TargetInfo,
    lint_report,
)


def complete_report() -> ReportDraft:
    finding = FindingArtifact(
        title="IDOR exposes owned test profile address",
        bug_class="idor",
        reward_category="S2b",
        target="https://accounts.google.com/profile",
        preconditions=["two owned test accounts with separate profile records"],
        impact="An attacker can read the saved address from another owned test profile.",
        reproduction_steps=[
            "Sign in as owned test account A and create a profile address.",
            "Sign in as owned test account B and request account A's test record id.",
            "Observe that account B receives account A's profile address response.",
        ],
        evidence=[
            EvidenceItem(
                kind="http",
                description="redacted Burp request/response pair",
                path_or_ref="evidence/idor-http-redacted.txt",
            ),
        ],
    )
    target_info = TargetInfo(
        product="Google Account",
        component="Profile address API",
        hostnames=["accounts.google.com"],
        platform="web",
        version="observed 2026-05-16",
    )
    environment = EnvironmentInfo(
        researcher_accounts=["vrp-test-a", "vrp-test-b"],
        client="Chrome stable with Burp proxy",
        operating_system="macOS",
        observed_from="research workstation",
    )
    evidence = EvidenceBundle(
        finding_id=finding.finding_id,
        target_info=target_info,
        environment=environment,
        items=finding.evidence,
    )
    poc = PocArtifact(
        title="Owned-account IDOR clean-state check",
        automated=True,
        command="uv run python poc_idor_check.py --account-a vrp-test-a --account-b vrp-test-b",
        steps=[
            "Create fresh records in both owned accounts.",
            "Run the command with test account aliases only.",
        ],
        expected_output="The script prints only account A's researcher-created address.",
        clean_state_reproducible=True,
    )
    return ReportDraft(
        finding=finding,
        target_info=target_info,
        environment=environment,
        evidence=evidence,
        poc=poc,
        vulnerability_description=(
            "The profile address API authorizes by record existence but not by the owning "
            "account. An owned account can request another owned account's profile record id."
        ),
        attack_preconditions=[
            "Attacker controls a Google account.",
            "Attacker knows or can obtain the target profile record id.",
        ],
        impact_analysis=(
            "The flaw exposes saved profile address data across accounts. The observed impact "
            "is limited to researcher-created records in owned test accounts."
        ),
        reproduction_steps=finding.reproduction_steps,
        reproduction_output=(
            "The unauthorized request returns HTTP 200 with the owned test address fields "
            "for account A while authenticated as account B."
        ),
        researcher_response_plan="Respond to triage questions within three business days.",
    )


def issue_messages(report: ReportDraft) -> list[str]:
    return [issue.message for issue in lint_report(report).issues]


def test_complete_report_passes_exceptional_quality_gate() -> None:
    result = lint_report(complete_report())

    assert result.passed
    assert result.quality_multiplier == "1.2"
    assert {item.dimension for item in result.dimension_results} == {
        "vulnerability_description",
        "attack_preconditions",
        "impact_analysis",
        "reproduction_steps_poc",
        "target_info",
        "reproduction_output",
        "researcher_responsiveness",
        "evidence",
        "conciseness_precision",
    }


def test_linter_rejects_missing_impact_analysis() -> None:
    report = complete_report().model_copy(update={"impact_analysis": "theoretical"})

    result = lint_report(report)

    assert not result.passed
    assert any("impact" in message for message in issue_messages(report))


def test_linter_rejects_missing_target_info() -> None:
    report = complete_report()
    target_info = report.target_info.model_copy(update={"hostnames": []})
    report = report.model_copy(update={"target_info": target_info})

    result = lint_report(report)

    assert not result.passed
    assert any("target" in message for message in issue_messages(report))


def test_linter_rejects_missing_automated_poc_when_feasible() -> None:
    report = complete_report()
    poc = report.poc.model_copy(update={"automated": False, "command": None})
    report = report.model_copy(update={"poc": poc})

    result = lint_report(report)

    assert not result.passed
    assert any("automated PoC" in message for message in issue_messages(report))


def test_linter_rejects_unredacted_evidence() -> None:
    report = complete_report()
    item = EvidenceItem(
        kind="http",
        description="raw request containing a token",
        path_or_ref="evidence/raw.txt",
        redacted=False,
    )
    evidence = report.evidence.model_copy(update={"items": [item]})
    report = report.model_copy(update={"evidence": evidence})

    result = lint_report(report)

    assert not result.passed
    assert any("redacted" in message for message in issue_messages(report))


def test_linter_rejects_placeholder_or_ai_slop_language() -> None:
    report = complete_report().model_copy(
        update={"vulnerability_description": "As an AI, TODO maybe insecure."}
    )

    result = lint_report(report)

    assert not result.passed
    assert any("placeholder" in message for message in issue_messages(report))
