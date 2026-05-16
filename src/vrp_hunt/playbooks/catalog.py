"""Default manual testing playbook catalog."""

from __future__ import annotations

from vrp_hunt.playbooks.models import BugClass, Playbook, PlaybookStep
from vrp_hunt.triage.models import RewardCategory


def default_playbooks() -> list[Playbook]:
    return [
        _playbook(
            "xss",
            "XSS and client-side code execution",
            "C0",
            ["Candidate is in scope and rendered in a browser context."],
            ["Use only dedicated owned test accounts and non-sensitive test data."],
            ["Proxy the owned-account browser session through Burp.", "Keep active scanner disabled unless explicitly reviewed."],
            ["Sandbox domains without sensitive-data impact are non-qualifying."],
        ),
        _playbook(
            "csrf",
            "CSRF state-change validation",
            "C1b",
            ["Candidate has a meaningful state-changing action."],
            ["Use two owned test accounts only when role separation is needed."],
            ["Capture original request and controlled replay in Burp Repeater."],
            ["Logout CSRF is non-qualifying."],
        ),
        _playbook(
            "idor",
            "IDOR and authorization testing",
            "S2b",
            ["Two owned test accounts exist with distinct test objects."],
            ["Use only researcher-created objects and records."],
            ["Compare authorized and unauthorized owned-account requests in Burp Comparer."],
            ["Stop immediately if non-owned data appears."],
        ),
        _playbook(
            "xsleak",
            "XSLeak side-channel validation",
            "C1b",
            ["Candidate has cross-origin observable behavior without needing victim data."],
            ["Use owned accounts as both attacker and victim roles."],
            ["Record timing/state observations without capturing private user content."],
            ["Theoretical impact without a valid scenario is non-qualifying."],
        ),
        _playbook(
            "oauth",
            "OAuth and consent-flow review",
            "C1b",
            ["Candidate involves OAuth, scopes, redirect URIs, or consent state."],
            ["Use test OAuth clients and owned accounts only."],
            ["Capture redirect and token-exchange boundaries without logging secrets."],
            ["OAuth-consent issues may receive fixed step-downs by scope sensitivity."],
        ),
        _playbook(
            "server_side",
            "Server-side bug class review",
            "S1",
            ["Candidate has server-side input handling or integration behavior."],
            ["Use non-destructive test data and stop before any disruptive action."],
            ["Use Burp Logger/Replayer only for minimal manual confirmation."],
            ["DoS, destructive testing, and data access beyond owned accounts are prohibited."],
        ),
    ]


def get_playbook(bug_class: BugClass) -> Playbook:
    for playbook in default_playbooks():
        if playbook.bug_class == bug_class:
            return playbook
    raise KeyError(bug_class)


def _playbook(
    bug_class: BugClass,
    title: str,
    reward_category: RewardCategory,
    preconditions: list[str],
    account_setup: list[str],
    burp_workflow: list[str],
    pitfalls: list[str],
) -> Playbook:
    return Playbook(
        bug_class=bug_class,
        title=title,
        reward_category=reward_category,
        preconditions=preconditions,
        account_setup=account_setup,
        burp_workflow=burp_workflow,
        steps=[
            PlaybookStep(
                title="Confirm scope and safety",
                instruction="Verify the candidate still passes the guardrail gate and uses only owned test-account state.",
                evidence=["gate decision", "test-account note"],
                stop_if=["target is out of scope", "test would touch non-owned data"],
            ),
            PlaybookStep(
                title="Capture baseline",
                instruction="Record the normal owned-account request/response or UI flow before changing variables.",
                evidence=["baseline HTTP exchange", "screen recording or note"],
            ),
            PlaybookStep(
                title="Perform minimal manual variation",
                instruction="Change one controlled variable at a time and observe only owned-account impact.",
                evidence=["changed request", "observed response", "impact note"],
                stop_if=["unexpected third-party data appears", "test becomes disruptive"],
            ),
        ],
        evidence_to_capture=[
            "target URL/app/component",
            "owned-account preconditions",
            "minimal reproduction steps",
            "impact bounded to owned accounts",
            "redacted HTTP evidence",
        ],
        non_qualifying_pitfalls=pitfalls,
        stop_conditions=[
            "non-owned data appears",
            "test requires high-volume traffic",
            "test risks disruption or damage",
            "target no longer passes guardrail gate",
        ],
    )
