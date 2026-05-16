"""Convert agent observations into finding and report artifacts."""

from __future__ import annotations

from typing import cast
from urllib.parse import urlsplit

from pydantic import Field

from vrp_hunt.agent.models import AgentAction, AgentObservation, AgentPlan, AgentRunResult
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.playbooks import BugClass, EvidenceItem, FindingArtifact, get_playbook
from vrp_hunt.reporting import (
    EnvironmentInfo,
    EvidenceBundle,
    PocArtifact,
    Platform,
    ReportDraft,
    TargetInfo,
)


class ObservationConversionError(ValueError):
    """Raised when an observation cannot safely become report artifacts."""


class ObservationArtifact(StrictModel):
    """Structured artifacts derived from one agent observation."""

    action_id: str = Field(min_length=1)
    finding: FindingArtifact
    report: ReportDraft


class AgentArtifactBundle(StrictModel):
    """Structured findings and reports derived from an agent run."""

    artifacts: list[ObservationArtifact] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)

    @property
    def findings(self) -> list[FindingArtifact]:
        return [artifact.finding for artifact in self.artifacts]

    @property
    def reports(self) -> list[ReportDraft]:
        return [artifact.report for artifact in self.artifacts]


BUG_CLASS_BY_ACTION = {
    "idor_testing": "idor",
    "csrf_testing": "csrf",
    "oauth_testing": "oauth",
    "xsleak_testing": "xsleak",
    "xss_testing": "xss",
}


def finding_from_observation(action: AgentAction, observation: AgentObservation) -> FindingArtifact:
    if observation.third_party_data_seen:
        raise ObservationConversionError("observations with third-party data cannot become findings")
    bug_class = _bug_class_for_action(action)
    playbook = get_playbook(bug_class)
    category = (
        action.candidate.hypothesis.category
        if action.candidate is not None
        else playbook.reward_category
    )
    evidence = _evidence_from_observation(action, observation)
    return FindingArtifact(
        title=f"Draft {bug_class.upper()} candidate on {action.target}",
        bug_class=bug_class,
        reward_category=category,
        status="needs_review" if observation.success else "draft",
        target=action.target,
        affected_assets=observation.assets,
        preconditions=[*playbook.preconditions, *playbook.account_setup],
        impact="Potential impact requires human validation using owned accounts only.",
        reproduction_steps=[
            action.description,
            "Validate with the matching playbook and stop if non-owned data appears.",
        ],
        evidence=evidence,
        own_account_only=action.researcher_owned_account,
        third_party_data_touched=False,
        notes=observation.notes,
    )


def finding_report_from_observation(
    action: AgentAction,
    observation: AgentObservation,
    *,
    researcher_accounts: list[str],
    product: str = "Google",
    component: str = "VRP target",
    platform: Platform = "web",
    client: str = "Chrome stable with Burp proxy",
    operating_system: str = "research workstation",
    observed_from: str = "owned-account validation environment",
) -> ObservationArtifact:
    finding = finding_from_observation(action, observation)
    report = report_draft_from_finding(
        finding,
        researcher_accounts=researcher_accounts,
        product=product,
        component=component,
        platform=platform,
        client=client,
        operating_system=operating_system,
        observed_from=observed_from,
    )
    return ObservationArtifact(
        action_id=action.action_id,
        finding=finding,
        report=report,
    )


def artifact_bundle_from_agent_run(
    plan: AgentPlan,
    result: AgentRunResult,
    *,
    researcher_accounts: list[str],
    product: str = "Google",
    component: str = "VRP target",
    platform: Platform = "web",
    client: str = "Chrome stable with Burp proxy",
    operating_system: str = "research workstation",
    observed_from: str = "owned-account validation environment",
) -> AgentArtifactBundle:
    actions_by_id = {action.action_id: action for action in plan.actions}
    artifacts: list[ObservationArtifact] = []
    skipped: list[str] = []

    for observation in result.observations:
        action = actions_by_id.get(observation.action_id)
        if action is None:
            skipped.append(f"{observation.action_id}: no matching action")
            continue
        try:
            artifacts.append(
                finding_report_from_observation(
                    action,
                    observation,
                    researcher_accounts=researcher_accounts,
                    product=product,
                    component=component,
                    platform=platform,
                    client=client,
                    operating_system=operating_system,
                    observed_from=observed_from,
                )
            )
        except ObservationConversionError as exc:
            skipped.append(f"{observation.action_id}: {exc}")

    return AgentArtifactBundle(artifacts=artifacts, skipped=skipped)


def report_draft_from_finding(
    finding: FindingArtifact,
    *,
    researcher_accounts: list[str],
    product: str = "Google",
    component: str = "VRP target",
    platform: Platform = "web",
    client: str = "Chrome stable with Burp proxy",
    operating_system: str = "research workstation",
    observed_from: str = "owned-account validation environment",
) -> ReportDraft:
    target_info = TargetInfo(
        product=product,
        component=component,
        platform=platform,
        hostnames=_hostnames_for_target(finding.target),
    )
    environment = EnvironmentInfo(
        researcher_accounts=researcher_accounts,
        client=client,
        operating_system=operating_system,
        observed_from=observed_from,
    )
    evidence = EvidenceBundle(
        finding_id=finding.finding_id,
        target_info=target_info,
        environment=environment,
        items=finding.evidence,
    )
    poc = PocArtifact(
        title=f"Manual owned-account reproduction for {finding.title}",
        automated=False,
        steps=finding.reproduction_steps,
        expected_output="Owned-account impact is observable without third-party data access.",
        automated_poc_feasible=False,
        infeasible_reason="Manual validation keeps account state, secrets, and replay volume controlled.",
    )
    return ReportDraft(
        finding=finding,
        target_info=target_info,
        environment=environment,
        evidence=evidence,
        poc=poc,
        vulnerability_description=finding.title,
        attack_preconditions=finding.preconditions,
        impact_analysis=finding.impact,
        reproduction_steps=finding.reproduction_steps,
        reproduction_output="Pending final human-reviewed validation evidence.",
        researcher_response_plan="Respond to VRP triage questions within three business days.",
    )


def _bug_class_for_action(action: AgentAction) -> BugClass:
    if action.candidate is not None:
        candidate_bug_class = action.candidate.hypothesis.bug_class.lower()
        if candidate_bug_class in {"authz", "authorization"}:
            return "idor"
        if candidate_bug_class in {"xss", "csrf", "idor", "xsleak", "oauth", "server_side"}:
            return cast(BugClass, candidate_bug_class)
    mapped = BUG_CLASS_BY_ACTION.get(action.intended_action, "server_side")
    return cast(BugClass, mapped)


def _evidence_from_observation(
    action: AgentAction,
    observation: AgentObservation,
) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    for index, note in enumerate(observation.notes, start=1):
        evidence.append(
            EvidenceItem(
                kind="note",
                description=note,
                path_or_ref=f"agent-observation:{action.action_id}:note:{index}",
                redacted=True,
            )
        )
    for asset in observation.assets:
        evidence.append(
            EvidenceItem(
                kind="note",
                description=f"{asset.kind} asset from {asset.source}",
                path_or_ref=asset.fingerprint,
                redacted=True,
            )
        )
    return evidence


def _hostnames_for_target(target: str) -> list[str]:
    host = urlsplit(target).hostname
    if host:
        return [host]
    if "/" not in target:
        return [target]
    return []
