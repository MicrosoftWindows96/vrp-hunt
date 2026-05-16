"""Finding artifact helpers."""

from __future__ import annotations

from vrp_hunt.playbooks.catalog import get_playbook
from vrp_hunt.playbooks.models import BugClass, FindingArtifact
from vrp_hunt.triage.models import TriageCandidate


def create_finding_from_candidate(candidate: TriageCandidate) -> FindingArtifact:
    playbook = get_playbook(_bug_class_key(candidate.hypothesis.bug_class))
    return FindingArtifact(
        title=f"{playbook.title}: {candidate.asset.value}",
        bug_class=playbook.bug_class,
        reward_category=candidate.hypothesis.category,
        target=candidate.asset.value,
        affected_assets=[candidate.asset],
        preconditions=playbook.preconditions,
        impact="Describe concrete impact observed only in owned test-account data.",
        reproduction_steps=[step.instruction for step in playbook.steps],
        notes=[candidate.rank_reason, candidate.reward.explanation],
    )


def _bug_class_key(value: str) -> BugClass:
    normalized = value.lower().replace("-", "_").replace(" ", "_")
    aliases: dict[str, BugClass] = {
        "authorization": "idor",
        "authz": "idor",
        "idor": "idor",
        "xss": "xss",
        "csrf": "csrf",
        "xsleak": "xsleak",
        "xs_leak": "xsleak",
        "oauth": "oauth",
        "rce": "server_side",
        "sqli": "server_side",
        "xxe": "server_side",
        "deserialization": "server_side",
        "server_side": "server_side",
    }
    if normalized not in aliases:
        raise KeyError(value)
    return aliases[normalized]
