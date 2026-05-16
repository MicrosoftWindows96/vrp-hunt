from decimal import Decimal

import pytest
from pydantic import ValidationError

from vrp_hunt.playbooks import FindingArtifact, create_finding_from_candidate
from vrp_hunt.recon import Asset
from vrp_hunt.triage import BugHypothesis, build_triage_queue


def test_create_finding_from_triage_candidate() -> None:
    asset = Asset(kind="url", value="https://accounts.google.com/", source="test")
    candidate = build_triage_queue(
        [asset],
        [BugHypothesis(bug_class="idor", category="S2b", confidence=Decimal("0.8"))],
    )[0]

    finding = create_finding_from_candidate(candidate)

    assert finding.bug_class == "idor"
    assert finding.target == asset.value
    assert finding.own_account_only is True
    assert finding.third_party_data_touched is False
    assert finding.reproduction_steps


def test_finding_rejects_third_party_data() -> None:
    with pytest.raises(ValidationError):
        FindingArtifact(
            title="bad",
            bug_class="idor",
            reward_category="S2b",
            target="https://example.com",
            preconditions=["owned account"],
            impact="impact",
            reproduction_steps=["step"],
            third_party_data_touched=True,
        )


def test_finding_rejects_non_owned_account_scope() -> None:
    with pytest.raises(ValidationError):
        FindingArtifact(
            title="bad",
            bug_class="idor",
            reward_category="S2b",
            target="https://example.com",
            preconditions=["owned account"],
            impact="impact",
            reproduction_steps=["step"],
            own_account_only=False,
        )
