from decimal import Decimal

from vrp_hunt.recon import Asset
from vrp_hunt.triage import BugHypothesis, build_triage_queue


def test_queue_orders_by_expected_value() -> None:
    assets = [
        Asset(kind="url", value="https://www.google.com/", source="test"),
        Asset(kind="url", value="https://accounts.google.com/", source="test"),
    ]
    hypotheses = [
        BugHypothesis(bug_class="xss", category="C0", confidence=Decimal("0.5")),
        BugHypothesis(bug_class="idor", category="S2b", confidence=Decimal("0.8")),
    ]

    queue = build_triage_queue(assets, hypotheses)

    assert queue[0].asset.value == "https://accounts.google.com/"
    assert queue[0].expected_value > queue[-1].expected_value
    assert queue[0].rank_reason


def test_queue_is_deterministic_for_ties() -> None:
    assets = [
        Asset(kind="url", value="https://b.google.com/", source="test"),
        Asset(kind="url", value="https://a.google.com/", source="test"),
    ]
    hypotheses = [BugHypothesis(bug_class="xss", category="C0")]

    queue = build_triage_queue(assets, hypotheses)

    assert [candidate.asset.value for candidate in queue] == [
        "https://a.google.com/",
        "https://b.google.com/",
    ]
