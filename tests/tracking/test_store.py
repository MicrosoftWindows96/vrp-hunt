from datetime import date
from pathlib import Path

from tests.reporting.test_linter import complete_report
from vrp_hunt.tracking import SubmissionStore, create_submission
from vrp_hunt.triage import RewardInput, estimate_reward


def test_store_round_trips_submission_record(tmp_path: Path) -> None:
    store = SubmissionStore(tmp_path / "submissions.json")
    reward_input = RewardInput(domain_tier="T2", category="S2b")
    record = create_submission(
        complete_report(),
        reward_input=reward_input,
        submitted_at=date(2026, 5, 16),
        dedupe_notes="No matching public duplicate found before submission.",
        first_reporter_notes="Submitted immediately after validation.",
    )

    store.upsert(record)
    loaded = store.get(record.submission_id)

    assert loaded.submission_id == record.submission_id
    assert loaded.status == "submitted"
    assert loaded.estimated_reward == estimate_reward(reward_input)
    assert loaded.dedupe_notes is not None


def test_status_update_records_history(tmp_path: Path) -> None:
    store = SubmissionStore(tmp_path / "submissions.json")
    record = create_submission(
        complete_report(),
        reward_input=RewardInput(domain_tier="T2", category="S2b"),
        submitted_at=date(2026, 5, 16),
    )
    store.upsert(record)

    updated = store.update_status(
        record.submission_id,
        "triaged",
        changed_at=date(2026, 5, 20),
        note="Google triage accepted the report for review.",
    )

    assert updated.status == "triaged"
    assert updated.status_history[-1].status == "triaged"
    assert updated.status_history[-1].note == "Google triage accepted the report for review."
