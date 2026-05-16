from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_ethics_checklist_required_terms() -> None:
    text = (ROOT / "docs" / "ethics-checklist.md").read_text(encoding="utf-8").lower()
    for term in ("owned", "third-party data", "coordinated disclosure", "sanctions"):
        assert term in text


def test_account_runbook_forbids_automation() -> None:
    text = (ROOT / "docs" / "test-account-runbook.md").read_text(encoding="utf-8").lower()
    assert "scripts for registration" in text
    assert "browser automation for account creation" in text
    assert "account farms" in text
