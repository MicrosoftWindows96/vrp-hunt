from vrp_hunt.reporting import render_markdown_report
from tests.reporting.test_linter import complete_report


def test_renderer_outputs_submission_sections() -> None:
    markdown = render_markdown_report(complete_report())

    assert "## Vulnerability Description" in markdown
    assert "## Attack Preconditions" in markdown
    assert "## Impact Analysis" in markdown
    assert "## Reproduction Steps" in markdown
    assert "## Proof of Concept" in markdown
    assert "## Target Information" in markdown
    assert "## Reproduction Output" in markdown
    assert "accounts.google.com" in markdown
