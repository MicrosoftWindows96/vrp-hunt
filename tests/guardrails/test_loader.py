from pathlib import Path

import pytest

from vrp_hunt.guardrails.loader import RulesetLoadError, load_ruleset


def test_load_default_ruleset() -> None:
    ruleset = load_ruleset()
    assert ruleset.version == "google-vrp-2026-05-16"
    assert any(rule.id == "allow-google-domain" for rule in ruleset.allow_rules)


def test_load_ruleset_rejects_unknown_fields(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        """
version: v
captured_date: 2026-05-16
source_digest_path: digest.md
digest_hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
allow_rules: []
deny_rules: []
ethics: {}
acquisition:
  blackout_days: 183
  domains: [withgoogle.com]
rate_limit_defaults:
  global_max_rps: 1.0
  per_host_max_rps: 1.0
  burst_size: 1
  retry_budget: 1
  backoff_base_seconds: 1.0
  backoff_cap_seconds: 2.0
  retry_strategy: full_jitter
  require_single_flight: true
  honor_robots_txt: true
  honor_retry_after: true
  user_agent_contact: contact
unexpected: true
""",
        encoding="utf-8",
    )
    with pytest.raises(RulesetLoadError):
        load_ruleset(rules_path, verify_digest=False)


def test_load_ruleset_rejects_malformed_yaml(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text("version: [", encoding="utf-8")
    with pytest.raises(RulesetLoadError):
        load_ruleset(rules_path, verify_digest=False)
