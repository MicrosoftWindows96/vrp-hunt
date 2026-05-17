import pytest
from pydantic import ValidationError

from vrp_hunt.recon import (
    RecursivePassiveConfig,
    build_recursive_passive_plan,
    recursive_passive_assets,
)


def test_recursive_passive_plan_groups_child_zones() -> None:
    plan = build_recursive_passive_plan(
        [
            "a.mail.google.com",
            "b.mail.google.com",
            "x.accounts.google.com",
            "evil.com",
        ],
        config=RecursivePassiveConfig(
            seed_domains=["google.com"],
            min_hosts_per_zone=2,
            max_queries=10,
        ),
    )

    assert plan.total_hosts == 4
    assert len(plan.candidates) == 1
    assert plan.candidates[0].zone == "mail.google.com"
    assert plan.candidates[0].command == ["subfinder", "-d", "mail.google.com", "-oJ", "-silent"]


def test_recursive_passive_plan_respects_query_cap() -> None:
    plan = build_recursive_passive_plan(
        [
            "a.mail.google.com",
            "b.mail.google.com",
            "a.admin.google.com",
            "b.admin.google.com",
        ],
        config=RecursivePassiveConfig(
            seed_domains=["google.com"],
            min_hosts_per_zone=2,
            max_queries=1,
        ),
    )

    assert len(plan.candidates) == 1
    assert plan.truncated


def test_recursive_passive_assets_emit_note_assets() -> None:
    plan = build_recursive_passive_plan(
        ["a.mail.google.com", "b.mail.google.com"],
        config=RecursivePassiveConfig(seed_domains=["google.com"], min_hosts_per_zone=2),
    )

    assets = recursive_passive_assets(plan)

    assert assets[0].kind == "note"
    assert assets[0].source == "recursive-passive-plan"
    assert assets[0].metadata["zone"] == "mail.google.com"


def test_recursive_passive_config_rejects_unbounded_depth() -> None:
    with pytest.raises(ValidationError):
        RecursivePassiveConfig(seed_domains=["google.com"], max_depth=99)
