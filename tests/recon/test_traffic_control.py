from vrp_hunt.guardrails import RateLimitPolicy
from vrp_hunt.recon import (
    Asset,
    HostRequestBudgetPolicy,
    RunCacheEntry,
    build_request_budget_ledger,
    build_run_cache_report,
    build_traffic_control_plan,
    request_fingerprint,
    robots_policies_from_assets,
    traffic_request_from_target,
)


def test_budget_ledger_flags_global_host_and_repeat_limits() -> None:
    records = [
        traffic_request_from_target("https://www.google.com/admin", source="test"),
        traffic_request_from_target("https://www.google.com/admin?token=secret", source="test"),
        traffic_request_from_target("https://mail.google.com/", source="test"),
    ]
    clean_records = [record for record in records if record is not None]

    report = build_request_budget_ledger(
        clean_records,
        policy=HostRequestBudgetPolicy(
            global_request_budget=2,
            per_host_request_budget=1,
            max_repeat_target_count=1,
        ),
    )

    assert report.global_over_budget is True
    assert "host budget exceeded: www.google.com" in report.violations
    assert "repeat target exceeded: https://www.google.com/admin" in report.violations
    assert "global request budget exceeded" in report.violations


def test_run_cache_detects_existing_hits_and_current_duplicates() -> None:
    first = traffic_request_from_target("https://www.google.com/admin", source="test")
    duplicate = traffic_request_from_target("https://www.google.com/admin?token=secret", source="test")
    cached = traffic_request_from_target("https://mail.google.com/", source="test")
    assert first is not None
    assert duplicate is not None
    assert cached is not None
    existing = RunCacheEntry(
        fingerprint=request_fingerprint(cached),
        method=cached.method,
        normalized_target=cached.normalized_target,
        host=cached.host,
        source="prior",
    )

    report = build_run_cache_report([first, duplicate, cached], existing_entries=[existing])

    assert [decision.decision for decision in report.decisions] == ["miss", "duplicate", "hit"]
    assert report.new_entry_count == 1


def test_traffic_plan_applies_scope_robots_cache_and_rate_schedule() -> None:
    first = traffic_request_from_target("https://www.google.com/admin", source="test")
    second = traffic_request_from_target("https://www.google.com/public", source="test")
    third = traffic_request_from_target("https://evil.com/", source="test")
    assert first is not None
    assert second is not None
    assert third is not None
    robots_assets = [
        Asset(
            kind="endpoint",
            value="https://www.google.com/admin",
            source="robots-txt",
            parent="https://www.google.com/robots.txt",
            metadata={"directive": "disallow"},
        ),
        Asset(
            kind="note",
            value="robots-crawl-delay:https://www.google.com/robots.txt",
            source="robots-txt-crawl-delay",
            parent="https://www.google.com/robots.txt",
            metadata={"delay_seconds": "7"},
        ),
    ]

    report = build_traffic_control_plan(
        [first, second, third],
        scope_domains=["google.com"],
        rate_policy=RateLimitPolicy(global_max_rps=1.0, per_host_max_rps=1.0),
        robots_assets=robots_assets,
    )

    by_target = {item.normalized_target: item for item in report.schedule.scheduled}

    assert report.total_inputs == 3
    assert report.requests == [first, second]
    assert "skipped third-party host evil.com" in report.warnings
    assert by_target["https://www.google.com/admin"].blocked is True
    assert by_target["https://www.google.com/admin"].block_reason == "robots disallow:/admin"
    assert by_target["https://www.google.com/public"].scheduled_after_seconds == 0
    assert report.schedule.robots_policies[0].crawl_delay_seconds == 7
    assert "token=secret" not in report.model_dump_json()


def test_robots_policies_from_assets_extracts_delay_and_disallow() -> None:
    policies = robots_policies_from_assets(
        [
            Asset(
                kind="endpoint",
                value="https://www.google.com/private",
                source="robots-txt",
                parent="https://www.google.com/robots.txt",
                metadata={"directive": "disallow"},
            ),
            Asset(
                kind="note",
                value="robots-crawl-delay:https://www.google.com/robots.txt",
                source="robots-txt-crawl-delay",
                parent="https://www.google.com/robots.txt",
                metadata={"delay_seconds": "3"},
            ),
        ]
    )

    assert policies[0].host == "www.google.com"
    assert policies[0].crawl_delay_seconds == 3
    assert policies[0].disallowed_paths == ["/private"]
