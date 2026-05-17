import json

import pytest

from vrp_hunt.web_recon import (
    DeadHostSuppressionConfig,
    HostProbeDocument,
    analyze_host_availability,
    dead_host_suppression_assets,
)


def test_analyze_host_availability_suppresses_dead_hosts_and_redacts_queries() -> None:
    report = analyze_host_availability(
        [
            HostProbeDocument(
                source="httpx",
                evidence="httpx.jsonl",
                text="\n".join(
                    [
                        json.dumps(
                            {
                                "input": "https://dead.google.com/?token=secret",
                                "failed": True,
                                "error": "timeout",
                            }
                        ),
                        json.dumps(
                            {
                                "input": "dead.google.com",
                                "failed": True,
                                "error": "connection refused",
                            }
                        ),
                        json.dumps({"url": "https://alive.google.com/hidden", "status_code": 404}),
                        json.dumps(
                            {
                                "url": "https://quota.google.com/",
                                "status_code": 429,
                                "headers": {"Retry-After": "120"},
                            }
                        ),
                        json.dumps({"url": "https://evil.com/", "failed": True}),
                    ]
                ),
            )
        ],
        scope_domains=["google.com"],
        config=DeadHostSuppressionConfig(
            min_failures=2,
            suppress_after_failures=2,
            retry_budget=3,
            backoff_base_seconds=30.0,
            backoff_cap_seconds=300.0,
        ),
    )

    hosts = {host.host: host for host in report.hosts}

    assert report.total_inputs == 5
    assert report.total_records == 4
    assert report.suppressed_hosts == ["dead.google.com"]
    assert hosts["dead.google.com"].status == "dead"
    assert hosts["dead.google.com"].failure_streak == 2
    assert hosts["dead.google.com"].retry_allowed is False
    assert hosts["dead.google.com"].next_retry_delay_seconds == 60
    assert hosts["alive.google.com"].status == "alive"
    assert hosts["quota.google.com"].status == "backoff"
    assert hosts["quota.google.com"].retry_allowed is True
    assert hosts["quota.google.com"].next_retry_delay_seconds == 120
    assert report.assets[0].value == "dead-host:dead.google.com"
    assert "httpx.jsonl:5: skipped third-party host evil.com" in report.warnings
    assert "secret" not in report.model_dump_json()


def test_analyze_host_availability_loads_live_run_failures() -> None:
    report = analyze_host_availability(
        [
            HostProbeDocument(
                source="live_run",
                evidence="run.json",
                text=json.dumps(
                    {
                        "decisions": [
                            {"gate_decision": {"normalized_target": "https://run-dead.google.com/"}}
                        ],
                        "observations": [{"success": False, "assets": []}],
                    }
                ),
            )
        ],
        scope_domains=["google.com"],
        config=DeadHostSuppressionConfig(min_failures=1, suppress_after_failures=1),
    )

    assert report.suppressed_hosts == ["run-dead.google.com"]
    assert report.hosts[0].status == "dead"


def test_analyze_host_availability_requires_scope() -> None:
    with pytest.raises(ValueError, match="at least one scope domain"):
        analyze_host_availability([], scope_domains=[])


def test_dead_host_suppression_assets_dedupes() -> None:
    report = analyze_host_availability(
        [
            HostProbeDocument(
                evidence="httpx.jsonl",
                text="\n".join(
                    [
                        '{"input":"https://dead.google.com/","failed":true}',
                        '{"input":"https://dead.google.com/","failed":true}',
                    ]
                ),
            )
        ],
        scope_domains=["google.com"],
    )

    assets = dead_host_suppression_assets([*report.hosts, *report.hosts])

    assert [asset.value for asset in assets] == ["dead-host:dead.google.com"]
