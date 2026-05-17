from datetime import UTC, datetime, timedelta

from vrp_hunt.recon import Asset, score_asset, score_assets


def test_score_asset_uses_source_kind_metadata_and_freshness() -> None:
    now = datetime(2026, 5, 16, tzinfo=UTC)
    asset = Asset(
        kind="url",
        value="https://www.google.com",
        source="httpx",
        parent="www.google.com",
        metadata={"status_code": "200"},
        first_seen=now - timedelta(days=1),
        last_seen=now,
    )

    score = score_asset(asset, now=now)

    assert score.confidence > 0.9
    assert score.freshness == 1.0
    assert score.priority > 0.9
    assert any("status_code_boost" in reason for reason in score.reasons)


def test_score_assets_sorts_high_priority_first() -> None:
    now = datetime(2026, 5, 16, tzinfo=UTC)
    fresh_http = Asset(
        kind="url",
        value="https://www.google.com",
        source="httpx",
        last_seen=now,
    )
    stale_note = Asset(
        kind="note",
        value="old note",
        source="unknown",
        last_seen=now - timedelta(days=120),
    )

    report = score_assets([stale_note, fresh_http], now=now)

    assert report.total_assets == 2
    assert report.scores[0].asset.value == "https://www.google.com"
    assert report.scores[1].asset.value == "old note"
    assert report.scores[1].freshness == 0.15


def test_score_asset_uses_subdomain_source_attribution() -> None:
    now = datetime(2026, 5, 16, tzinfo=UTC)
    single_source = Asset(kind="host", value="one.google.com", source="subfinder", last_seen=now)
    attributed = Asset(
        kind="host",
        value="www.google.com",
        source="subfinder",
        metadata={"sources": "crtsh,chaos", "source_count": "2"},
        last_seen=now,
    )

    single_score = score_asset(single_source, now=now)
    attributed_score = score_asset(attributed, now=now)

    assert attributed_score.confidence > single_score.confidence
    assert attributed_score.attributed_sources == ["subfinder", "crtsh", "chaos"]
    assert any("multi_source_boost" in reason for reason in attributed_score.reasons)
