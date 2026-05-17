import json
from pathlib import Path

from vrp_hunt.recon import (
    historical_url_assets,
    ingest_historical_url_files,
    load_historical_url_records,
)


def test_wayback_cdx_import_redacts_query_values_and_scopes(tmp_path: Path) -> None:
    wayback_path = tmp_path / "wayback.json"
    wayback_path.write_text(
        json.dumps(
            [
                ["timestamp", "original", "mimetype", "statuscode", "digest"],
                ["20260101000000", "https://accounts.google.com/profile?id=secret&tab=a", "text/html", "200", "ABC"],
                ["20260101000001", "https://evil.com/path", "text/html", "200", "DEF"],
            ]
        ),
        encoding="utf-8",
    )

    records, warnings, total = load_historical_url_records(
        wayback_path,
        source="wayback",
        scope_domains=["google.com"],
    )

    assert warnings == []
    assert total == 2
    assert len(records) == 1
    assert records[0].url == "https://accounts.google.com/profile"
    assert records[0].parameter_names == ["id", "tab"]
    assert records[0].status_code == "200"
    assert records[0].digest == "ABC"


def test_urlscan_import_extracts_nested_page_urls(tmp_path: Path) -> None:
    urlscan_path = tmp_path / "urlscan.json"
    urlscan_path.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "page": {"url": "https://mail.google.com/mail/u/0/"},
                        "task": {"time": "2026-01-02T00:00:00Z"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    records, warnings, total = load_historical_url_records(
        urlscan_path,
        source="urlscan",
        scope_domains=["google.com"],
    )

    assert warnings == []
    assert total == 1
    assert records[0].url == "https://mail.google.com/mail/u/0/"
    assert records[0].source == "urlscan"


def test_common_crawl_jsonl_import_and_assets(tmp_path: Path) -> None:
    common_path = tmp_path / "cc.jsonl"
    common_path.write_text(
        '{"url":"https://www.google.com/app.js","mime":"application/javascript","status":"200"}\n'
        '{"url":"https://www.google.com/api/profile?token=secret","mime":"application/json","status":"200"}\n',
        encoding="utf-8",
    )

    report = ingest_historical_url_files(
        common_crawl_files=[common_path],
        scope_domains=["google.com"],
    )

    assert report.total_inputs == 2
    assert report.total_records == 2
    assets_by_value = {asset.value: asset for asset in report.assets}
    assert assets_by_value["https://www.google.com/app.js"].kind == "javascript"
    assert assets_by_value["https://www.google.com/api/profile"].kind == "endpoint"
    assert assets_by_value["https://www.google.com/api/profile"].metadata["parameter_names"] == "token"
    assert assets_by_value["https://www.google.com/api/profile"].metadata["query_values_redacted"] == "true"


def test_historical_url_assets_preserve_source_metadata(tmp_path: Path) -> None:
    common_path = tmp_path / "cc.txt"
    common_path.write_text("https://www.google.com/search?q=redacted\n", encoding="utf-8")
    records, _, _ = load_historical_url_records(
        common_path,
        source="common_crawl",
        scope_domains=["google.com"],
    )

    assets = historical_url_assets(records)

    assert assets[0].source == "historical-url-import"
    assert assets[0].metadata["historical_source"] == "common_crawl"
    assert assets[0].metadata["parameter_names"] == "q"
