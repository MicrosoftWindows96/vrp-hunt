import json

import pytest

from vrp_hunt.web_recon import (
    ScreenshotManifestDocument,
    analyze_screenshot_manifests,
    screenshot_analysis_assets,
)


def test_analyze_screenshot_manifests_clusters_and_diffs() -> None:
    report = analyze_screenshot_manifests(
        [
            ScreenshotManifestDocument(
                role="previous",
                evidence="previous.jsonl",
                text="\n".join(
                    [
                        json.dumps(
                            {
                                "url": "https://www.google.com/app",
                                "visual_hash": "aaa111",
                                "title": "Old app",
                                "status_code": 200,
                            }
                        ),
                        json.dumps(
                            {
                                "url": "https://www.google.com/removed",
                                "visual_hash": "removed",
                                "title": "Removed",
                                "status_code": 200,
                            }
                        ),
                    ]
                ),
            ),
            ScreenshotManifestDocument(
                role="current",
                evidence="current.jsonl",
                text="\n".join(
                    [
                        json.dumps(
                            {
                                "url": "https://www.google.com/app?id=owned-a&token=secret",
                                "visual_hash": "bbb222",
                                "title": "New app",
                                "screenshot_path": "screens/app.png",
                                "width": 1440,
                                "height": 900,
                            }
                        ),
                        json.dumps(
                            {
                                "url": "https://mail.google.com/app",
                                "visual_hash": "bbb222",
                                "title": "New app",
                                "screenshot_path": "screens/mail.png",
                            }
                        ),
                        json.dumps({"url": "https://evil.com/app", "visual_hash": "evil"}),
                    ]
                ),
            ),
        ],
        scope_domains=["google.com"],
    )

    cluster = next(item for item in report.clusters if item.representative_hash == "bbb222")
    changed = next(item for item in report.diffs if item.url == "https://www.google.com/app")
    removed = next(item for item in report.diffs if item.url == "https://www.google.com/removed")
    app_asset = next(asset for asset in report.assets if asset.value == "https://www.google.com/app")

    assert report.total_observations == 4
    assert cluster.observation_count == 2
    assert cluster.hosts == ["mail.google.com", "www.google.com"]
    assert changed.diff_type == "changed"
    assert changed.previous_hash == "aaa111"
    assert changed.current_hash == "bbb222"
    assert removed.diff_type == "removed"
    assert app_asset.kind == "url"
    assert app_asset.metadata["parameter_names"] == "id,token"
    assert app_asset.metadata["query_values_redacted"] == "true"
    assert "current.jsonl:3: skipped third-party host evil.com" in report.warnings
    assert "secret" not in report.model_dump_json()


def test_analyze_screenshot_manifests_warns_on_missing_hash() -> None:
    report = analyze_screenshot_manifests(
        [
            ScreenshotManifestDocument(
                evidence="current.jsonl",
                text='{"url":"https://www.google.com/","title":"No hash"}\n',
            )
        ],
        scope_domains=["google.com"],
    )

    assert report.observations == []
    assert report.warnings == ["current.jsonl:1: missing visual or content hash"]


def test_analyze_screenshot_manifests_requires_scope() -> None:
    with pytest.raises(ValueError, match="at least one scope domain"):
        analyze_screenshot_manifests([], scope_domains=[])


def test_screenshot_analysis_assets_dedupes() -> None:
    report = analyze_screenshot_manifests(
        [
            ScreenshotManifestDocument(
                evidence="current.jsonl",
                text='{"url":"https://www.google.com/","visual_hash":"aaa"}\n',
            )
        ],
        scope_domains=["google.com"],
    )

    assets = screenshot_analysis_assets(report.observations, report.clusters, report.diffs)

    assert {asset.value for asset in assets} == {
        "https://www.google.com/",
        "screenshot-cluster:cluster-0001",
        "screenshot-diff:https://www.google.com/",
    }
