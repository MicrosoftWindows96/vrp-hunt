import json

import pytest

from vrp_hunt.web_recon import AppSnapshotDocument, app_change_assets, monitor_app_changes


def test_monitor_app_changes_diffs_saved_snapshots_without_query_values() -> None:
    report = monitor_app_changes(
        [
            AppSnapshotDocument(
                role="previous",
                evidence="previous.jsonl",
                text="\n".join(
                    [
                        json.dumps(
                            {
                                "url": "https://www.google.com/app",
                                "status_code": 200,
                                "title": "Old app",
                                "body_hash": "body1",
                                "headers": {"server": "gws", "x-build": "1"},
                                "javascript_hashes": ["js1"],
                            }
                        ),
                        json.dumps(
                            {
                                "url": "https://www.google.com/removed",
                                "status_code": 200,
                                "title": "Removed",
                                "body_hash": "removed",
                            }
                        ),
                    ]
                ),
            ),
            AppSnapshotDocument(
                role="current",
                evidence="current.jsonl",
                text="\n".join(
                    [
                        json.dumps(
                            {
                                "url": "https://www.google.com/app?id=owned-a&token=secret",
                                "status_code": 200,
                                "title": "New app",
                                "body_hash": "body2",
                                "headers": {"server": "gws", "x-build": "2"},
                                "js_hashes": ["js2"],
                            }
                        ),
                        json.dumps(
                            {
                                "url": "https://www.google.com/new",
                                "status_code": 200,
                                "title": "New",
                                "body_hash": "new",
                            }
                        ),
                        json.dumps({"url": "https://evil.com/app", "body_hash": "evil"}),
                    ]
                ),
            ),
        ],
        scope_domains=["google.com"],
    )

    changed = next(change for change in report.changes if change.url == "https://www.google.com/app")
    new = next(change for change in report.changes if change.url == "https://www.google.com/new")
    removed = next(change for change in report.changes if change.url == "https://www.google.com/removed")
    app_asset = next(asset for asset in report.assets if asset.value == "app-change:https://www.google.com/app")

    assert report.total_inputs == 5
    assert report.total_snapshots == 4
    assert report.total_changes == 3
    assert {"title", "body_hash", "header_hash", "javascript_hashes"} <= set(changed.changed_fields)
    assert new.change_type == "new"
    assert removed.change_type == "removed"
    assert app_asset.kind == "note"
    assert app_asset.source == "app-change-monitor"
    assert app_asset.parent == "https://www.google.com/app"
    assert "current.jsonl:3: skipped third-party host evil.com" in report.warnings
    assert "secret" not in report.model_dump_json()


def test_monitor_app_changes_warns_on_missing_url() -> None:
    report = monitor_app_changes(
        [
            AppSnapshotDocument(
                evidence="current.jsonl",
                text='{"title":"No URL","body_hash":"abc"}\n',
            )
        ],
        scope_domains=["google.com"],
    )

    assert report.snapshots == []
    assert report.warnings == ["current.jsonl:1: missing url"]


def test_monitor_app_changes_requires_scope() -> None:
    with pytest.raises(ValueError, match="at least one scope domain"):
        monitor_app_changes([], scope_domains=[])


def test_app_change_assets_dedupes() -> None:
    report = monitor_app_changes(
        [
            AppSnapshotDocument(
                evidence="current.jsonl",
                text='{"url":"https://www.google.com/","body_hash":"aaa"}\n',
            )
        ],
        scope_domains=["google.com"],
    )

    assets = app_change_assets([*report.changes, *report.changes])

    assert [asset.value for asset in assets] == ["app-change:https://www.google.com/"]
