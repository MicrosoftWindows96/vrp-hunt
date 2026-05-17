import pytest

from vrp_hunt.recon import Asset
from vrp_hunt.web_recon import interesting_app_assets, rank_interesting_apps


def test_rank_interesting_apps_scores_auth_api_js_cookie_form_and_tech() -> None:
    report = rank_interesting_apps(
        [
            Asset(kind="endpoint", value="https://accounts.google.com/o/oauth2/v2/auth", source="api-spec-import"),
            Asset(kind="javascript", value="https://accounts.google.com/app.js", source="endpoint-mine"),
            Asset(
                kind="url",
                value="https://accounts.google.com/login",
                source="httpx",
                metadata={"header:set-cookie": "SID=redacted", "form_count": "2"},
            ),
            Asset(kind="technology", value="React", source="technology-fingerprint", parent="https://accounts.google.com/"),
            Asset(
                kind="note",
                value="app-change:https://accounts.google.com/login",
                source="app-change-monitor",
                parent="https://accounts.google.com/login",
            ),
            Asset(kind="endpoint", value="https://api.google.com/v1/search", source="api-spec-import"),
            Asset(kind="endpoint", value="https://evil.com/api", source="api-spec-import"),
        ],
        scope_domains=["google.com"],
    )

    top = report.apps[0]

    assert top.host == "accounts.google.com"
    assert top.score > report.apps[1].score
    assert {"auth", "api", "javascript", "cookie", "form", "technology", "change"} <= set(top.signal_categories)
    assert top.technologies == ["React"]
    assert "skipped third-party host evil.com" in report.warnings
    assert report.assets[0].kind == "note"
    assert report.assets[0].source == "interesting-app-rank"


def test_rank_interesting_apps_requires_scope() -> None:
    with pytest.raises(ValueError, match="at least one scope domain"):
        rank_interesting_apps([], scope_domains=[])


def test_interesting_app_assets_dedupes() -> None:
    report = rank_interesting_apps(
        [Asset(kind="endpoint", value="https://www.google.com/api/me", source="api-spec-import")],
        scope_domains=["google.com"],
    )

    assets = interesting_app_assets([*report.apps, *report.apps])

    assert [asset.value for asset in assets] == ["interesting-app:https://www.google.com/"]
