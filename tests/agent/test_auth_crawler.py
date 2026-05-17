from datetime import UTC, datetime

import pytest

from vrp_hunt.agent import (
    OwnedAccountCrawlConfig,
    OwnedAccountCrawlPage,
    build_owned_account_crawl_plan,
)


def test_owned_account_crawl_feeds_idor_oauth_and_csrf_validators() -> None:
    result = build_owned_account_crawl_plan(
        [
            OwnedAccountCrawlPage(
                account_id="owned-a",
                url="https://docs.google.com/document/d/owned/edit?usp=sharing",
                body="""
                <a href="https://docs.google.com/document/d/owned-b/edit?secret=drop">doc</a>
                <a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&redirect_uri=https://www.google.com/cb&scope=openid">oauth</a>
                <form method="post" action="/document/d/owned/update?debug=1">
                  <input name="csrf_token" value="redacted">
                  <input name="title" value="owned">
                </form>
                """,
            )
        ],
        config=OwnedAccountCrawlConfig(scope_domains=["google.com"]),
        now=datetime(2026, 5, 16, tzinfo=UTC),
    )

    action_types = {action.action_type for action in result.validation_plan.actions}
    values = {asset.value for asset in result.assets}

    assert {"idor_validation", "oauth_validation", "csrf_validation"} <= action_types
    assert "https://docs.google.com/document/d/owned-b/edit" in values
    assert "https://accounts.google.com/o/oauth2/v2/auth" in values
    assert not any("secret=drop" in asset.value for asset in result.assets)
    assert result.forms[0].has_csrf_token
    assert result.forms[0].csrf_token_names == ["csrf_token"]


def test_owned_account_crawl_filters_out_of_scope_links() -> None:
    result = build_owned_account_crawl_plan(
        [
            OwnedAccountCrawlPage(
                account_id="owned-a",
                url="https://docs.google.com/document/d/owned/edit",
                body='<a href="https://evil.example/private">skip</a>',
            )
        ],
        config=OwnedAccountCrawlConfig(scope_domains=["google.com"]),
    )

    assert not result.assets
    assert result.validation_plan.actions == []
    assert result.warnings == ["skipped out-of-scope crawl URL host evil.example"]


def test_owned_account_crawl_rejects_third_party_snapshot_data() -> None:
    with pytest.raises(ValueError, match="third-party data"):
        OwnedAccountCrawlPage(
            account_id="owned-a",
            url="https://docs.google.com/document/d/owned/edit",
            third_party_data_present=True,
        )
