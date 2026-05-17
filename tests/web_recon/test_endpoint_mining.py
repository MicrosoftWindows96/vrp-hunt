from datetime import UTC, datetime

from vrp_hunt.web_recon import (
    EndpointMiningConfig,
    WebContentDocument,
    mine_javascript_and_api_endpoints,
)


def test_endpoint_mining_resolves_assets_and_redacts_query_values() -> None:
    report = mine_javascript_and_api_endpoints(
        [
            WebContentDocument(
                url="https://www.google.com/app?page=seed",
                body="""
                <script src="/static/app.js?build=123"></script>
                fetch("/api/v1/profile?id=owned-a&token=secret")
                const graph = "https://www.google.com/graphql?query=viewer";
                """,
            )
        ],
        config=EndpointMiningConfig(scope_domains=["google.com"]),
        now=datetime(2026, 5, 16, tzinfo=UTC),
    )

    values = {asset.value for asset in report.assets}

    assert "https://www.google.com/static/app.js" in values
    assert "https://www.google.com/api/v1/profile" in values
    assert "https://www.google.com/graphql" in values
    assert {"id", "token", "query"} <= {
        asset.value for asset in report.assets if asset.kind == "parameter"
    }
    assert not any("secret" in asset.value for asset in report.assets)
    assert report.document_urls == ["https://www.google.com/app"]


def test_endpoint_mining_filters_third_party_absolute_urls() -> None:
    report = mine_javascript_and_api_endpoints(
        [
            WebContentDocument(
                url="https://www.google.com/",
                body='fetch("https://evil.example/api/private")',
            )
        ],
        config=EndpointMiningConfig(scope_domains=["google.com"]),
    )

    assert not report.assets
    assert report.warnings == ["skipped third-party host evil.example"]


def test_endpoint_mining_can_keep_redacted_secret_pattern_notes() -> None:
    report = mine_javascript_and_api_endpoints(
        [
            WebContentDocument(
                url="https://www.google.com/app.js",
                body="const apiKey = 'AIza12345678901234567890';",
            )
        ]
    )

    notes = [asset for asset in report.assets if asset.kind == "note"]
    assert notes
    assert notes[0].value == "potential-secret-pattern:api_key"
    assert notes[0].metadata["redacted"] == "true"
