import json

from vrp_hunt.web_recon import build_graphql_import_bundle, discover_graphql_endpoints


def test_discover_graphql_endpoints_from_saved_content() -> None:
    report = discover_graphql_endpoints(
        "https://www.google.com/app.js",
        """
        fetch("https://api.google.com/graphql?token=secret", { body: "{ __typename }" });
        fetch("https://evil.com/graphql");
        fetch("/api/query?id=owned-a", { body: "query Viewer { viewer { id } }" });
        """,
        scope_domains=["google.com"],
    )

    values = {asset.value for asset in report.assets}
    absolute_asset = next(asset for asset in report.assets if asset.value == "https://api.google.com/graphql")
    relative_asset = next(asset for asset in report.assets if asset.value == "https://www.google.com/api/query")

    assert report.total_candidates == 2
    assert "https://api.google.com/graphql" in values
    assert "https://www.google.com/api/query" in values
    assert absolute_asset.metadata["parameter_names"] == "token"
    assert relative_asset.metadata["parameter_names"] == "id"
    assert report.introspection_plans[0].approval_required
    assert report.introspection_plans[0].sends_traffic
    assert "skipped third-party GraphQL host evil.com" in report.warnings
    assert "secret" not in report.model_dump_json()


def test_discover_graphql_endpoint_from_introspection_response() -> None:
    report = discover_graphql_endpoints(
        "https://api.google.com/graphql",
        json.dumps({"data": {"__schema": {"queryType": {"name": "Query"}}}}),
        scope_domains=["google.com"],
    )

    assert report.candidates[0].evidence_type == "document-url"
    assert report.candidates[0].confidence == "high"
    assert report.total_candidates == 1


def test_discover_graphql_defaults_scope_to_document_host() -> None:
    report = discover_graphql_endpoints(
        "https://www.google.com/app.js",
        'fetch("https://api.google.com/graphql"); fetch("/graphql");',
    )

    assert {asset.value for asset in report.assets} == {"https://www.google.com/graphql"}
    assert report.warnings == ["skipped third-party GraphQL host api.google.com"]


def test_build_graphql_import_bundle_dedupes_assets_and_plans() -> None:
    report = discover_graphql_endpoints(
        "https://www.google.com/app.js",
        'fetch("/graphql");',
    )

    bundle = build_graphql_import_bundle([report, report])

    assert bundle.report_count == 2
    assert bundle.total_candidates == 2
    assert bundle.total_assets == 1
    assert len(bundle.introspection_plans) == 1
