import json

import pytest

from vrp_hunt.web_recon import build_api_spec_import_bundle, discover_api_spec_assets


def test_discover_openapi_assets_extracts_scoped_redacted_endpoints() -> None:
    report = discover_api_spec_assets(
        "https://www.google.com/openapi.json?token=secret",
        json.dumps(
            {
                "openapi": "3.0.3",
                "servers": [
                    {"url": "https://api.google.com"},
                    {"url": "https://evil.com"},
                ],
                "paths": {
                    "/v1/users/{id}": {
                        "get": {
                            "operationId": "getUser",
                            "tags": ["users"],
                            "parameters": [
                                {"name": "id", "in": "path"},
                                {"name": "includePrivate", "in": "query"},
                            ],
                        }
                    }
                },
            }
        ),
        scope_domains=["google.com"],
    )

    values = {asset.value for asset in report.assets}
    endpoint_asset = next(asset for asset in report.assets if asset.value == "https://api.google.com/v1/users/{id}")

    assert report.spec_url == "https://www.google.com/openapi.json"
    assert report.spec_kind == "openapi"
    assert report.total_endpoints == 1
    assert "https://api.google.com/v1/users/{id}" in values
    assert {"id", "includePrivate"} <= values
    assert endpoint_asset.metadata["operation_id"] == "getUser"
    assert endpoint_asset.metadata["tags"] == "users"
    assert endpoint_asset.metadata["parameter_names"] == "id,includePrivate"
    assert endpoint_asset.metadata["templated"] == "true"
    assert "GET /v1/users/{id}: skipped third-party host evil.com" in report.warnings
    assert "secret" not in report.model_dump_json()


def test_discover_swagger_yaml_assets() -> None:
    report = discover_api_spec_assets(
        "https://www.google.com/swagger.yaml",
        """swagger: "2.0"
host: api.google.com
basePath: /v2
schemes:
  - https
paths:
  /pets:
    get:
      operationId: listPets
      parameters:
        - name: page
          in: query
""",
        scope_domains=["google.com"],
    )

    assert report.spec_kind == "swagger"
    assert {endpoint.url for endpoint in report.endpoints} == {"https://api.google.com/v2/pets"}
    assert {asset.value for asset in report.assets} == {"https://api.google.com/v2/pets", "page"}


def test_discover_postman_collection_assets() -> None:
    report = discover_api_spec_assets(
        "https://www.google.com/postman.json",
        json.dumps(
            {
                "info": {
                    "name": "Owned collection",
                    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
                },
                "item": [
                    {
                        "name": "Search",
                        "request": {
                            "method": "POST",
                            "url": "https://api.google.com/v1/search?q=owned-a&token=secret",
                        },
                    },
                    {
                        "name": "Third party",
                        "request": {
                            "method": "GET",
                            "url": "https://evil.com/private",
                        },
                    },
                ],
            }
        ),
        scope_domains=["google.com"],
    )

    endpoint = report.endpoints[0]

    assert report.spec_kind == "postman"
    assert report.total_endpoints == 1
    assert endpoint.method == "POST"
    assert endpoint.url == "https://api.google.com/v1/search"
    assert endpoint.parameter_names == ["q", "token"]
    assert "request 2: skipped third-party host evil.com" in report.warnings
    assert "secret" not in report.model_dump_json()


def test_discover_api_spec_rejects_unsupported_document() -> None:
    with pytest.raises(ValueError, match="unsupported API spec"):
        discover_api_spec_assets("https://www.google.com/spec.json", "{}")


def test_build_api_spec_import_bundle_dedupes_assets() -> None:
    report = discover_api_spec_assets(
        "https://www.google.com/openapi.json",
        json.dumps({"openapi": "3.0.3", "paths": {"/api": {"get": {}}}}),
    )

    bundle = build_api_spec_import_bundle([report, report])

    assert bundle.report_count == 2
    assert bundle.total_endpoints == 2
    assert bundle.total_assets == 1
