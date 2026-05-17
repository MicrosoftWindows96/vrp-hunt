import json

import pytest

from vrp_hunt.web_recon import (
    TechnologyMetadataDocument,
    fingerprint_technology_metadata,
    technology_fingerprint_assets,
)


def test_fingerprint_httpx_metadata_extracts_scoped_technologies_and_headers() -> None:
    report = fingerprint_technology_metadata(
        [
            TechnologyMetadataDocument(
                source="httpx",
                evidence="httpx.jsonl",
                text="\n".join(
                    [
                        json.dumps(
                            {
                                "url": "https://www.google.com/?token=secret",
                                "technologies": ["GFE", {"name": "React", "version": "19"}],
                                "headers": {"server": "gws", "x-powered-by": "Express"},
                                "cdn_name": "google",
                            }
                        ),
                        json.dumps(
                            {
                                "url": "https://evil.com/",
                                "technologies": ["ThirdParty"],
                            }
                        ),
                    ]
                ),
            )
        ],
        scope_domains=["google.com"],
    )

    names = {fingerprint.name for fingerprint in report.fingerprints}
    gfe_asset = next(asset for asset in report.assets if asset.value == "GFE")

    assert report.total_inputs == 2
    assert {"GFE", "React", "gws", "Express", "google"} <= names
    assert "ThirdParty" not in names
    assert gfe_asset.kind == "technology"
    assert gfe_asset.metadata["parameter_names"] == "token"
    assert gfe_asset.metadata["query_values_redacted"] == "true"
    assert "httpx.jsonl:2: skipped third-party host evil.com" in report.warnings
    assert "secret" not in report.model_dump_json()


def test_fingerprint_wappalyzer_metadata_extracts_versions_and_categories() -> None:
    report = fingerprint_technology_metadata(
        [
            TechnologyMetadataDocument(
                source="wappalyzer",
                evidence="wappalyzer.json",
                text=json.dumps(
                    {
                        "url": "https://www.google.com/app",
                        "technologies": [
                            {
                                "name": "Next.js",
                                "version": "16.0",
                                "confidence": 100,
                                "categories": [{"name": "Web frameworks"}],
                            }
                        ],
                        "apps": {
                            "React": {
                                "version": "19",
                                "confidence": 95,
                                "categories": [{"name": "JavaScript frameworks"}],
                            }
                        },
                    }
                ),
            )
        ],
        scope_domains=["google.com"],
    )

    by_name = {fingerprint.name: fingerprint for fingerprint in report.fingerprints}

    assert by_name["Next.js"].version == "16.0"
    assert by_name["Next.js"].confidence == "100"
    assert by_name["Next.js"].categories == ["Web frameworks"]
    assert by_name["React"].version == "19"
    assert by_name["React"].categories == ["JavaScript frameworks"]


def test_fingerprint_technology_metadata_requires_scope() -> None:
    with pytest.raises(ValueError, match="at least one scope domain"):
        fingerprint_technology_metadata([], scope_domains=[])


def test_technology_fingerprint_assets_dedupes() -> None:
    report = fingerprint_technology_metadata(
        [
            TechnologyMetadataDocument(
                source="httpx",
                evidence="httpx.jsonl",
                text='{"url":"https://www.google.com/","technologies":["GFE","GFE"]}\n',
            )
        ],
        scope_domains=["google.com"],
    )

    assets = technology_fingerprint_assets([*report.fingerprints, *report.fingerprints])

    assert [asset.value for asset in assets] == ["GFE"]
