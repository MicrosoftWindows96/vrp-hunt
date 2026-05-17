from pathlib import Path

import pytest

from vrp_hunt.recon import (
    PassiveSourceCatalog,
    PassiveSourceCatalogError,
    PassiveSourceConfig,
    evaluate_passive_source_health,
    load_passive_source_catalog,
    passive_source_env_template,
)


def test_load_default_passive_source_catalog() -> None:
    catalog = load_passive_source_catalog()

    assert catalog.version == "passive-sources-2026-05-16"
    assert any(source.id == "github-code-search" for source in catalog.sources)


def test_passive_source_health_redacts_env_values() -> None:
    catalog = PassiveSourceCatalog(
        version="test",
        sources=[
            PassiveSourceConfig(
                id="github",
                name="GitHub",
                categories=["code"],
                required_env=["GITHUB_TOKEN"],
                optional_env=["GITHUB_ORG"],
                source_reference="test",
            ),
            PassiveSourceConfig(
                id="crtsh",
                name="crt.sh",
                categories=["certificate"],
                source_reference="test",
            ),
            PassiveSourceConfig(
                id="disabled",
                name="Disabled",
                categories=["search"],
                enabled=False,
                required_env=["DISABLED_KEY"],
                source_reference="test",
            ),
        ],
    )

    report = evaluate_passive_source_health(
        catalog,
        env={"GITHUB_TOKEN": "secret-value", "GITHUB_ORG": "owned-org"},
        include_disabled=True,
    )

    assert report.total_sources == 3
    assert report.ready_sources == 2
    assert report.disabled_sources == 1
    github = next(source for source in report.sources if source.id == "github")
    assert github.status == "ready"
    assert github.configured_env == ["GITHUB_TOKEN"]
    assert github.configured_optional_env == ["GITHUB_ORG"]
    assert "secret-value" not in report.model_dump_json()


def test_passive_source_health_reports_missing_env() -> None:
    catalog = PassiveSourceCatalog(
        version="test",
        sources=[
            PassiveSourceConfig(
                id="shodan",
                name="Shodan",
                categories=["search"],
                required_env=["SHODAN_API_KEY"],
                source_reference="test",
            )
        ],
    )

    report = evaluate_passive_source_health(catalog, env={})

    assert report.ready_sources == 0
    assert report.missing_env_sources == 1
    assert report.sources[0].status == "missing_env"
    assert report.sources[0].missing_env == ["SHODAN_API_KEY"]


def test_passive_source_env_template_lists_unique_names() -> None:
    catalog = PassiveSourceCatalog(
        version="test",
        sources=[
            PassiveSourceConfig(
                id="one",
                name="One",
                categories=["search"],
                required_env=["API_KEY"],
                optional_env=["ORG"],
                source_reference="test",
            ),
            PassiveSourceConfig(
                id="two",
                name="Two",
                categories=["url"],
                required_env=["API_KEY"],
                source_reference="test",
            ),
        ],
    )

    template = passive_source_env_template(catalog)

    assert template.count("API_KEY=") == 1
    assert "ORG=" in template


def test_load_passive_source_catalog_rejects_malformed_yaml(tmp_path: Path) -> None:
    catalog_path = tmp_path / "sources.yaml"
    catalog_path.write_text("version: [", encoding="utf-8")

    with pytest.raises(PassiveSourceCatalogError):
        load_passive_source_catalog(catalog_path)
