import pytest

from vrp_hunt.web_recon import build_sitemap_import_bundle, parse_sitemap_xml


def test_parse_sitemap_xml_extracts_scoped_redacted_url_assets() -> None:
    report = parse_sitemap_xml(
        "https://www.google.com/sitemap.xml?token=secret",
        """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url>
            <loc>https://www.google.com/account/profile?id=owned-a&amp;token=secret</loc>
            <lastmod>2026-05-16</lastmod>
            <changefreq>daily</changefreq>
            <priority>0.8</priority>
          </url>
          <url>
            <loc>https://static.google.com/logo.png</loc>
          </url>
          <url>
            <loc>https://evil.com/private</loc>
          </url>
        </urlset>
        """,
        scope_domains=["google.com"],
    )

    values = {asset.value for asset in report.assets}
    profile_asset = next(asset for asset in report.assets if asset.value == "https://www.google.com/account/profile")

    assert report.sitemap_url == "https://www.google.com/sitemap.xml"
    assert report.total_entries == 2
    assert "https://www.google.com/account/profile" in values
    assert "https://static.google.com/logo.png" in values
    assert "https://evil.com/private" not in values
    assert profile_asset.kind == "endpoint"
    assert profile_asset.metadata["parameter_names"] == "id,token"
    assert profile_asset.metadata["query_values_redacted"] == "true"
    assert profile_asset.metadata["lastmod"] == "2026-05-16"
    assert "secret" not in report.model_dump_json()
    assert report.warnings == ["url entry 3: skipped third-party host evil.com"]


def test_parse_sitemap_xml_extracts_sitemap_index_assets() -> None:
    report = parse_sitemap_xml(
        "https://www.google.com/sitemap.xml",
        """<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap>
            <loc>https://www.google.com/news-sitemap.xml</loc>
            <lastmod>2026-05-16</lastmod>
          </sitemap>
        </sitemapindex>
        """,
    )

    assert report.scope_domains == ["www.google.com"]
    assert report.entries[0].entry_type == "sitemap"
    assert report.assets[0].kind == "url"
    assert report.assets[0].value == "https://www.google.com/news-sitemap.xml"
    assert report.assets[0].metadata["sitemap_entry_type"] == "sitemap"


def test_parse_sitemap_xml_rejects_invalid_xml() -> None:
    with pytest.raises(ValueError, match="invalid sitemap XML"):
        parse_sitemap_xml("https://www.google.com/sitemap.xml", "<urlset>")


def test_build_sitemap_import_bundle_dedupes_assets() -> None:
    report_a = parse_sitemap_xml(
        "https://www.google.com/sitemap.xml",
        "<urlset><url><loc>https://www.google.com/path</loc></url></urlset>",
    )
    report_b = parse_sitemap_xml(
        "https://www.google.com/other-sitemap.xml",
        "<urlset><url><loc>https://www.google.com/path</loc></url></urlset>",
    )

    bundle = build_sitemap_import_bundle([report_a, report_b])

    assert bundle.report_count == 2
    assert bundle.total_entries == 2
    assert bundle.total_assets == 2
