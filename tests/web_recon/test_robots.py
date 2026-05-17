from vrp_hunt.web_recon import build_robots_import_bundle, parse_robots_txt, robots_assets


def test_parse_robots_txt_extracts_scoped_redacted_assets() -> None:
    report = parse_robots_txt(
        "https://www.google.com/robots.txt?ignored=true",
        """
        User-agent: *
        User-agent: Googlebot
        Disallow: /private?id=owned-a&token=secret
        Allow: /public
        Crawl-delay: 5
        Sitemap: /sitemap.xml
        Host: www.google.com
        """,
        scope_domains=["google.com"],
    )

    values = {asset.value for asset in report.assets}
    private_asset = next(asset for asset in report.assets if asset.value == "https://www.google.com/private")

    assert report.robots_url == "https://www.google.com/robots.txt"
    assert report.rules[0].path == "/private"
    assert report.rules[0].parameter_names == ["id", "token"]
    assert "https://www.google.com/private" in values
    assert "https://www.google.com/public" in values
    assert "https://www.google.com/sitemap.xml" in values
    assert "robots-crawl-delay:https://www.google.com/robots.txt" in values
    assert "www.google.com" in values
    assert private_asset.metadata["parameter_names"] == "id,token"
    assert private_asset.metadata["query_values_redacted"] == "true"
    assert private_asset.metadata["user_agents"] == "*,googlebot"
    assert "secret" not in report.model_dump_json()


def test_parse_robots_txt_defaults_scope_to_robots_host() -> None:
    report = parse_robots_txt(
        "https://www.google.com/robots.txt",
        """
        Disallow: /owned
        Sitemap: https://evil.example/sitemap.xml
        Host: evil.example
        """,
    )

    values = {asset.value for asset in report.assets}

    assert "https://www.google.com/owned" in values
    assert "https://evil.example/sitemap.xml" not in values
    assert "evil.example" not in values
    assert report.warnings == [
        "skipped third-party host directive evil.example",
        "skipped third-party sitemap host evil.example",
    ]


def test_parse_robots_txt_warns_on_invalid_lines() -> None:
    report = parse_robots_txt(
        "https://www.google.com/robots.txt",
        """
        malformed
        User-agent: *
        Crawl-delay: later
        """,
    )

    assert report.assets == []
    assert report.warnings == [
        "line 2: ignored malformed directive",
        "line 4: invalid crawl-delay",
    ]


def test_robots_assets_recomputes_assets_for_new_scope() -> None:
    report = parse_robots_txt(
        "https://www.google.com/robots.txt",
        """
        Disallow: https://admin.google.com/private
        Disallow: https://evil.example/private
        """,
        scope_domains=["google.com"],
    )

    assets = robots_assets(report, scope_domains=["admin.google.com"])

    assert {asset.value for asset in assets} == {"https://admin.google.com/private"}


def test_build_robots_import_bundle_dedupes_assets_and_warnings() -> None:
    report_a = parse_robots_txt("https://www.google.com/robots.txt", "Disallow: /private")
    report_b = parse_robots_txt("https://www.google.com/robots.txt", "Disallow: /private")

    bundle = build_robots_import_bundle([report_a, report_b])

    assert bundle.report_count == 2
    assert bundle.total_assets == 1
    assert bundle.assets[0].value == "https://www.google.com/private"
