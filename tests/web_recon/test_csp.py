from vrp_hunt.web_recon import build_csp_import_bundle, extract_csp_from_text


def test_extract_csp_from_header_redacts_scoped_endpoint_sources() -> None:
    report = extract_csp_from_text(
        "https://www.google.com/app",
        """
        Content-Security-Policy: default-src 'self'; connect-src https://api.google.com/v1?token=secret https://evil.com/api; report-uri /csp/report?id=owned-a
        """,
        scope_domains=["google.com"],
    )

    values = {asset.value for asset in report.assets}
    api_asset = next(asset for asset in report.assets if asset.value == "https://api.google.com/v1")
    report_asset = next(asset for asset in report.assets if asset.value == "https://www.google.com/csp/report")

    assert report.policy_count == 1
    assert "https://www.google.com/" in values
    assert "https://api.google.com/v1" in values
    assert "https://www.google.com/csp/report" in values
    assert "https://evil.com/api" not in values
    assert api_asset.kind == "endpoint"
    assert api_asset.metadata["parameter_names"] == "token"
    assert report_asset.metadata["parameter_names"] == "id"
    assert "secret" not in report.model_dump_json()
    assert report.warnings == ["policy 1 connect-src: skipped third-party host evil.com"]


def test_extract_csp_from_meta_tag_and_host_sources() -> None:
    report = extract_csp_from_text(
        "https://www.google.com/app",
        """
        <meta http-equiv="Content-Security-Policy"
          content="img-src *.google.com data:; form-action https://accounts.google.com/ServiceLogin">
        """,
        scope_domains=["google.com"],
    )

    host_asset = next(asset for asset in report.assets if asset.kind == "host")

    assert host_asset.value == "google.com"
    assert host_asset.metadata["wildcard_source"] == "true"
    assert "https://accounts.google.com/ServiceLogin" in {asset.value for asset in report.assets}


def test_extract_csp_from_raw_policy_defaults_scope_to_document_host() -> None:
    report = extract_csp_from_text(
        "https://www.google.com/app",
        "connect-src https://www.google.com/api https://api.google.com/v1",
    )

    assert {asset.value for asset in report.assets} == {"https://www.google.com/api"}
    assert report.warnings == ["policy 1 connect-src: skipped third-party host api.google.com"]


def test_build_csp_import_bundle_dedupes_assets() -> None:
    report_a = extract_csp_from_text("https://www.google.com/app", "connect-src https://www.google.com/api")
    report_b = extract_csp_from_text("https://www.google.com/app", "connect-src https://www.google.com/api")

    bundle = build_csp_import_bundle([report_a, report_b])

    assert bundle.report_count == 2
    assert bundle.policy_count == 2
    assert bundle.total_assets == 1
