from datetime import UTC, datetime

from vrp_hunt.web_recon import build_security_txt_import_bundle, parse_security_txt


def test_parse_security_txt_redacts_contacts_and_extracts_scoped_links() -> None:
    report = parse_security_txt(
        "https://www.google.com/.well-known/security.txt?token=secret",
        """
        Contact: mailto:security@google.com
        Contact: https://bughunters.google.com/report?id=owned-a&token=secret
        Policy: https://www.google.com/about/appsecurity/
        Canonical: https://www.google.com/.well-known/security.txt
        Expires: 2027-12-31T23:59:59Z
        Preferred-Languages: en
        """,
        scope_domains=["google.com"],
        now=datetime(2026, 5, 16, tzinfo=UTC),
    )

    values = {asset.value for asset in report.assets}
    contact_url = next(asset for asset in report.assets if asset.value == "https://bughunters.google.com/report")

    assert report.security_txt_url == "https://www.google.com/.well-known/security.txt"
    assert report.total_records == 6
    assert "security-contact:mailto:google.com" in values
    assert "https://bughunters.google.com/report" in values
    assert "https://www.google.com/about/appsecurity/" in values
    assert "https://www.google.com/.well-known/security.txt" in values
    assert contact_url.metadata["parameter_names"] == "id,token"
    assert contact_url.metadata["query_values_redacted"] == "true"
    assert "security@google.com" not in report.model_dump_json()
    assert "secret" not in report.model_dump_json()
    assert report.warnings == []


def test_parse_security_txt_skips_third_party_url_assets() -> None:
    report = parse_security_txt(
        "https://www.google.com/.well-known/security.txt",
        """
        Contact: https://evil.com/report
        Policy: https://www.google.com/policy
        """,
        scope_domains=["google.com"],
    )

    values = {asset.value for asset in report.assets}

    assert "https://www.google.com/policy" in values
    assert "https://evil.com/report" not in values
    assert report.warnings == ["line 2: skipped third-party contact host evil.com"]


def test_parse_security_txt_warns_on_expired_or_malformed_files() -> None:
    report = parse_security_txt(
        "https://www.google.com/.well-known/security.txt",
        """
        malformed
        Expires: 2025-01-01T00:00:00Z
        """,
        now=datetime(2026, 5, 16, tzinfo=UTC),
    )

    assert report.expires_at == "2025-01-01T00:00:00Z"
    assert report.warnings == [
        "line 2: ignored malformed field",
        "security.txt is expired",
    ]


def test_build_security_txt_import_bundle_dedupes_assets() -> None:
    report_a = parse_security_txt(
        "https://www.google.com/.well-known/security.txt",
        "Policy: https://www.google.com/policy",
    )
    report_b = parse_security_txt(
        "https://www.google.com/security.txt",
        "Policy: https://www.google.com/policy",
    )

    bundle = build_security_txt_import_bundle([report_a, report_b])

    assert bundle.report_count == 2
    assert bundle.total_records == 2
    assert bundle.total_assets == 2
