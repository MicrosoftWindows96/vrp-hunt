from vrp_hunt.recon import (
    Asset,
    DnsRecord,
    cdn_waf_fingerprint_assets,
    fingerprint_cdn_waf,
)


def test_fingerprint_cdn_waf_from_http_headers() -> None:
    report = fingerprint_cdn_waf(
        [
            Asset(
                kind="url",
                value="https://www.google.com/",
                source="httpx",
                metadata={
                    "webserver": "cloudflare",
                    "header:cf-ray": "abc-LHR",
                },
            )
        ]
    )

    fingerprint = report.fingerprints[0]

    assert fingerprint.target == "www.google.com"
    assert fingerprint.provider == "Cloudflare"
    assert fingerprint.category == "cdn_waf"
    assert fingerprint.confidence > 0.96
    assert {signal.key for signal in fingerprint.signals} == {"webserver", "header:cf-ray"}


def test_fingerprint_cdn_waf_from_dns_cname() -> None:
    report = fingerprint_cdn_waf(
        [],
        dns_records=[
            DnsRecord(
                name="static.google.com",
                record_type="CNAME",
                value="d123.cloudfront.net",
                source="fixture",
            )
        ],
    )

    assert report.total_targets == 1
    assert report.fingerprints[0].provider == "Amazon CloudFront"
    assert report.fingerprints[0].category == "cdn"


def test_cdn_waf_fingerprint_assets_emit_technology_assets() -> None:
    report = fingerprint_cdn_waf(
        [
            Asset(
                kind="technology",
                value="AkamaiGHost",
                source="httpx",
                parent="https://assets.google.com/",
            )
        ]
    )

    assets = cdn_waf_fingerprint_assets(report)

    assert assets[0].kind == "technology"
    assert assets[0].value == "Akamai"
    assert assets[0].parent == "assets.google.com"
    assert assets[0].metadata["category"] == "cdn_waf"
