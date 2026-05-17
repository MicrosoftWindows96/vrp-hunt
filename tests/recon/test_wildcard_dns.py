import pytest

from vrp_hunt.recon import (
    Asset,
    WildcardDnsProbe,
    detect_wildcard_dns_patterns,
    filter_wildcard_dns_assets,
    wildcard_probe_from_spec,
)


def test_wildcard_dns_filter_eliminates_matching_host_address_sets() -> None:
    assets = [
        Asset(
            kind="host",
            value="www.google.com",
            source="dns",
            metadata={"addresses": "142.250.1.1"},
        ),
        Asset(
            kind="host",
            value="random-looking.google.com",
            source="dns",
            metadata={"addresses": "203.0.113.10"},
        ),
    ]
    probes = [
        wildcard_probe_from_spec("probe-one.google.com=203.0.113.10"),
        wildcard_probe_from_spec("probe-two.google.com=203.0.113.10"),
    ]

    report = filter_wildcard_dns_assets(assets, probes)

    assert [asset.value for asset in report.kept_assets] == ["www.google.com"]
    assert [asset.value for asset in report.eliminated_assets] == ["random-looking.google.com"]
    assert report.patterns[0].domain == "google.com"
    assert report.decisions[1].matched_domain == "google.com"


def test_wildcard_dns_requires_repeated_matching_probes() -> None:
    probes = [WildcardDnsProbe(probe_host="one.google.com", domain="google.com", addresses=["203.0.113.10"])]

    patterns, warnings = detect_wildcard_dns_patterns(probes)

    assert patterns == []
    assert "need 2" in warnings[0]


def test_wildcard_probe_spec_rejects_bad_format() -> None:
    with pytest.raises(ValueError, match="expected HOST"):
        wildcard_probe_from_spec("probe.google.com")
