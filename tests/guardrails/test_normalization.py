import pytest

from vrp_hunt.guardrails.normalization import (
    NormalizationError,
    host_matches_domain,
    normalize_host,
    normalize_url,
)


def test_host_case_and_trailing_dot_normalize() -> None:
    normalized = normalize_host("GOOGLE.COM.")
    assert normalized.host == "google.com"
    assert normalized.registrable_domain == "google.com"


def test_url_userinfo_uses_real_host() -> None:
    normalized = normalize_url("https://google.com@evil.com/path")
    assert normalized.host == "evil.com"
    assert not host_matches_domain(normalized, "google.com")


@pytest.mark.parametrize("host", ["notgoogle.com", "google.com.evil.com"])
def test_boundary_bypass_hosts_do_not_match_google(host: str) -> None:
    normalized = normalize_host(host)
    assert not host_matches_domain(normalized, "google.com")


@pytest.mark.parametrize("host", ["bad host.com", "a..google.com", "google.com/path"])
def test_invalid_hosts_raise(host: str) -> None:
    with pytest.raises(NormalizationError):
        normalize_host(host)
