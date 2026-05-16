from hypothesis import given, settings, strategies as st

from vrp_hunt.guardrails.normalization import NormalizationError, host_matches_domain, normalize_host


@given(st.text())
@settings(max_examples=200)
def test_normalize_host_never_raises_unexpected_errors(value: str) -> None:
    try:
        normalize_host(value)
    except NormalizationError:
        pass


@given(st.text(min_size=1, max_size=80))
@settings(max_examples=200)
def test_google_match_requires_boundary(value: str) -> None:
    try:
        normalized = normalize_host(value)
    except NormalizationError:
        return
    if host_matches_domain(normalized, "google.com"):
        assert normalized.host == "google.com" or normalized.host.endswith(".google.com")
        assert normalized.registrable_domain == "google.com"
