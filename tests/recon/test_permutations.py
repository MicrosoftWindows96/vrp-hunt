import pytest
from pydantic import ValidationError

from vrp_hunt.recon import SubdomainPermutationConfig, generate_subdomain_permutations


def test_subdomain_permutations_generate_scoped_candidates_with_caps() -> None:
    report = generate_subdomain_permutations(
        ["accounts.google.com", "evil.com"],
        config=SubdomainPermutationConfig(
            scope_domains=["google.com"],
            words=["admin", "login"],
            max_candidates=4,
            max_per_seed=4,
        ),
    )

    assert report.total_seeds == 1
    assert report.total_candidates == 4
    assert report.truncated
    assert [candidate.host for candidate in report.candidates] == [
        "admin.google.com",
        "accounts-admin.google.com",
        "admin-accounts.google.com",
        "login.google.com",
    ]
    assert report.assets[0].source == "subdomain-permutation"
    assert any("out-of-scope" in warning for warning in report.warnings)


def test_subdomain_permutations_do_not_mutate_root_seed_leftmost_label() -> None:
    report = generate_subdomain_permutations(
        ["google.com"],
        config=SubdomainPermutationConfig(
            scope_domains=["google.com"],
            words=["admin"],
            max_candidates=10,
            max_per_seed=10,
        ),
    )

    assert [candidate.host for candidate in report.candidates] == ["admin.google.com"]


def test_subdomain_permutation_config_rejects_unbounded_caps() -> None:
    with pytest.raises(ValidationError):
        SubdomainPermutationConfig(
            scope_domains=["google.com"],
            words=["admin"],
            max_candidates=5000,
        )


def test_subdomain_permutation_config_rejects_bad_words() -> None:
    with pytest.raises(ValidationError):
        SubdomainPermutationConfig(scope_domains=["google.com"], words=["bad/word"])
