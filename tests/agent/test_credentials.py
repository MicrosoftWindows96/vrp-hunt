import pytest

from vrp_hunt.agent import CookieRef, CredentialSet, OwnedAccount, OwnedTestObject, SecretRef


def test_cookie_refs_keep_values_as_redacted_secret_references() -> None:
    cookie = CookieRef(
        name="SID",
        value=SecretRef(name="sid-cookie", purpose="cookie", env_var="VRP_TEST_SID"),
        domain="accounts.google.com",
        same_site="lax",
    )

    summary = cookie.redacted_summary()

    assert summary["name"] == "SID"
    assert summary["domain"] == "accounts.google.com"
    assert "VRP_TEST_SID" in str(summary)
    assert "[REDACTED]" in str(summary)
    assert "secret-value" not in str(summary)


def test_cookie_ref_rejects_unsafe_cookie_metadata() -> None:
    with pytest.raises(ValueError, match="SameSite=None"):
        CookieRef(
            name="SID",
            value=SecretRef(name="sid-cookie", purpose="cookie", env_var="VRP_TEST_SID"),
            secure=False,
            same_site="none",
        )

    with pytest.raises(ValueError, match="cookie name"):
        CookieRef(
            name="SID=bad",
            value=SecretRef(name="sid-cookie", purpose="cookie", env_var="VRP_TEST_SID"),
        )


def test_owned_account_handles_roles_and_legacy_cookie_refs() -> None:
    account = OwnedAccount(
        account_id="acct-a",
        role="attacker",
        secondary_roles=["viewer"],
        username="vrp-test-a@example.com",
        cookies={"SID": SecretRef(name="sid-a", purpose="cookie", env_var="VRP_TEST_A_SID")},
    )

    assert account.roles == ("attacker", "viewer")
    assert account.has_role("viewer")
    assert account.cookie_refs()[0].name == "SID"


def test_owned_account_rejects_unowned_or_ambiguous_role_metadata() -> None:
    with pytest.raises(ValueError, match="researcher-owned"):
        OwnedAccount(account_id="acct-a", role="owner", researcher_owned=False)

    with pytest.raises(ValueError, match="custom"):
        OwnedAccount(account_id="acct-a", role="custom")

    with pytest.raises(ValueError, match="roles"):
        OwnedAccount(account_id="acct-a", role="viewer", secondary_roles=["viewer"])


def test_credential_set_supports_role_and_owned_object_queries() -> None:
    credentials = CredentialSet(
        accounts=[
            OwnedAccount(account_id="acct-owner", role="owner"),
            OwnedAccount(account_id="acct-actor", role="attacker", secondary_roles=["viewer"]),
        ],
        test_objects=[
            OwnedTestObject(
                object_id="profile-a",
                owner_account_id="acct-owner",
                object_type="profile",
                target_ref="https://accounts.google.com/profile/profile-a",
                accessible_by_account_ids=["acct-owner"],
                required_role="owner",
            )
        ],
    )

    owner, actor = credentials.validation_pair(owner_role="owner", actor_role="attacker")

    assert owner.account_id == "acct-owner"
    assert actor.account_id == "acct-actor"
    assert credentials.objects_owned_by("acct-owner")[0].object_id == "profile-a"
    assert credentials.objects_accessible_by("acct-actor") == []


def test_credential_set_rejects_unknown_access_accounts_and_third_party_objects() -> None:
    with pytest.raises(ValueError, match="third-party"):
        OwnedTestObject(
            object_id="profile-a",
            owner_account_id="acct-owner",
            object_type="profile",
            target_ref="https://accounts.google.com/profile/profile-a",
            third_party_data=True,
        )

    with pytest.raises(ValueError, match="unknown access accounts"):
        CredentialSet(
            accounts=[OwnedAccount(account_id="acct-owner", role="owner")],
            test_objects=[
                OwnedTestObject(
                    object_id="profile-a",
                    owner_account_id="acct-owner",
                    object_type="profile",
                    target_ref="https://accounts.google.com/profile/profile-a",
                    accessible_by_account_ids=["acct-owner", "acct-missing"],
                )
            ],
        )
