import pytest
from pydantic import ValidationError

from vrp_hunt.reporting import EnvironmentInfo, PocArtifact


def test_automated_poc_requires_command() -> None:
    with pytest.raises(ValidationError):
        PocArtifact(
            title="bad poc",
            automated=True,
            steps=["run the local check"],
            expected_output="owned account output only",
        )


def test_poc_rejects_non_owned_account_scope() -> None:
    with pytest.raises(ValidationError):
        PocArtifact(
            title="bad poc",
            automated=False,
            steps=["manual check"],
            expected_output="owned account output only",
            own_account_only=False,
        )


def test_poc_rejects_third_party_data() -> None:
    with pytest.raises(ValidationError):
        PocArtifact(
            title="bad poc",
            automated=False,
            steps=["manual check"],
            expected_output="owned account output only",
            third_party_data_touched=True,
        )


def test_environment_requires_owned_account_alias() -> None:
    with pytest.raises(ValidationError):
        EnvironmentInfo(
            researcher_accounts=[],
            client="Chrome",
            operating_system="macOS",
            observed_from="research workstation",
        )
