from pathlib import Path

import pytest

from vrp_hunt.agent import (
    LiveReconAuthorizationError,
    LiveReconOperatorPolicy,
    authorize_live_recon,
    load_operator_policy,
)


def operator_policy() -> LiveReconOperatorPolicy:
    return LiveReconOperatorPolicy(
        authorized_operator_id="owner",
        authorized_local_user="local-owner",
        allowed_tools=["subfinder", "httpx", "jadx"],
        require_liability_ack=True,
    )


def test_authorization_allows_configured_operator_and_tool() -> None:
    authorization = authorize_live_recon(
        tool="subfinder",
        operator_id="owner",
        legal_liability_accepted=True,
        policy=operator_policy(),
        local_user="local-owner",
    )

    assert authorization.operator_id == "owner"
    assert authorization.local_user == "local-owner"
    assert authorization.tool == "subfinder"


def test_authorization_rejects_wrong_operator() -> None:
    with pytest.raises(LiveReconAuthorizationError, match="operator"):
        authorize_live_recon(
            tool="subfinder",
            operator_id="someone-else",
            legal_liability_accepted=True,
            policy=operator_policy(),
            local_user="local-owner",
        )


def test_authorization_rejects_wrong_local_user() -> None:
    with pytest.raises(LiveReconAuthorizationError, match="OS user"):
        authorize_live_recon(
            tool="subfinder",
            operator_id="owner",
            legal_liability_accepted=True,
            policy=operator_policy(),
            local_user="different-user",
        )


def test_authorization_requires_liability_acknowledgement() -> None:
    with pytest.raises(LiveReconAuthorizationError, match="liability"):
        authorize_live_recon(
            tool="httpx",
            operator_id="owner",
            legal_liability_accepted=False,
            policy=operator_policy(),
            local_user="local-owner",
        )


def test_authorization_rejects_unapproved_tool() -> None:
    with pytest.raises(LiveReconAuthorizationError, match="approved"):
        authorize_live_recon(
            tool="sqlmap",
            operator_id="owner",
            legal_liability_accepted=True,
            policy=operator_policy(),
            local_user="local-owner",
        )


def test_authorization_rejects_tool_not_allowed_by_operator_policy() -> None:
    with pytest.raises(LiveReconAuthorizationError, match="not allowed"):
        authorize_live_recon(
            tool="nuclei",
            operator_id="owner",
            legal_liability_accepted=True,
            policy=operator_policy(),
            local_user="local-owner",
        )


def test_operator_policy_loads_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "operator_policy.yaml"
    path.write_text(
        "\n".join(
            [
                'authorized_operator_id: "owner"',
                'authorized_local_user: "local-owner"',
                "allowed_tools:",
                '  - "subfinder"',
                '  - "httpx"',
                "require_liability_ack: true",
            ]
        ),
        encoding="utf-8",
    )

    policy = load_operator_policy(path)

    assert policy.authorized_operator_id == "owner"
    assert policy.allowed_tools == ["subfinder", "httpx"]
