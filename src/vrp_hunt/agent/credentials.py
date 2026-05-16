"""Owned-account credential metadata without secret exposure."""

from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Literal

from pydantic import Field, field_validator, model_validator

from vrp_hunt.guardrails.models import StrictModel

AccountRole = Literal["owner", "attacker", "victim", "admin", "viewer", "custom"]
SecretProvider = Literal["env", "file", "external"]
SecretPurpose = Literal[
    "password",
    "cookie",
    "oauth_token",
    "api_token",
    "totp_seed",
    "recovery_code",
    "other",
]
SameSitePolicy = Literal["strict", "lax", "none", "unspecified"]


class SecretRef(StrictModel):
    name: str = Field(min_length=1)
    provider: SecretProvider = "env"
    purpose: SecretPurpose = "other"
    env_var: str | None = None
    path: str | None = None
    description: str | None = None

    @model_validator(mode="after")
    def require_locator(self) -> "SecretRef":
        if self.provider == "env" and not self.env_var:
            raise ValueError("env secret references require env_var")
        if self.provider == "file" and not self.path:
            raise ValueError("file secret references require path")
        return self

    def resolve_env(self, env: Mapping[str, str] | None = None) -> str:
        if self.provider != "env" or self.env_var is None:
            raise ValueError("only env-backed secrets can be resolved directly")
        values = env or os.environ
        value = values.get(self.env_var)
        if value is None:
            raise KeyError(self.env_var)
        return value

    def redacted_label(self) -> str:
        locator = self.env_var or self.path or self.provider
        return f"{self.name}:{locator}:[REDACTED]"


class CookieRef(StrictModel):
    """Cookie metadata with the cookie value held only by a secret reference."""

    name: str = Field(min_length=1, max_length=128)
    value: SecretRef
    domain: str | None = Field(default=None, max_length=255)
    path: str = Field(default="/", min_length=1, max_length=255)
    secure: bool = True
    http_only: bool = True
    same_site: SameSitePolicy = "unspecified"
    description: str | None = None

    @field_validator("name")
    @classmethod
    def cookie_name_must_be_safe(cls, value: str) -> str:
        if any(char.isspace() or char in {";", "=", ","} for char in value):
            raise ValueError("cookie name must not contain whitespace or separators")
        return value

    @field_validator("domain")
    @classmethod
    def cookie_domain_must_be_host_only(cls, value: str | None) -> str | None:
        if value is None:
            return None
        domain = value.strip().lower().lstrip(".")
        if not domain:
            raise ValueError("cookie domain cannot be blank")
        if "/" in domain or ":" in domain or "@" in domain:
            raise ValueError("cookie domain must be a host or registrable domain")
        return domain

    @model_validator(mode="after")
    def enforce_cookie_secret_boundary(self) -> "CookieRef":
        if self.value.purpose not in {"cookie", "other"}:
            raise ValueError("cookie value secret must be marked for cookie use")
        if self.same_site == "none" and not self.secure:
            raise ValueError("SameSite=None cookies must be secure")
        return self

    def redacted_summary(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value": self.value.redacted_label(),
            "domain": self.domain,
            "path": self.path,
            "secure": self.secure,
            "http_only": self.http_only,
            "same_site": self.same_site,
        }


class OwnedAccount(StrictModel):
    account_id: str = Field(min_length=1)
    role: AccountRole
    secondary_roles: list[AccountRole] = Field(default_factory=list)
    custom_role: str | None = Field(default=None, min_length=1)
    username: str | None = None
    password: SecretRef | None = None
    cookies: dict[str, SecretRef] = Field(default_factory=dict)
    session_cookies: list[CookieRef] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    researcher_owned: bool = True

    @model_validator(mode="after")
    def enforce_owned_account(self) -> "OwnedAccount":
        if not self.researcher_owned:
            raise ValueError("account metadata must represent researcher-owned accounts")
        roles = [self.role, *self.secondary_roles]
        if len(roles) != len(set(roles)):
            raise ValueError("account roles must be unique")
        if "custom" in roles and not self.custom_role:
            raise ValueError("custom account roles require custom_role")
        cookie_names = [*self.cookies, *(cookie.name for cookie in self.session_cookies)]
        if len(cookie_names) != len(set(cookie_names)):
            raise ValueError("cookie names must be unique for an account")
        for name, secret in self.cookies.items():
            CookieRef(name=name, value=secret)
        return self

    @property
    def roles(self) -> tuple[AccountRole, ...]:
        return (self.role, *self.secondary_roles)

    def has_role(self, role: AccountRole) -> bool:
        return role in self.roles

    def cookie_refs(self) -> list[CookieRef]:
        legacy_refs = [
            CookieRef(name=name, value=secret)
            for name, secret in sorted(self.cookies.items())
        ]
        return [*legacy_refs, *self.session_cookies]


class OwnedTestObject(StrictModel):
    object_id: str = Field(min_length=1)
    owner_account_id: str = Field(min_length=1)
    object_type: str = Field(min_length=1)
    target_ref: str = Field(min_length=1)
    accessible_by_account_ids: list[str] = Field(default_factory=list)
    required_role: AccountRole | None = None
    can_be_reset: bool = True
    contains_sensitive_data: bool = False
    third_party_data: bool = False
    notes: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def enforce_safe_object(self) -> "OwnedTestObject":
        if self.contains_sensitive_data:
            raise ValueError("owned test objects must not contain sensitive data")
        if self.third_party_data:
            raise ValueError("owned test objects must not contain third-party data")
        if not self.accessible_by_account_ids:
            self.accessible_by_account_ids = [self.owner_account_id]
        if self.owner_account_id not in self.accessible_by_account_ids:
            raise ValueError("owner account must be allowed to access its test object")
        if len(self.accessible_by_account_ids) != len(set(self.accessible_by_account_ids)):
            raise ValueError("accessible account ids must be unique")
        return self


class CredentialSet(StrictModel):
    accounts: list[OwnedAccount] = Field(min_length=1)
    test_objects: list[OwnedTestObject] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_relationships(self) -> "CredentialSet":
        account_ids = [account.account_id for account in self.accounts]
        if len(account_ids) != len(set(account_ids)):
            raise ValueError("account ids must be unique")
        missing_owners = {
            item.owner_account_id
            for item in self.test_objects
            if item.owner_account_id not in account_ids
        }
        if missing_owners:
            raise ValueError("owned test objects reference unknown accounts")
        referenced_access_accounts = {
            account_id
            for item in self.test_objects
            for account_id in item.accessible_by_account_ids
        }
        unknown_access_accounts = referenced_access_accounts.difference(account_ids)
        if unknown_access_accounts:
            raise ValueError("owned test objects reference unknown access accounts")
        return self

    def account(self, account_id: str) -> OwnedAccount:
        for account in self.accounts:
            if account.account_id == account_id:
                return account
        raise KeyError(account_id)

    def accounts_by_role(self, role: AccountRole) -> list[OwnedAccount]:
        return [account for account in self.accounts if account.has_role(role)]

    def require_role(self, role: AccountRole) -> OwnedAccount:
        matches = self.accounts_by_role(role)
        if not matches:
            raise KeyError(role)
        return matches[0]

    def test_object(self, object_id: str) -> OwnedTestObject:
        for item in self.test_objects:
            if item.object_id == object_id:
                return item
        raise KeyError(object_id)

    def objects_owned_by(self, account_id: str) -> list[OwnedTestObject]:
        self.account(account_id)
        return [item for item in self.test_objects if item.owner_account_id == account_id]

    def objects_accessible_by(self, account_id: str) -> list[OwnedTestObject]:
        self.account(account_id)
        return [item for item in self.test_objects if account_id in item.accessible_by_account_ids]

    def validation_pair(self, *, owner_role: AccountRole, actor_role: AccountRole) -> tuple[OwnedAccount, OwnedAccount]:
        owner = self.require_role(owner_role)
        actor = self.require_role(actor_role)
        if owner.account_id == actor.account_id:
            raise ValueError("validation pair requires distinct accounts")
        return owner, actor

    def redacted_summary(self) -> dict[str, object]:
        return {
            "accounts": [
                {
                    "account_id": account.account_id,
                    "role": account.role,
                    "secondary_roles": account.secondary_roles,
                    "custom_role": account.custom_role,
                    "username": account.username,
                    "password": account.password.redacted_label() if account.password else None,
                    "cookies": [cookie.redacted_summary() for cookie in account.cookie_refs()],
                }
                for account in self.accounts
            ],
            "test_objects": [item.model_dump(mode="json") for item in self.test_objects],
        }
