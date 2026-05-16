"""Recon core data models."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel

AssetKind = Literal[
    "host",
    "url",
    "endpoint",
    "parameter",
    "javascript",
    "technology",
    "mobile_component",
    "note",
]


def utc_now() -> datetime:
    return datetime.now(UTC)


class Asset(StrictModel):
    kind: AssetKind
    value: str = Field(min_length=1, max_length=4096)
    source: str = Field(min_length=1, max_length=256)
    parent: str | None = Field(default=None, max_length=4096)
    metadata: dict[str, str] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)

    @field_validator("value", "source", "parent")
    @classmethod
    def strip_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        if not stripped:
            raise ValueError("value cannot be blank")
        return stripped

    @property
    def fingerprint(self) -> str:
        metadata_parts = [f"{key}={value}" for key, value in sorted(self.metadata.items())]
        raw = "\x1f".join([self.kind, self.value.lower(), self.parent or "", *metadata_parts])
        return sha256(raw.encode("utf-8")).hexdigest()


class AssetInventory(StrictModel):
    assets: list[Asset] = Field(default_factory=list)

    def deduped(self) -> "AssetInventory":
        by_fingerprint: dict[str, Asset] = {}
        for asset in self.assets:
            existing = by_fingerprint.get(asset.fingerprint)
            if existing is None or asset.last_seen >= existing.last_seen:
                by_fingerprint[asset.fingerprint] = asset
        return AssetInventory(assets=list(by_fingerprint.values()))

    def add(self, asset: Asset) -> None:
        self.assets.append(asset)
        self.assets = self.deduped().assets


class ReconScope(StrictModel):
    seeds: list[str] = Field(min_length=1)
    researcher_owned_account: bool = True
    will_access_third_party_data: bool = False
    legal_acknowledged: bool = True
    metadata: dict[str, str] = Field(default_factory=dict)


class AdapterCapability(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    asset_kinds: list[AssetKind] = Field(default_factory=list)
    sends_traffic: bool = False


class AdapterResult(StrictModel):
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class HttpRequest(StrictModel):
    method: str = Field(default="GET", min_length=1, max_length=16)
    url: str = Field(min_length=1, max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: float = Field(default=10.0, gt=0)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()


class HttpResponse(StrictModel):
    status_code: int = Field(ge=100, le=599)
    headers: dict[str, str] = Field(default_factory=dict)
    text: str = ""
    final_url: str | None = None

    def retry_after_seconds(self) -> float | None:
        value = None
        for key, header_value in self.headers.items():
            if key.lower() == "retry-after":
                value = header_value
                break
        if value is None:
            return None
        try:
            parsed = float(value)
        except ValueError:
            return None
        return max(parsed, 0.0)
