from pathlib import Path

import pytest
from pydantic import ValidationError

from vrp_hunt.recon import Asset, AssetInventory, AssetStore, ReconScope


def test_asset_fingerprint_is_deterministic() -> None:
    first = Asset(kind="host", value="WWW.Google.COM", source="test")
    second = Asset(kind="host", value="www.google.com", source="other")

    assert first.fingerprint == second.fingerprint


def test_inventory_dedupes_duplicate_assets() -> None:
    asset = Asset(kind="host", value="google.com", source="a")
    inventory = AssetInventory(assets=[asset, asset]).deduped()

    assert len(inventory.assets) == 1


def test_invalid_asset_kind_rejected() -> None:
    with pytest.raises(ValidationError):
        Asset(kind="invalid", value="google.com", source="test")


def test_recon_scope_carries_safety_acknowledgements() -> None:
    scope = ReconScope(seeds=["google.com"])

    assert scope.researcher_owned_account is True
    assert scope.will_access_third_party_data is False
    assert scope.legal_acknowledged is True


def test_asset_store_round_trips_and_dedupes(tmp_path: Path) -> None:
    store = AssetStore(tmp_path / "assets.jsonl")
    asset = Asset(kind="url", value="https://www.google.com/", source="adapter")

    saved = store.save_all([asset, asset])
    loaded = store.load()

    assert len(saved.assets) == 1
    assert loaded.assets[0].fingerprint == asset.fingerprint


def test_asset_store_ignores_malformed_rows(tmp_path: Path) -> None:
    path = tmp_path / "assets.jsonl"
    path.write_text("{bad json}\n", encoding="utf-8")

    assert AssetStore(path).load().assets == []
