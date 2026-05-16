"""Persistent asset inventory store."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from vrp_hunt.recon.models import Asset, AssetInventory

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_STORE_PATH = REPO_ROOT / "data" / "assets.jsonl"


class AssetStore:
    """Simple JSONL store with deterministic asset dedupe."""

    def __init__(self, path: str | Path = DEFAULT_STORE_PATH) -> None:
        self.path = Path(path)

    def load(self) -> AssetInventory:
        if not self.path.exists():
            return AssetInventory()

        assets: list[Asset] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                assets.append(Asset.model_validate_json(line))
            except (ValidationError, ValueError, json.JSONDecodeError):
                continue
        return AssetInventory(assets=assets).deduped()

    def save_all(self, assets: list[Asset] | AssetInventory) -> AssetInventory:
        existing = self.load()
        incoming = assets.assets if isinstance(assets, AssetInventory) else assets
        merged = AssetInventory(assets=[*existing.assets, *incoming]).deduped()

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            for asset in merged.assets:
                handle.write(asset.model_dump_json() + "\n")
        return merged
