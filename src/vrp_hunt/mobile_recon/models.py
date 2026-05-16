"""Models for mobile recon targets and configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
Platform = Literal["android", "ios"]


class MobileAppTarget(StrictModel):
    app_id: str = Field(min_length=1, max_length=256)
    publisher: str = Field(min_length=1, max_length=256)
    platform: Platform
    artifact_path: Path | None = None

    @field_validator("app_id", "publisher")
    @classmethod
    def strip_text(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("field cannot be blank")
        return stripped


class MobileReconConfig(StrictModel):
    targets: list[MobileAppTarget] = Field(default_factory=list)
    jadx_output_dir: Path = Path("data/mobile/jadx")
    frida_scripts_dir: Path = Path("data/mobile/frida")
    dynamic_enabled: bool = False
    allowed_publishers: tuple[str, ...] = ("Google LLC", "Google", "Waymo LLC", "Waymo")
    runner: Any | None = Field(default=None, exclude=True)

    model_config = {"arbitrary_types_allowed": True, "extra": "forbid"}
