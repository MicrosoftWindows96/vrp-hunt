"""Models for web recon adapter configuration and command execution."""

from __future__ import annotations

from datetime import date
from typing import Protocol, Sequence

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel


class CommandResult(StrictModel):
    command: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    async def run(self, command: Sequence[str], *, stdin: str | None = None) -> CommandResult:
        """Run a command without shell expansion."""


class WebReconConfig(StrictModel):
    passive_tools_enabled: bool = True
    subfinder_enabled: bool = True
    amass_enabled: bool = True
    live_probe_enabled: bool = True
    max_live_hosts: int = Field(default=20, ge=0)
    acquisition_dates: dict[str, date] = Field(default_factory=dict)
    http_timeout_seconds: float = Field(default=10.0, gt=0)
    user_agent: str = Field(default="vrp-hunt-web-recon", min_length=1)
