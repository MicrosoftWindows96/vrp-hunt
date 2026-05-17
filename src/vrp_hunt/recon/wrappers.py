"""Safe wrapper surfaces for external recon tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon.models import HttpRequest, HttpResponse

AGGRESSIVE_NUCLEI_TAGS = {"dos", "fuzz", "bruteforce", "brute-force", "intrusive", "dast"}
SAFE_NUCLEI_PROTOCOLS = {"http"}
NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}


class HttpxTransport:
    """Adapt an HTTPX async client to the scheduler transport interface."""

    def __init__(self, client: httpx.AsyncClient | Any | None = None) -> None:
        self.client = client or httpx.AsyncClient()

    async def __call__(self, request: HttpRequest) -> HttpResponse:
        response = await self.client.request(
            request.method,
            request.url,
            headers=request.headers,
            timeout=request.timeout_seconds,
        )
        return HttpResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            final_url=str(response.url),
        )


class NucleiTemplatePolicy(StrictModel):
    templates: list[str] = Field(min_length=1)
    tags: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=list)
    protocol_types: list[str] = Field(default_factory=lambda: ["http"])

    @field_validator("templates")
    @classmethod
    def templates_must_be_explicit(cls, value: list[str]) -> list[str]:
        for template in value:
            path = Path(template)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("nuclei templates must be explicit relative paths")
        return value

    @field_validator("tags")
    @classmethod
    def tags_must_not_be_aggressive(cls, value: list[str]) -> list[str]:
        aggressive = AGGRESSIVE_NUCLEI_TAGS.intersection({tag.lower() for tag in value})
        if aggressive:
            raise ValueError(f"blocked aggressive nuclei tags: {', '.join(sorted(aggressive))}")
        return value

    @field_validator("severity")
    @classmethod
    def severity_must_be_known(cls, value: list[str]) -> list[str]:
        unknown = sorted({severity.lower() for severity in value}.difference(NUCLEI_SEVERITIES))
        if unknown:
            raise ValueError(f"unknown nuclei severity values: {', '.join(unknown)}")
        return value

    @field_validator("protocol_types")
    @classmethod
    def protocol_types_must_be_safe(cls, value: list[str]) -> list[str]:
        selected = {protocol.lower() for protocol in value}
        blocked = sorted(selected.difference(SAFE_NUCLEI_PROTOCOLS))
        if blocked:
            raise ValueError(f"blocked nuclei protocol types: {', '.join(blocked)}")
        return value


class NucleiCommandBuilder:
    def __init__(self, *, binary: str = "nuclei", policy: NucleiTemplatePolicy) -> None:
        self.binary = binary
        self.policy = policy

    def build(self, targets_file: str | Path, *, rate_limit: float) -> list[str]:
        if rate_limit <= 0:
            raise ValueError("rate_limit must be positive")
        command = [
            self.binary,
            "-list",
            str(targets_file),
            "-rl",
            str(rate_limit),
            "-j",
            "-silent",
            "-duc",
            "-ni",
        ]
        for template in self.policy.templates:
            command.extend(["-t", template])
        if self.policy.tags:
            command.extend(["-tags", ",".join(self.policy.tags)])
        if self.policy.severity:
            command.extend(["-s", ",".join(self.policy.severity)])
        if self.policy.protocol_types:
            command.extend(["-pt", ",".join(self.policy.protocol_types)])
        return command
