"""Command builders and optional subprocess runner for web recon tools."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Sequence

from vrp_hunt.web_recon.models import CommandResult


def build_subfinder_command(domain: str) -> list[str]:
    return ["subfinder", "-d", domain, "-oJ", "-silent"]


def build_amass_command(domain: str) -> list[str]:
    return ["amass", "enum", "-passive", "-d", domain]


def build_httpx_command(targets_file: str | Path, *, rate_limit_per_minute: int) -> list[str]:
    if rate_limit_per_minute <= 0:
        raise ValueError("rate_limit_per_minute must be positive")
    return [
        "httpx",
        "-l",
        str(targets_file),
        "-sc",
        "-title",
        "-cl",
        "-server",
        "-td",
        "-j",
        "-rlm",
        str(rate_limit_per_minute),
    ]


def build_katana_command(
    targets_file: str | Path,
    *,
    depth: int = 1,
    rate_limit_per_minute: int = 30,
    field_scope: str = "fqdn",
    js_crawl: bool = False,
    known_files: str | None = None,
    crawl_duration_seconds: int = 30,
) -> list[str]:
    if depth < 0:
        raise ValueError("depth must be non-negative")
    if rate_limit_per_minute <= 0:
        raise ValueError("rate_limit_per_minute must be positive")
    if crawl_duration_seconds <= 0:
        raise ValueError("crawl_duration_seconds must be positive")
    command = [
        "katana",
        "-list",
        str(targets_file),
        "-j",
        "-silent",
        "-d",
        str(depth),
        "-fs",
        field_scope,
        "-rlm",
        str(rate_limit_per_minute),
        "-ct",
        f"{crawl_duration_seconds}s",
    ]
    if js_crawl:
        command.append("-jc")
    if known_files:
        command.extend(["-kf", known_files])
    return command


class SubprocessCommandRunner:
    """Run allowlisted recon commands without shell expansion."""

    def __init__(self, *, timeout_seconds: float = 300.0, max_output_bytes: int = 2_000_000) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    async def run(self, command: Sequence[str], *, stdin: str | None = None) -> CommandResult:
        if not command or command[0] not in {"subfinder", "amass", "httpx", "katana", "nuclei"}:
            raise ValueError("unsupported command")

        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(stdin.encode("utf-8") if stdin is not None else None),
            timeout=self.timeout_seconds,
        )
        stdout = stdout_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
        stderr = stderr_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
        return CommandResult(command=list(command), returncode=proc.returncode or 0, stdout=stdout, stderr=stderr)
