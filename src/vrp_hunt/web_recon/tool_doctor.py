"""Local tool inventory and install guidance for approved recon helpers."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable
from typing import Literal

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel

ApprovedDoctorTool = Literal["subfinder", "httpx", "katana", "nuclei", "jadx", "mobsf"]

Resolver = Callable[[str], str | None]
VersionRunner = Callable[[list[str]], str]


class ToolInstallOption(StrictModel):
    method: str = Field(min_length=1)
    command: str = Field(min_length=1)
    notes: str = ""


class ToolSpec(StrictModel):
    name: ApprovedDoctorTool
    binary: str = Field(min_length=1)
    version_args: list[str] = Field(default_factory=list)
    required_for: list[str] = Field(default_factory=list)
    install_options: list[ToolInstallOption] = Field(default_factory=list)


class ToolInventoryItem(StrictModel):
    name: ApprovedDoctorTool
    binary: str = Field(min_length=1)
    installed: bool
    path: str | None = None
    version: str = ""
    required_for: list[str] = Field(default_factory=list)
    install_options: list[ToolInstallOption] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ToolDoctorReport(StrictModel):
    total_tools: int = Field(ge=0)
    installed_count: int = Field(ge=0)
    missing_tools: list[ApprovedDoctorTool] = Field(default_factory=list)
    tools: list[ToolInventoryItem] = Field(default_factory=list)
    install_plan: list[ToolInstallOption] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


TOOL_SPECS: dict[ApprovedDoctorTool, ToolSpec] = {
    "subfinder": ToolSpec(
        name="subfinder",
        binary="subfinder",
        version_args=["-version"],
        required_for=["passive subdomain discovery", "live-recon subfinder"],
        install_options=[
            ToolInstallOption(
                method="go",
                command="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            ),
            ToolInstallOption(method="brew", command="brew install subfinder"),
        ],
    ),
    "httpx": ToolSpec(
        name="httpx",
        binary="httpx",
        version_args=["-version"],
        required_for=["low-volume HTTP metadata probes"],
        install_options=[
            ToolInstallOption(
                method="go",
                command="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
            ),
            ToolInstallOption(method="brew", command="brew install httpx"),
        ],
    ),
    "katana": ToolSpec(
        name="katana",
        binary="katana",
        version_args=["-version"],
        required_for=["bounded URL crawling"],
        install_options=[
            ToolInstallOption(
                method="go",
                command="go install github.com/projectdiscovery/katana/cmd/katana@latest",
            )
        ],
    ),
    "nuclei": ToolSpec(
        name="nuclei",
        binary="nuclei",
        version_args=["-version"],
        required_for=["allowlisted template checks"],
        install_options=[
            ToolInstallOption(
                method="go",
                command="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            ),
            ToolInstallOption(method="brew", command="brew install nuclei"),
        ],
    ),
    "jadx": ToolSpec(
        name="jadx",
        binary="jadx",
        version_args=["--version"],
        required_for=["APK static analysis"],
        install_options=[ToolInstallOption(method="brew", command="brew install jadx")],
    ),
    "mobsf": ToolSpec(
        name="mobsf",
        binary="mobsfscan",
        version_args=["--version"],
        required_for=["MobSF-style mobile static analysis import"],
        install_options=[
            ToolInstallOption(method="pipx", command="pipx install mobsfscan"),
            ToolInstallOption(
                method="docker",
                command="docker pull opensecurity/mobile-security-framework-mobsf",
                notes="Use only for local analysis of authorized mobile artifacts.",
            ),
        ],
    ),
}


def check_tool_inventory(
    *,
    tools: list[ApprovedDoctorTool] | None = None,
    resolver: Resolver | None = None,
    version_runner: VersionRunner | None = None,
    assume_missing: bool = False,
) -> ToolDoctorReport:
    selected = tools or list(TOOL_SPECS)
    resolve = resolver or shutil.which
    run_version = version_runner or _run_version
    items: list[ToolInventoryItem] = []
    warnings: list[str] = []
    for tool in selected:
        spec = TOOL_SPECS[tool]
        path = None if assume_missing else resolve(spec.binary)
        installed = path is not None
        version = ""
        item_warnings: list[str] = []
        if installed and spec.version_args:
            try:
                version = run_version([spec.binary, *spec.version_args]).strip()
            except (OSError, subprocess.SubprocessError, TimeoutError) as exc:
                item_warnings.append(f"version check failed: {exc}")
        items.append(
            ToolInventoryItem(
                name=tool,
                binary=spec.binary,
                installed=installed,
                path=path,
                version=version.splitlines()[0] if version else "",
                required_for=spec.required_for,
                install_options=spec.install_options,
                warnings=item_warnings,
            )
        )
        warnings.extend(f"{tool}: {warning}" for warning in item_warnings)
    missing = [item.name for item in items if not item.installed]
    install_plan: list[ToolInstallOption] = []
    for item in items:
        if not item.installed:
            install_plan.extend(item.install_options[:1])
    return ToolDoctorReport(
        total_tools=len(items),
        installed_count=sum(1 for item in items if item.installed),
        missing_tools=missing,
        tools=items,
        install_plan=install_plan,
        warnings=warnings,
    )


def render_tool_install_plan(report: ToolDoctorReport) -> str:
    lines: list[str] = []
    for option in report.install_plan:
        suffix = f"  # {option.notes}" if option.notes else ""
        lines.append(f"{option.command}{suffix}")
    return "\n".join(lines) + ("\n" if lines else "")


def _run_version(command: list[str]) -> str:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result.stdout.strip() or result.stderr.strip()
