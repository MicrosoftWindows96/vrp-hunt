"""Command builders for mobile recon tooling."""

from __future__ import annotations

from pathlib import Path


def build_jadx_command(artifact_path: str | Path, output_dir: str | Path) -> list[str]:
    return ["jadx", "-d", str(output_dir), str(artifact_path)]


def build_frida_ps_command(*, serial: str | None = None, installed_apps: bool = True) -> list[str]:
    if serial:
        command = ["frida-ps", "-D", serial]
    else:
        command = ["frida-ps", "-U"]
    if installed_apps:
        command.append("-ai")
    return command


def build_frida_script_command(app_id: str, script_path: str | Path, *, serial: str | None = None) -> list[str]:
    command = ["frida"]
    if serial:
        command.extend(["-D", serial])
    else:
        command.append("-U")
    command.extend([app_id, "-l", str(script_path)])
    return command


def build_objection_explore_command(app_id: str) -> list[str]:
    return ["objection", "--gadget", app_id, "explore"]


def build_emulator_list_command() -> list[str]:
    return ["emulator", "-list-avds"]


def build_emulator_start_command(avd_name: str, *, wipe_data: bool = False) -> list[str]:
    command = ["emulator", "-avd", avd_name]
    if wipe_data:
        command.append("-wipe-data")
    return command
