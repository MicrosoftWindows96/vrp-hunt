from vrp_hunt.mobile_recon import (
    build_emulator_list_command,
    build_emulator_start_command,
    build_frida_ps_command,
    build_frida_script_command,
    build_jadx_command,
    build_objection_explore_command,
)


def test_jadx_command_uses_output_dir() -> None:
    assert build_jadx_command("app.apk", "out") == ["jadx", "-d", "out", "app.apk"]


def test_frida_ps_usb_installed_apps_command() -> None:
    assert build_frida_ps_command() == ["frida-ps", "-U", "-ai"]


def test_frida_script_command_loads_script() -> None:
    assert build_frida_script_command("com.google.app", "observe.js") == [
        "frida",
        "-U",
        "com.google.app",
        "-l",
        "observe.js",
    ]


def test_objection_explore_command() -> None:
    assert build_objection_explore_command("com.google.app") == [
        "objection",
        "--gadget",
        "com.google.app",
        "explore",
    ]


def test_emulator_commands() -> None:
    assert build_emulator_list_command() == ["emulator", "-list-avds"]
    assert build_emulator_start_command("Pixel_8") == ["emulator", "-avd", "Pixel_8"]
    assert build_emulator_start_command("Pixel_8", wipe_data=True)[-1] == "-wipe-data"
