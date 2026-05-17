from vrp_hunt.web_recon import check_tool_inventory, render_tool_install_plan


def test_tool_doctor_reports_installed_versions_with_fake_resolver() -> None:
    report = check_tool_inventory(
        tools=["subfinder", "httpx"],
        resolver=lambda binary: f"/usr/local/bin/{binary}" if binary == "httpx" else None,
        version_runner=lambda command: "httpx 1.2.3" if command[0] == "httpx" else "",
    )

    by_name = {item.name: item for item in report.tools}

    assert report.installed_count == 1
    assert report.missing_tools == ["subfinder"]
    assert by_name["httpx"].installed is True
    assert by_name["httpx"].version == "httpx 1.2.3"
    assert "go install github.com/projectdiscovery/subfinder" in report.install_plan[0].command


def test_tool_doctor_assume_missing_renders_install_plan() -> None:
    report = check_tool_inventory(tools=["jadx", "mobsf"], assume_missing=True)
    rendered = render_tool_install_plan(report)

    assert report.missing_tools == ["jadx", "mobsf"]
    assert "brew install jadx" in rendered
    assert "pipx install mobsfscan" in rendered
