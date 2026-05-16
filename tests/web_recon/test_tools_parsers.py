from vrp_hunt.web_recon import (
    build_amass_command,
    build_httpx_command,
    build_subfinder_command,
    parse_amass_text,
    parse_httpx_jsonl,
    parse_subfinder_jsonl,
)


def test_subfinder_command_is_passive_json_silent() -> None:
    assert build_subfinder_command("google.com") == ["subfinder", "-d", "google.com", "-oJ", "-silent"]


def test_amass_command_is_passive() -> None:
    assert build_amass_command("google.com") == ["amass", "enum", "-passive", "-d", "google.com"]


def test_httpx_command_uses_json_and_rate_limit() -> None:
    command = build_httpx_command("hosts.txt", rate_limit_per_minute=30)
    assert command[:2] == ["httpx", "-l"]
    assert "-j" in command
    assert command[-2:] == ["-rlm", "30"]


def test_parse_subfinder_jsonl() -> None:
    assets = parse_subfinder_jsonl('{"host":"www.google.com","sources":["crtsh"]}\n')
    assert assets[0].kind == "host"
    assert assets[0].value == "www.google.com"
    assert assets[0].metadata["sources"] == "crtsh"


def test_parse_amass_text() -> None:
    assets = parse_amass_text("mail.google.com\nnot a host\n")
    assert [asset.value for asset in assets] == ["mail.google.com"]


def test_parse_httpx_jsonl() -> None:
    assets = parse_httpx_jsonl(
        '{"url":"https://www.google.com/","status_code":200,'
        '"title":"Google","technologies":["GFE"]}\n'
    )
    assert {asset.kind for asset in assets} == {"url", "host", "technology"}
