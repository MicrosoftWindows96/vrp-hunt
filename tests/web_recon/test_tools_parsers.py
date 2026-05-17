from vrp_hunt.web_recon import (
    build_amass_command,
    build_httpx_command,
    build_katana_command,
    build_subfinder_command,
    parse_amass_text,
    parse_httpx_jsonl,
    parse_katana_jsonl,
    parse_nuclei_jsonl,
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


def test_katana_command_is_scoped_json_and_rate_limited() -> None:
    command = build_katana_command(
        "urls.txt",
        depth=1,
        rate_limit_per_minute=5,
        field_scope="fqdn",
        js_crawl=True,
        known_files="robotstxt",
    )

    assert command[:2] == ["katana", "-list"]
    assert "-j" in command
    assert "-silent" in command
    assert "-rlm" in command
    assert "-jc" in command
    assert "-sr" not in command


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


def test_parse_katana_jsonl() -> None:
    assets = parse_katana_jsonl('{"url":"https://www.google.com/app.js","source":"script"}\n')

    assert {asset.kind for asset in assets} == {"javascript", "host"}
    assert assets[0].value == "https://www.google.com/app.js"


def test_parse_nuclei_jsonl() -> None:
    assets = parse_nuclei_jsonl(
        '{"template-id":"safe","matched-at":"https://www.google.com",'
        '"info":{"severity":"info","name":"safe check"}}\n'
    )

    assert assets[0].kind == "note"
    assert assets[0].metadata["template_id"] == "safe"
    assert assets[1].kind == "host"
