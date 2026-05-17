from pathlib import Path

from vrp_hunt.recon import build_dns_record_plan, import_dns_record_files, parse_dig_records


def test_dns_record_plan_includes_security_records() -> None:
    plan = build_dns_record_plan("Google.COM.")

    commands = {tuple(query.command) for query in plan.queries}

    assert plan.domain == "google.com"
    assert ("dig", "+short", "MX", "google.com") in commands
    assert ("dig", "+short", "CAA", "google.com") in commands
    assert ("dig", "+short", "TXT", "_dmarc.google.com") in commands


def test_parse_dig_records_identifies_spf_and_dmarc() -> None:
    spf = parse_dig_records(
        "google.com",
        "TXT",
        '"v=spf1 include:_spf.google.com ~all"\n"plain txt"\n',
    )
    dmarc = parse_dig_records(
        "_dmarc.google.com",
        "TXT",
        '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"\n',
    )

    assert [record.record_type for record in spf] == ["SPF", "TXT"]
    assert spf[0].value == "v=spf1 include:_spf.google.com ~all"
    assert dmarc[0].record_type == "DMARC"


def test_parse_dig_records_normalizes_mx_ns_caa_values() -> None:
    mx = parse_dig_records("google.com", "MX", "10 smtp.google.com.\n")
    ns = parse_dig_records("google.com", "NS", "ns1.google.com.\n")
    caa = parse_dig_records("google.com", "CAA", '0 issue "pki.goog"\n')

    assert mx[0].value == "10 smtp.google.com"
    assert ns[0].value == "ns1.google.com"
    assert caa[0].value == "0 issue pki.goog"


def test_import_dns_record_files_collects_saved_dig_outputs(tmp_path: Path) -> None:
    mx_path = tmp_path / "mx.txt"
    txt_path = tmp_path / "txt.txt"
    mx_path.write_text("10 smtp.google.com.\n", encoding="utf-8")
    txt_path.write_text('"v=spf1 include:_spf.google.com ~all"\n', encoding="utf-8")

    collection = import_dns_record_files(
        "google.com",
        [
            f"google.com:MX={mx_path}",
            f"google.com:TXT={txt_path}",
        ],
    )

    assert collection.warnings == []
    assert [record.record_type for record in collection.records] == ["MX", "SPF"]
