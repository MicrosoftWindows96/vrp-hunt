import json
from pathlib import Path

from vrp_hunt.recon import (
    build_reverse_ct_expansion_report,
    load_certificate_transparency_records,
    load_reverse_ip_records,
    passive_expansion_assets,
)


def test_reverse_ip_import_filters_to_scope(tmp_path: Path) -> None:
    reverse_path = tmp_path / "reverse.json"
    reverse_path.write_text(
        json.dumps(
            [
                {
                    "ip": "203.0.113.10",
                    "hosts": ["www.google.com", "evil.example"],
                }
            ]
        ),
        encoding="utf-8",
    )

    records, warnings, total = load_reverse_ip_records(
        reverse_path,
        scope_domains=["google.com"],
    )

    assert warnings == []
    assert total == 1
    assert [record.host for record in records] == ["www.google.com"]
    assert records[0].parent == "203.0.113.10"
    assert records[0].source == "reverse_ip"


def test_ct_import_splits_name_value_and_wildcards(tmp_path: Path) -> None:
    ct_path = tmp_path / "ct.json"
    ct_path.write_text(
        json.dumps(
            [
                {
                    "name_value": "*.mail.google.com\naccounts.google.com",
                    "common_name": "ignored.example",
                }
            ]
        ),
        encoding="utf-8",
    )

    records, warnings, total = load_certificate_transparency_records(
        ct_path,
        scope_domains=["google.com"],
    )

    assert warnings == []
    assert total == 1
    assert [record.host for record in records] == ["mail.google.com", "accounts.google.com"]
    assert {record.source for record in records} == {"certificate_transparency"}


def test_reverse_ct_report_dedupes_and_emits_assets(tmp_path: Path) -> None:
    reverse_path = tmp_path / "reverse.jsonl"
    ct_path = tmp_path / "ct.txt"
    reverse_path.write_text(
        '{"ip":"203.0.113.10","hosts":["www.google.com","www.google.com"]}\n',
        encoding="utf-8",
    )
    ct_path.write_text("www.google.com\nstatic.google.com\n", encoding="utf-8")

    report = build_reverse_ct_expansion_report(
        reverse_ip_files=[reverse_path],
        certificate_transparency_files=[ct_path],
        scope_domains=["google.com"],
    )

    assert report.total_inputs == 3
    assert report.total_records == 3
    assert [asset.value for asset in report.assets] == ["static.google.com", "www.google.com"]
    www = next(asset for asset in report.assets if asset.value == "www.google.com")
    assert www.metadata["expansion_sources"] == "certificate_transparency,reverse_ip"


def test_passive_expansion_assets_groups_records(tmp_path: Path) -> None:
    ct_path = tmp_path / "ct.txt"
    ct_path.write_text("www.google.com\n", encoding="utf-8")
    records, _, _ = load_certificate_transparency_records(ct_path, scope_domains=["google.com"])

    assets = passive_expansion_assets(records)

    assert assets[0].kind == "host"
    assert assets[0].source == "passive-expansion"
    assert assets[0].metadata["scope_domains"] == "google.com"
