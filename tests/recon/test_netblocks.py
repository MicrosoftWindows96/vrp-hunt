import json
from pathlib import Path

from vrp_hunt.recon import (
    AsnNetblockRecord,
    asn_netblock_assets,
    asn_netblock_record_from_spec,
    build_asn_netblock_report,
    load_asn_netblock_records,
)


def test_asn_netblock_report_normalizes_and_summarizes_prefixes() -> None:
    records = [
        AsnNetblockRecord(
            asn="AS15169",
            organization="Google LLC",
            cidr="8.8.8.8/24",
            source="fixture",
        ),
        AsnNetblockRecord(
            asn=15169,
            organization="Google LLC",
            cidr="2001:4860::/32",
            source="fixture",
        ),
    ]

    report = build_asn_netblock_report(records)

    assert report.total_asns == 1
    assert report.total_netblocks == 2
    assert report.records[0].cidr == "8.8.8.0/24"
    assert report.summaries[0].ipv4_count == 1
    assert report.summaries[0].ipv6_count == 1


def test_asn_netblock_assets_emit_note_assets() -> None:
    report = build_asn_netblock_report(
        [
            AsnNetblockRecord(
                asn=15169,
                organization="Google LLC",
                cidr="8.8.8.0/24",
                source="fixture",
            )
        ]
    )

    assets = asn_netblock_assets(report)

    assert assets[0].kind == "note"
    assert assets[0].value == "asn-netblock:AS15169:8.8.8.0/24"
    assert assets[0].metadata["organization"] == "Google LLC"


def test_asn_netblock_record_from_spec() -> None:
    record = asn_netblock_record_from_spec("AS15169:Google LLC=8.8.8.0/24")

    assert record.asn == 15169
    assert record.organization == "Google LLC"
    assert record.cidr == "8.8.8.0/24"


def test_load_asn_netblock_records_skips_invalid_rows(tmp_path: Path) -> None:
    input_path = tmp_path / "netblocks.json"
    input_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "asn": "AS15169",
                        "organization": "Google LLC",
                        "cidr": "8.8.8.0/24",
                        "source": "fixture",
                    },
                    {
                        "asn": "AS15169",
                        "organization": "Google LLC",
                        "cidr": "bad",
                        "source": "fixture",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    records, warnings = load_asn_netblock_records(input_path)

    assert len(records) == 1
    assert warnings
