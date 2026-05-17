import json
from datetime import date
from pathlib import Path

import pytest

from vrp_hunt.programs import ScopeIngestionError, ScopeIngestionOptions, ingest_scope_export


def test_ingest_hackerone_structured_scope_export(tmp_path: Path) -> None:
    path = tmp_path / "h1.json"
    path.write_text(
        json.dumps(
            {
                "handle": "google",
                "name": "Google VRP",
                "policy_url": "https://hackerone.com/google",
                "structured_scopes": [
                    {
                        "attributes": {
                            "asset_identifier": "*.google.com",
                            "asset_type": "WILDCARD",
                            "eligible_for_submission": True,
                            "eligible_for_bounty": True,
                            "instruction": "Google web scope",
                        }
                    },
                    {
                        "attributes": {
                            "asset_identifier": "legacy.example.com",
                            "asset_type": "DOMAIN",
                            "eligible_for_submission": False,
                            "eligible_for_bounty": False,
                            "instruction": "Out of scope legacy host",
                        }
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    report = ingest_scope_export(
        path,
        options=ScopeIngestionOptions(source="hackerone", captured_date=date(2026, 5, 16)),
    )

    program = report.registry.programs[0]
    assert report.source == "hackerone"
    assert program.id == "google"
    assert program.scope[0].kind == "host_suffix"
    assert program.scope[0].value == "google.com"
    assert program.exclusions[0].value == "legacy.example.com"


def test_ingest_bugcrowd_target_groups(tmp_path: Path) -> None:
    path = tmp_path / "bugcrowd.json"
    path.write_text(
        json.dumps(
            {
                "code": "google",
                "name": "Google",
                "target_groups": [
                    {
                        "name": "web",
                        "targets": [
                            {
                                "target": "https://accounts.google.com/",
                                "type": "website",
                                "in_scope": True,
                                "reward": True,
                            },
                            {
                                "target": "*.appspot.com",
                                "type": "wildcard",
                                "in_scope": False,
                                "description": "Customer apps",
                            },
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = ingest_scope_export(
        path,
        options=ScopeIngestionOptions(source="bugcrowd", captured_date=date(2026, 5, 16)),
    )

    program = report.registry.programs[0]
    assert program.scope[0].kind == "exact_url"
    assert program.scope[0].value == "https://accounts.google.com/"
    assert program.exclusions[0].kind == "host_suffix"
    assert program.exclusions[0].value == "appspot.com"


def test_ingest_intigriti_scope_sections(tmp_path: Path) -> None:
    path = tmp_path / "intigriti.json"
    path.write_text(
        json.dumps(
            {
                "id": "deepmind",
                "name": "DeepMind",
                "in_scope": [
                    {
                        "endpoint": "deepmind.com",
                        "type": "domain",
                        "bounty": True,
                    },
                    {
                        "endpoint": "com.google.android.apps.maps",
                        "type": "android app",
                        "bounty": False,
                    },
                ],
                "out_of_scope": [
                    {
                        "endpoint": "research.example.com",
                        "type": "domain",
                        "description": "Example only",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = ingest_scope_export(
        path,
        options=ScopeIngestionOptions(source="intigriti", captured_date=date(2026, 5, 16)),
    )

    values = {entry.value: entry for entry in report.registry.programs[0].scope}
    assert values["deepmind.com"].reward_eligible
    assert values["com.google.android.apps.maps"].kind == "mobile_app"
    assert not values["com.google.android.apps.maps"].reward_eligible
    assert report.registry.programs[0].exclusions[0].value == "research.example.com"


def test_ingest_public_json_native_registry(tmp_path: Path) -> None:
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps(
            {
                "version": "native",
                "programs": [
                    {
                        "id": "test-program",
                        "name": "Test Program",
                        "platform": "Public JSON",
                        "policy_url": "https://example.com",
                        "captured_date": "2026-05-16",
                        "safe_harbor": {
                            "summary": "Test safely",
                            "source_reference": "fixture",
                        },
                        "scope": [
                            {
                                "id": "example",
                                "kind": "domain",
                                "value": "example.com",
                                "source_reference": "fixture",
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = ingest_scope_export(path, options=ScopeIngestionOptions(source="auto"))

    assert report.source == "public_json"
    assert report.registry.version == "native"
    assert report.scope_count == 1


def test_ingest_rejects_exports_without_supported_scope(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text('{"name":"Empty","scope":[]}', encoding="utf-8")

    with pytest.raises(ScopeIngestionError, match="no supported"):
        ingest_scope_export(path, options=ScopeIngestionOptions(source="public_json"))
