import pytest

from vrp_hunt.recon import Asset
from vrp_hunt.web_recon import ExposureDocument, check_safe_exposures, safe_exposure_assets


def test_check_safe_exposures_flags_panels_debug_and_config_without_secret_values() -> None:
    report = check_safe_exposures(
        [
            ExposureDocument(
                url="https://www.google.com/.env?token=secret",
                body="DB_PASSWORD=supersecret",
                source="env.txt",
            ),
            ExposureDocument(
                url="https://www.google.com/debug",
                body="Traceback (most recent call last)",
                source="debug.html",
            ),
            ExposureDocument(
                url="https://admin.google.com/admin",
                body="<title>Admin Console</title>",
                source="admin.html",
            ),
        ],
        scope_domains=["google.com"],
        assets=[Asset(kind="url", value="https://evil.com/debug", source="httpx")],
    )

    categories = {signal.category for signal in report.signals}
    matches = {signal.matched for signal in report.signals}
    config_signal = next(signal for signal in report.signals if signal.category == "config_leak")

    assert {"admin_panel", "debug_page", "config_leak"} <= categories
    assert {"path:/.env", "body:db-password", "body:python-traceback", "body:admin-console"} <= matches
    assert config_signal.confidence == "high"
    assert config_signal.parameter_names == ["token"]
    assert "asset:httpx:4: skipped third-party host evil.com" in report.warnings
    assert "supersecret" not in report.model_dump_json()
    assert "token=secret" not in report.model_dump_json()


def test_check_safe_exposures_detects_directory_listing() -> None:
    report = check_safe_exposures(
        [
            ExposureDocument(
                url="https://www.google.com/files/",
                body="<title>Index of /files</title><a>Parent Directory</a>",
                source="listing.html",
            )
        ],
        scope_domains=["google.com"],
    )

    assert report.signals[0].category == "directory_listing"
    assert report.signals[0].confidence == "medium"


def test_check_safe_exposures_requires_scope() -> None:
    with pytest.raises(ValueError, match="at least one scope domain"):
        check_safe_exposures([], scope_domains=[])


def test_safe_exposure_assets_dedupes() -> None:
    report = check_safe_exposures(
        [
            ExposureDocument(
                url="https://www.google.com/.env",
                body="DB_PASSWORD=redacted",
                source="env.txt",
            )
        ],
        scope_domains=["google.com"],
    )

    assets = safe_exposure_assets([*report.signals, *report.signals])

    assert sorted(asset.value for asset in assets) == [
        "safe-exposure:config_leak:https://www.google.com/.env",
        "safe-exposure:config_leak:https://www.google.com/.env",
    ]
