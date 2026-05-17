import json
import zipfile
from pathlib import Path

import pytest

from vrp_hunt.mobile_recon import (
    MobileArtifactImportError,
    import_apk_artifact,
    import_jadx_output,
    import_mobile_artifacts,
    import_mobsf_static_report,
)


def test_import_apk_artifact_fingerprints_zip(tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("classes.dex", b"dex")
        archive.writestr("AndroidManifest.xml", b"manifest")

    record, assets = import_apk_artifact(app_id="com.google.example", path=apk_path)

    assert record.kind == "apk"
    assert record.metadata["sha256"]
    assert {asset.value for asset in assets} >= {
        "com.google.example",
        "apk:archive-summary",
    }
    assert assets[1].metadata["dex_count"] == "1"


def test_import_jadx_output_extracts_manifest_endpoints_and_notes(tmp_path: Path) -> None:
    jadx_dir = tmp_path / "jadx"
    jadx_dir.mkdir()
    (jadx_dir / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.google.example">
  <application>
    <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter>
        <data android:scheme="gexample" android:host="open" android:pathPrefix="/item" />
      </intent-filter>
    </activity>
  </application>
</manifest>
""",
        encoding="utf-8",
    )
    (jadx_dir / "Client.java").write_text(
        'String auth = "https://accounts.google.com/o/oauth2/v2/auth?client_id=owned";',
        encoding="utf-8",
    )

    record, assets = import_jadx_output(app_id="com.google.example", path=jadx_dir)

    assert record.kind == "jadx"
    assert "com.google.example.DeepLinkActivity" in {asset.value for asset in assets}
    assert "https://accounts.google.com/o/oauth2/v2/auth?client_id=owned" in {
        asset.value for asset in assets
    }


def test_import_mobsf_static_report_extracts_redacted_assets(tmp_path: Path) -> None:
    report_path = tmp_path / "mobsf.json"
    report_path.write_text(
        json.dumps(
            {
                "package_name": "com.google.example",
                "app_name": "Example",
                "activities": ["com.google.example.MainActivity"],
                "exported_activities": ["com.google.example.DeepLinkActivity"],
                "permissions": ["android.permission.INTERNET"],
                "urls": [
                    "https://www.googleapis.com/oauth2/v1/userinfo?access_token=secret",
                    "www.google.com",
                ],
            }
        ),
        encoding="utf-8",
    )

    record, assets = import_mobsf_static_report(app_id="com.google.example", path=report_path)
    values = {asset.value for asset in assets}

    assert record.kind == "mobsf"
    assert "com.google.example.MainActivity" in values
    assert "https://www.googleapis.com/oauth2/v1/userinfo" in values
    assert "www.google.com" in values
    assert not any("secret" in asset.value for asset in assets)


def test_import_mobile_artifacts_combines_inputs_and_hypotheses(tmp_path: Path) -> None:
    apk_path = tmp_path / "app.apk"
    with zipfile.ZipFile(apk_path, "w") as archive:
        archive.writestr("classes.dex", b"dex")
    mobsf_path = tmp_path / "mobsf.json"
    mobsf_path.write_text(
        json.dumps(
            {
                "package_name": "com.google.example",
                "urls": ["https://accounts.google.com/o/oauth2/v2/auth?client_id=owned"],
            }
        ),
        encoding="utf-8",
    )

    report = import_mobile_artifacts(
        app_id="com.google.example",
        apk_path=apk_path,
        mobsf_report_path=mobsf_path,
    )

    assert report.import_count == 2
    assert report.asset_count >= 2
    assert report.hypotheses[0].title == "OAuth redirect and account-switching review"


def test_import_mobile_artifacts_requires_input() -> None:
    with pytest.raises(MobileArtifactImportError, match="at least one"):
        import_mobile_artifacts(app_id="com.google.example")
