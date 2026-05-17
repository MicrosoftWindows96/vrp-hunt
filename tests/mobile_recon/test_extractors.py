from vrp_hunt.mobile_recon import (
    extract_certificate_pinning_indicators,
    extract_mobile_endpoints,
    extract_mobile_risk_notes,
    extract_mobile_secret_notes,
    parse_android_manifest,
    parse_dynamic_messages,
    summarize_android_manifest_permissions,
)


ANDROID_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.google.example">
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <data android:scheme="gexample" android:host="open" android:pathPrefix="/item" />
      </intent-filter>
    </activity>
    <service android:name="com.google.example.SyncService" android:exported="false" />
  </application>
</manifest>
"""


def test_parse_android_manifest_components_and_deeplinks() -> None:
    assets = parse_android_manifest(ANDROID_MANIFEST)
    values = {asset.value for asset in assets}

    assert "com.google.example.MainActivity" in values
    assert "com.google.example.SyncService" in values
    assert "gexample://open/item" in values
    main_activity = next(asset for asset in assets if asset.value == "com.google.example.MainActivity")
    assert main_activity.metadata["intent_filters"] == "1"
    sync_service = next(asset for asset in assets if asset.value == "com.google.example.SyncService")
    assert sync_service.metadata["exported"] == "false"
    permission_risks = [asset for asset in assets if asset.value.startswith("android-permission-risk:")]
    assert {asset.metadata["risk"] for asset in permission_risks} == {"high", "low"}


def test_summarize_android_manifest_permissions_counts_risk_levels() -> None:
    summary = summarize_android_manifest_permissions(ANDROID_MANIFEST)

    assert summary.package_name == "com.google.example"
    assert summary.permission_count == 2
    assert summary.high_risk_count == 1
    assert summary.low_risk_count == 1
    assert summary.risks[0].permission == "android.permission.ACCESS_FINE_LOCATION"


def test_extract_certificate_pinning_indicators() -> None:
    notes = extract_certificate_pinning_indicators(
        (
            "val pinner = okhttp3.CertificatePinner.Builder().add("
            '"www.google.com", "sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=")'
        ),
        parent="com.google.app",
    )

    assert {note.value for note in notes} == {
        "mobile-pinning:okhttp-certificate-pinner",
        "mobile-pinning:public-key-pin",
    }
    assert all(note.metadata["requires_manual_review"] == "true" for note in notes)


def test_extract_mobile_endpoints() -> None:
    assets = extract_mobile_endpoints(
        'val url = "https://www.googleapis.com/oauth2/v1/userinfo"; val d = "gapp://open"',
        parent="com.google.app",
    )
    assert {asset.kind for asset in assets} == {"url", "endpoint"}


def test_extract_mobile_secret_notes_redacts_values() -> None:
    notes = extract_mobile_secret_notes("apiKey = 'AIza12345678901234567890'", parent="app")
    assert notes[0].value == "potential-secret-pattern:api_key"
    assert notes[0].metadata["redacted"] == "true"


def test_extract_mobile_risk_notes() -> None:
    notes = extract_mobile_risk_notes(
        "webView.getSettings().setJavaScriptEnabled(true); webView.addJavascriptInterface(obj, 'bridge');",
        parent="app",
    )

    assert {note.value for note in notes} == {
        "mobile-risk:webview-javascript-enabled",
        "mobile-risk:webview-js-bridge",
    }
    assert all(note.metadata["redacted"] == "true" for note in notes)


def test_parse_dynamic_messages() -> None:
    assets = parse_dynamic_messages(
        '{"payload":{"url":"https://www.google.com/mobile","component":"MainActivity"}}\n',
        parent="com.google.app",
    )
    assert {asset.kind for asset in assets} == {"url", "mobile_component"}
