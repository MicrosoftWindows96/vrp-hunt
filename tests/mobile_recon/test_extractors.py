from vrp_hunt.mobile_recon import (
    extract_mobile_endpoints,
    extract_mobile_secret_notes,
    parse_android_manifest,
    parse_dynamic_messages,
)


ANDROID_MANIFEST = """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.google.example">
  <application>
    <activity android:name=".MainActivity">
      <intent-filter>
        <data android:scheme="gexample" android:host="open" android:pathPrefix="/item" />
      </intent-filter>
    </activity>
    <service android:name="com.google.example.SyncService" />
  </application>
</manifest>
"""


def test_parse_android_manifest_components_and_deeplinks() -> None:
    assets = parse_android_manifest(ANDROID_MANIFEST)
    values = {asset.value for asset in assets}

    assert "com.google.example.MainActivity" in values
    assert "com.google.example.SyncService" in values
    assert "gexample://open/item" in values


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


def test_parse_dynamic_messages() -> None:
    assets = parse_dynamic_messages(
        '{"payload":{"url":"https://www.google.com/mobile","component":"MainActivity"}}\n',
        parent="com.google.app",
    )
    assert {asset.kind for asset in assets} == {"url", "mobile_component"}
