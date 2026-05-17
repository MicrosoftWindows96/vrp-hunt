from pathlib import Path

from vrp_hunt.mobile_recon import build_mobile_static_report


def test_mobile_static_report_ranks_oauth_deeplink_and_webview_hypotheses(tmp_path: Path) -> None:
    decompiled = tmp_path / "jadx"
    decompiled.mkdir()
    (decompiled / "AndroidManifest.xml").write_text(
        """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.google.example">
  <application>
    <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter>
        <data android:scheme="gexample" android:host="oauth" android:pathPrefix="/callback" />
      </intent-filter>
    </activity>
  </application>
</manifest>
""",
        encoding="utf-8",
    )
    (decompiled / "Client.java").write_text(
        "\n".join(
            [
                'String auth = "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=gexample://oauth/callback";',
                'String api = "https://www.googleapis.com/oauth2/v1/userinfo";',
                "webView.getSettings().setJavaScriptEnabled(true);",
                "webView.addJavascriptInterface(bridge, \"ownedBridge\");",
            ]
        ),
        encoding="utf-8",
    )

    report = build_mobile_static_report(
        app_id="com.google.example",
        artifact_path=decompiled,
        limit=5,
    )

    titles = {hypothesis.title for hypothesis in report.hypotheses}

    assert report.asset_count >= 5
    assert "OAuth redirect and account-switching review" in titles
    assert "Deep-link authorization boundary review" in titles
    assert "WebView bridge and navigation boundary review" in titles
    assert all("Passive hypothesis only" in hypothesis.safety_notes[0] for hypothesis in report.hypotheses)
