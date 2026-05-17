import pytest

from vrp_hunt.agent import (
    BrowserCheckError,
    classify_access_text,
    redact_object_url,
    validate_owned_object_url,
)


def test_validate_owned_object_url_accepts_exact_drive_file() -> None:
    validate_owned_object_url("https://drive.google.com/file/d/abc123/view")
    validate_owned_object_url("https://docs.google.com/document/d/abc123/edit")
    validate_owned_object_url("https://script.google.com/macros/s/abc123/exec")
    validate_owned_object_url("https://script.google.com/macros/s/abc123/dev")


def test_validate_owned_object_url_rejects_broad_pages() -> None:
    with pytest.raises(BrowserCheckError, match="broad Drive"):
        validate_owned_object_url("https://drive.google.com/drive/my-drive")
    with pytest.raises(BrowserCheckError, match="limited"):
        validate_owned_object_url("https://accounts.google.com/")
    with pytest.raises(BrowserCheckError, match="Apps Script"):
        validate_owned_object_url("https://script.google.com/home/projects/abc123/edit")


def test_redact_object_url_does_not_keep_object_id() -> None:
    redacted = redact_object_url("https://drive.google.com/file/d/secret-object-id/view?usp=sharing")

    assert "secret-object-id" not in redacted
    assert redacted.startswith("https://drive.google.com/[path:")
    assert "keys=usp" in redacted


def test_classify_access_text_detects_denied_and_login_states() -> None:
    denied = classify_access_text("You need access. Request access from the owner.")
    login = classify_access_text("", current_url="https://accounts.google.com/signin")

    assert denied[0] == "access_denied"
    assert "you need access" in denied[2]
    assert login[0] == "login_required"


def test_classify_access_text_is_conservative_for_granted_access() -> None:
    granted = classify_access_text(
        "Google Docs File Share Open with",
        current_url="https://docs.google.com/document/d/abc/edit",
    )
    unknown = classify_access_text("plain page text", current_url="https://docs.google.com/document/d/abc/edit")

    assert granted[0] == "access_granted"
    assert granted[1] < 0.8
    assert unknown[0] == "unknown"


def test_classify_access_text_detects_apps_script_marker() -> None:
    result = classify_access_text(
        "VRP_SCRIPT_OK owned web app",
        current_url="https://script.googleusercontent.com/macros/echo?user_content_key=redacted",
    )

    assert result[0] == "access_granted"
    assert "vrp_script_ok" in result[2]
