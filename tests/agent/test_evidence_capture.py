from pathlib import Path

import pytest

from vrp_hunt.agent import EvidenceCapture, EvidenceCaptureError, HttpEvidenceExchange


PNG_BYTES = b"\x89PNG\r\n\x1a\nredacted-png"
WEBM_BYTES = b"\x1a\x45\xdf\xa3redacted-webm"


def test_capture_http_log_writes_redacted_jsonl(tmp_path: Path) -> None:
    capture = EvidenceCapture(finding_id="finding-1", output_dir=tmp_path)
    exchange = HttpEvidenceExchange(
        method="get",
        url="https://accounts.google.com/profile?access_token=secret-token",
        status_code=200,
        request_headers={
            "Authorization": "Bearer raw-token",
            "X-Test": "marker",
        },
        response_headers={"Set-Cookie": "SID=secret"},
        request_body='{"password":"secret-pass","field":"ok"}',
        response_body="profile_id=owned-test-object&api_key=secret-key",
        note="Bearer note-token",
    )

    item = capture.capture_http_log([exchange])
    path = Path(item.path_or_ref)
    content = path.read_text(encoding="utf-8")

    assert item.kind == "http"
    assert item.redacted
    assert path.name == "001-http.jsonl"
    assert "secret-token" not in content
    assert "raw-token" not in content
    assert "secret-pass" not in content
    assert "secret-key" not in content
    assert "[REDACTED]" in content
    assert "marker" in content


def test_capture_screenshot_and_video_write_evidence_files(tmp_path: Path) -> None:
    capture = EvidenceCapture(finding_id="finding-1", output_dir=tmp_path)

    screenshot = capture.capture_screenshot(PNG_BYTES)
    video = capture.capture_video(WEBM_BYTES)

    assert [item.kind for item in capture.items] == ["screenshot", "video"]
    assert Path(screenshot.path_or_ref).read_bytes() == PNG_BYTES
    assert Path(video.path_or_ref).read_bytes() == WEBM_BYTES
    assert Path(screenshot.path_or_ref).name == "001-screenshot.png"
    assert Path(video.path_or_ref).name == "002-video.webm"


def test_capture_artifacts_batches_all_supported_evidence(tmp_path: Path) -> None:
    capture = EvidenceCapture(finding_id="finding-1", output_dir=tmp_path)
    exchange = HttpEvidenceExchange(method="GET", url="https://accounts.google.com/profile")

    items = capture.capture_artifacts(
        http_exchanges=[exchange],
        screenshot_bytes=PNG_BYTES,
        video_bytes=WEBM_BYTES,
    )

    assert [item.kind for item in items] == ["http", "screenshot", "video"]
    assert len(capture.items) == 3


def test_capture_rejects_unsafe_media_and_filenames(tmp_path: Path) -> None:
    capture = EvidenceCapture(finding_id="finding-1", output_dir=tmp_path)

    with pytest.raises(EvidenceCaptureError, match="screenshot"):
        capture.capture_screenshot(b"not-an-image")

    with pytest.raises(EvidenceCaptureError, match="video"):
        capture.capture_video(b"not-a-video")

    with pytest.raises(EvidenceCaptureError, match="filename"):
        capture.capture_http_log(
            [HttpEvidenceExchange(method="GET", url="https://accounts.google.com/profile")],
            filename="../http.jsonl",
        )
