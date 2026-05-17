"""Evidence capture helpers for agent observations and reports."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path

from pydantic import Field, model_validator

from vrp_hunt.guardrails.audit import SENSITIVE_KEY_PARTS
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.playbooks import EvidenceItem
from vrp_hunt.playbooks.models import EvidenceKind

MAX_TEXT_EVIDENCE_BYTES = 2_000_000
MAX_MEDIA_EVIDENCE_BYTES = 25_000_000
SECRET_PATTERNS = (
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(
        r"(?i)\b([A-Za-z0-9_.-]*(?:auth|cookie|key|password|secret|sid|token)[A-Za-z0-9_.-]*)"
        r"=([^&\s;]+)"
    ),
    re.compile(
        r'(?i)("?[A-Za-z0-9_.-]*(?:auth|cookie|key|password|secret|sid|token)[A-Za-z0-9_.-]*"?)'
        r"\s*:\s*"
        r'("[^"]*"|[^\s,}]+)'
    ),
)


class EvidenceCaptureError(ValueError):
    """Raised when evidence cannot be captured safely."""


class HttpEvidenceExchange(StrictModel):
    """One redacted HTTP exchange candidate for evidence capture."""

    method: str = Field(min_length=1, max_length=16)
    url: str = Field(min_length=1, max_length=4096)
    status_code: int | None = Field(default=None, ge=100, le=599)
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = Field(default=None, max_length=200_000)
    response_body: str | None = Field(default=None, max_length=200_000)
    note: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def normalize_method(self) -> "HttpEvidenceExchange":
        self.method = self.method.strip().upper()
        return self

    def redacted_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "url": redact_text(self.url),
            "status_code": self.status_code,
            "request_headers": redact_headers(self.request_headers),
            "response_headers": redact_headers(self.response_headers),
            "request_body": redact_text(self.request_body) if self.request_body is not None else None,
            "response_body": redact_text(self.response_body) if self.response_body is not None else None,
            "note": redact_text(self.note) if self.note is not None else None,
        }


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in sorted(headers.items()):
        lowered = key.lower()
        if any(part in lowered for part in SENSITIVE_KEY_PARTS):
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = redact_text(value)
    return redacted


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(_redacted_match, redacted)
    return redacted


def _redacted_match(match: re.Match[str]) -> str:
    if match.re.pattern.startswith("(?i)\\bbearer"):
        return "Bearer [REDACTED]"
    if match.re.pattern.startswith("\\bAIza"):
        return "[REDACTED]"
    if len(match.groups()) >= 2 and ":" in match.group(0):
        return f"{match.group(1)}: [REDACTED]"
    if len(match.groups()) >= 2:
        return f"{match.group(1)}=[REDACTED]"
    return "[REDACTED]"


class EvidenceCapture(StrictModel):
    finding_id: str = Field(min_length=1)
    output_dir: Path = Path("data/evidence")
    items: list[EvidenceItem] = Field(default_factory=list)

    def record_http_log(self, path_or_ref: str, *, description: str = "redacted HTTP log") -> EvidenceItem:
        return self._append("http", description, path_or_ref)

    def record_screenshot(
        self,
        path_or_ref: str,
        *,
        description: str = "redacted browser screenshot",
    ) -> EvidenceItem:
        return self._append("screenshot", description, path_or_ref)

    def record_video(
        self,
        path_or_ref: str,
        *,
        description: str = "redacted reproduction video",
    ) -> EvidenceItem:
        return self._append("video", description, path_or_ref)

    def record_burp_export(
        self,
        path_or_ref: str,
        *,
        description: str = "redacted Burp evidence export",
    ) -> EvidenceItem:
        return self._append("burp", description, path_or_ref)

    def record_har(
        self,
        path_or_ref: str,
        *,
        description: str = "redacted HAR evidence export",
    ) -> EvidenceItem:
        return self._append("har", description, path_or_ref)

    def record_tool_versions(
        self,
        path_or_ref: str,
        *,
        description: str = "tool version inventory",
    ) -> EvidenceItem:
        return self._append("tool_versions", description, path_or_ref)

    def record_note(self, note: str, *, ref: str) -> EvidenceItem:
        return self._append("note", note, ref)

    def capture_http_log(
        self,
        exchanges: Sequence[HttpEvidenceExchange],
        *,
        filename: str | None = None,
        description: str = "redacted HTTP log",
    ) -> EvidenceItem:
        if not exchanges:
            raise EvidenceCaptureError("at least one HTTP exchange is required")
        path = self._artifact_path("http", "jsonl", filename)
        lines = [
            json.dumps(exchange.redacted_dict(), sort_keys=True)
            for exchange in exchanges
        ]
        content = "\n".join(lines) + "\n"
        if len(content.encode("utf-8")) > MAX_TEXT_EVIDENCE_BYTES:
            raise EvidenceCaptureError("HTTP evidence exceeds size limit")
        path.write_text(content, encoding="utf-8")
        return self.record_http_log(str(path), description=description)

    def capture_har(
        self,
        har_json: str,
        *,
        filename: str | None = None,
        description: str = "redacted HAR evidence export",
    ) -> EvidenceItem:
        redacted = redact_text(har_json)
        if len(redacted.encode("utf-8")) > MAX_TEXT_EVIDENCE_BYTES:
            raise EvidenceCaptureError("HAR evidence exceeds size limit")
        path = self._artifact_path("har", "har", filename)
        path.write_text(redacted, encoding="utf-8")
        return self.record_har(str(path), description=description)

    def capture_tool_versions(
        self,
        versions: dict[str, str],
        *,
        filename: str | None = None,
        description: str = "tool version inventory",
    ) -> EvidenceItem:
        if not versions:
            raise EvidenceCaptureError("at least one tool version is required")
        content = json.dumps(redact_headers(versions), indent=2, sort_keys=True) + "\n"
        if len(content.encode("utf-8")) > MAX_TEXT_EVIDENCE_BYTES:
            raise EvidenceCaptureError("tool version evidence exceeds size limit")
        path = self._artifact_path("tool_versions", "json", filename)
        path.write_text(content, encoding="utf-8")
        return self.record_tool_versions(str(path), description=description)

    def capture_screenshot(
        self,
        image_bytes: bytes,
        *,
        filename: str | None = None,
        description: str = "redacted browser screenshot",
    ) -> EvidenceItem:
        suffix = _screenshot_suffix(image_bytes)
        path = self._artifact_path("screenshot", suffix, filename)
        _write_media(path, image_bytes)
        return self.record_screenshot(str(path), description=description)

    def capture_video(
        self,
        video_bytes: bytes,
        *,
        filename: str | None = None,
        description: str = "redacted reproduction video",
    ) -> EvidenceItem:
        suffix = _video_suffix(video_bytes)
        path = self._artifact_path("video", suffix, filename)
        _write_media(path, video_bytes)
        return self.record_video(str(path), description=description)

    def capture_artifacts(
        self,
        *,
        http_exchanges: Sequence[HttpEvidenceExchange] | None = None,
        screenshot_bytes: bytes | None = None,
        video_bytes: bytes | None = None,
    ) -> list[EvidenceItem]:
        captured: list[EvidenceItem] = []
        if http_exchanges is not None:
            captured.append(self.capture_http_log(http_exchanges))
        if screenshot_bytes is not None:
            captured.append(self.capture_screenshot(screenshot_bytes))
        if video_bytes is not None:
            captured.append(self.capture_video(video_bytes))
        return captured

    def _append(self, kind: EvidenceKind, description: str, path_or_ref: str) -> EvidenceItem:
        item = EvidenceItem(
            kind=kind,
            description=description,
            path_or_ref=path_or_ref,
            redacted=True,
        )
        self.items.append(item)
        return item

    def _artifact_path(self, kind: EvidenceKind, suffix: str, filename: str | None) -> Path:
        directory = self.output_dir / self.finding_id
        directory.mkdir(parents=True, exist_ok=True)
        if filename is None:
            name = f"{len(self.items) + 1:03d}-{kind}.{suffix}"
        else:
            candidate = Path(filename)
            if candidate.is_absolute() or candidate.name != filename or ".." in candidate.parts:
                raise EvidenceCaptureError("evidence filename must be a simple relative filename")
            name = filename
        return directory / name


def _write_media(path: Path, data: bytes) -> None:
    if not data:
        raise EvidenceCaptureError("media evidence cannot be empty")
    if len(data) > MAX_MEDIA_EVIDENCE_BYTES:
        raise EvidenceCaptureError("media evidence exceeds size limit")
    path.write_bytes(data)


def _screenshot_suffix(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    raise EvidenceCaptureError("screenshot evidence must be PNG, JPEG, or WebP")


def _video_suffix(data: bytes) -> str:
    if data.startswith(b"\x1a\x45\xdf\xa3"):
        return "webm"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "mp4"
    raise EvidenceCaptureError("video evidence must be WebM or MP4")
