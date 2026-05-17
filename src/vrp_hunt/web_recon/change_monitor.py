"""Offline app change monitoring from saved HTTP metadata."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field, field_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

ChangeSnapshotRole = Literal["current", "previous"]
ChangeType = Literal["new", "removed", "changed"]


class AppSnapshotDocument(StrictModel):
    role: ChangeSnapshotRole = "current"
    evidence: str = Field(min_length=1)
    text: str = ""


class AppSnapshot(StrictModel):
    url: str = Field(min_length=1)
    host: str = Field(min_length=1)
    role: ChangeSnapshotRole = "current"
    evidence: str = Field(min_length=1)
    status_code: str | None = None
    title: str | None = None
    body_hash: str | None = None
    header_hash: str | None = None
    javascript_hashes: list[str] = Field(default_factory=list)
    observed_at: str | None = None
    parameter_names: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("snapshot URL must be absolute http(s)")
        return sanitized.url

    @field_validator("body_hash", "header_hash")
    @classmethod
    def normalize_hash(cls, value: str | None) -> str | None:
        return value.strip().lower() if isinstance(value, str) and value.strip() else None

    @field_validator("javascript_hashes", "parameter_names")
    @classmethod
    def clean_string_list(cls, value: list[str]) -> list[str]:
        items: list[str] = []
        seen: set[str] = set()
        for item in value:
            candidate = item.strip().lower()
            if candidate and candidate not in seen:
                seen.add(candidate)
                items.append(candidate)
        return items


class AppChange(StrictModel):
    url: str = Field(min_length=1)
    change_type: ChangeType
    changed_fields: list[str] = Field(default_factory=list)
    previous_status_code: str | None = None
    current_status_code: str | None = None
    previous_title: str | None = None
    current_title: str | None = None

    @field_validator("url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        sanitized = _sanitize_url(value)
        if sanitized is None:
            raise ValueError("change URL must be absolute http(s)")
        return sanitized.url


class AppChangeReport(StrictModel):
    scope_domains: list[str] = Field(min_length=1)
    total_inputs: int = Field(ge=0)
    total_snapshots: int = Field(ge=0)
    total_changes: int = Field(ge=0)
    snapshots: list[AppSnapshot] = Field(default_factory=list)
    changes: list[AppChange] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def monitor_app_changes(
    documents: list[AppSnapshotDocument],
    *,
    scope_domains: list[str],
) -> AppChangeReport:
    normalized_scope = _normalize_scope_domains(scope_domains)
    snapshots: list[AppSnapshot] = []
    warnings: list[str] = []
    total_inputs = 0
    for document in documents:
        items = _items_from_text(document.text)
        total_inputs += len(items)
        for index, item in enumerate(items, start=1):
            snapshot, warning = _snapshot_from_item(
                item,
                document=document,
                index=index,
                scope_domains=normalized_scope,
            )
            if snapshot is not None:
                snapshots.append(snapshot)
            if warning is not None:
                warnings.append(warning)
    deduped_snapshots = _dedupe_snapshots(snapshots)
    changes = _changes_for_snapshots(deduped_snapshots)
    assets = app_change_assets(changes)
    return AppChangeReport(
        scope_domains=normalized_scope,
        total_inputs=total_inputs,
        total_snapshots=len(deduped_snapshots),
        total_changes=len(changes),
        snapshots=deduped_snapshots,
        changes=changes,
        assets=assets,
        warnings=sorted(set(warnings)),
    )


def load_app_snapshot_documents(
    *,
    current_files: list[Path] | None = None,
    previous_files: list[Path] | None = None,
) -> list[AppSnapshotDocument]:
    documents: list[AppSnapshotDocument] = []
    for path in current_files or []:
        documents.append(
            AppSnapshotDocument(role="current", evidence=str(path), text=path.read_text(encoding="utf-8"))
        )
    for path in previous_files or []:
        documents.append(
            AppSnapshotDocument(role="previous", evidence=str(path), text=path.read_text(encoding="utf-8"))
        )
    return documents


def app_change_assets(changes: list[AppChange]) -> list[Asset]:
    assets: list[Asset] = []
    for change in changes:
        assets.append(
            Asset(
                kind="note",
                value=f"app-change:{change.url}",
                source="app-change-monitor",
                parent=change.url,
                metadata={
                    "change_type": change.change_type,
                    "changed_fields": ",".join(change.changed_fields),
                    "previous_status_code": change.previous_status_code or "",
                    "current_status_code": change.current_status_code or "",
                    "previous_title": change.previous_title or "",
                    "current_title": change.current_title or "",
                },
            )
        )
    return _dedupe_assets(assets)


def _snapshot_from_item(
    item: object,
    *,
    document: AppSnapshotDocument,
    index: int,
    scope_domains: list[str],
) -> tuple[AppSnapshot | None, str | None]:
    if not isinstance(item, dict):
        return None, f"{document.evidence}:{index}: skipped non-object record"
    raw_url = _first_string(item, ("url", "final_url", "input", "target"))
    if raw_url is None:
        return None, f"{document.evidence}:{index}: missing url"
    sanitized = _sanitize_url(raw_url)
    if sanitized is None:
        return None, f"{document.evidence}:{index}: invalid url"
    host = urlsplit(sanitized.url).hostname or ""
    if not _host_allowed(host, scope_domains):
        return None, f"{document.evidence}:{index}: skipped third-party host {host}"
    header_hash = _first_string(item, ("header_hash", "headers_hash"))
    headers = item.get("headers") or item.get("header")
    if header_hash is None and isinstance(headers, dict):
        header_hash = _headers_hash(headers)
    return (
        AppSnapshot(
            url=sanitized.url,
            host=host,
            role=document.role,
            evidence=document.evidence,
            status_code=_string_or_none(item.get("status_code") or item.get("status")),
            title=_first_string(item, ("title", "page_title")),
            body_hash=_first_string(item, ("body_hash", "content_hash", "dom_hash", "hash")),
            header_hash=header_hash,
            javascript_hashes=_string_list(item.get("javascript_hashes") or item.get("js_hashes")),
            observed_at=_first_string(item, ("observed_at", "timestamp", "captured_at", "time")),
            parameter_names=sanitized.parameter_names,
        ),
        None,
    )


def _changes_for_snapshots(snapshots: list[AppSnapshot]) -> list[AppChange]:
    current_by_url = {snapshot.url: snapshot for snapshot in snapshots if snapshot.role == "current"}
    previous_by_url = {snapshot.url: snapshot for snapshot in snapshots if snapshot.role == "previous"}
    changes: list[AppChange] = []
    for url in sorted(set(current_by_url) | set(previous_by_url)):
        current = current_by_url.get(url)
        previous = previous_by_url.get(url)
        if current is None and previous is not None:
            changes.append(_change_from(previous=previous, current=None, change_type="removed"))
        elif current is not None and previous is None:
            changes.append(_change_from(previous=None, current=current, change_type="new"))
        elif current is not None and previous is not None:
            changed_fields = _changed_fields(previous, current)
            if changed_fields:
                changes.append(
                    _change_from(previous=previous, current=current, change_type="changed", fields=changed_fields)
                )
    return changes


def _change_from(
    *,
    previous: AppSnapshot | None,
    current: AppSnapshot | None,
    change_type: ChangeType,
    fields: list[str] | None = None,
) -> AppChange:
    url = current.url if current is not None else previous.url if previous is not None else ""
    return AppChange(
        url=url,
        change_type=change_type,
        changed_fields=fields or [],
        previous_status_code=previous.status_code if previous is not None else None,
        current_status_code=current.status_code if current is not None else None,
        previous_title=previous.title if previous is not None else None,
        current_title=current.title if current is not None else None,
    )


def _changed_fields(previous: AppSnapshot, current: AppSnapshot) -> list[str]:
    fields: list[str] = []
    for field in ("status_code", "title", "body_hash", "header_hash", "javascript_hashes"):
        if getattr(previous, field) != getattr(current, field):
            fields.append(field)
    return fields


def _items_from_text(text: str) -> list[object]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        items: list[object] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("snapshots", "results", "items", "data", "pages"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    return []


class _SanitizedUrl(StrictModel):
    url: str
    parameter_names: list[str] = Field(default_factory=list)


def _sanitize_url(value: str) -> _SanitizedUrl | None:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = _normalize_host(parsed.hostname)
    if host is None:
        return None
    port = f":{parsed.port}" if parsed.port is not None else ""
    path = parsed.path or "/"
    parameter_names = sorted({name for name, _value in parse_qsl(parsed.query, keep_blank_values=True) if name})
    return _SanitizedUrl(
        url=urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, "", "")),
        parameter_names=parameter_names,
    )


def _headers_hash(headers: dict[object, object]) -> str:
    items = sorted(headers.items(), key=lambda item: str(item[0]).strip().lower())
    parts = [f"{str(key).strip().lower()}={str(value).strip()}" for key, value in items]
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _normalize_scope_domains(scope_domains: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for value in scope_domains:
        candidate = value.strip().lower().removeprefix("*.").rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        host = _normalize_host(candidate)
        if host is None:
            continue
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    if not normalized:
        raise ValueError("at least one scope domain is required")
    return normalized


def _normalize_host(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None
    try:
        return normalize_host(candidate).host
    except NormalizationError:
        return None


def _host_allowed(host: str, scope_domains: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    return any(normalized_host == domain or normalized_host.endswith(f".{domain}") for domain in scope_domains)


def _first_string(item: dict[object, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _string_or_none(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    return None


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [token.strip() for token in value.split(",") if token.strip()]
    return []


def _dedupe_snapshots(snapshots: list[AppSnapshot]) -> list[AppSnapshot]:
    by_key = {(snapshot.role, snapshot.url): snapshot for snapshot in snapshots}
    return sorted(by_key.values(), key=lambda snapshot: (snapshot.role, snapshot.url))


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))
