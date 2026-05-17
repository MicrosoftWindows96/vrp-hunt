"""Offline importers for APK, JADX, and MobSF mobile artifacts."""

from __future__ import annotations

import json
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.mobile_recon.adapter import MobileReconAdapter
from vrp_hunt.mobile_recon.extractors import extract_mobile_endpoints
from vrp_hunt.mobile_recon.hypotheses import MobileStaticHypothesis, build_mobile_static_hypotheses
from vrp_hunt.recon import Asset

MobileImportKind = Literal["apk", "jadx", "mobsf"]
MAX_MOBSF_REPORT_BYTES = 10_000_000


class MobileArtifactImportError(ValueError):
    """Raised when a mobile artifact cannot be imported safely."""


class MobileImportRecord(StrictModel):
    kind: MobileImportKind
    path: Path
    asset_count: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class MobileArtifactImportReport(StrictModel):
    app_id: str = Field(min_length=1)
    generated_at: datetime
    import_count: int = Field(ge=0)
    asset_count: int = Field(ge=0)
    hypothesis_count: int = Field(ge=0)
    imports: list[MobileImportRecord] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    hypotheses: list[MobileStaticHypothesis] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def import_mobile_artifacts(
    *,
    app_id: str,
    apk_path: Path | None = None,
    jadx_output_path: Path | None = None,
    mobsf_report_path: Path | None = None,
    hypothesis_limit: int = 10,
    now: datetime | None = None,
) -> MobileArtifactImportReport:
    """Import local mobile analysis artifacts without running tools or sending traffic."""

    if not any((apk_path, jadx_output_path, mobsf_report_path)):
        raise MobileArtifactImportError("at least one APK, JADX output, or MobSF report is required")
    if hypothesis_limit < 1:
        raise MobileArtifactImportError("hypothesis_limit must be at least 1")

    imports: list[MobileImportRecord] = []
    assets: list[Asset] = []
    warnings: list[str] = []
    if apk_path is not None:
        record, imported_assets = import_apk_artifact(app_id=app_id, path=apk_path)
        imports.append(record)
        assets.extend(imported_assets)
        warnings.extend(record.warnings)
    if jadx_output_path is not None:
        record, imported_assets = import_jadx_output(app_id=app_id, path=jadx_output_path)
        imports.append(record)
        assets.extend(imported_assets)
        warnings.extend(record.warnings)
    if mobsf_report_path is not None:
        record, imported_assets = import_mobsf_static_report(app_id=app_id, path=mobsf_report_path)
        imports.append(record)
        assets.extend(imported_assets)
        warnings.extend(record.warnings)

    deduped_assets = _dedupe_assets([_sanitize_asset(asset) for asset in assets])
    hypotheses = build_mobile_static_hypotheses(deduped_assets, limit=hypothesis_limit)
    return MobileArtifactImportReport(
        app_id=app_id,
        generated_at=now or datetime.now(UTC),
        import_count=len(imports),
        asset_count=len(deduped_assets),
        hypothesis_count=len(hypotheses),
        imports=imports,
        assets=deduped_assets,
        hypotheses=hypotheses,
        warnings=sorted(set(warnings)),
    )


def import_apk_artifact(*, app_id: str, path: Path) -> tuple[MobileImportRecord, list[Asset]]:
    _require_existing_file(path, noun="APK")
    digest = _sha256_file(path)
    metadata = {
        "artifact_type": "apk",
        "sha256": digest,
        "size_bytes": str(path.stat().st_size),
    }
    assets = [
        Asset(
            kind="mobile_component",
            value=app_id,
            source="mobile-apk-import",
            metadata=metadata,
        )
    ]
    warnings: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile:
        warnings.append("APK is not a readable zip archive; imported fingerprint only")
    else:
        dex_count = sum(1 for name in names if name.endswith(".dex"))
        assets.append(
            Asset(
                kind="note",
                value="apk:archive-summary",
                source="mobile-apk-import",
                parent=app_id,
                metadata={
                    "file_count": str(len(names)),
                    "dex_count": str(dex_count),
                    "has_android_manifest": str("AndroidManifest.xml" in names).lower(),
                    "redacted": "true",
                },
            )
        )
    return (
        MobileImportRecord(
            kind="apk",
            path=path,
            asset_count=len(assets),
            warnings=warnings,
            metadata=metadata,
        ),
        assets,
    )


def import_jadx_output(*, app_id: str, path: Path) -> tuple[MobileImportRecord, list[Asset]]:
    if not path.exists():
        raise MobileArtifactImportError(f"JADX output path does not exist: {path}")
    assets = MobileReconAdapter._scan_artifact_texts_from_path(path, parent=app_id)
    assets.append(
        Asset(
            kind="mobile_component",
            value=app_id,
            source="mobile-jadx-import",
            metadata={"artifact_path": str(path)},
        )
    )
    return (
        MobileImportRecord(
            kind="jadx",
            path=path,
            asset_count=len(assets),
            metadata={"artifact_path": str(path)},
        ),
        assets,
    )


def import_mobsf_static_report(*, app_id: str, path: Path) -> tuple[MobileImportRecord, list[Asset]]:
    _require_existing_file(path, noun="MobSF report")
    if path.stat().st_size > MAX_MOBSF_REPORT_BYTES:
        raise MobileArtifactImportError(
            f"MobSF report exceeds {MAX_MOBSF_REPORT_BYTES} bytes: {path}"
        )
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MobileArtifactImportError(f"MobSF report must be UTF-8 JSON: {path}") from exc
    if not isinstance(parsed, dict):
        raise MobileArtifactImportError("MobSF report root must be a JSON object")

    assets = [
        Asset(
            kind="mobile_component",
            value=_first_string(parsed, ("package_name", "package", "app_id")) or app_id,
            source="mobsf-import",
            metadata={
                "artifact_path": str(path),
                "app_name": _first_string(parsed, ("app_name", "file_name")) or "",
                "version_name": _first_string(parsed, ("version_name", "version")) or "",
            },
        )
    ]
    assets.extend(_mobsf_component_assets(parsed, app_id=app_id))
    assets.extend(_mobsf_permission_assets(parsed, app_id=app_id))
    assets.extend(_mobsf_domain_assets(parsed, app_id=app_id))
    for text in _walk_strings(parsed):
        assets.extend(extract_mobile_endpoints(text, parent=app_id, source="mobsf-import"))
    deduped = _dedupe_assets([_sanitize_asset(asset) for asset in assets])
    return (
        MobileImportRecord(
            kind="mobsf",
            path=path,
            asset_count=len(deduped),
            metadata={
                "artifact_path": str(path),
                "package_name": _first_string(parsed, ("package_name", "package", "app_id")) or "",
            },
        ),
        deduped,
    )


def _mobsf_component_assets(parsed: dict[str, object], *, app_id: str) -> list[Asset]:
    assets: list[Asset] = []
    for key, component_type in {
        "activities": "activity",
        "services": "service",
        "receivers": "receiver",
        "providers": "provider",
        "exported_activities": "activity",
        "exported_services": "service",
        "exported_receivers": "receiver",
        "exported_providers": "provider",
    }.items():
        for value in _strings_from_value(parsed.get(key)):
            metadata = {"component_type": component_type}
            if key.startswith("exported_"):
                metadata["exported"] = "true"
            assets.append(
                Asset(
                    kind="mobile_component",
                    value=value,
                    source="mobsf-import",
                    parent=app_id,
                    metadata=metadata,
                )
            )
    return assets


def _mobsf_permission_assets(parsed: dict[str, object], *, app_id: str) -> list[Asset]:
    assets: list[Asset] = []
    for permission in _strings_from_value(parsed.get("permissions")):
        assets.append(
            Asset(
                kind="note",
                value=f"android-permission:{permission}",
                source="mobsf-import",
                parent=app_id,
                metadata={"redacted": "true"},
            )
        )
    return assets


def _mobsf_domain_assets(parsed: dict[str, object], *, app_id: str) -> list[Asset]:
    assets: list[Asset] = []
    for key in ("domains", "domain_info", "urls"):
        for value in _strings_from_value(parsed.get(key)):
            host = urlsplit(value).hostname or value if "." in value else ""
            if host and "/" not in host:
                assets.append(Asset(kind="host", value=host.lower(), source="mobsf-import", parent=app_id))
    return assets


def _strings_from_value(value: object) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    if isinstance(value, dict):
        strings: list[str] = []
        for key, nested in value.items():
            if isinstance(key, str) and key.strip():
                strings.append(key.strip())
            strings.extend(_strings_from_value(nested))
        return strings
    return []


def _walk_strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _walk_strings(item)


def _first_string(parsed: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = parsed.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _sanitize_asset(asset: Asset) -> Asset:
    if asset.kind not in {"url", "endpoint"} or not asset.value.startswith(("http://", "https://")):
        return asset
    sanitized, parameter_names = _sanitize_url(asset.value)
    metadata = dict(asset.metadata)
    if parameter_names:
        metadata["parameter_names"] = ",".join(parameter_names)
        metadata["query_values_redacted"] = "true"
    return asset.model_copy(update={"value": sanitized, "metadata": metadata})


def _sanitize_url(value: str) -> tuple[str, list[str]]:
    parsed = urlsplit(value.strip())
    path = parsed.path or "/"
    parameter_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    return (
        urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", "")),
        parameter_names,
    )


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_key: dict[tuple[str, str, str], Asset] = {}
    for asset in assets:
        key = (asset.kind, asset.value, asset.parent or "")
        by_key.setdefault(key, asset)
    return list(by_key.values())


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_existing_file(path: Path, *, noun: str) -> None:
    if not path.exists():
        raise MobileArtifactImportError(f"{noun} path does not exist: {path}")
    if not path.is_file():
        raise MobileArtifactImportError(f"{noun} path must be a file: {path}")
