"""Parsers for passive recon tool output."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from vrp_hunt.recon import Asset
from vrp_hunt.recon.models import AssetKind


def parse_subfinder_jsonl(output: str, *, source: str = "subfinder") -> list[Asset]:
    assets: list[Asset] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        host: str | None = None
        sources = ""
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            host = line
        else:
            if isinstance(parsed, dict):
                raw_host = parsed.get("host") or parsed.get("name") or parsed.get("subdomain")
                if isinstance(raw_host, str):
                    host = raw_host
                raw_sources = parsed.get("sources") or parsed.get("source")
                if isinstance(raw_sources, list):
                    sources = ",".join(_source_tokens(raw_sources))
                elif isinstance(raw_sources, str):
                    sources = ",".join(_source_tokens([raw_sources]))
        if host:
            metadata = {"sources": sources, "source_count": str(len(sources.split(",")))} if sources else {}
            assets.append(Asset(kind="host", value=host.lower(), source=source, metadata=metadata))
    return assets


def parse_amass_text(output: str, *, source: str = "amass") -> list[Asset]:
    assets: list[Asset] = []
    for line in output.splitlines():
        candidate = line.strip().split(" ")[0]
        if "." in candidate and "/" not in candidate and not candidate.replace(".", "").isdigit():
            assets.append(Asset(kind="host", value=candidate.lower(), source=source))
    return assets


def parse_httpx_jsonl(output: str, *, source: str = "httpx") -> list[Asset]:
    assets: list[Asset] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        url = parsed.get("url") or parsed.get("final_url")
        if isinstance(url, str):
            assets.append(
                Asset(
                    kind="url",
                    value=url,
                    source=source,
                    metadata=_metadata(parsed, ["status_code", "title", "webserver", "content_length"]),
                )
            )
            host = urlsplit(url).hostname
            if host:
                assets.append(Asset(kind="host", value=host, source=source, parent=url))
        technologies = parsed.get("technologies") or parsed.get("tech")
        if isinstance(technologies, list) and isinstance(url, str):
            for technology in technologies:
                assets.append(Asset(kind="technology", value=str(technology), source=source, parent=url))
    return assets


def parse_katana_jsonl(output: str, *, source: str = "katana") -> list[Asset]:
    assets: list[Asset] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        url = _first_string(parsed, ["url", "endpoint", "request_url"])
        if url is None:
            continue
        kind: AssetKind = "javascript" if urlsplit(url).path.lower().endswith(".js") else "endpoint"
        assets.append(
            Asset(
                kind=kind,
                value=url,
                source=source,
                metadata=_metadata(parsed, ["method", "source", "tag", "attribute"]),
            )
        )
        host = urlsplit(url).hostname
        if host:
            assets.append(Asset(kind="host", value=host, source=source, parent=url))
    return assets


def parse_nuclei_jsonl(output: str, *, source: str = "nuclei") -> list[Asset]:
    assets: list[Asset] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(parsed, dict):
            continue
        matched = _first_string(parsed, ["matched-at", "matched", "url", "host"])
        template_id = _first_string(parsed, ["template-id", "templateID", "id"]) or "unknown-template"
        info = parsed.get("info")
        info_mapping = info if isinstance(info, dict) else {}
        metadata = {
            "template_id": template_id,
            "severity": str(info_mapping.get("severity", "")),
            "name": str(info_mapping.get("name", "")),
        }
        if matched:
            assets.append(
                Asset(
                    kind="note",
                    value=f"nuclei:{template_id}:{matched}",
                    source=source,
                    parent=matched,
                    metadata=metadata,
                )
            )
            host = urlsplit(matched).hostname
            if host:
                assets.append(Asset(kind="host", value=host, source=source, parent=matched))
    return assets


def _metadata(parsed: dict[object, object], keys: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key in keys:
        value = parsed.get(key)
        if value is not None:
            metadata[key] = str(value)
    return metadata


def _source_tokens(values: list[object]) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()
    for value in values:
        for token in str(value).replace(";", ",").split(","):
            normalized = token.strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                tokens.append(normalized)
    return tokens


def _first_string(parsed: dict[object, object], keys: list[str]) -> str | None:
    for key in keys:
        value = parsed.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
