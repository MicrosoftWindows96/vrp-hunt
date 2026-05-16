"""Parsers for passive recon tool output."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from vrp_hunt.recon import Asset


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
                    sources = ",".join(str(item) for item in raw_sources)
                elif isinstance(raw_sources, str):
                    sources = raw_sources
        if host:
            assets.append(Asset(kind="host", value=host.lower(), source=source, metadata={"sources": sources}))
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


def _metadata(parsed: dict[object, object], keys: list[str]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for key in keys:
        value = parsed.get(key)
        if value is not None:
            metadata[key] = str(value)
    return metadata
