"""Low-noise extraction helpers for fetched web content."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urljoin, urlsplit

from vrp_hunt.recon import Asset

SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
ENDPOINT_RE = re.compile(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/?)+" )
QUERY_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]{1,80})=")
SECRET_PATTERNS = {
    "api_key": re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    "google_api_key_shape": re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
}


def extract_javascript_urls(html: str, base_url: str) -> list[str]:
    return sorted({urljoin(base_url, match.group(1)) for match in SCRIPT_SRC_RE.finditer(html)})


def extract_endpoint_paths(text: str) -> list[str]:
    endpoints = {
        match.group(0)
        for match in ENDPOINT_RE.finditer(text)
        if not match.group(0).startswith("//") and "." not in match.group(0).rsplit("/", 1)[-1]
    }
    return sorted(endpoints)


def extract_parameter_names(*values: str) -> list[str]:
    names: set[str] = set()
    for value in values:
        parsed = urlsplit(value)
        names.update(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))
        names.update(match.group(1) for match in QUERY_RE.finditer(value))
    return sorted(names)


def extract_secret_notes(text: str, *, parent: str, source: str = "js-secret-scan") -> list[Asset]:
    assets: list[Asset] = []
    for pattern_name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            assets.append(
                Asset(
                    kind="note",
                    value=f"potential-secret-pattern:{pattern_name}",
                    source=source,
                    parent=parent,
                    metadata={"redacted": "true"},
                )
            )
    return assets
