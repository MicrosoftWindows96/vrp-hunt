"""Static and dynamic mobile artifact extraction helpers."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from vrp_hunt.recon import Asset

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DEEPLINK_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,40}://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+")
SECRET_PATTERNS = {
    "api_key": re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    "google_api_key_shape": re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
}


def extract_mobile_endpoints(text: str, *, parent: str, source: str = "mobile-static") -> list[Asset]:
    assets: list[Asset] = []
    seen: set[str] = set()
    for pattern in (URL_RE, DEEPLINK_RE):
        for match in pattern.finditer(text):
            value = match.group(0).rstrip('"\'),;')
            if value in seen:
                continue
            seen.add(value)
            if value.startswith(("http://", "https://")):
                assets.append(Asset(kind="url", value=value, source=source, parent=parent))
            else:
                assets.append(Asset(kind="endpoint", value=value, source=source, parent=parent))
    return assets


def extract_mobile_secret_notes(text: str, *, parent: str, source: str = "mobile-secret-scan") -> list[Asset]:
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


def parse_android_manifest(manifest_xml: str, *, source: str = "android-manifest") -> list[Asset]:
    root = ET.fromstring(manifest_xml)
    package_name = root.attrib.get("package", "")
    assets: list[Asset] = []
    for tag in ("activity", "service", "receiver", "provider"):
        for element in root.findall(f".//{tag}"):
            name = element.attrib.get(f"{ANDROID_NS}name")
            if name:
                assets.append(
                    Asset(
                        kind="mobile_component",
                        value=_qualify_component(name, package_name),
                        source=source,
                        parent=package_name or None,
                        metadata={"component_type": tag},
                    )
                )
            for data in element.findall(".//data"):
                deep_link = _deep_link_from_data(data)
                if deep_link:
                    assets.append(
                        Asset(kind="endpoint", value=deep_link, source=source, parent=package_name or None)
                    )
    return assets


def parse_dynamic_messages(output: str, *, parent: str, source: str = "frida-dynamic") -> list[Asset]:
    assets: list[Asset] = []
    for line in output.splitlines():
        payload: object
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            payload = line
        else:
            payload = parsed.get("payload", parsed) if isinstance(parsed, dict) else parsed
        if isinstance(payload, dict):
            for key in ("url", "endpoint", "component"):
                value = payload.get(key)
                if isinstance(value, str):
                    if key == "component":
                        assets.append(
                            Asset(kind="mobile_component", value=value, source=source, parent=parent)
                        )
                    elif value.startswith("http"):
                        assets.append(Asset(kind="url", value=value, source=source, parent=parent))
                    else:
                        assets.append(
                            Asset(kind="endpoint", value=value, source=source, parent=parent)
                        )
        elif isinstance(payload, str):
            assets.extend(extract_mobile_endpoints(payload, parent=parent, source=source))
    return assets


def _qualify_component(name: str, package_name: str) -> str:
    if name.startswith(".") and package_name:
        return f"{package_name}{name}"
    return name


def _deep_link_from_data(element: ET.Element) -> str | None:
    scheme = element.attrib.get(f"{ANDROID_NS}scheme")
    host = element.attrib.get(f"{ANDROID_NS}host")
    path = (
        element.attrib.get(f"{ANDROID_NS}path")
        or element.attrib.get(f"{ANDROID_NS}pathPrefix")
        or ""
    )
    if not scheme:
        return None
    if host:
        return f"{scheme}://{host}{path}"
    return f"{scheme}://"
