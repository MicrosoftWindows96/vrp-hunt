"""Static and dynamic mobile artifact extraction helpers."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Literal

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DEEPLINK_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{1,40}://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+")
SECRET_PATTERNS = {
    "api_key": re.compile(r"(?i)\b(api[_-]?key|apikey)\b\s*[:=]"),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    "google_api_key_shape": re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
}
RISK_PATTERNS = {
    "webview-js-bridge": re.compile(r"\baddJavascriptInterface\s*\("),
    "webview-javascript-enabled": re.compile(r"\bsetJavaScriptEnabled\s*\(\s*true\s*\)"),
    "webview-file-access-enabled": re.compile(r"\bsetAllowFileAccess\s*\(\s*true\s*\)"),
    "intent-uri-parsing": re.compile(r"\bIntent\.parseUri\s*\("),
    "custom-tab-or-browser-fallback": re.compile(r"\bS\.browser_fallback_url\b|\bbrowser_fallback_url\b"),
}
CERTIFICATE_PINNING_PATTERNS = {
    "okhttp-certificate-pinner": re.compile(r"\b(?:okhttp3\.)?CertificatePinner\b"),
    "network-security-config-pins": re.compile(r"\bpin-set\b|<pin\s+digest="),
    "trustkit": re.compile(r"\bTrustKit\b|\bkTSKPublicKeyHashes\b"),
    "ios-pinned-domains": re.compile(r"\bNSPinnedDomains\b|\bNSPinnedCAIdentities\b"),
    "custom-trust-manager": re.compile(r"\bX509TrustManager\b|\bcheckServerTrusted\s*\("),
    "public-key-pin": re.compile(r"\bsha256/[A-Za-z0-9+/=]{20,}"),
}
PermissionRiskLevel = Literal["low", "medium", "high"]
HIGH_RISK_PERMISSIONS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION": (
        "location",
        "background location can expose sensitive user movement data",
    ),
    "android.permission.ACCESS_FINE_LOCATION": (
        "location",
        "precise location can expose sensitive user movement data",
    ),
    "android.permission.CAMERA": ("sensors", "camera access can capture sensitive user data"),
    "android.permission.GET_ACCOUNTS": ("identity", "account inventory can expose user identity data"),
    "android.permission.READ_CALENDAR": ("personal-data", "calendar reads expose personal data"),
    "android.permission.READ_CALL_LOG": ("communications", "call-log reads expose sensitive metadata"),
    "android.permission.READ_CONTACTS": ("personal-data", "contact reads expose personal data"),
    "android.permission.READ_PHONE_NUMBERS": ("identity", "phone-number reads expose identity data"),
    "android.permission.READ_PHONE_STATE": ("identity", "phone state can expose device identifiers"),
    "android.permission.READ_SMS": ("communications", "SMS reads expose sensitive messages"),
    "android.permission.RECORD_AUDIO": ("sensors", "microphone access can capture sensitive user data"),
    "android.permission.SEND_SMS": ("communications", "SMS sends can create user-impacting actions"),
}
MEDIUM_RISK_PERMISSIONS = {
    "android.permission.ACCESS_COARSE_LOCATION": (
        "location",
        "coarse location can still expose user movement data",
    ),
    "android.permission.BLUETOOTH_CONNECT": (
        "nearby-devices",
        "nearby device access can expose local environment data",
    ),
    "android.permission.NFC": ("nearby-devices", "NFC access can interact with nearby devices"),
    "android.permission.POST_NOTIFICATIONS": (
        "notifications",
        "notification access can affect user-visible trust boundaries",
    ),
    "android.permission.READ_EXTERNAL_STORAGE": (
        "storage",
        "external storage reads can expose user files on older Android versions",
    ),
    "android.permission.READ_MEDIA_AUDIO": ("storage", "media reads expose user audio files"),
    "android.permission.READ_MEDIA_IMAGES": ("storage", "media reads expose user image files"),
    "android.permission.READ_MEDIA_VIDEO": ("storage", "media reads expose user video files"),
    "android.permission.SYSTEM_ALERT_WINDOW": (
        "overlay",
        "overlay permission can affect UI trust boundaries",
    ),
    "android.permission.USE_BIOMETRIC": (
        "authentication",
        "biometric use is an authentication-boundary signal",
    ),
    "android.permission.WRITE_EXTERNAL_STORAGE": (
        "storage",
        "external storage writes can affect user files on older Android versions",
    ),
}


class AndroidPermissionRisk(StrictModel):
    permission: str = Field(min_length=1)
    risk: PermissionRiskLevel
    category: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class AndroidManifestPermissionRiskSummary(StrictModel):
    package_name: str = ""
    permission_count: int = Field(ge=0)
    high_risk_count: int = Field(ge=0)
    medium_risk_count: int = Field(ge=0)
    low_risk_count: int = Field(ge=0)
    risks: list[AndroidPermissionRisk] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)


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


def extract_mobile_risk_notes(text: str, *, parent: str, source: str = "mobile-risk-scan") -> list[Asset]:
    assets: list[Asset] = []
    for pattern_name, pattern in RISK_PATTERNS.items():
        if pattern.search(text):
            assets.append(
                Asset(
                    kind="note",
                    value=f"mobile-risk:{pattern_name}",
                    source=source,
                    parent=parent,
                    metadata={"redacted": "true"},
                )
            )
    return assets


def extract_certificate_pinning_indicators(
    text: str,
    *,
    parent: str,
    source: str = "mobile-pinning-scan",
) -> list[Asset]:
    assets: list[Asset] = []
    for indicator, pattern in CERTIFICATE_PINNING_PATTERNS.items():
        if pattern.search(text):
            assets.append(
                Asset(
                    kind="note",
                    value=f"mobile-pinning:{indicator}",
                    source=source,
                    parent=parent,
                    metadata={
                        "indicator": indicator,
                        "requires_manual_review": "true",
                        "redacted": "true",
                    },
                )
            )
    return assets


def parse_android_manifest(manifest_xml: str, *, source: str = "android-manifest") -> list[Asset]:
    root = ET.fromstring(manifest_xml)
    package_name = root.attrib.get("package", "")
    assets: list[Asset] = []
    assets.extend(
        summarize_android_manifest_permissions(
            manifest_xml,
            source=source,
        ).assets
    )
    for tag in ("activity", "service", "receiver", "provider"):
        for element in root.findall(f".//{tag}"):
            name = element.attrib.get(f"{ANDROID_NS}name")
            if name:
                metadata = {"component_type": tag}
                exported = element.attrib.get(f"{ANDROID_NS}exported")
                permission = element.attrib.get(f"{ANDROID_NS}permission")
                intent_filter_count = len(element.findall("intent-filter"))
                if exported is not None:
                    metadata["exported"] = exported
                if permission is not None:
                    metadata["permission"] = permission
                if intent_filter_count:
                    metadata["intent_filters"] = str(intent_filter_count)
                assets.append(
                    Asset(
                        kind="mobile_component",
                        value=_qualify_component(name, package_name),
                        source=source,
                        parent=package_name or None,
                        metadata=metadata,
                    )
                )
            for data in element.findall(".//data"):
                deep_link = _deep_link_from_data(data)
                if deep_link:
                    assets.append(
                        Asset(kind="endpoint", value=deep_link, source=source, parent=package_name or None)
                    )
    return assets


def summarize_android_manifest_permissions(
    manifest_xml: str,
    *,
    source: str = "android-manifest-permissions",
) -> AndroidManifestPermissionRiskSummary:
    root = ET.fromstring(manifest_xml)
    package_name = root.attrib.get("package", "")
    risks = [
        classify_android_permission_risk(permission)
        for permission in _manifest_permissions(root)
    ]
    assets = [
        Asset(
            kind="note",
            value=f"android-permission-risk:{risk.permission}",
            source=source,
            parent=package_name or None,
            metadata={
                "risk": risk.risk,
                "category": risk.category,
                "reason": risk.reason,
                "redacted": "true",
            },
        )
        for risk in risks
    ]
    return AndroidManifestPermissionRiskSummary(
        package_name=package_name,
        permission_count=len(risks),
        high_risk_count=sum(1 for risk in risks if risk.risk == "high"),
        medium_risk_count=sum(1 for risk in risks if risk.risk == "medium"),
        low_risk_count=sum(1 for risk in risks if risk.risk == "low"),
        risks=risks,
        assets=assets,
    )


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


def _manifest_permissions(root: ET.Element) -> list[str]:
    permissions: list[str] = []
    seen: set[str] = set()
    for tag in ("uses-permission", "uses-permission-sdk-23"):
        for element in root.findall(tag):
            permission = element.attrib.get(f"{ANDROID_NS}name")
            if permission and permission not in seen:
                seen.add(permission)
                permissions.append(permission)
    return permissions


def classify_android_permission_risk(permission: str) -> AndroidPermissionRisk:
    if permission in HIGH_RISK_PERMISSIONS:
        category, reason = HIGH_RISK_PERMISSIONS[permission]
        return AndroidPermissionRisk(
            permission=permission,
            risk="high",
            category=category,
            reason=reason,
        )
    if permission in MEDIUM_RISK_PERMISSIONS:
        category, reason = MEDIUM_RISK_PERMISSIONS[permission]
        return AndroidPermissionRisk(
            permission=permission,
            risk="medium",
            category=category,
            reason=reason,
        )
    return AndroidPermissionRisk(
        permission=permission,
        risk="low",
        category="platform",
        reason="normal or context-dependent permission; keep for manifest inventory",
    )
