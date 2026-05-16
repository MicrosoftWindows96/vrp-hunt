"""Target normalization and boundary-safe host matching."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=False,
)


class NormalizationError(ValueError):
    """Raised when a target cannot be safely normalized."""


@dataclass(frozen=True)
class NormalizedHost:
    host: str
    registrable_domain: str


def _contains_control_or_space(value: str) -> bool:
    return any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)


def normalize_host(raw_host: str) -> NormalizedHost:
    """Normalize a hostname and derive its registrable domain."""

    host = raw_host.strip()
    if not host:
        raise NormalizationError("host is empty")
    if "/" in host or "\\" in host or "@" in host:
        raise NormalizationError("host contains URL-only syntax")
    if _contains_control_or_space(host):
        raise NormalizationError("host contains whitespace or control characters")
    if host.endswith("."):
        host = host[:-1]
    if not host:
        raise NormalizationError("host is empty after normalization")

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NormalizationError("host is not valid IDNA") from exc

    labels = ascii_host.split(".")
    if any(not label for label in labels):
        raise NormalizationError("host contains an empty label")
    if any(len(label.encode("ascii")) > 63 for label in labels):
        raise NormalizationError("host contains an overlong label")
    if len(ascii_host.encode("ascii")) > 253:
        raise NormalizationError("host is too long")

    extracted = _EXTRACT(ascii_host)
    if not extracted.domain or not extracted.suffix:
        raise NormalizationError("host has no registrable domain")
    registrable_domain = f"{extracted.domain}.{extracted.suffix}".lower()
    return NormalizedHost(host=ascii_host, registrable_domain=registrable_domain)


def normalize_url(raw_url: str) -> NormalizedHost:
    parsed = urlsplit(raw_url.strip())
    if not parsed.scheme or not parsed.netloc or not parsed.hostname:
        raise NormalizationError("url must include scheme and host")
    return normalize_host(parsed.hostname)


def normalize_mobile_app(raw_app: str) -> str:
    app = raw_app.strip()
    if not app or _contains_control_or_space(app):
        raise NormalizationError("mobile app identifier is invalid")
    return app.lower()


def host_matches_domain(normalized: NormalizedHost, domain: str) -> bool:
    target_domain = domain.lower().strip().removeprefix("*.").rstrip(".")
    return (
        normalized.registrable_domain == target_domain
        and (normalized.host == target_domain or normalized.host.endswith(f".{target_domain}"))
    )


def host_matches_suffix(normalized: NormalizedHost, suffix: str) -> bool:
    target_suffix = suffix.lower().strip().removeprefix("*.").rstrip(".")
    return normalized.host == target_suffix or normalized.host.endswith(f".{target_suffix}")
