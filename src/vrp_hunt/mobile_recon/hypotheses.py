"""Rank passive mobile static-analysis output into validation hypotheses."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.mobile_recon.adapter import MobileReconAdapter
from vrp_hunt.playbooks.models import BugClass
from vrp_hunt.recon import Asset


class MobileStaticHypothesis(StrictModel):
    title: str = Field(min_length=1)
    bug_class: BugClass
    target: str = Field(min_length=1)
    score: int = Field(ge=0)
    confidence: float = Field(ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)
    evidence: list[Asset] = Field(default_factory=list)
    manual_validation_steps: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)


class MobileStaticReport(StrictModel):
    app_id: str = Field(min_length=1)
    artifact_path: str = Field(min_length=1)
    asset_count: int = Field(ge=0)
    hypothesis_count: int = Field(ge=0)
    hypotheses: list[MobileStaticHypothesis] = Field(default_factory=list)


def build_mobile_static_report(
    *,
    app_id: str,
    artifact_path: Path,
    limit: int = 10,
) -> MobileStaticReport:
    assets = _scan_static_assets(app_id=app_id, artifact_path=artifact_path)
    hypotheses = build_mobile_static_hypotheses(assets, limit=limit)
    return MobileStaticReport(
        app_id=app_id,
        artifact_path=str(artifact_path),
        asset_count=len(assets),
        hypothesis_count=len(hypotheses),
        hypotheses=hypotheses,
    )


def build_mobile_static_hypotheses(
    assets: list[Asset],
    *,
    limit: int = 10,
) -> list[MobileStaticHypothesis]:
    candidates = [
        *_oauth_hypotheses(assets),
        *_deeplink_hypotheses(assets),
        *_webview_hypotheses(assets),
        *_api_surface_hypotheses(assets),
        *_secret_shape_hypotheses(assets),
    ]
    deduped: dict[tuple[BugClass, str, str], MobileStaticHypothesis] = {}
    for candidate in candidates:
        key = (candidate.bug_class, candidate.target, candidate.title)
        existing = deduped.get(key)
        if existing is None or candidate.score > existing.score:
            deduped[key] = candidate
    return sorted(
        deduped.values(),
        key=lambda item: (-item.score, item.target, item.title),
    )[:limit]


def _scan_static_assets(*, app_id: str, artifact_path: Path) -> list[Asset]:
    return MobileReconAdapter._scan_artifact_texts_from_path(artifact_path, parent=app_id)


def _oauth_hypotheses(assets: list[Asset]) -> list[MobileStaticHypothesis]:
    evidence = [
        asset
        for asset in assets
        if asset.kind in {"url", "endpoint"}
        and _contains_any(asset.value, ("oauth", "oauth2", "redirect_uri", "accounts.google.com"))
    ]
    if not evidence:
        return []
    target = _best_target(evidence)
    return [
        MobileStaticHypothesis(
            title="OAuth redirect and account-switching review",
            bug_class="oauth",
            target=target,
            score=min(100, 65 + len(evidence) * 5),
            confidence=0.35,
            reasons=[
                "static artifact references OAuth/account-flow endpoints",
                "mobile account chooser and redirect handling are stateful surfaces",
            ],
            evidence=evidence[:8],
            manual_validation_steps=[
                "Use only an owned Google Cloud OAuth test client and owned accounts.",
                "Check account chooser, redirect URI, state, and scope transitions without logging tokens.",
                "Stop if any non-owned account or third-party data appears.",
            ],
            safety_notes=_default_safety_notes(),
        )
    ]


def _deeplink_hypotheses(assets: list[Asset]) -> list[MobileStaticHypothesis]:
    evidence = [
        asset
        for asset in assets
        if (
            asset.kind == "endpoint"
            and "://" in asset.value
            and not asset.value.startswith(("http://", "https://"))
        )
        or (
            asset.kind == "mobile_component"
            and asset.metadata.get("intent_filters")
            and asset.metadata.get("component_type") == "activity"
        )
    ]
    if not evidence:
        return []
    target = _best_target(evidence)
    exported = [asset for asset in evidence if asset.metadata.get("exported") == "true"]
    return [
        MobileStaticHypothesis(
            title="Deep-link authorization boundary review",
            bug_class="idor",
            target=target,
            score=min(95, 55 + len(evidence) * 4 + len(exported) * 10),
            confidence=0.3,
            reasons=[
                "manifest or code exposes deep-link entry points",
                "deep links can cross account/session boundaries if state checks are incomplete",
            ],
            evidence=evidence[:10],
            manual_validation_steps=[
                "Open deep links only with researcher-owned accounts and benign marker objects.",
                "Compare owner and actor account behavior for the same owned object reference.",
                "Do not enumerate IDs or follow links that show non-owned data.",
            ],
            safety_notes=_default_safety_notes(),
        )
    ]


def _webview_hypotheses(assets: list[Asset]) -> list[MobileStaticHypothesis]:
    evidence = [
        asset
        for asset in assets
        if asset.kind == "note" and asset.value.startswith("mobile-risk:webview")
    ]
    if not evidence:
        return []
    return [
        MobileStaticHypothesis(
            title="WebView bridge and navigation boundary review",
            bug_class="xss",
            target=evidence[0].parent or evidence[0].value,
            score=min(90, 60 + len(evidence) * 8),
            confidence=0.28,
            reasons=[
                "static artifact references WebView JavaScript or bridge configuration",
                "owned-content rendering can validate bridge exposure without exploit payloads",
            ],
            evidence=evidence[:8],
            manual_validation_steps=[
                "Use only owned hosted content with a benign marker string.",
                "Check whether untrusted owned content can reach native bridge methods.",
                "Do not use credential-stealing payloads or third-party pages.",
            ],
            safety_notes=_default_safety_notes(),
        )
    ]


def _api_surface_hypotheses(assets: list[Asset]) -> list[MobileStaticHypothesis]:
    evidence = [
        asset
        for asset in assets
        if asset.kind == "url"
        and _contains_any(asset.value, ("googleapis.com", "pa.googleapis.com", "firebase"))
    ]
    if not evidence:
        return []
    return [
        MobileStaticHypothesis(
            title="Mobile API authorization and scope review",
            bug_class="server_side",
            target=_best_target(evidence),
            score=min(75, 45 + len(evidence) * 4),
            confidence=0.2,
            reasons=[
                "mobile artifact references Google API surfaces",
                "API scope and caller identity can differ across account and app contexts",
            ],
            evidence=evidence[:8],
            manual_validation_steps=[
                "Validate only with documented API behavior and owned accounts.",
                "Do not replay app traffic with real tokens or non-owned resources.",
                "Prefer static endpoint mapping before any live API request.",
            ],
            safety_notes=_default_safety_notes(),
        )
    ]


def _secret_shape_hypotheses(assets: list[Asset]) -> list[MobileStaticHypothesis]:
    evidence = [
        asset
        for asset in assets
        if asset.kind == "note" and asset.value.startswith("potential-secret-pattern:")
    ]
    if not evidence:
        return []
    return [
        MobileStaticHypothesis(
            title="Redacted embedded secret-shape review",
            bug_class="server_side",
            target=evidence[0].parent or evidence[0].value,
            score=min(65, 35 + len(evidence) * 5),
            confidence=0.15,
            reasons=[
                "static artifact contains redacted key or token-shaped strings",
                "many mobile API keys are intentionally public, so impact needs careful review",
            ],
            evidence=evidence[:8],
            manual_validation_steps=[
                "Do not print or commit raw secret-like values.",
                "Determine whether the key is restricted and whether misuse is possible without abuse.",
                "Report only if the impact is concrete and safely demonstrated.",
            ],
            safety_notes=_default_safety_notes(),
        )
    ]


def _best_target(assets: list[Asset]) -> str:
    for asset in assets:
        if asset.kind == "url":
            host = urlsplit(asset.value).hostname
            if host:
                return host
        if asset.parent:
            return asset.parent
    return assets[0].value


def _contains_any(value: str, needles: tuple[str, ...]) -> bool:
    lowered = value.lower()
    return any(needle in lowered for needle in needles)


def _default_safety_notes() -> list[str]:
    return [
        "Passive hypothesis only; no live validation performed by this command.",
        "Use owned accounts and owned test objects only.",
        "Stop immediately if third-party data appears.",
    ]
