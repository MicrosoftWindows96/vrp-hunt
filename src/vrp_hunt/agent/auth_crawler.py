"""Owned-account crawl snapshots feeding safe validation handlers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from html.parser import HTMLParser
from typing import Literal
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from pydantic import Field, field_validator, model_validator

from vrp_hunt.agent.browser_check import BrowserCheckError, validate_owned_object_url
from vrp_hunt.agent.models import AgentAction, AgentPlan
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset
from vrp_hunt.recon.models import AssetKind

CSRF_NAME_MARKERS = ("csrf", "xsrf", "authenticity_token", "requestverificationtoken")
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
XSLEAK_REDIRECT_PARAMETERS = {"continue", "next", "redirect", "redirect_uri", "return_to", "url"}
XssReflectionContext = Literal["html", "attribute", "script", "url"]
XsLeakSurfaceType = Literal["frameable", "redirect", "cacheable-auth-boundary"]


class OwnedAccountCrawlError(ValueError):
    """Raised when owned-account crawl input is unsafe or malformed."""


class OwnedAccountCrawlPage(StrictModel):
    """One saved authenticated page snapshot from a researcher-owned account."""

    account_id: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=4096)
    body: str = ""
    response_headers: dict[str, str] = Field(default_factory=dict)
    source: str = Field(default="owned-account-page", min_length=1, max_length=256)
    researcher_owned_account: bool = True
    third_party_data_present: bool = False

    @field_validator("url")
    @classmethod
    def url_must_be_https(cls, value: str) -> str:
        parsed = urlsplit(value.strip())
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("owned-account crawl pages require absolute https URLs")
        return _sanitize_url(value)

    @model_validator(mode="after")
    def enforce_owned_snapshot_contract(self) -> "OwnedAccountCrawlPage":
        if not self.researcher_owned_account:
            raise ValueError("page must confirm researcher_owned_account=true")
        if self.third_party_data_present:
            raise ValueError("owned-account crawl pages must not contain third-party data")
        return self


class OwnedAccountCrawlConfig(StrictModel):
    scope_domains: list[str] = Field(default_factory=list)
    max_links_per_page: int = Field(default=100, ge=1, le=1000)
    max_forms_per_page: int = Field(default=50, ge=1, le=200)

    @field_validator("scope_domains")
    @classmethod
    def normalize_scope_domains(cls, value: list[str]) -> list[str]:
        domains: set[str] = set()
        for raw_domain in value:
            candidate = raw_domain.strip().lower()
            if not candidate:
                continue
            if "://" in candidate:
                parsed = urlsplit(candidate)
                candidate = parsed.hostname or ""
            candidate = candidate.strip(".")
            if candidate:
                domains.add(candidate)
        return sorted(domains)


class OwnedAccountCrawlForm(StrictModel):
    account_id: str = Field(min_length=1)
    page_url: str = Field(min_length=1)
    method: str = Field(min_length=1, max_length=16)
    action_url: str = Field(min_length=1)
    parameter_names: list[str] = Field(default_factory=list)
    csrf_token_names: list[str] = Field(default_factory=list)
    csrf_cookie_names: list[str] = Field(default_factory=list)
    same_site_cookie_names: list[str] = Field(default_factory=list)
    has_csrf_token: bool = False
    cookie_context_available: bool = False
    state_changing: bool = False

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.strip().upper()


class OwnedAccountCrawlResult(StrictModel):
    generated_at: datetime
    page_count: int = Field(ge=0)
    assets: list[Asset] = Field(default_factory=list)
    forms: list[OwnedAccountCrawlForm] = Field(default_factory=list)
    idor_candidates: list["OwnedIdorCandidate"] = Field(default_factory=list)
    oauth_flows: list["OwnedOAuthFlow"] = Field(default_factory=list)
    xss_reflections: list["OwnedXssReflection"] = Field(default_factory=list)
    xsleak_surfaces: list["OwnedXsLeakSurface"] = Field(default_factory=list)
    validation_plan: AgentPlan
    warnings: list[str] = Field(default_factory=list)


class OwnedIdorCandidate(StrictModel):
    account_id: str = Field(min_length=1)
    url: str = Field(min_length=1)
    object_host: str = Field(min_length=1)
    object_path_hash: str = Field(min_length=12)
    source: str = Field(min_length=1)


class OwnedOAuthFlow(StrictModel):
    account_id: str = Field(min_length=1)
    authorization_url: str = Field(min_length=1)
    client_id_hash: str | None = Field(default=None, min_length=12)
    redirect_uri: str | None = None
    scope_names: list[str] = Field(default_factory=list)
    response_type: str | None = None
    has_state: bool = False
    consent_screen_hint: bool = False


class OwnedXssReflection(StrictModel):
    account_id: str = Field(min_length=1)
    page_url: str = Field(min_length=1)
    parameter_name: str = Field(min_length=1)
    context: XssReflectionContext
    evidence_ref: str = Field(min_length=12)


class OwnedXsLeakSurface(StrictModel):
    account_id: str = Field(min_length=1)
    page_url: str = Field(min_length=1)
    surface_type: XsLeakSurfaceType
    evidence: str = Field(min_length=1)
    target_url: str | None = None


def build_owned_account_crawl_plan(
    pages: list[OwnedAccountCrawlPage],
    *,
    config: OwnedAccountCrawlConfig | None = None,
    now: datetime | None = None,
) -> OwnedAccountCrawlResult:
    """Convert saved owned-account pages into safe validator preparation actions."""

    crawl_config = config or OwnedAccountCrawlConfig()
    warnings: set[str] = set()
    assets: list[Asset] = []
    forms: list[OwnedAccountCrawlForm] = []
    oauth_flows: list[OwnedOAuthFlow] = []
    xsleak_surfaces: list[OwnedXsLeakSurface] = []
    for page in pages:
        page_assets, page_forms, page_oauth_flows, page_xsleak_surfaces = _crawl_page(
            page,
            crawl_config,
            warnings,
        )
        assets.extend(page_assets)
        forms.extend(page_forms)
        oauth_flows.extend(page_oauth_flows)
        xsleak_surfaces.extend(page_xsleak_surfaces)
    deduped_assets = _dedupe_assets(assets)
    deduped_forms = _dedupe_forms(forms)
    deduped_oauth_flows = _dedupe_oauth_flows(oauth_flows)
    idor_candidates = _idor_candidates_from_assets(deduped_assets)
    xss_reflections = _xss_reflections_from_pages(pages)
    xsleak_surfaces.extend(_xsleak_surfaces_from_pages(pages))
    deduped_xsleak_surfaces = _dedupe_xsleak_surfaces(xsleak_surfaces)
    return OwnedAccountCrawlResult(
        generated_at=now or datetime.now(UTC),
        page_count=len(pages),
        assets=deduped_assets,
        forms=deduped_forms,
        idor_candidates=idor_candidates,
        oauth_flows=deduped_oauth_flows,
        xss_reflections=xss_reflections,
        xsleak_surfaces=deduped_xsleak_surfaces,
        validation_plan=_validation_plan_from_crawl(
            deduped_assets,
            deduped_forms,
            xss_reflections,
            deduped_xsleak_surfaces,
        ),
        warnings=sorted(warnings),
    )


def _crawl_page(
    page: OwnedAccountCrawlPage,
    config: OwnedAccountCrawlConfig,
    warnings: set[str],
) -> tuple[
    list[Asset],
    list[OwnedAccountCrawlForm],
    list[OwnedOAuthFlow],
    list[OwnedXsLeakSurface],
]:
    parser = _OwnedHTMLParser()
    parser.feed(page.body)
    parser.close()
    assets: list[Asset] = []
    forms: list[OwnedAccountCrawlForm] = []
    oauth_flows: list[OwnedOAuthFlow] = []
    xsleak_surfaces: list[OwnedXsLeakSurface] = []
    page_url = _sanitize_url(page.url)
    cookie_context = _cookie_context_from_headers(page.response_headers)

    for raw_url in parser.links[: config.max_links_per_page]:
        raw_absolute_url = urljoin(page.url, raw_url)
        absolute_url = _sanitize_url(raw_absolute_url)
        if not _url_allowed(absolute_url, page.url, config, warnings):
            continue
        metadata = _metadata_for_url(raw_url, page)
        kind: AssetKind = "endpoint" if _looks_like_endpoint(absolute_url) else "url"
        assets.append(
            Asset(
                kind=kind,
                value=absolute_url,
                source="owned-account-crawl-link",
                parent=page_url,
                metadata=metadata,
            )
        )
        for parameter_name in _parameter_names(raw_url):
            assets.append(
                Asset(
                    kind="parameter",
                    value=parameter_name,
                    source="owned-account-crawl-parameter",
                    parent=absolute_url,
                    metadata={"account_id": page.account_id},
                )
            )
        oauth_flow = _oauth_flow_from_url(raw_absolute_url, page)
        if oauth_flow is not None:
            oauth_flows.append(oauth_flow)
        xsleak_surface = _redirect_xsleak_surface(raw_absolute_url, page)
        if xsleak_surface is not None:
            xsleak_surfaces.append(xsleak_surface)

    for parsed_form in parser.forms[: config.max_forms_per_page]:
        action_url = _sanitize_url(urljoin(page.url, parsed_form.action or page.url))
        if not _url_allowed(action_url, page.url, config, warnings):
            continue
        parameter_names = sorted(set(parsed_form.input_names + _parameter_names(parsed_form.action)))
        csrf_names = _csrf_token_names(parameter_names)
        method = parsed_form.method.upper()
        form = OwnedAccountCrawlForm(
            account_id=page.account_id,
            page_url=page_url,
            method=method,
            action_url=action_url,
            parameter_names=parameter_names,
            csrf_token_names=csrf_names,
            csrf_cookie_names=_csrf_cookie_names(cookie_context),
            same_site_cookie_names=_same_site_cookie_names(cookie_context),
            has_csrf_token=bool(csrf_names),
            cookie_context_available=bool(cookie_context),
            state_changing=method in STATE_CHANGING_METHODS,
        )
        forms.append(form)
        assets.append(
            Asset(
                kind="endpoint",
                value=action_url,
                source="owned-account-crawl-form",
                parent=page_url,
                metadata={
                    "account_id": page.account_id,
                    "method": method,
                    "parameter_names": ",".join(parameter_names),
                    "csrf_token_names": ",".join(csrf_names),
                },
            )
        )

    return assets, forms, oauth_flows, xsleak_surfaces


def _validation_plan_from_crawl(
    assets: list[Asset],
    forms: list[OwnedAccountCrawlForm],
    xss_reflections: list[OwnedXssReflection],
    xsleak_surfaces: list[OwnedXsLeakSurface],
) -> AgentPlan:
    actions: list[AgentAction] = []
    for asset in assets:
        if asset.kind not in {"url", "endpoint"}:
            continue
        if _is_owned_object_url(asset.value):
            actions.append(
                AgentAction(
                    action_type="idor_validation",
                    target_kind="url",
                    target=asset.value,
                    intended_action="idor_testing",
                    description="Prepare owned-account IDOR validation from crawl-discovered object URL.",
                    requires_human_approval=True,
                    metadata=_action_metadata(asset),
                )
            )
        if _looks_like_oauth(asset.value, asset.metadata):
            actions.append(
                AgentAction(
                    action_type="oauth_validation",
                    target_kind="url",
                    target=asset.value,
                    intended_action="oauth_testing",
                    description="Prepare OAuth validation from crawl-discovered auth flow URL.",
                    metadata=_action_metadata(asset),
                )
            )
    for form in forms:
        if form.state_changing:
            actions.append(
                AgentAction(
                    action_type="csrf_validation",
                    target_kind="url",
                    target=form.action_url,
                    intended_action="csrf_testing",
                    description="Prepare CSRF validation from crawl-discovered state-changing form.",
                    requires_human_approval=True,
                    metadata={
                        "account_id": form.account_id,
                        "method": form.method,
                        "has_csrf_token": str(form.has_csrf_token).lower(),
                        "csrf_token_names": ",".join(form.csrf_token_names),
                    },
                )
            )
    for reflection in xss_reflections:
        actions.append(
            AgentAction(
                action_type="xss_validation",
                target_kind="url",
                target=reflection.page_url,
                intended_action="xss_testing",
                description="Prepare benign owned-account XSS reflection validation.",
                requires_human_approval=True,
                metadata={
                    "account_id": reflection.account_id,
                    "parameter_name": reflection.parameter_name,
                    "reflection_context": reflection.context,
                    "evidence_ref": reflection.evidence_ref,
                },
            )
        )
    for surface in xsleak_surfaces:
        actions.append(
            AgentAction(
                action_type="xsleak_validation",
                target_kind="url",
                target=surface.target_url or surface.page_url,
                intended_action="xsleak_testing",
                description="Prepare owned-account XSLeak surface validation.",
                requires_human_approval=True,
                metadata={
                    "account_id": surface.account_id,
                    "surface_type": surface.surface_type,
                    "evidence": surface.evidence,
                },
            )
        )
    return AgentPlan(
        actions=_dedupe_actions(actions),
        notes=[
            "owned-account crawl consumed saved page snapshots only",
            "validation actions prepare safe registered handlers; no validation traffic was sent",
        ],
    )


def _action_metadata(asset: Asset) -> dict[str, str]:
    metadata = dict(asset.metadata)
    metadata["source"] = asset.source
    return metadata


def _metadata_for_url(raw_url: str, page: OwnedAccountCrawlPage) -> dict[str, str]:
    metadata = {
        "account_id": page.account_id,
        "page_source": page.source,
    }
    parameter_names = _parameter_names(raw_url)
    if parameter_names:
        metadata["parameter_names"] = ",".join(parameter_names)
        metadata["query_values_redacted"] = "true"
    return metadata


def _url_allowed(
    url: str,
    page_url: str,
    config: OwnedAccountCrawlConfig,
    warnings: set[str],
) -> bool:
    host = urlsplit(url).hostname
    page_host = urlsplit(page_url).hostname
    scope_domains = config.scope_domains or ([page_host] if page_host else [])
    if host is not None and any(_host_in_domain(host, domain) for domain in scope_domains):
        return True
    if host:
        warnings.add(f"skipped out-of-scope crawl URL host {host}")
    return False


def _sanitize_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, "", ""))


def _parameter_names(url: str) -> list[str]:
    return sorted({name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)})


def _csrf_token_names(parameter_names: list[str]) -> list[str]:
    return [
        name
        for name in parameter_names
        if any(marker in name.lower() for marker in CSRF_NAME_MARKERS)
    ]


def _looks_like_endpoint(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(marker in path for marker in ("/api/", "/graphql", "/rpc/", "/oauth", "/v1/", "/v2/"))


def _looks_like_oauth(url: str, metadata: dict[str, str]) -> bool:
    text = " ".join([url, metadata.get("parameter_names", "")]).lower()
    return any(marker in text for marker in ("oauth", "redirect_uri", "client_id", "scope", "openid"))


def _is_owned_object_url(url: str) -> bool:
    try:
        validate_owned_object_url(url)
    except BrowserCheckError:
        return False
    return True


def _oauth_flow_from_url(raw_url: str, page: OwnedAccountCrawlPage) -> OwnedOAuthFlow | None:
    if not _looks_like_oauth(raw_url, {"parameter_names": ",".join(_parameter_names(raw_url))}):
        return None
    parsed = urlsplit(raw_url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    scopes = [
        scope
        for scope in _split_scopes(params.get("scope", ""))
        if scope and not scope.startswith("http")
    ]
    redirect_uri = params.get("redirect_uri")
    return OwnedOAuthFlow(
        account_id=page.account_id,
        authorization_url=_sanitize_url(raw_url),
        client_id_hash=_hash_optional(params.get("client_id")),
        redirect_uri=_sanitize_url(redirect_uri) if redirect_uri else None,
        scope_names=scopes,
        response_type=params.get("response_type") or None,
        has_state=bool(params.get("state")),
        consent_screen_hint="consent" in raw_url.lower() or "prompt=consent" in raw_url.lower(),
    )


def _split_scopes(value: str) -> list[str]:
    return sorted({scope for scope in value.replace(",", " ").split() if scope})


def _redirect_xsleak_surface(
    raw_url: str,
    page: OwnedAccountCrawlPage,
) -> OwnedXsLeakSurface | None:
    parameter_names = set(_parameter_names(raw_url))
    if not parameter_names.intersection(XSLEAK_REDIRECT_PARAMETERS):
        return None
    return OwnedXsLeakSurface(
        account_id=page.account_id,
        page_url=_sanitize_url(page.url),
        surface_type="redirect",
        evidence="redirect-like parameter on authenticated owned-account page",
        target_url=_sanitize_url(raw_url),
    )


def _xsleak_surfaces_from_pages(pages: list[OwnedAccountCrawlPage]) -> list[OwnedXsLeakSurface]:
    surfaces: list[OwnedXsLeakSurface] = []
    for page in pages:
        headers = {key.lower(): value.lower() for key, value in page.response_headers.items()}
        page_url = _sanitize_url(page.url)
        csp = headers.get("content-security-policy", "")
        if headers and "frame-ancestors" not in csp and "x-frame-options" not in headers:
            surfaces.append(
                OwnedXsLeakSurface(
                    account_id=page.account_id,
                    page_url=page_url,
                    surface_type="frameable",
                    evidence="saved response metadata lacks frame-ancestor or x-frame-options policy",
                )
            )
        cache_control = headers.get("cache-control", "")
        if (
            _looks_like_authenticated_page(page.url, page.body)
            and cache_control
            and "no-store" not in cache_control
            and "private" not in cache_control
        ):
            surfaces.append(
                OwnedXsLeakSurface(
                    account_id=page.account_id,
                    page_url=page_url,
                    surface_type="cacheable-auth-boundary",
                    evidence="authenticated-looking page has cacheable response metadata",
                )
            )
    return surfaces


def _xss_reflections_from_pages(pages: list[OwnedAccountCrawlPage]) -> list[OwnedXssReflection]:
    reflections: list[OwnedXssReflection] = []
    for page in pages:
        parser = _OwnedHTMLParser()
        parser.feed(page.body)
        parser.close()
        parameter_names = set(_parameter_names(page.url))
        for raw_url in parser.links:
            parameter_names.update(_parameter_names(urljoin(page.url, raw_url)))
        for form in parser.forms:
            parameter_names.update(form.input_names)
            parameter_names.update(_parameter_names(form.action))
        lower_body = page.body.lower()
        for name in sorted(parameter_names):
            if name.lower() not in lower_body:
                continue
            reflections.append(
                OwnedXssReflection(
                    account_id=page.account_id,
                    page_url=_sanitize_url(page.url),
                    parameter_name=name,
                    context=_reflection_context(page.body, name),
                    evidence_ref=_short_hash(f"{page.account_id}:{page.url}:{name}"),
                )
            )
    return _dedupe_xss_reflections(reflections)


def _reflection_context(body: str, parameter_name: str) -> XssReflectionContext:
    lowered = body.lower()
    name = parameter_name.lower()
    if "<script" in lowered and name in lowered:
        return "script"
    if f'name="{name}"' in lowered or f"'{name}'" in lowered:
        return "attribute"
    if f"?{name}=" in lowered or f"&{name}=" in lowered:
        return "url"
    return "html"


def _cookie_context_from_headers(headers: dict[str, str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        for cookie_text in value.split(","):
            name = cookie_text.split("=", maxsplit=1)[0].strip()
            if not name:
                continue
            same_site = "unspecified"
            for part in cookie_text.split(";"):
                part_value = part.strip().lower()
                if part_value.startswith("samesite="):
                    same_site = part_value.split("=", maxsplit=1)[1]
            cookies[name] = same_site
    return cookies


def _csrf_cookie_names(cookies: dict[str, str]) -> list[str]:
    return sorted(name for name in cookies if any(marker in name.lower() for marker in CSRF_NAME_MARKERS))


def _same_site_cookie_names(cookies: dict[str, str]) -> list[str]:
    return sorted(f"{name}:{same_site}" for name, same_site in cookies.items())


def _looks_like_authenticated_page(url: str, body: str) -> bool:
    text = f"{url} {body[:1000]}".lower()
    return any(marker in text for marker in ("account", "profile", "settings", "logout", "my "))


def _hash_optional(value: str | None) -> str | None:
    if value is None:
        return None
    return _short_hash(value)


def _short_hash(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()[:16]


def _host_in_domain(host: str, domain: str | None) -> bool:
    if domain is None:
        return False
    normalized_host = host.lower().strip(".")
    normalized_domain = domain.lower().strip(".")
    return normalized_host == normalized_domain or normalized_host.endswith(f".{normalized_domain}")


def _idor_candidates_from_assets(assets: list[Asset]) -> list[OwnedIdorCandidate]:
    candidates: list[OwnedIdorCandidate] = []
    for asset in assets:
        if asset.kind not in {"url", "endpoint"} or not _is_owned_object_url(asset.value):
            continue
        host = urlsplit(asset.value).hostname or ""
        candidates.append(
            OwnedIdorCandidate(
                account_id=asset.metadata.get("account_id", "unknown"),
                url=asset.value,
                object_host=host,
                object_path_hash=_short_hash(urlsplit(asset.value).path),
                source=asset.source,
            )
        )
    by_key = {(candidate.account_id, candidate.url): candidate for candidate in candidates}
    return list(by_key.values())


def _dedupe_oauth_flows(flows: list[OwnedOAuthFlow]) -> list[OwnedOAuthFlow]:
    by_key = {
        (
            flow.account_id,
            flow.authorization_url,
            flow.client_id_hash or "",
            flow.redirect_uri or "",
        ): flow
        for flow in flows
    }
    return list(by_key.values())


def _dedupe_xss_reflections(
    reflections: list[OwnedXssReflection],
) -> list[OwnedXssReflection]:
    by_key = {
        (reflection.account_id, reflection.page_url, reflection.parameter_name): reflection
        for reflection in reflections
    }
    return list(by_key.values())


def _dedupe_xsleak_surfaces(
    surfaces: list[OwnedXsLeakSurface],
) -> list[OwnedXsLeakSurface]:
    by_key = {
        (
            surface.account_id,
            surface.page_url,
            surface.surface_type,
            surface.target_url or "",
        ): surface
        for surface in surfaces
    }
    return list(by_key.values())


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_key: dict[tuple[str, str, str], Asset] = {}
    for asset in assets:
        key = (asset.kind, asset.value, asset.parent or "")
        by_key.setdefault(key, asset)
    return list(by_key.values())


def _dedupe_forms(forms: list[OwnedAccountCrawlForm]) -> list[OwnedAccountCrawlForm]:
    by_key: dict[tuple[str, str, str, str], OwnedAccountCrawlForm] = {}
    for form in forms:
        key = (form.account_id, form.method, form.page_url, form.action_url)
        by_key.setdefault(key, form)
    return list(by_key.values())


def _dedupe_actions(actions: list[AgentAction]) -> list[AgentAction]:
    by_key: dict[tuple[str, str, str], AgentAction] = {}
    for action in actions:
        key = (
            action.action_type,
            action.target,
            "|".join(f"{key}={value}" for key, value in sorted(action.metadata.items())),
        )
        by_key.setdefault(key, action)
    return list(by_key.values())


@dataclass
class _ParsedForm:
    method: str = "GET"
    action: str = ""
    input_names: list[str] = field(default_factory=list)


class _OwnedHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[_ParsedForm] = []
        self._current_form: _ParsedForm | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value or "" for key, value in attrs}
        normalized_tag = tag.lower()
        if normalized_tag in {"a", "link"} and attributes.get("href"):
            self.links.append(attributes["href"])
        if normalized_tag in {"script", "iframe"} and attributes.get("src"):
            self.links.append(attributes["src"])
        if normalized_tag == "form":
            self._current_form = _ParsedForm(
                method=attributes.get("method", "GET").upper(),
                action=attributes.get("action", ""),
            )
        if normalized_tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = attributes.get("name", "").strip()
            if name:
                self._current_form.input_names.append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def close(self) -> None:
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        super().close()
