"""Owned-account crawl snapshots feeding safe validation handlers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

from pydantic import Field, field_validator, model_validator

from vrp_hunt.agent.browser_check import BrowserCheckError, validate_owned_object_url
from vrp_hunt.agent.models import AgentAction, AgentPlan
from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.recon import Asset
from vrp_hunt.recon.models import AssetKind

CSRF_NAME_MARKERS = ("csrf", "xsrf", "authenticity_token", "requestverificationtoken")
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class OwnedAccountCrawlError(ValueError):
    """Raised when owned-account crawl input is unsafe or malformed."""


class OwnedAccountCrawlPage(StrictModel):
    """One saved authenticated page snapshot from a researcher-owned account."""

    account_id: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=1, max_length=4096)
    body: str = ""
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
    has_csrf_token: bool = False
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
    validation_plan: AgentPlan
    warnings: list[str] = Field(default_factory=list)


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
    for page in pages:
        page_assets, page_forms = _crawl_page(page, crawl_config, warnings)
        assets.extend(page_assets)
        forms.extend(page_forms)
    deduped_assets = _dedupe_assets(assets)
    deduped_forms = _dedupe_forms(forms)
    return OwnedAccountCrawlResult(
        generated_at=now or datetime.now(UTC),
        page_count=len(pages),
        assets=deduped_assets,
        forms=deduped_forms,
        validation_plan=_validation_plan_from_crawl(deduped_assets, deduped_forms),
        warnings=sorted(warnings),
    )


def _crawl_page(
    page: OwnedAccountCrawlPage,
    config: OwnedAccountCrawlConfig,
    warnings: set[str],
) -> tuple[list[Asset], list[OwnedAccountCrawlForm]]:
    parser = _OwnedHTMLParser()
    parser.feed(page.body)
    parser.close()
    assets: list[Asset] = []
    forms: list[OwnedAccountCrawlForm] = []
    page_url = _sanitize_url(page.url)

    for raw_url in parser.links[: config.max_links_per_page]:
        absolute_url = _sanitize_url(urljoin(page.url, raw_url))
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
            has_csrf_token=bool(csrf_names),
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

    return assets, forms


def _validation_plan_from_crawl(
    assets: list[Asset],
    forms: list[OwnedAccountCrawlForm],
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


def _host_in_domain(host: str, domain: str | None) -> bool:
    if domain is None:
        return False
    normalized_host = host.lower().strip(".")
    normalized_domain = domain.lower().strip(".")
    return normalized_host == normalized_domain or normalized_host.endswith(f".{normalized_domain}")


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
            action.metadata.get("account_id", ""),
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
