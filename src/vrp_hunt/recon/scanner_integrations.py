"""Offline scanner integration planning and result importers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Iterable
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from vrp_hunt.guardrails.models import StrictModel
from vrp_hunt.guardrails.normalization import NormalizationError, normalize_host
from vrp_hunt.recon.models import Asset

NucleiAuditStatus = Literal["allowed", "blocked"]
ScannerPriority = Literal["low", "medium", "high", "critical"]
CloudBucketProvider = Literal["gcs", "s3"]
SecretScanner = Literal["gitleaks", "trufflehog"]
CiCdProvider = Literal["github_actions", "generic"]
CiCdSignalCategory = Literal[
    "public_artifact",
    "workflow_log",
    "actions_config",
    "secret_reference",
]
ConfidenceValue = Literal["low", "medium", "high"]

AGGRESSIVE_NUCLEI_TAGS = {"dos", "fuzz", "bruteforce", "brute-force", "intrusive", "dast"}
SAFE_NUCLEI_PROTOCOLS = {"http"}
NUCLEI_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
SECRET_PATTERN_NAMES = (
    "private-key",
    "github-token",
    "google-api-key",
    "bearer-token",
    "password-assignment",
)


class NucleiAllowlistProfile(StrictModel):
    profile_id: str = Field(min_length=1, max_length=128)
    templates: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    severity: list[str] = Field(default_factory=list)
    protocol_types: list[str] = Field(default_factory=lambda: ["http"])
    description: str | None = Field(default=None, max_length=500)

    @field_validator("templates")
    @classmethod
    def templates_must_be_explicit(cls, value: list[str]) -> list[str]:
        return [_normalize_relative_template_path(template) for template in value]

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str]) -> list[str]:
        tags = _dedupe_lower_tokens(value)
        blocked = sorted(set(tags).intersection(AGGRESSIVE_NUCLEI_TAGS))
        if blocked:
            raise ValueError(f"blocked aggressive nuclei tags: {', '.join(blocked)}")
        return tags

    @field_validator("severity")
    @classmethod
    def normalize_severity(cls, value: list[str]) -> list[str]:
        severities = _dedupe_lower_tokens(value)
        unknown = sorted(set(severities).difference(NUCLEI_SEVERITIES))
        if unknown:
            raise ValueError(f"unknown nuclei severity values: {', '.join(unknown)}")
        return severities

    @field_validator("protocol_types")
    @classmethod
    def normalize_protocols(cls, value: list[str]) -> list[str]:
        protocols = _dedupe_lower_tokens(value)
        blocked = sorted(set(protocols).difference(SAFE_NUCLEI_PROTOCOLS))
        if blocked:
            raise ValueError(f"blocked nuclei protocol types: {', '.join(blocked)}")
        return protocols

    @model_validator(mode="after")
    def profile_must_select_something(self) -> "NucleiAllowlistProfile":
        if not self.templates and not self.tags and not self.severity:
            raise ValueError("allowlist profile must include templates, tags, or severity")
        return self


class NucleiTemplateMetadata(StrictModel):
    template_id: str = Field(min_length=1, max_length=256)
    path: str = Field(min_length=1, max_length=1024)
    name: str | None = Field(default=None, max_length=512)
    severity: str = "unknown"
    tags: list[str] = Field(default_factory=list)
    authors: list[str] = Field(default_factory=list)
    protocol_types: list[str] = Field(default_factory=lambda: ["http"])

    @field_validator("path")
    @classmethod
    def path_must_be_relative(cls, value: str) -> str:
        return _normalize_relative_template_path(value)

    @field_validator("severity")
    @classmethod
    def severity_must_be_known(cls, value: str) -> str:
        severity = value.strip().lower() if value.strip() else "unknown"
        if severity not in NUCLEI_SEVERITIES:
            raise ValueError(f"unknown nuclei severity value: {severity}")
        return severity

    @field_validator("tags")
    @classmethod
    def normalize_template_tags(cls, value: list[str]) -> list[str]:
        return _dedupe_lower_tokens(value)

    @field_validator("protocol_types")
    @classmethod
    def normalize_template_protocols(cls, value: list[str]) -> list[str]:
        return _dedupe_lower_tokens(value)


class NucleiTemplateAuditFinding(StrictModel):
    template_id: str
    path: str
    status: NucleiAuditStatus
    reasons: list[str] = Field(default_factory=list)


class NucleiTemplateAuditReport(StrictModel):
    profile: NucleiAllowlistProfile
    total_templates: int = Field(ge=0)
    allowed_templates: list[NucleiTemplateMetadata] = Field(default_factory=list)
    blocked_templates: list[NucleiTemplateMetadata] = Field(default_factory=list)
    findings: list[NucleiTemplateAuditFinding] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class VulnerabilityReference(StrictModel):
    cve_id: str = Field(min_length=9, max_length=32)
    technology: str = Field(min_length=1, max_length=256)
    affected_versions: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0.0, le=10.0)
    kev: bool = False
    summary: str | None = Field(default=None, max_length=1000)
    source: str = Field(default="vulnerability-catalog", min_length=1, max_length=256)

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, value: str) -> str:
        cve_id = value.strip().upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            raise ValueError("cve_id must look like CVE-YYYY-NNNN")
        return cve_id

    @field_validator("technology")
    @classmethod
    def normalize_technology(cls, value: str) -> str:
        return value.strip()

    @field_validator("affected_versions")
    @classmethod
    def clean_versions(cls, value: list[str]) -> list[str]:
        return _dedupe_tokens(value)


class TechnologyVulnerabilityMatch(StrictModel):
    technology: str
    asset_parent: str | None = None
    detected_version: str | None = None
    cve_id: str
    cvss_score: float | None = None
    kev: bool = False
    priority: ScannerPriority
    reason: str
    source: str


class VulnerabilityMatchReport(StrictModel):
    total_technology_assets: int = Field(ge=0)
    total_references: int = Field(ge=0)
    matches: list[TechnologyVulnerabilityMatch] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class CloudBucketCandidate(StrictModel):
    provider: CloudBucketProvider
    name: str = Field(min_length=3, max_length=63)
    source_domain: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class CloudBucketMetadataRequest(StrictModel):
    provider: CloudBucketProvider
    bucket: str
    method: Literal["HEAD"] = "HEAD"
    url: str
    metadata_only: bool = True
    sends_traffic_if_executed: bool = True
    approval_required: bool = True


class CloudBucketCheckPlan(StrictModel):
    total_domains: int = Field(ge=0)
    total_candidates: int = Field(ge=0)
    candidates: list[CloudBucketCandidate] = Field(default_factory=list)
    metadata_requests: list[CloudBucketMetadataRequest] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class GitHubSearchQuery(StrictModel):
    kind: Literal["repo", "code", "actions_config", "workflow_log"]
    query: str = Field(min_length=1, max_length=1024)
    purpose: str = Field(min_length=1, max_length=300)
    sends_traffic_if_executed: bool = True
    approval_required: bool = True


class GitHubDiscoveryPlan(StrictModel):
    scope_domains: list[str] = Field(default_factory=list)
    orgs: list[str] = Field(default_factory=list)
    queries: list[GitHubSearchQuery] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SecretScanFinding(StrictModel):
    scanner: SecretScanner
    rule_id: str = Field(min_length=1, max_length=256)
    file: str = Field(min_length=1, max_length=4096)
    line: int | None = Field(default=None, ge=1)
    fingerprint: str = Field(min_length=12, max_length=128)
    redacted_secret: str = "<redacted>"
    verified: bool | None = None
    source: str = Field(min_length=1, max_length=256)

    @field_validator("redacted_secret")
    @classmethod
    def refuse_raw_secret_storage(cls, value: str) -> str:
        if value != "<redacted>":
            raise ValueError("secret scan findings only store <redacted>")
        return value


class SecretScanImportReport(StrictModel):
    scanner: SecretScanner
    total_inputs: int = Field(ge=0)
    total_findings: int = Field(ge=0)
    findings: list[SecretScanFinding] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class CiCdExposureSignal(StrictModel):
    provider: CiCdProvider
    repo: str = Field(min_length=1, max_length=512)
    category: CiCdSignalCategory
    evidence: str = Field(min_length=1, max_length=1000)
    confidence: ConfidenceValue
    source: str = Field(min_length=1, max_length=256)


class CiCdExposureReport(StrictModel):
    total_inputs: int = Field(ge=0)
    signals: list[CiCdExposureSignal] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ContainerImageMetadata(StrictModel):
    image: str = Field(min_length=1, max_length=512)
    registry: str | None = Field(default=None, max_length=256)
    tags: list[str] = Field(default_factory=list)
    digest: str | None = Field(default=None, max_length=256)
    source: str = Field(min_length=1, max_length=256)
    labels: dict[str, str] = Field(default_factory=dict)
    exposed_ports: list[str] = Field(default_factory=list)
    base_images: list[str] = Field(default_factory=list)


class ContainerMetadataReport(StrictModel):
    total_inputs: int = Field(ge=0)
    images: list[ContainerImageMetadata] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def audit_nuclei_templates(
    profile: NucleiAllowlistProfile,
    templates: list[NucleiTemplateMetadata],
) -> NucleiTemplateAuditReport:
    findings: list[NucleiTemplateAuditFinding] = []
    allowed: list[NucleiTemplateMetadata] = []
    blocked: list[NucleiTemplateMetadata] = []
    warnings: list[str] = []
    profile_templates = set(profile.templates)
    profile_tags = set(profile.tags)
    profile_severity = set(profile.severity)
    profile_protocols = set(profile.protocol_types)
    if not templates:
        warnings.append("no nuclei template metadata was provided")

    for template in templates:
        reasons = _nuclei_block_reasons(
            template,
            profile_templates=profile_templates,
            profile_tags=profile_tags,
            profile_severity=profile_severity,
            profile_protocols=profile_protocols,
        )
        if reasons:
            status: NucleiAuditStatus = "blocked"
            blocked.append(template)
        else:
            status = "allowed"
            allowed.append(template)
        findings.append(
            NucleiTemplateAuditFinding(
                template_id=template.template_id,
                path=template.path,
                status=status,
                reasons=reasons,
            )
        )

    return NucleiTemplateAuditReport(
        profile=profile,
        total_templates=len(templates),
        allowed_templates=allowed,
        blocked_templates=blocked,
        findings=findings,
        warnings=warnings,
    )


def match_cves_to_technologies(
    technology_assets: list[Asset],
    references: list[VulnerabilityReference],
) -> VulnerabilityMatchReport:
    tech_assets = [asset for asset in technology_assets if asset.kind == "technology"]
    matches: list[TechnologyVulnerabilityMatch] = []
    for asset in tech_assets:
        asset_name = _technology_key(asset.value)
        detected_version = asset.metadata.get("version")
        for reference in references:
            if _technology_key(reference.technology) != asset_name:
                continue
            version_reason = _version_match_reason(detected_version, reference.affected_versions)
            if version_reason is None:
                continue
            matches.append(
                TechnologyVulnerabilityMatch(
                    technology=asset.value,
                    asset_parent=asset.parent,
                    detected_version=detected_version,
                    cve_id=reference.cve_id,
                    cvss_score=reference.cvss_score,
                    kev=reference.kev,
                    priority=_vulnerability_priority(reference),
                    reason=version_reason,
                    source=reference.source,
                )
            )
    deduped = _dedupe_vulnerability_matches(matches)
    return VulnerabilityMatchReport(
        total_technology_assets=len(tech_assets),
        total_references=len(references),
        matches=deduped,
        assets=vulnerability_match_assets(deduped),
        warnings=[],
    )


def vulnerability_match_assets(matches: list[TechnologyVulnerabilityMatch]) -> list[Asset]:
    assets: list[Asset] = []
    for match in matches:
        metadata = {
            "technology": match.technology,
            "priority": match.priority,
            "kev": str(match.kev).lower(),
            "source": match.source,
        }
        if match.cvss_score is not None:
            metadata["cvss_score"] = f"{match.cvss_score:.1f}"
        if match.detected_version is not None:
            metadata["detected_version"] = match.detected_version
        assets.append(
            Asset(
                kind="note",
                value=f"vuln-match:{match.cve_id}:{match.technology}",
                source="scanner-vuln-match",
                parent=match.asset_parent,
                metadata=metadata,
            )
        )
    return _dedupe_assets(assets)


def build_cloud_bucket_check_plan(
    domains: list[str],
    *,
    org_tokens: list[str] | None = None,
) -> CloudBucketCheckPlan:
    warnings: list[str] = []
    normalized_domains = _normalize_domains(domains, warnings=warnings)
    candidates = generate_cloud_bucket_candidates(
        normalized_domains,
        org_tokens=org_tokens or [],
    )
    requests = [_cloud_metadata_request(candidate) for candidate in candidates]
    assets = [
        Asset(
            kind="note",
            value=f"bucket-candidate:{candidate.provider}:{candidate.name}",
            source="scanner-cloud-plan",
            parent=candidate.source_domain,
            metadata={
                "provider": candidate.provider,
                "confidence": f"{candidate.confidence:.2f}",
                "metadata_only": "true",
                "approval_required": "true",
            },
        )
        for candidate in candidates
    ]
    return CloudBucketCheckPlan(
        total_domains=len(normalized_domains),
        total_candidates=len(candidates),
        candidates=candidates,
        metadata_requests=requests,
        assets=_dedupe_assets(assets),
        warnings=warnings,
    )


def generate_cloud_bucket_candidates(
    domains: list[str],
    *,
    org_tokens: list[str] | None = None,
) -> list[CloudBucketCandidate]:
    candidates: list[CloudBucketCandidate] = []
    tokens = [_bucket_token(token) for token in org_tokens or []]
    clean_tokens = [token for token in tokens if token is not None]
    for domain in domains:
        dotted = _bucket_token(domain)
        hyphenated = _bucket_token(domain.replace(".", "-"))
        compact = _bucket_token(domain.replace(".", ""))
        root = _bucket_token(domain.split(".")[0])
        candidate_specs: list[tuple[str, float, list[str]]] = []
        for name, confidence, reason in (
            (dotted, 0.78, "domain as bucket"),
            (hyphenated, 0.72, "hyphenated domain"),
            (compact, 0.58, "compact domain"),
            (root, 0.42, "root label"),
        ):
            if name is not None:
                candidate_specs.append((name, confidence, [reason]))
        for token in clean_tokens:
            if root is not None:
                for value in (f"{token}-{root}", f"{root}-{token}"):
                    name = _bucket_token(value)
                    if name is not None:
                        candidate_specs.append((name, 0.52, ["org token plus root label"]))
            if hyphenated is not None:
                name = _bucket_token(f"{token}-{hyphenated}")
                if name is not None:
                    candidate_specs.append((name, 0.48, ["org token plus domain"]))
        for provider in ("gcs", "s3"):
            for name, confidence, reasons in candidate_specs:
                candidates.append(
                    CloudBucketCandidate(
                        provider=provider,
                        name=name,
                        source_domain=domain,
                        confidence=confidence,
                        reasons=reasons,
                    )
                )
    return _dedupe_bucket_candidates(candidates)


def build_github_discovery_plan(
    *,
    scope_domains: list[str],
    orgs: list[str] | None = None,
) -> GitHubDiscoveryPlan:
    warnings: list[str] = []
    normalized_domains = _normalize_domains(scope_domains, warnings=warnings)
    normalized_orgs = _normalize_github_orgs(orgs or [])
    if not normalized_orgs:
        normalized_orgs = _normalize_github_orgs([domain.split(".")[0] for domain in normalized_domains])
    queries: list[GitHubSearchQuery] = []
    for org in normalized_orgs:
        queries.append(
            GitHubSearchQuery(
                kind="repo",
                query=f"org:{org}",
                purpose="discover public repositories for an in-scope organization",
            )
        )
        for domain in normalized_domains:
            queries.append(
                GitHubSearchQuery(
                    kind="code",
                    query=f'org:{org} "{domain}"',
                    purpose="find references to approved scope domains in owned-org code",
                )
            )
        queries.extend(
            [
                GitHubSearchQuery(
                    kind="actions_config",
                    query=f"org:{org} path:.github/workflows extension:yml",
                    purpose="review public GitHub Actions workflow configuration",
                ),
                GitHubSearchQuery(
                    kind="actions_config",
                    query=f"org:{org} path:.github/workflows extension:yaml",
                    purpose="review public GitHub Actions workflow configuration",
                ),
                GitHubSearchQuery(
                    kind="workflow_log",
                    query=f'org:{org} "ACTIONS_STEP_DEBUG" OR "upload-artifact"',
                    purpose="identify public workflow log and artifact exposure signals",
                ),
            ]
        )
    assets = [
        Asset(
            kind="note",
            value=f"github-query:{query.kind}:{_short_hash(query.query)}",
            source="scanner-github-plan",
            metadata={
                "kind": query.kind,
                "approval_required": str(query.approval_required).lower(),
                "sends_traffic_if_executed": str(query.sends_traffic_if_executed).lower(),
            },
        )
        for query in queries
    ]
    return GitHubDiscoveryPlan(
        scope_domains=normalized_domains,
        orgs=normalized_orgs,
        queries=queries,
        assets=assets,
        warnings=warnings,
    )


def import_secret_scan_results(
    texts: list[str],
    *,
    scanner: SecretScanner,
) -> SecretScanImportReport:
    findings: list[SecretScanFinding] = []
    warnings: list[str] = []
    total_inputs = 0
    for source_index, text in enumerate(texts, start=1):
        source = f"{scanner}:{source_index}"
        items = _items_from_text(text)
        total_inputs += len(items)
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                warnings.append(f"{source}:{index}: skipped non-object finding")
                continue
            parsed = (
                _gitleaks_finding(item, source=source)
                if scanner == "gitleaks"
                else _trufflehog_finding(item, source=source)
            )
            if parsed is None:
                warnings.append(f"{source}:{index}: skipped incomplete finding")
                continue
            findings.append(parsed)
    deduped = _dedupe_secret_findings(findings)
    return SecretScanImportReport(
        scanner=scanner,
        total_inputs=total_inputs,
        total_findings=len(deduped),
        findings=deduped,
        assets=secret_scan_assets(deduped),
        warnings=warnings,
    )


def secret_scan_assets(findings: list[SecretScanFinding]) -> list[Asset]:
    assets = [
        Asset(
            kind="note",
            value=f"secret-scan:{finding.scanner}:{finding.fingerprint}",
            source="scanner-secret-import",
            parent=finding.file,
            metadata={
                "scanner": finding.scanner,
                "rule_id": finding.rule_id,
                "line": str(finding.line or ""),
                "verified": str(finding.verified).lower()
                if finding.verified is not None
                else "unknown",
                "secret_redacted": "true",
            },
        )
        for finding in findings
    ]
    return _dedupe_assets(assets)


def detect_cicd_exposures(texts: list[str]) -> CiCdExposureReport:
    warnings: list[str] = []
    signals: list[CiCdExposureSignal] = []
    total_inputs = 0
    for source_index, text in enumerate(texts, start=1):
        source = f"cicd:{source_index}"
        items = _items_from_text(text)
        total_inputs += len(items)
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                warnings.append(f"{source}:{index}: skipped non-object record")
                continue
            signals.extend(_cicd_signals_from_item(item, source=source))
    deduped = _dedupe_cicd_signals(signals)
    return CiCdExposureReport(
        total_inputs=total_inputs,
        signals=deduped,
        assets=cicd_exposure_assets(deduped),
        warnings=warnings,
    )


def cicd_exposure_assets(signals: list[CiCdExposureSignal]) -> list[Asset]:
    assets = [
        Asset(
            kind="note",
            value=f"cicd:{signal.category}:{_short_hash(signal.repo + signal.evidence)}",
            source="scanner-cicd-import",
            parent=signal.repo,
            metadata={
                "provider": signal.provider,
                "category": signal.category,
                "confidence": signal.confidence,
            },
        )
        for signal in signals
    ]
    return _dedupe_assets(assets)


def import_container_metadata(texts: list[str]) -> ContainerMetadataReport:
    warnings: list[str] = []
    images: list[ContainerImageMetadata] = []
    total_inputs = 0
    for source_index, text in enumerate(texts, start=1):
        source = f"container:{source_index}"
        items = _items_from_text(text)
        total_inputs += len(items)
        for index, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                warnings.append(f"{source}:{index}: skipped non-object image metadata")
                continue
            parsed = _container_image_from_item(item, source=source)
            if parsed is None:
                warnings.append(f"{source}:{index}: skipped image metadata without image name")
                continue
            images.append(parsed)
    deduped = _dedupe_container_images(images)
    return ContainerMetadataReport(
        total_inputs=total_inputs,
        images=deduped,
        assets=container_metadata_assets(deduped),
        warnings=warnings,
    )


def container_metadata_assets(images: list[ContainerImageMetadata]) -> list[Asset]:
    assets: list[Asset] = []
    for image in images:
        metadata = {
            "registry": image.registry or "",
            "tags": ",".join(image.tags),
            "digest": image.digest or "",
            "exposed_ports": ",".join(image.exposed_ports),
            "base_images": ",".join(image.base_images),
        }
        assets.append(
            Asset(
                kind="note",
                value=f"container-image:{image.image}",
                source="scanner-container-import",
                metadata=metadata,
            )
        )
    return _dedupe_assets(assets)


def _nuclei_block_reasons(
    template: NucleiTemplateMetadata,
    *,
    profile_templates: set[str],
    profile_tags: set[str],
    profile_severity: set[str],
    profile_protocols: set[str],
) -> list[str]:
    reasons: list[str] = []
    blocked_tags = sorted(set(template.tags).intersection(AGGRESSIVE_NUCLEI_TAGS))
    if blocked_tags:
        reasons.append(f"aggressive tags blocked: {', '.join(blocked_tags)}")
    unsafe_protocols = sorted(set(template.protocol_types).difference(SAFE_NUCLEI_PROTOCOLS))
    if unsafe_protocols:
        reasons.append(f"unsafe protocols blocked: {', '.join(unsafe_protocols)}")
    outside_profile_protocols = sorted(set(template.protocol_types).difference(profile_protocols))
    if outside_profile_protocols:
        reasons.append(
            "protocols not in profile: " + ", ".join(outside_profile_protocols)
        )
    selectors_matched = (
        template.path in profile_templates
        or template.template_id in profile_templates
        or bool(profile_tags.intersection(template.tags))
        or template.severity in profile_severity
    )
    if not selectors_matched:
        reasons.append("template was not selected by the allowlist profile")
    return reasons


def _normalize_relative_template_path(value: str) -> str:
    path = value.strip()
    if not path:
        raise ValueError("nuclei template path cannot be blank")
    if path.startswith("/") or "\\" in path:
        raise ValueError("nuclei templates must be explicit relative paths")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("nuclei templates must be explicit relative paths")
    return path


def _vulnerability_priority(reference: VulnerabilityReference) -> ScannerPriority:
    score = reference.cvss_score or 0.0
    if reference.kev or score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _version_match_reason(detected_version: str | None, affected_versions: list[str]) -> str | None:
    if not affected_versions:
        return "technology matched; reference has no version constraint"
    lowered = {version.lower() for version in affected_versions}
    if "*" in lowered or "all" in lowered:
        return "technology matched; reference affects all listed versions"
    if detected_version is None or not detected_version.strip():
        return "technology matched; detected version needs manual confirmation"
    version = detected_version.strip().lower()
    for affected in lowered:
        if affected == version or version in affected:
            return f"detected version {detected_version} matched catalog constraint"
    return None


def _technology_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _dedupe_vulnerability_matches(
    matches: list[TechnologyVulnerabilityMatch],
) -> list[TechnologyVulnerabilityMatch]:
    by_key = {
        (
            match.technology.lower(),
            match.asset_parent or "",
            match.cve_id,
            match.detected_version or "",
        ): match
        for match in matches
    }
    return sorted(
        by_key.values(),
        key=lambda match: (match.priority, match.technology.lower(), match.cve_id),
    )


def _normalize_domains(values: list[str], *, warnings: list[str]) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = value.strip().lower().removeprefix("*.").rstrip(".")
        if "://" in candidate:
            candidate = urlsplit(candidate).hostname or ""
        try:
            host = normalize_host(candidate).host
        except NormalizationError:
            warnings.append(f"skipped invalid domain: {value}")
            continue
        if host not in seen:
            seen.add(host)
            domains.append(host)
    return domains


def _bucket_token(value: str) -> str | None:
    candidate = re.sub(r"[^a-z0-9.-]+", "-", value.lower().strip())
    candidate = re.sub(r"-+", "-", candidate).strip(".-")
    if len(candidate) < 3 or len(candidate) > 63:
        return None
    if ".." in candidate or ".-" in candidate or "-." in candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return None


def _cloud_metadata_request(candidate: CloudBucketCandidate) -> CloudBucketMetadataRequest:
    if candidate.provider == "gcs":
        url = f"https://storage.googleapis.com/{candidate.name}"
    else:
        url = f"https://{candidate.name}.s3.amazonaws.com/"
    return CloudBucketMetadataRequest(
        provider=candidate.provider,
        bucket=candidate.name,
        url=url,
    )


def _dedupe_bucket_candidates(
    candidates: list[CloudBucketCandidate],
) -> list[CloudBucketCandidate]:
    by_key = {(candidate.provider, candidate.name): candidate for candidate in candidates}
    return sorted(by_key.values(), key=lambda candidate: (candidate.provider, candidate.name))


def _normalize_github_orgs(values: list[str]) -> list[str]:
    orgs: list[str] = []
    seen: set[str] = set()
    for value in values:
        candidate = value.strip().removeprefix("@").lower()
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,38}", candidate) and candidate not in seen:
            seen.add(candidate)
            orgs.append(candidate)
    return orgs


def _gitleaks_finding(item: dict[object, object], *, source: str) -> SecretScanFinding | None:
    file_path = _first_string(item, ("File", "file", "Path", "path")) or "unknown"
    rule_id = _first_string(item, ("RuleID", "rule_id", "Rule", "rule")) or "unknown-rule"
    raw_secret = _first_string(item, ("Secret", "secret", "Match", "match"))
    fingerprint = _first_string(item, ("Fingerprint", "fingerprint"))
    if fingerprint is None:
        fingerprint = _secret_fingerprint(raw_secret or f"{file_path}:{rule_id}")
    return SecretScanFinding(
        scanner="gitleaks",
        rule_id=rule_id,
        file=file_path,
        line=_int_or_none(item.get("StartLine") or item.get("Line") or item.get("line")),
        fingerprint=fingerprint,
        verified=_bool_or_none(item.get("Verified") or item.get("verified")),
        source=source,
    )


def _trufflehog_finding(
    item: dict[object, object],
    *,
    source: str,
) -> SecretScanFinding | None:
    file_path = _trufflehog_file(item) or "unknown"
    rule_id = _first_string(item, ("DetectorName", "detector_name", "DetectorType")) or "unknown-rule"
    raw_secret = _first_string(item, ("Raw", "RawV2", "raw", "raw_v2"))
    fingerprint = _first_string(item, ("Fingerprint", "fingerprint"))
    if fingerprint is None:
        fingerprint = _secret_fingerprint(raw_secret or f"{file_path}:{rule_id}")
    return SecretScanFinding(
        scanner="trufflehog",
        rule_id=rule_id,
        file=file_path,
        line=_int_or_none(item.get("Line") or item.get("line")),
        fingerprint=fingerprint,
        verified=_bool_or_none(item.get("Verified") or item.get("verified")),
        source=source,
    )


def _trufflehog_file(item: dict[object, object]) -> str | None:
    direct = _first_string(item, ("file", "File", "path", "Path"))
    if direct is not None:
        return direct
    source_metadata = item.get("SourceMetadata")
    if not isinstance(source_metadata, dict):
        return None
    data = source_metadata.get("Data")
    if not isinstance(data, dict):
        return None
    for value in data.values():
        if isinstance(value, dict):
            path = _first_string(value, ("file", "path", "filename"))
            if path is not None:
                return path
    return None


def _secret_fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _cicd_signals_from_item(
    item: dict[object, object],
    *,
    source: str,
) -> list[CiCdExposureSignal]:
    signals: list[CiCdExposureSignal] = []
    repo = _repo_from_item(item)
    if _looks_like_public_artifact(item):
        signals.append(
            CiCdExposureSignal(
                provider="github_actions",
                repo=repo,
                category="public_artifact",
                evidence="non-expired public workflow artifact metadata",
                confidence="medium",
                source=source,
            )
        )
    path = _first_string(item, ("path", "name", "file", "workflow_path")) or ""
    body = _first_string(item, ("content", "text", "body", "log", "message")) or ""
    lower_path = path.lower()
    lower_body = body.lower()
    if ".github/workflows/" in lower_path or "on:" in lower_body and "jobs:" in lower_body:
        if "pull_request_target" in lower_body:
            signals.append(
                CiCdExposureSignal(
                    provider="github_actions",
                    repo=repo,
                    category="actions_config",
                    evidence="workflow uses pull_request_target",
                    confidence="high",
                    source=source,
                )
            )
        if "upload-artifact" in lower_body:
            signals.append(
                CiCdExposureSignal(
                    provider="github_actions",
                    repo=repo,
                    category="public_artifact",
                    evidence="workflow uploads artifacts",
                    confidence="medium",
                    source=source,
                )
            )
    pattern_name = _secret_pattern_name(body)
    if pattern_name is not None:
        signals.append(
            CiCdExposureSignal(
                provider="github_actions" if repo != "unknown" else "generic",
                repo=repo,
                category="secret_reference",
                evidence=f"redacted secret-like pattern detected: {pattern_name}",
                confidence="high",
                source=source,
            )
        )
    if "workflow log" in lower_path or "github action" in lower_body:
        if "warning:" in lower_body or "error:" in lower_body:
            signals.append(
                CiCdExposureSignal(
                    provider="github_actions",
                    repo=repo,
                    category="workflow_log",
                    evidence="workflow log metadata contains warning/error output",
                    confidence="low",
                    source=source,
                )
            )
    return signals


def _looks_like_public_artifact(item: dict[object, object]) -> bool:
    if "archive_download_url" not in item and "artifact_url" not in item:
        return False
    expired = item.get("expired")
    if isinstance(expired, bool) and expired:
        return False
    return True


def _repo_from_item(item: dict[object, object]) -> str:
    repo = _first_string(item, ("repo", "repository", "full_name"))
    if repo is not None:
        return repo
    repository = item.get("repository")
    if isinstance(repository, dict):
        full_name = _first_string(repository, ("full_name", "name"))
        if full_name is not None:
            return full_name
    workflow_run = item.get("workflow_run")
    if isinstance(workflow_run, dict):
        repository_name = _first_string(workflow_run, ("repository", "repo", "head_repository"))
        if repository_name is not None:
            return repository_name
    return "unknown"


def _secret_pattern_name(text: str) -> str | None:
    patterns = [
        ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ("github-token", r"gh[pousr]_[A-Za-z0-9_]{20,}"),
        ("google-api-key", r"AIza[0-9A-Za-z_-]{20,}"),
        ("bearer-token", r"bearer\s+[A-Za-z0-9._~+/=-]{20,}"),
        ("password-assignment", r"(?i)(password|passwd|secret)\s*[:=]\s*['\"]?[^'\"\s]{8,}"),
    ]
    for name, pattern in patterns:
        if re.search(pattern, text):
            return name
    return None


def _dedupe_cicd_signals(signals: list[CiCdExposureSignal]) -> list[CiCdExposureSignal]:
    by_key = {
        (signal.repo, signal.category, signal.evidence, signal.source): signal
        for signal in signals
    }
    return sorted(by_key.values(), key=lambda signal: (signal.repo, signal.category, signal.evidence))


def _container_image_from_item(
    item: dict[object, object],
    *,
    source: str,
) -> ContainerImageMetadata | None:
    image = _first_string(item, ("image", "Image", "name", "Name"))
    repo_tags = _string_list(item.get("RepoTags") or item.get("repoTags") or item.get("tags"))
    repo_digests = _string_list(item.get("RepoDigests") or item.get("repoDigests") or item.get("digests"))
    if image is None and repo_tags:
        image = repo_tags[0]
    if image is None:
        syft_source = item.get("source")
        if isinstance(syft_source, dict):
            image = _first_string(syft_source, ("target", "name"))
    if image is None:
        return None
    config = item.get("Config") or item.get("config")
    config_map = config if isinstance(config, dict) else {}
    labels = _string_dict(config_map.get("Labels") or item.get("labels"))
    exposed = _exposed_ports(config_map.get("ExposedPorts") or item.get("exposedPorts"))
    base_images = _base_images(item)
    digest = _first_digest(repo_digests) or _first_string(item, ("digest", "Digest"))
    return ContainerImageMetadata(
        image=image,
        registry=_registry_from_image(image),
        tags=repo_tags,
        digest=digest,
        source=source,
        labels=labels,
        exposed_ports=exposed,
        base_images=base_images,
    )


def _base_images(item: dict[object, object]) -> list[str]:
    labels_source = item.get("Config") or item.get("config")
    labels: dict[str, str] = {}
    if isinstance(labels_source, dict):
        labels = _string_dict(labels_source.get("Labels"))
    labels.update(_string_dict(item.get("labels")))
    base_keys = (
        "org.opencontainers.image.base.name",
        "org.opencontainers.image.base.digest",
        "dockerfile.base",
    )
    values = [labels[key] for key in base_keys if key in labels and labels[key]]
    return _dedupe_tokens(values)


def _exposed_ports(value: object) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(key) for key in value.keys())
    return _string_list(value)


def _first_digest(values: list[str]) -> str | None:
    for value in values:
        if "@sha256:" in value:
            return value.rsplit("@", maxsplit=1)[-1]
        if value.startswith("sha256:"):
            return value
    return None


def _registry_from_image(image: str) -> str | None:
    first = image.split("/", maxsplit=1)[0]
    if "." in first or ":" in first or first == "localhost":
        return first
    return "docker.io"


def _dedupe_container_images(images: list[ContainerImageMetadata]) -> list[ContainerImageMetadata]:
    by_key = {(image.image, image.digest or ""): image for image in images}
    return sorted(by_key.values(), key=lambda image: image.image)


def _dedupe_secret_findings(findings: list[SecretScanFinding]) -> list[SecretScanFinding]:
    by_key = {(finding.scanner, finding.fingerprint): finding for finding in findings}
    return sorted(by_key.values(), key=lambda finding: (finding.scanner, finding.file, finding.rule_id))


def _items_from_text(text: str) -> list[object]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        items: list[object] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("results", "items", "data", "findings", "artifacts", "images"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
        return [parsed]
    return []


def _first_string(item: dict[object, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return _dedupe_tokens(str(item) for item in value if item is not None)
    if isinstance(value, str) and value.strip():
        return _dedupe_tokens(value.split(","))
    return []


def _string_dict(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, str] = {}
    for key, item in value.items():
        if isinstance(key, str) and item is not None:
            output[key] = str(item)
    return output


def _int_or_none(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _bool_or_none(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _dedupe_lower_tokens(values: list[str]) -> list[str]:
    return _dedupe_tokens(value.lower() for value in values)


def _dedupe_tokens(values: Iterable[object] | str) -> list[str]:
    tokens: list[str] = []
    seen: set[str] = set()
    if isinstance(values, str):
        iterable: Iterable[object] = values.split(",")
    else:
        iterable = values
    for value in iterable:
        token = str(value).strip()
        if token and token not in seen:
            seen.add(token)
            tokens.append(token)
    return tokens


def _dedupe_assets(assets: list[Asset]) -> list[Asset]:
    by_fingerprint = {asset.fingerprint: asset for asset in assets}
    return sorted(by_fingerprint.values(), key=lambda asset: (asset.kind, asset.value))


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
