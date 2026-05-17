import json

import pytest

from vrp_hunt.recon import (
    Asset,
    NucleiAllowlistProfile,
    NucleiTemplateMetadata,
    VulnerabilityReference,
    audit_nuclei_templates,
    build_cloud_bucket_check_plan,
    build_github_discovery_plan,
    detect_cicd_exposures,
    import_container_metadata,
    import_secret_scan_results,
    match_cves_to_technologies,
)


def test_nuclei_template_audit_allows_only_profile_safe_templates() -> None:
    profile = NucleiAllowlistProfile(
        profile_id="safe-http",
        templates=["http/exposures/git-config.yaml"],
        tags=["exposure"],
        severity=["low", "medium"],
    )

    report = audit_nuclei_templates(
        profile,
        [
            NucleiTemplateMetadata(
                template_id="git-config",
                path="http/exposures/git-config.yaml",
                severity="low",
                tags=["exposure"],
                protocol_types=["http"],
            ),
            NucleiTemplateMetadata(
                template_id="intrusive-check",
                path="http/fuzz/intrusive.yaml",
                severity="high",
                tags=["fuzz"],
                protocol_types=["http"],
            ),
        ],
    )

    assert [template.template_id for template in report.allowed_templates] == ["git-config"]
    assert report.blocked_templates[0].template_id == "intrusive-check"
    assert "aggressive tags blocked: fuzz" in report.findings[1].reasons


def test_nuclei_profile_rejects_aggressive_tags() -> None:
    with pytest.raises(ValueError, match="blocked aggressive nuclei tags"):
        NucleiAllowlistProfile(profile_id="bad", tags=["dast"])


def test_cve_matching_enriches_with_kev_and_cvss_priority() -> None:
    report = match_cves_to_technologies(
        [
            Asset(
                kind="technology",
                value="ExampleCMS",
                source="technology-fingerprint",
                parent="https://www.google.com/",
                metadata={"version": "1.2.3"},
            )
        ],
        [
            VulnerabilityReference(
                cve_id="CVE-2025-12345",
                technology="example cms",
                affected_versions=["1.2.3"],
                cvss_score=9.8,
                kev=True,
                source="local-catalog",
            )
        ],
    )

    assert report.matches[0].cve_id == "CVE-2025-12345"
    assert report.matches[0].priority == "critical"
    assert report.assets[0].metadata["kev"] == "true"
    assert report.assets[0].metadata["cvss_score"] == "9.8"


def test_cloud_bucket_plan_builds_metadata_only_requests() -> None:
    report = build_cloud_bucket_check_plan(["www.google.com"], org_tokens=["vrp"])

    assert report.total_candidates > 0
    assert {request.provider for request in report.metadata_requests} == {"gcs", "s3"}
    assert all(request.method == "HEAD" for request in report.metadata_requests)
    assert all(request.metadata_only for request in report.metadata_requests)
    assert all(request.approval_required for request in report.metadata_requests)
    assert any(candidate.name == "www.google.com" for candidate in report.candidates)


def test_github_discovery_plan_builds_owned_org_queries() -> None:
    report = build_github_discovery_plan(scope_domains=["google.com"], orgs=["google"])

    queries = {query.query for query in report.queries}

    assert "org:google" in queries
    assert 'org:google "google.com"' in queries
    assert any("path:.github/workflows" in query for query in queries)
    assert all(query.approval_required for query in report.queries)


def test_gitleaks_import_redacts_secret_values() -> None:
    raw_secret = "AIzaSyVerySecretGoogleApiKeyValue"
    report = import_secret_scan_results(
        [
            json.dumps(
                [
                    {
                        "RuleID": "generic-api-key",
                        "File": "src/app.py",
                        "StartLine": 7,
                        "Secret": raw_secret,
                        "Fingerprint": "abcdef1234567890",
                    }
                ]
            )
        ],
        scanner="gitleaks",
    )

    dumped = report.model_dump_json()

    assert report.findings[0].redacted_secret == "<redacted>"
    assert report.assets[0].metadata["secret_redacted"] == "true"
    assert raw_secret not in dumped


def test_trufflehog_import_redacts_secret_values() -> None:
    raw_secret = "ghp_verysecretverysecretverysecret"
    report = import_secret_scan_results(
        [
            json.dumps(
                {
                    "DetectorName": "GitHub",
                    "Raw": raw_secret,
                    "Verified": True,
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "repo/ci.log"}}},
                }
            )
        ],
        scanner="trufflehog",
    )

    dumped = report.model_dump_json()

    assert report.findings[0].verified is True
    assert report.findings[0].file == "repo/ci.log"
    assert raw_secret not in dumped


def test_cicd_import_flags_public_artifacts_and_redacted_secret_patterns() -> None:
    raw_secret = "ghp_verysecretverysecretverysecret"
    report = detect_cicd_exposures(
        [
            json.dumps(
                [
                    {
                        "repo": "google/example",
                        "archive_download_url": "https://api.github.com/repos/google/example/actions/artifacts/1/zip",
                        "expired": False,
                    },
                    {
                        "repo": "google/example",
                        "path": ".github/workflows/test.yml",
                        "content": "on: pull_request_target\njobs:\n  test:\n    steps:\n      - uses: actions/upload-artifact@v4\n",
                    },
                    {
                        "repo": "google/example",
                        "log": f"leaked token {raw_secret}",
                    },
                ]
            )
        ]
    )

    categories = {signal.category for signal in report.signals}

    assert {"public_artifact", "actions_config", "secret_reference"} <= categories
    assert raw_secret not in report.model_dump_json()


def test_container_metadata_imports_docker_inspect_shape() -> None:
    report = import_container_metadata(
        [
            json.dumps(
                [
                    {
                        "RepoTags": ["ghcr.io/google/example:latest"],
                        "RepoDigests": ["ghcr.io/google/example@sha256:abc123"],
                        "Config": {
                            "Labels": {
                                "org.opencontainers.image.base.name": "gcr.io/distroless/base"
                            },
                            "ExposedPorts": {"8080/tcp": {}},
                        },
                    }
                ]
            )
        ]
    )

    image = report.images[0]

    assert image.image == "ghcr.io/google/example:latest"
    assert image.registry == "ghcr.io"
    assert image.digest == "sha256:abc123"
    assert image.exposed_ports == ["8080/tcp"]
    assert image.base_images == ["gcr.io/distroless/base"]
