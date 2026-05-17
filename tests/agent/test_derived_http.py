from pathlib import Path

import httpx
import pytest

from vrp_hunt.agent import (
    DerivedHttpCheckError,
    DerivedHttpCheckResult,
    DerivedHttpObservation,
    artifact_bundle_from_derived_http_check,
    build_derived_http_targets,
    cookie_header_from_env,
    load_derived_http_check_result,
    run_derived_http_check,
    sanitize_cookie_header,
)


def test_build_derived_http_targets_for_docs_exports() -> None:
    targets = build_derived_http_targets("https://docs.google.com/document/d/owned/edit")
    by_name = {target.name: target for target in targets}

    assert set(by_name) == {"preview", "export-txt", "export-pdf"}
    assert by_name["export-pdf"].url == "https://docs.google.com/document/d/owned/export?format=pdf"
    assert all(target.method == "HEAD" for target in targets)


def test_build_derived_http_targets_for_drive_download_and_thumbnail() -> None:
    targets = build_derived_http_targets("https://drive.google.com/file/d/owned/view", method="GET")
    by_name = {target.name: target for target in targets}

    assert set(by_name) == {"preview", "download", "thumbnail"}
    assert by_name["download"].url == "https://drive.google.com/uc?id=owned&export=download"
    assert by_name["thumbnail"].url == "https://drive.google.com/thumbnail?id=owned&sz=w320"
    assert all(target.method == "GET" for target in targets)


def test_cookie_header_from_env_redacts_storage_boundary() -> None:
    assert sanitize_cookie_header("Cookie: SID=abc; HSID=def") == "SID=abc; HSID=def"
    assert cookie_header_from_env("OWNED_COOKIE", {"OWNED_COOKIE": "SID=abc"}) == "SID=abc"

    with pytest.raises(DerivedHttpCheckError, match="single line"):
        sanitize_cookie_header("SID=abc\nHSID=def")


def test_run_derived_http_check_records_metadata_only_high_signal() -> None:
    captured_headers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_headers.append(request.headers["cookie"])
        if request.url.params.get("format") == "pdf":
            return httpx.Response(
                200,
                headers={
                    "content-type": "application/pdf",
                    "content-disposition": 'attachment; filename="owned-secret-title.pdf"',
                    "content-length": "1234",
                },
            )
        return httpx.Response(403, headers={"content-type": "text/html"})

    client = httpx.Client(transport=httpx.MockTransport(handler))

    result = run_derived_http_check(
        account_id="owned-b",
        owned_object_url="https://docs.google.com/document/d/owned/edit",
        expected_state="access_denied",
        cookie_header="SID=abc",
        confirm_owned_object=True,
        client=client,
    )

    assert result.target_count == 3
    assert result.high_signal_mismatches == 1
    assert result.errors == 0
    assert set(captured_headers) == {"SID=abc"}
    granted = [item for item in result.observations if item.state == "access_granted_metadata"][0]
    assert granted.response_headers["content-disposition"] == "[PRESENT]"
    assert "owned-secret-title" not in str(granted.response_headers)
    assert granted.response_body_stored is False
    assert granted.response_body_bytes_read == 0


def test_run_derived_http_check_classifies_login_redirect_without_following_cross_site() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(
            302,
            headers={"location": "https://accounts.google.com/signin?continue=https://docs.google.com/"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))

    result = run_derived_http_check(
        account_id="owned-b",
        owned_object_url="https://docs.google.com/document/d/owned/edit",
        expected_state="access_denied",
        cookie_header="SID=abc",
        confirm_owned_object=True,
        max_targets=1,
        client=client,
    )

    assert len(requests) == 1
    assert result.observations[0].state == "login_required"
    assert result.observations[0].redirect_location_host == "accounts.google.com"
    assert result.high_signal_mismatches == 0


def test_run_derived_http_check_follows_same_host_redirect_only() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if len(requests) == 1:
            return httpx.Response(
                302,
                headers={"location": "/document/d/owned/export?format=pdf"},
            )
        return httpx.Response(200, headers={"content-type": "application/pdf"})

    client = httpx.Client(transport=httpx.MockTransport(handler))

    result = run_derived_http_check(
        account_id="owned-b",
        owned_object_url="https://docs.google.com/document/d/owned/edit",
        expected_state="access_denied",
        cookie_header="SID=abc",
        confirm_owned_object=True,
        max_targets=1,
        client=client,
    )

    assert len(requests) == 2
    assert result.observations[0].redirect_count == 1
    assert result.observations[0].state == "access_granted_metadata"


def test_run_derived_http_check_requires_owned_confirmation() -> None:
    with pytest.raises(DerivedHttpCheckError, match="confirm-owned-object"):
        run_derived_http_check(
            account_id="owned-b",
            owned_object_url="https://docs.google.com/document/d/owned/edit",
            expected_state="access_denied",
            cookie_header="SID=abc",
            confirm_owned_object=False,
        )


def test_load_derived_http_check_result_from_json(tmp_path: Path) -> None:
    result_path = tmp_path / "derived-http-result.json"
    result_path.write_text(
        DerivedHttpCheckResult(
            account_id="owned-b",
            source_url="https://docs.google.com/[path:abc123]",
            expected_state="access_denied",
            target_count=1,
            observations=[
                DerivedHttpObservation(
                    target_name="export-pdf",
                    method="HEAD",
                    checked_url="https://docs.google.com/[path:def456]?keys=format",
                    status_code=200,
                    final_host="docs.google.com",
                    state="access_granted_metadata",
                    response_body_stored=False,
                    response_body_bytes_read=0,
                )
            ],
        ).model_dump_json(),
        encoding="utf-8",
    )

    result = load_derived_http_check_result(result_path)

    assert result.account_id == "owned-b"
    assert result.observations[0].state == "access_granted_metadata"


def test_derived_http_metadata_mismatch_converts_to_finding_artifact() -> None:
    result = DerivedHttpCheckResult(
        account_id="owned-b",
        source_url="https://docs.google.com/[path:abc123]",
        expected_state="access_denied",
        target_count=1,
        observations=[
            DerivedHttpObservation(
                target_name="export-pdf",
                method="HEAD",
                checked_url="https://docs.google.com/[path:def456]?keys=format",
                status_code=200,
                final_host="docs.google.com",
                final_path_hash="abc123",
                response_headers={"content-type": "application/pdf"},
                state="access_granted_metadata",
                confidence=0.7,
                matched_signals=["content-type:application/pdf"],
                response_body_stored=False,
                response_body_bytes_read=0,
            )
        ],
        high_signal_mismatches=1,
    )

    bundle = artifact_bundle_from_derived_http_check(
        result,
        researcher_accounts=["owned-a", "owned-b"],
        component="Docs export endpoint",
    )

    assert len(bundle.artifacts) == 1
    assert bundle.artifacts[0].finding.bug_class == "idor"
    assert bundle.artifacts[0].finding.status == "needs_review"
    assert bundle.artifacts[0].report.target_info.component == "Docs export endpoint"
    assert all(item.redacted for item in bundle.artifacts[0].finding.evidence)


def test_derived_http_artifacts_skip_body_reads() -> None:
    result = DerivedHttpCheckResult(
        account_id="owned-b",
        source_url="https://docs.google.com/[path:abc123]",
        expected_state="access_denied",
        target_count=1,
        observations=[
            DerivedHttpObservation(
                target_name="export-pdf",
                method="GET",
                checked_url="https://docs.google.com/[path:def456]?keys=format",
                status_code=200,
                state="access_granted_metadata",
                response_body_stored=False,
                response_body_bytes_read=1,
            )
        ],
    )

    bundle = artifact_bundle_from_derived_http_check(
        result,
        researcher_accounts=["owned-b"],
    )

    assert not bundle.artifacts
    assert "response body bytes were read" in bundle.skipped[0]
