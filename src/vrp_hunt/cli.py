"""Command-line entry point for VRP Hunt."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import date
from pathlib import Path
from typing import cast

from vrp_hunt.agent import (
    ActionBudget,
    ActionRunner,
    AgentAction,
    AgentArtifactBundle,
    AgentPlan,
    AgentRunResult,
    ApprovalGateError,
    ApprovalMode,
    ApprovedSubprocessRunner,
    AutonomyPolicy,
    AutonomousAgent,
    BrowserAccessState,
    BrowserCheckError,
    DerivedHttpCheckError,
    DerivedHttpMethod,
    LiveReconAuthorizationError,
    LiveReconRunner,
    ModelProviderError,
    ModelProviderName,
    OwnedAccountCrawlConfig,
    OwnedAccountCrawlError,
    OwnedAccountCrawlPage,
    OwnedBrowserScenarioError,
    OwnedObjectPipelineError,
    OwnedPermissionMatrixError,
    ReconDepthError,
    ReconDepthProfile,
    ReconWorkflowError,
    apply_approval_gate,
    artifact_bundle_from_agent_run,
    artifact_bundle_from_derived_http_check,
    artifact_bundle_from_owned_browser_scenario,
    build_agent_brain,
    build_submission_assistance,
    build_owned_account_crawl_plan,
    build_agent_plan,
    cookie_header_from_env,
    build_offline_analysis_plan,
    build_recon_iteration_summary,
    expand_owned_browser_scenario_derived_urls,
    load_derived_http_check_result,
    load_operator_policy,
    load_owned_browser_scenario,
    load_owned_browser_scenario_result,
    load_owned_object_catalog,
    load_owned_permission_matrix,
    run_derived_http_check,
    run_owned_browser_check,
    run_owned_browser_check_cdp,
    run_owned_browser_scenario,
    run_owned_object_pipeline,
    run_owned_permission_matrix,
    run_recon_depth,
    load_recon_workflow,
    run_recon_workflow,
    write_generated_owned_browser_scenarios,
    write_owned_permission_matrix_template,
    write_recon_iteration_outputs,
)
from vrp_hunt.agent.runners import build_safe_offline_runner, build_safe_validation_runner
from vrp_hunt.guardrails.models import TargetKind
from vrp_hunt.mobile_recon import (
    MobileArtifactImportError,
    build_mobile_static_report,
    import_mobile_artifacts,
)
from vrp_hunt.programs import (
    ProgramRegistryLoadError,
    ScopeIngestionError,
    ScopeIngestionOptions,
    ScopeIngestionSource,
    diff_program_registries,
    ingest_scope_export,
    load_program_registry,
    match_program_scope,
)
from vrp_hunt.recon import (
    Asset,
    DnsRecord,
    DnsRecordCollection,
    PassiveSourceCatalogError,
    WildcardDnsProbe,
    asn_netblock_assets,
    asn_netblock_record_from_spec,
    build_asn_netblock_report,
    build_dns_record_plan,
    build_recursive_passive_plan,
    build_reverse_ct_expansion_report,
    cdn_waf_fingerprint_assets,
    evaluate_passive_source_health,
    fingerprint_cdn_waf,
    filter_wildcard_dns_assets,
    generate_subdomain_permutations,
    ingest_historical_url_files,
    import_dns_record_files,
    load_asn_netblock_records,
    load_words,
    load_passive_source_catalog,
    passive_source_env_template,
    passive_expansion_assets,
    recursive_passive_assets,
    RecursivePassiveConfig,
    SubdomainPermutationConfig,
    score_assets,
    wildcard_probe_from_asset,
    wildcard_probe_from_spec,
)
from vrp_hunt.reporting import Platform, ReportDraft, render_markdown_report
from vrp_hunt.ui import build_dashboard_data, write_dashboard
from vrp_hunt.web_recon import (
    EndpointMiningConfig,
    WebContentDocument,
    mine_javascript_and_api_endpoints,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "agent-plan":
        return _agent_plan(args)
    if args.command == "agent-run":
        return _agent_run(args)
    if args.command == "agent-auto":
        return _agent_auto(args)
    if args.command == "recon-iterate":
        return _recon_iterate(args)
    if args.command == "recon-depth":
        return _recon_depth(args)
    if args.command == "recon-workflow":
        return _recon_workflow(args)
    if args.command == "program-list":
        return _program_list(args)
    if args.command == "program-match":
        return _program_match(args)
    if args.command == "program-diff":
        return _program_diff(args)
    if args.command == "program-ingest":
        return _program_ingest(args)
    if args.command == "passive-sources":
        return _passive_sources(args)
    if args.command == "passive-sources-env-template":
        return _passive_sources_env_template(args)
    if args.command == "asset-score":
        return _asset_score(args)
    if args.command == "wildcard-dns-filter":
        return _wildcard_dns_filter(args)
    if args.command == "dns-record-plan":
        return _dns_record_plan(args)
    if args.command == "dns-record-import":
        return _dns_record_import(args)
    if args.command == "cdn-waf-fingerprint":
        return _cdn_waf_fingerprint(args)
    if args.command == "asn-netblock-import":
        return _asn_netblock_import(args)
    if args.command == "reverse-ct-import":
        return _reverse_ct_import(args)
    if args.command == "subdomain-permute":
        return _subdomain_permute(args)
    if args.command == "recursive-passive-plan":
        return _recursive_passive_plan(args)
    if args.command == "historical-url-import":
        return _historical_url_import(args)
    if args.command == "endpoint-mine":
        return _endpoint_mine(args)
    if args.command == "owned-crawl-plan":
        return _owned_crawl_plan(args)
    if args.command == "owned-browser-check":
        return _owned_browser_check(args)
    if args.command == "owned-browser-scenario":
        return _owned_browser_scenario(args)
    if args.command == "scenario-generate":
        return _scenario_generate(args)
    if args.command == "scenario-artifacts":
        return _scenario_artifacts(args)
    if args.command == "derived-http-check":
        return _derived_http_check(args)
    if args.command == "derived-http-artifacts":
        return _derived_http_artifacts(args)
    if args.command == "owned-object-pipeline":
        return _owned_object_pipeline(args)
    if args.command == "owned-permission-matrix-template":
        return _owned_permission_matrix_template(args)
    if args.command == "owned-permission-matrix":
        return _owned_permission_matrix(args)
    if args.command == "mobile-hypotheses":
        return _mobile_hypotheses(args)
    if args.command == "mobile-import":
        return _mobile_import(args)
    if args.command == "submission-checklist":
        return _submission_checklist(args)
    if args.command == "dashboard":
        return _dashboard(args)
    if args.command == "live-recon":
        return _live_recon(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vrp-hunt")
    subparsers = parser.add_subparsers(dest="command")

    plan = subparsers.add_parser("agent-plan", help="Build an autonomous agent plan")
    _add_agent_inputs(plan)
    _add_model_inputs(plan)
    plan.add_argument("--mode", choices=("offline", "testing"), default="offline")
    plan.add_argument("--max-actions", type=int, default=10)

    run = subparsers.add_parser("agent-run", help="Run a safe autonomous agent plan")
    _add_agent_inputs(run)
    _add_model_inputs(run)
    run.add_argument("--mode", choices=("offline", "testing"), default="offline")
    run.add_argument("--max-actions", type=int, default=10)
    run.add_argument("--execute-safe", action="store_true", help="Execute safe non-traffic handlers")
    run.add_argument(
        "--approve-risky",
        action="store_true",
        help="Legacy shortcut: approve all approval-required actions for this run",
    )
    run.add_argument(
        "--approval-mode",
        choices=("block", "explicit", "prompt", "approve-all"),
        default="block",
        help="How the CLI approval gate handles risky actions",
    )
    run.add_argument(
        "--approve-action",
        action="append",
        default=[],
        help="Approve one risky action by 1-based index, action id, or 'all'",
    )
    run.add_argument(
        "--yolo",
        action="store_true",
        help="Approve all approval-required actions without disabling guardrails or budgets",
    )
    run.add_argument("--max-live-requests", type=int, default=0)

    auto = subparsers.add_parser(
        "agent-auto",
        help="Run an approval-gated safe pipeline and emit report artifacts",
    )
    _add_agent_inputs(auto)
    _add_model_inputs(auto)
    _add_approval_inputs(auto)
    _add_artifact_inputs(auto)
    auto.add_argument("--mode", choices=("offline", "testing"), default="testing")
    auto.add_argument("--max-actions", type=int, default=10)
    auto.add_argument("--max-live-requests", type=int, default=0)
    auto.add_argument(
        "--artifact-output-dir",
        type=Path,
        help="Optional directory for plan.json, run.json, and artifact-bundle.json",
    )

    iterate = subparsers.add_parser(
        "recon-iterate",
        help="Rank passive recon output and emit the next approval queue",
    )
    iterate.add_argument("--run-json", type=Path, required=True, help="live-recon JSON output to rank")
    iterate.add_argument(
        "--httpx-dir",
        type=Path,
        action="append",
        default=[],
        help="Optional directory of prior httpx live-recon JSON outputs to exclude failed hosts",
    )
    iterate.add_argument("--limit", type=int, default=10, help="Maximum approval candidates to emit")
    iterate.add_argument("--output-dir", type=Path, help="Directory for ranked-targets and approval queue files")

    depth = subparsers.add_parser(
        "recon-depth",
        help="Run a scoped multi-phase recon pipeline",
    )
    depth.add_argument("--domain", required=True, help="Root scoped domain, e.g. google.com")
    depth.add_argument("--output-dir", type=Path, required=True)
    depth.add_argument(
        "--profile",
        choices=("passive", "balanced", "deep", "owned-auth"),
        default="balanced",
    )
    depth.add_argument("--max-hosts", type=int, default=25)
    depth.add_argument("--max-urls", type=int, default=25)
    depth.add_argument("--rate-limit-per-minute", type=int, default=5)
    depth.add_argument("--katana-depth", type=int, default=1)
    depth.add_argument("--katana-js-crawl", action="store_true")
    depth.add_argument("--katana-known-files")
    depth.add_argument("--katana-crawl-duration-seconds", type=int, default=30)
    depth.add_argument(
        "--template",
        action="append",
        default=[],
        help="explicit relative nuclei template path; repeat for multiple templates",
    )
    depth.add_argument("--tag", action="append", default=[], help="nuclei tag filter")
    depth.add_argument("--severity", action="append", default=[], help="nuclei severity filter")
    depth.add_argument("--nuclei-rate-limit-per-second", type=int, default=1)
    depth.add_argument("--max-validation-actions", type=int, default=20)
    depth.add_argument("--max-live-requests", type=int, default=50)
    depth.add_argument("--operator-policy", type=Path, default=None)
    depth.add_argument("--operator-id", default=os.getenv("VRP_HUNT_OPERATOR_ID"))
    depth.add_argument(
        "--accept-legal-liability",
        action="store_true",
        help="Acknowledge that the configured operator is legally liable for this live run",
    )

    workflow = subparsers.add_parser(
        "recon-workflow",
        help="Run a scoped recon workflow YAML file",
    )
    workflow.add_argument("--workflow", type=Path, required=True)
    workflow.add_argument("--max-live-requests", type=int, default=50)
    workflow.add_argument("--operator-policy", type=Path, default=None)
    workflow.add_argument("--operator-id", default=os.getenv("VRP_HUNT_OPERATOR_ID"))
    workflow.add_argument(
        "--accept-legal-liability",
        action="store_true",
        help="Acknowledge that the configured operator is legally liable for this live run",
    )

    program_list = subparsers.add_parser(
        "program-list",
        help="List configured bug bounty program registry entries",
    )
    program_list.add_argument("--registry", type=Path, default=None)

    program_match = subparsers.add_parser(
        "program-match",
        help="Match one target against the bug bounty program registry",
    )
    program_match.add_argument("--target", required=True)
    program_match.add_argument("--kind", choices=("host", "url", "mobile_app"), default=None)
    program_match.add_argument("--publisher", help="Mobile app publisher for mobile_app targets")
    program_match.add_argument("--registry", type=Path, default=None)

    program_diff = subparsers.add_parser(
        "program-diff",
        help="Compare two bug bounty program registries for scope changes",
    )
    program_diff.add_argument("--old-registry", type=Path, required=True)
    program_diff.add_argument("--new-registry", type=Path, required=True)
    program_diff.add_argument(
        "--fresh-only",
        action="store_true",
        help="Print only fresh reward-eligible scope targets",
    )

    program_ingest = subparsers.add_parser(
        "program-ingest",
        help="Convert local HackerOne, Bugcrowd, Intigriti, or public JSON scope exports",
    )
    program_ingest.add_argument("--input", type=Path, required=True)
    program_ingest.add_argument(
        "--source",
        choices=("auto", "hackerone", "bugcrowd", "intigriti", "public_json"),
        default="auto",
    )
    program_ingest.add_argument("--program-id")
    program_ingest.add_argument("--name")
    program_ingest.add_argument("--platform")
    program_ingest.add_argument("--policy-url")
    program_ingest.add_argument("--captured-date")
    program_ingest.add_argument("--version")
    program_ingest.add_argument("--output", type=Path)

    passive_sources = subparsers.add_parser(
        "passive-sources",
        help="Report passive recon source readiness without printing secrets",
    )
    passive_sources.add_argument("--catalog", type=Path, default=None)
    passive_sources.add_argument(
        "--include-disabled",
        action="store_true",
        help="Include disabled sources in the health report",
    )

    passive_sources_env = subparsers.add_parser(
        "passive-sources-env-template",
        help="Print or write a blank env template for passive recon sources",
    )
    passive_sources_env.add_argument("--catalog", type=Path, default=None)
    passive_sources_env.add_argument("--output", type=Path)

    asset_score = subparsers.add_parser(
        "asset-score",
        help="Score recon assets by confidence, freshness, and priority",
    )
    _add_agent_inputs(asset_score)
    asset_score.add_argument("--output", type=Path)

    wildcard_dns = subparsers.add_parser(
        "wildcard-dns-filter",
        help="Eliminate wildcard DNS noise using saved nonexistent-host probe observations",
    )
    wildcard_dns.add_argument("--asset-file", type=Path, required=True)
    wildcard_dns.add_argument(
        "--probe",
        action="append",
        default=[],
        metavar="HOST=ADDR[,ADDR]",
        help="Pre-resolved nonexistent probe host; repeat for multiple probes",
    )
    wildcard_dns.add_argument(
        "--probe-file",
        type=Path,
        action="append",
        default=[],
        help="JSONL Asset file with host assets containing address metadata",
    )
    wildcard_dns.add_argument("--min-probes", type=int, default=2)
    wildcard_dns.add_argument("--output", type=Path)
    wildcard_dns.add_argument("--assets-output", type=Path, help="Optional filtered JSONL asset output")

    dns_plan = subparsers.add_parser(
        "dns-record-plan",
        help="Build offline dig commands for DNS record collection",
    )
    dns_plan.add_argument("--domain", required=True)
    dns_plan.add_argument("--output", type=Path)

    dns_import = subparsers.add_parser(
        "dns-record-import",
        help="Parse saved dig +short DNS record output",
    )
    dns_import.add_argument("--domain", required=True)
    dns_import.add_argument(
        "--record",
        action="append",
        default=[],
        metavar="NAME:TYPE=PATH",
        help="Saved dig output; TYPE is CNAME, MX, TXT, NS, or CAA",
    )
    dns_import.add_argument("--output", type=Path)

    cdn_waf = subparsers.add_parser(
        "cdn-waf-fingerprint",
        help="Fingerprint CDN/WAF providers from saved HTTP and DNS metadata",
    )
    cdn_waf.add_argument("--asset-file", type=Path, action="append", default=[])
    cdn_waf.add_argument("--dns-records", type=Path, action="append", default=[])
    cdn_waf.add_argument("--output", type=Path)
    cdn_waf.add_argument("--assets-output", type=Path, help="Optional technology JSONL output")

    asn_import = subparsers.add_parser(
        "asn-netblock-import",
        help="Normalize saved ASN/netblock ownership records",
    )
    asn_import.add_argument(
        "--record",
        action="append",
        default=[],
        metavar="ASNNN:ORG=CIDR",
        help="Owned netblock record; repeat for multiple prefixes",
    )
    asn_import.add_argument("--input", type=Path, action="append", default=[])
    asn_import.add_argument("--output", type=Path)
    asn_import.add_argument("--assets-output", type=Path, help="Optional note JSONL output")

    reverse_ct = subparsers.add_parser(
        "reverse-ct-import",
        help="Import saved reverse-IP and certificate-transparency host expansion outputs",
    )
    reverse_ct.add_argument(
        "--reverse-ip",
        type=Path,
        action="append",
        default=[],
        help="Saved reverse-IP JSON, JSONL, or text output",
    )
    reverse_ct.add_argument(
        "--ct",
        type=Path,
        action="append",
        default=[],
        help="Saved certificate-transparency JSON, JSONL, or text output",
    )
    reverse_ct.add_argument(
        "--scope-domain",
        action="append",
        default=[],
        help="Allowed domain or host suffix; repeat for multiple scope roots",
    )
    reverse_ct.add_argument("--output", type=Path)
    reverse_ct.add_argument("--assets-output", type=Path, help="Optional host JSONL output")

    permute = subparsers.add_parser(
        "subdomain-permute",
        help="Generate strictly capped offline subdomain permutation candidates",
    )
    permute.add_argument("--seed", action="append", default=[], help="Seed hostname")
    permute.add_argument("--seed-file", type=Path, action="append", default=[], help="Host Asset JSONL")
    permute.add_argument("--word", action="append", default=[], help="Permutation word")
    permute.add_argument("--word-file", type=Path, action="append", default=[])
    permute.add_argument(
        "--scope-domain",
        action="append",
        default=[],
        help="Allowed domain or host suffix; repeat for multiple scope roots",
    )
    permute.add_argument("--max-candidates", type=int, default=100)
    permute.add_argument("--max-per-seed", type=int, default=20)
    permute.add_argument("--output", type=Path)
    permute.add_argument("--assets-output", type=Path, help="Optional candidate host JSONL output")

    recursive_passive = subparsers.add_parser(
        "recursive-passive-plan",
        help="Plan capped recursive passive subdomain discovery from saved host assets",
    )
    recursive_passive.add_argument("--asset-file", type=Path, action="append", default=[])
    recursive_passive.add_argument("--host", action="append", default=[])
    recursive_passive.add_argument(
        "--seed-domain",
        action="append",
        default=[],
        help="Root domain already approved for passive discovery",
    )
    recursive_passive.add_argument("--max-depth", type=int, default=2)
    recursive_passive.add_argument("--max-queries", type=int, default=25)
    recursive_passive.add_argument("--min-hosts-per-zone", type=int, default=2)
    recursive_passive.add_argument("--output", type=Path)
    recursive_passive.add_argument("--assets-output", type=Path, help="Optional note JSONL output")

    historical = subparsers.add_parser(
        "historical-url-import",
        help="Import saved Wayback, urlscan, and Common Crawl URL exports",
    )
    historical.add_argument("--wayback", type=Path, action="append", default=[])
    historical.add_argument("--urlscan", type=Path, action="append", default=[])
    historical.add_argument("--common-crawl", type=Path, action="append", default=[])
    historical.add_argument(
        "--scope-domain",
        action="append",
        default=[],
        help="Allowed domain or host suffix; repeat for multiple scope roots",
    )
    historical.add_argument("--output", type=Path)
    historical.add_argument("--assets-output", type=Path, help="Optional URL/endpoint JSONL output")

    endpoint_mine = subparsers.add_parser(
        "endpoint-mine",
        help="Mine saved HTML/JS/API text for scoped JavaScript and endpoint assets",
    )
    endpoint_mine.add_argument(
        "--document",
        action="append",
        default=[],
        metavar="URL=PATH",
        help="Saved document to mine; repeat for multiple documents",
    )
    endpoint_mine.add_argument(
        "--scope-domain",
        action="append",
        default=[],
        help="Allowed registrable domain or host; repeat for multiple scope roots",
    )
    endpoint_mine.add_argument(
        "--include-third-party",
        action="store_true",
        help="Include absolute third-party URLs from saved content",
    )
    endpoint_mine.add_argument(
        "--no-secret-notes",
        action="store_true",
        help="Disable redacted potential-secret pattern notes",
    )
    endpoint_mine.add_argument("--output", type=Path)
    endpoint_mine.add_argument("--assets-output", type=Path, help="Optional JSONL asset output path")

    owned_crawl = subparsers.add_parser(
        "owned-crawl-plan",
        help="Build safe validator actions from saved owned-account page snapshots",
    )
    owned_crawl.add_argument(
        "--page",
        action="append",
        default=[],
        metavar="ACCOUNT=URL=PATH",
        help="Saved authenticated page snapshot; repeat for multiple pages",
    )
    owned_crawl.add_argument(
        "--scope-domain",
        action="append",
        default=[],
        help="Allowed registrable domain or host; repeat for multiple scope roots",
    )
    owned_crawl.add_argument("--max-links-per-page", type=int, default=100)
    owned_crawl.add_argument("--max-forms-per-page", type=int, default=50)
    owned_crawl.add_argument("--output", type=Path)
    owned_crawl.add_argument("--assets-output", type=Path, help="Optional JSONL asset output path")
    owned_crawl.add_argument("--plan-output", type=Path, help="Optional AgentPlan JSON output path")

    browser_check = subparsers.add_parser(
        "owned-browser-check",
        help="Check one explicit owned-object URL in an authenticated test profile",
    )
    browser_check.add_argument("--account-id", required=True, help="Owned account alias, e.g. owned-b")
    browser_check.add_argument(
        "--profile-dir",
        type=Path,
        help="Persistent browser profile directory for the owned account",
    )
    browser_check.add_argument(
        "--cdp-url",
        help="Attach to an already-open local Chrome instance with remote debugging enabled",
    )
    browser_check.add_argument("--url", required=True, help="Exact owned Drive/Docs/Sites object URL")
    browser_check.add_argument(
        "--confirm-owned-object",
        action="store_true",
        help="Confirm the URL points only to a researcher-owned test object",
    )
    browser_check.add_argument("--headless", action="store_true", help="Run Chrome headless")
    browser_check.add_argument("--timeout-ms", type=int, default=15_000)
    browser_check.add_argument("--output-path", type=Path, help="Optional JSON output path")

    scenario = subparsers.add_parser(
        "owned-browser-scenario",
        help="Run a bounded owned-object browser access scenario",
    )
    scenario.add_argument("--scenario", type=Path, required=True, help="YAML or JSON scenario file")
    scenario.add_argument(
        "--expand-derived",
        action="store_true",
        help="Check derived view/edit/preview URLs for each exact owned-object URL",
    )
    scenario.add_argument("--max-steps", type=int, default=25)
    scenario.add_argument(
        "--yolo",
        action="store_true",
        help="Continue through access-state mismatches without disabling owned-object checks",
    )
    scenario.add_argument("--output-dir", type=Path, help="Optional directory for scenario-result.json")

    scenario_generate = subparsers.add_parser(
        "scenario-generate",
        help="Generate owned-browser scenarios from an owned-object catalog",
    )
    scenario_generate.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and expected access states",
    )
    scenario_generate.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for generated scenario YAML files and scenario-index.json",
    )

    scenario_artifacts = subparsers.add_parser(
        "scenario-artifacts",
        help="Convert owned-browser scenario mismatches into draft finding artifacts",
    )
    scenario_artifacts.add_argument("--scenario", type=Path, required=True)
    scenario_artifacts.add_argument("--scenario-result", type=Path, required=True)
    scenario_artifacts.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for artifact-bundle.json, findings, reports, and Markdown drafts",
    )
    _add_artifact_inputs(scenario_artifacts)

    derived_http = subparsers.add_parser(
        "derived-http-check",
        help="Run metadata-only checks for derived owned-object HTTP resources",
    )
    derived_http.add_argument("--account-id", required=True, help="Owned test-account alias")
    derived_http.add_argument("--url", required=True, help="Exact owned Drive/Docs object URL")
    derived_http.add_argument(
        "--cookie-env",
        required=True,
        help="Env var containing the Cookie header value; value is never written to artifacts",
    )
    derived_http.add_argument(
        "--expected-state",
        choices=("access_denied", "access_granted", "login_required", "unknown"),
        required=True,
    )
    derived_http.add_argument("--method", choices=("HEAD", "GET"), default="HEAD")
    derived_http.add_argument("--max-targets", type=int, default=25)
    derived_http.add_argument("--max-redirects", type=int, default=2)
    derived_http.add_argument("--timeout-seconds", type=float, default=10.0)
    derived_http.add_argument(
        "--confirm-owned-object",
        action="store_true",
        help="Confirm the URL points only to a researcher-owned non-sensitive test object",
    )
    derived_http.add_argument("--output-dir", type=Path, help="Optional directory for derived-http-result.json")

    derived_artifacts = subparsers.add_parser(
        "derived-http-artifacts",
        help="Convert derived HTTP metadata mismatches into draft finding artifacts",
    )
    derived_artifacts.add_argument("--derived-http-result", type=Path, required=True)
    derived_artifacts.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory for artifact-bundle.json, findings, reports, and Markdown drafts",
    )
    _add_artifact_inputs(derived_artifacts)

    pipeline = subparsers.add_parser(
        "owned-object-pipeline",
        help="Run the owned-object scenario, derived HTTP, and artifact pipeline",
    )
    pipeline.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and expected access states",
    )
    pipeline.add_argument("--output-dir", type=Path, required=True)
    pipeline.add_argument(
        "--yolo",
        action="store_true",
        help="Continue through scenario mismatches without disabling safety checks",
    )
    pipeline.add_argument("--max-steps", type=int, default=50)
    pipeline.add_argument(
        "--no-expand-derived",
        action="store_true",
        help="Do not expand browser scenarios to view/edit/preview variants",
    )
    pipeline.add_argument(
        "--skip-derived-http",
        action="store_true",
        help="Skip metadata-only derived HTTP checks",
    )
    pipeline.add_argument("--derived-method", choices=("HEAD", "GET"), default="HEAD")
    pipeline.add_argument("--derived-max-targets", type=int, default=25)
    pipeline.add_argument("--derived-max-redirects", type=int, default=2)
    pipeline.add_argument("--derived-timeout-seconds", type=float, default=10.0)
    pipeline.add_argument(
        "--derive-cookies-from-cdp",
        action="store_true",
        help=(
            "For derived HTTP checks, read cookies in memory from each account's local CDP "
            "browser when cookie_env is missing or unset"
        ),
    )
    _add_artifact_inputs(pipeline)

    matrix = subparsers.add_parser(
        "owned-permission-matrix",
        help="Run owned-object checks across declared permission phases",
    )
    matrix.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and test accounts",
    )
    matrix.add_argument(
        "--matrix",
        type=Path,
        required=True,
        help="YAML or JSON permission matrix with phase expected states",
    )
    matrix.add_argument("--output-dir", type=Path, required=True)
    matrix.add_argument(
        "--yolo",
        action="store_true",
        help="Continue through scenario mismatches without disabling safety checks",
    )
    matrix.add_argument("--max-steps", type=int, default=50)
    matrix.add_argument(
        "--no-expand-derived",
        action="store_true",
        help="Do not expand browser scenarios to view/edit/preview variants",
    )
    matrix.add_argument(
        "--skip-derived-http",
        action="store_true",
        help="Skip metadata-only derived HTTP checks",
    )
    matrix.add_argument("--derived-method", choices=("HEAD", "GET"), default="HEAD")
    matrix.add_argument("--derived-max-targets", type=int, default=25)
    matrix.add_argument("--derived-max-redirects", type=int, default=2)
    matrix.add_argument("--derived-timeout-seconds", type=float, default=10.0)
    matrix.add_argument(
        "--phase",
        action="append",
        default=[],
        help="Run one phase id from the matrix; repeat to run multiple phases",
    )
    matrix.add_argument(
        "--derive-cookies-from-cdp",
        action="store_true",
        help=(
            "For derived HTTP checks, read cookies in memory from each account's local CDP "
            "browser when cookie_env is missing or unset"
        ),
    )
    _add_artifact_inputs(matrix)

    matrix_template = subparsers.add_parser(
        "owned-permission-matrix-template",
        help="Generate an owned-object permission transition matrix template",
    )
    matrix_template.add_argument(
        "--object-catalog",
        type=Path,
        required=True,
        help="YAML or JSON catalog of owned objects and test accounts",
    )
    matrix_template.add_argument(
        "--output-path",
        type=Path,
        required=True,
        help="YAML path for the generated permission matrix template",
    )
    matrix_template.add_argument("--matrix-id", help="Optional matrix id; defaults from catalog id")
    matrix_template.add_argument(
        "--grantee-account",
        action="append",
        default=[],
        help="Owned account to grant in direct-share phases; defaults to non-owner accounts",
    )
    matrix_template.add_argument(
        "--no-trash-phase",
        action="store_true",
        help="Do not include the trashed-or-archived phase",
    )

    mobile = subparsers.add_parser(
        "mobile-hypotheses",
        help="Rank passive hypotheses from JADX/decompiled mobile artifacts",
    )
    mobile.add_argument("--app-id", required=True, help="Mobile package id, e.g. com.google.android.gm")
    mobile.add_argument(
        "--artifact-path",
        type=Path,
        required=True,
        help="JADX output directory or local decompiled text artifact",
    )
    mobile.add_argument("--limit", type=int, default=10, help="Maximum hypotheses to emit")
    mobile.add_argument("--output-dir", type=Path, help="Optional directory for mobile-static-report.json")

    mobile_import = subparsers.add_parser(
        "mobile-import",
        help="Import APK, JADX, and MobSF artifacts into mobile assets and hypotheses",
    )
    mobile_import.add_argument("--app-id", required=True, help="Mobile package id, e.g. com.google.android.gm")
    mobile_import.add_argument("--apk-path", type=Path, help="Local APK artifact to fingerprint")
    mobile_import.add_argument(
        "--jadx-output",
        type=Path,
        help="JADX output directory or local decompiled text artifact",
    )
    mobile_import.add_argument("--mobsf-report", type=Path, help="MobSF static-analysis JSON report")
    mobile_import.add_argument("--limit", type=int, default=10, help="Maximum hypotheses to emit")
    mobile_import.add_argument("--output-dir", type=Path, help="Optional directory for import files")
    mobile_import.add_argument("--assets-output", type=Path, help="Optional JSONL asset output path")

    submission = subparsers.add_parser(
        "submission-checklist",
        help="Validate a saved ReportDraft against report quality and program rules",
    )
    submission.add_argument("--report", type=Path, required=True, help="ReportDraft JSON path")
    submission.add_argument("--registry", type=Path, default=None)
    submission.add_argument("--output", type=Path, help="Optional SubmissionAssistance JSON path")
    submission.add_argument(
        "--markdown-output",
        type=Path,
        help="Optional Markdown report output path",
    )

    dashboard = subparsers.add_parser(
        "dashboard",
        help="Render a local static dashboard from assets, approvals, and finding artifacts",
    )
    dashboard.add_argument("--title", default="VRP Hunt Dashboard")
    dashboard.add_argument("--asset-file", type=Path, action="append", default=[])
    dashboard.add_argument("--approval-queue", type=Path, action="append", default=[])
    dashboard.add_argument("--artifact-bundle", type=Path, action="append", default=[])
    dashboard.add_argument("--finding", type=Path, action="append", default=[])
    dashboard.add_argument("--report", type=Path, action="append", default=[])
    dashboard.add_argument("--summary-json", type=Path, action="append", default=[])
    dashboard.add_argument("--output", type=Path, required=True)

    live = subparsers.add_parser("live-recon", help="Run one approved live recon tool")
    live.add_argument("--tool", choices=("subfinder", "httpx", "katana", "nuclei", "jadx"), required=True)
    live.add_argument("--target", required=True, help="Domain/host/URL, or mobile app id for jadx")
    live.add_argument("--artifact-path", help="APK path for jadx static analysis")
    live.add_argument("--output-dir", help="jadx output directory")
    live.add_argument("--publisher", help="Mobile app publisher for guardrail scope checks")
    live.add_argument("--rate-limit-per-minute", type=int, default=5)
    live.add_argument("--depth", type=int, default=1, help="katana crawl depth")
    live.add_argument("--field-scope", default="fqdn", help="katana scope field")
    live.add_argument("--js-crawl", action="store_true", help="enable katana JavaScript crawling")
    live.add_argument("--known-files", help="katana known-files mode, e.g. robotstxt,sitemapxml")
    live.add_argument("--crawl-duration-seconds", type=int, default=30)
    live.add_argument(
        "--template",
        action="append",
        default=[],
        help="explicit relative nuclei template path; repeat for multiple templates",
    )
    live.add_argument(
        "--tag",
        action="append",
        default=[],
        help="nuclei tag filter; aggressive tags are rejected by policy",
    )
    live.add_argument(
        "--severity",
        action="append",
        default=[],
        help="nuclei severity filter, e.g. info, low, medium, high, critical",
    )
    live.add_argument("--rate-limit-per-second", type=int, default=1, help="nuclei request rate limit")
    live.add_argument("--max-live-requests", type=int, default=1)
    live.add_argument("--operator-policy", type=Path, default=None)
    live.add_argument("--operator-id", default=os.getenv("VRP_HUNT_OPERATOR_ID"))
    live.add_argument(
        "--accept-legal-liability",
        action="store_true",
        help="Acknowledge that the configured operator is legally liable for this live run",
    )

    return parser


def _add_agent_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--asset",
        action="append",
        default=[],
        help="Asset as kind:value, for example url:https://accounts.google.com/profile",
    )
    parser.add_argument("--asset-file", type=Path, help="JSONL file containing Asset records")


def _add_model_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--model-provider",
        choices=("heuristic", "openai"),
        default=_default_model_provider(),
        help="Hypothesis provider for ModelBrain; heuristic stays local",
    )
    parser.add_argument("--model", default=os.getenv("VRP_HUNT_OPENAI_MODEL"))
    parser.add_argument(
        "--model-base-url",
        default=os.getenv("VRP_HUNT_OPENAI_BASE_URL", "https://api.openai.com/v1"),
    )
    parser.add_argument("--model-timeout-seconds", type=float, default=30.0)
    parser.add_argument("--model-max-assets", type=int, default=50)
    parser.add_argument(
        "--allow-remote-model",
        action="store_true",
        help="Allow redacted recon asset summaries to be sent to the configured model provider",
    )


def _add_approval_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--approve-risky",
        action="store_true",
        help="Legacy shortcut: approve all approval-required actions for this run",
    )
    parser.add_argument(
        "--approval-mode",
        choices=("block", "explicit", "prompt", "approve-all"),
        default="block",
        help="How the CLI approval gate handles risky actions",
    )
    parser.add_argument(
        "--approve-action",
        action="append",
        default=[],
        help="Approve one risky action by 1-based index, action id, or 'all'",
    )
    parser.add_argument(
        "--yolo",
        action="store_true",
        help="Approve all approval-required actions without disabling guardrails or budgets",
    )


def _add_artifact_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--researcher-account",
        action="append",
        default=[],
        help="Owned test-account alias for generated report artifacts; never pass secrets",
    )
    parser.add_argument("--product", default="Google")
    parser.add_argument("--component", default="VRP target")
    parser.add_argument(
        "--platform",
        choices=("web", "api", "android", "ios", "browser_extension", "other"),
        default="web",
    )
    parser.add_argument("--client", default="Chrome stable with Burp proxy")
    parser.add_argument("--operating-system", default="research workstation")
    parser.add_argument("--observed-from", default="owned-account validation environment")


def _agent_plan(args: argparse.Namespace) -> int:
    try:
        plan = _build_plan(args)
    except ModelProviderError as exc:
        print(f"model provider error: {exc}", file=sys.stderr)
        return 2
    print(plan.model_dump_json(indent=2))
    return 0


def _agent_run(args: argparse.Namespace) -> int:
    policy = AutonomyPolicy(dry_run=not args.execute_safe)
    budget = ActionBudget(max_actions=args.max_actions, max_live_requests=args.max_live_requests)
    runner = _safe_runner_for_mode(args.mode) if args.execute_safe else None
    try:
        plan = _build_plan(args)
    except ModelProviderError as exc:
        print(f"model provider error: {exc}", file=sys.stderr)
        return 2
    try:
        plan = _apply_cli_approval_gate(plan, policy, args)
    except ApprovalGateError as exc:
        print(f"approval gate error: {exc}", file=sys.stderr)
        return 2
    result = AutonomousAgent(policy=policy, budget=budget, runner=runner).run_plan(plan)
    print(result.model_dump_json(indent=2))
    return 0 if not result.stopped else 1


def _agent_auto(args: argparse.Namespace) -> int:
    policy = AutonomyPolicy(dry_run=False)
    budget = ActionBudget(max_actions=args.max_actions, max_live_requests=args.max_live_requests)
    try:
        plan = _build_plan(args)
    except ModelProviderError as exc:
        print(f"model provider error: {exc}", file=sys.stderr)
        return 2
    try:
        gated_plan = _apply_cli_approval_gate(plan, policy, args)
    except ApprovalGateError as exc:
        print(f"approval gate error: {exc}", file=sys.stderr)
        return 2

    result = AutonomousAgent(
        policy=policy,
        budget=budget,
        runner=_safe_runner_for_mode(args.mode),
    ).run_plan(gated_plan)
    bundle = artifact_bundle_from_agent_run(
        gated_plan,
        result,
        researcher_accounts=_artifact_researcher_accounts(args),
        product=args.product,
        component=args.component,
        platform=cast(Platform, args.platform),
        client=args.client,
        operating_system=args.operating_system,
        observed_from=args.observed_from,
    )
    output = {
        "plan": gated_plan.model_dump(mode="json"),
        "run": result.model_dump(mode="json"),
        "artifacts": bundle.model_dump(mode="json"),
    }
    if args.artifact_output_dir is not None:
        _write_auto_artifacts(args.artifact_output_dir, output)
    print(json.dumps(output, indent=2))
    return 0 if not result.stopped else 1


def _recon_iterate(args: argparse.Namespace) -> int:
    if args.limit < 1:
        print("recon iterate error: --limit must be at least 1", file=sys.stderr)
        return 2
    try:
        summary = build_recon_iteration_summary(
            args.run_json,
            httpx_dirs=args.httpx_dir,
            limit=args.limit,
        )
        if args.output_dir is not None:
            write_recon_iteration_outputs(summary, args.output_dir)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"recon iterate error: {exc}", file=sys.stderr)
        return 2

    print(summary.model_dump_json(indent=2))
    return 0


def _recon_depth(args: argparse.Namespace) -> int:
    try:
        operator_policy = load_operator_policy(args.operator_policy) if args.operator_policy else load_operator_policy()
    except LiveReconAuthorizationError as exc:
        print(f"operator policy error: {exc}", file=sys.stderr)
        return 2

    live_runner = LiveReconRunner(
        ApprovedSubprocessRunner(
            operator_policy=operator_policy,
            operator_id=args.operator_id,
            legal_liability_accepted=args.accept_legal_liability,
        ),
        operator_policy=operator_policy,
        operator_id=args.operator_id,
        legal_liability_accepted=args.accept_legal_liability,
        default_httpx_rate_limit_per_minute=args.rate_limit_per_minute,
    )

    def execute(action: AgentAction) -> AgentRunResult:
        return AutonomousAgent(
            policy=AutonomyPolicy(dry_run=False),
            budget=ActionBudget(
                max_actions=1,
                max_live_requests=max(args.max_live_requests, action.request_budget),
                max_hosts=args.max_hosts,
            ),
            runner=live_runner,
        ).run_plan(AgentPlan(actions=[action]))

    try:
        result = run_recon_depth(
            domain=args.domain,
            output_dir=args.output_dir,
            profile=cast(ReconDepthProfile, args.profile),
            action_executor=execute,
            max_hosts=args.max_hosts,
            max_urls=args.max_urls,
            rate_limit_per_minute=args.rate_limit_per_minute,
            katana_depth=args.katana_depth,
            katana_js_crawl=args.katana_js_crawl,
            katana_known_files=args.katana_known_files,
            katana_crawl_duration_seconds=args.katana_crawl_duration_seconds,
            nuclei_templates=args.template,
            nuclei_tags=args.tag,
            nuclei_severity=args.severity,
            nuclei_rate_limit_per_second=args.nuclei_rate_limit_per_second,
            max_validation_actions=args.max_validation_actions,
        )
    except ReconDepthError as exc:
        print(f"recon depth error: {exc}", file=sys.stderr)
        return 2

    print(result.model_dump_json(indent=2))
    if result.errors or any(not phase.success for phase in result.phase_runs):
        return 1
    return 0


def _recon_workflow(args: argparse.Namespace) -> int:
    try:
        workflow = load_recon_workflow(args.workflow)
        operator_policy = load_operator_policy(args.operator_policy) if args.operator_policy else load_operator_policy()
    except ReconWorkflowError as exc:
        print(f"recon workflow error: {exc}", file=sys.stderr)
        return 2
    except LiveReconAuthorizationError as exc:
        print(f"operator policy error: {exc}", file=sys.stderr)
        return 2

    live_runner = LiveReconRunner(
        ApprovedSubprocessRunner(
            operator_policy=operator_policy,
            operator_id=args.operator_id,
            legal_liability_accepted=args.accept_legal_liability,
        ),
        operator_policy=operator_policy,
        operator_id=args.operator_id,
        legal_liability_accepted=args.accept_legal_liability,
    )

    def execute(action: AgentAction) -> AgentRunResult:
        return AutonomousAgent(
            policy=AutonomyPolicy(dry_run=False),
            budget=ActionBudget(
                max_actions=1,
                max_live_requests=max(args.max_live_requests, action.request_budget),
                max_hosts=1,
            ),
            runner=live_runner,
        ).run_plan(AgentPlan(actions=[action]))

    result = run_recon_workflow(workflow, action_executor=execute)
    print(result.model_dump_json(indent=2))
    if result.errors or any(run.errors for run in result.step_runs):
        return 1
    return 0


def _program_list(args: argparse.Namespace) -> int:
    try:
        registry = load_program_registry(args.registry) if args.registry else load_program_registry()
    except ProgramRegistryLoadError as exc:
        print(f"program registry error: {exc}", file=sys.stderr)
        return 2
    print(registry.model_dump_json(indent=2))
    return 0


def _program_match(args: argparse.Namespace) -> int:
    try:
        registry = load_program_registry(args.registry) if args.registry else load_program_registry()
    except ProgramRegistryLoadError as exc:
        print(f"program registry error: {exc}", file=sys.stderr)
        return 2
    decision = match_program_scope(
        registry,
        target=args.target,
        target_kind=cast(TargetKind | None, args.kind),
        publisher=args.publisher,
    )
    print(decision.model_dump_json(indent=2))
    return 0 if decision.decision == "IN_SCOPE" else 1


def _program_diff(args: argparse.Namespace) -> int:
    try:
        old_registry = load_program_registry(args.old_registry)
        new_registry = load_program_registry(args.new_registry)
    except ProgramRegistryLoadError as exc:
        print(f"program registry error: {exc}", file=sys.stderr)
        return 2
    diff = diff_program_registries(old_registry, new_registry)
    if args.fresh_only:
        print(
            json.dumps(
                {
                    "old_version": diff.old_version,
                    "new_version": diff.new_version,
                    "fresh_target_count": len(diff.fresh_targets),
                    "fresh_targets": [
                        change.model_dump(mode="json") for change in diff.fresh_targets
                    ],
                },
                indent=2,
            )
        )
        return 0
    print(diff.model_dump_json(indent=2))
    return 0


def _program_ingest(args: argparse.Namespace) -> int:
    try:
        captured_date = date.fromisoformat(args.captured_date) if args.captured_date else date.today()
    except ValueError:
        print("program ingest error: --captured-date must be YYYY-MM-DD", file=sys.stderr)
        return 2
    try:
        report = ingest_scope_export(
            args.input,
            options=ScopeIngestionOptions(
                source=cast(ScopeIngestionSource, args.source),
                program_id=args.program_id,
                name=args.name,
                platform=args.platform,
                policy_url=args.policy_url,
                captured_date=captured_date,
                version=args.version,
            ),
        )
    except ScopeIngestionError as exc:
        print(f"program ingest error: {exc}", file=sys.stderr)
        return 2
    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report.registry.model_dump_json(indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


def _passive_sources(args: argparse.Namespace) -> int:
    try:
        catalog = load_passive_source_catalog(args.catalog) if args.catalog else load_passive_source_catalog()
    except PassiveSourceCatalogError as exc:
        print(f"passive source catalog error: {exc}", file=sys.stderr)
        return 2
    report = evaluate_passive_source_health(
        catalog,
        include_disabled=args.include_disabled,
    )
    print(report.model_dump_json(indent=2))
    return 0


def _passive_sources_env_template(args: argparse.Namespace) -> int:
    try:
        catalog = load_passive_source_catalog(args.catalog) if args.catalog else load_passive_source_catalog()
    except PassiveSourceCatalogError as exc:
        print(f"passive source catalog error: {exc}", file=sys.stderr)
        return 2
    template = passive_source_env_template(catalog)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(template, encoding="utf-8")
    else:
        print(template, end="")
    return 0


def _asset_score(args: argparse.Namespace) -> int:
    assets = _load_assets(args.asset, args.asset_file)
    report = score_assets(assets)
    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


def _wildcard_dns_filter(args: argparse.Namespace) -> int:
    try:
        assets = _load_assets([], args.asset_file)
        probes = _load_wildcard_dns_probes(args.probe, args.probe_file)
        if not probes:
            raise ValueError("at least one --probe or --probe-file observation is required")
        report = filter_wildcard_dns_assets(
            assets,
            probes,
            min_probes=args.min_probes,
        )
    except (OSError, ValueError) as exc:
        print(f"wildcard dns filter error: {exc}", file=sys.stderr)
        return 2

    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, report.kept_assets)
    return 0


def _dns_record_plan(args: argparse.Namespace) -> int:
    try:
        plan = build_dns_record_plan(args.domain)
    except ValueError as exc:
        print(f"dns record plan error: {exc}", file=sys.stderr)
        return 2
    output = plan.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 0


def _dns_record_import(args: argparse.Namespace) -> int:
    try:
        collection = import_dns_record_files(args.domain, args.record)
    except ValueError as exc:
        print(f"dns record import error: {exc}", file=sys.stderr)
        return 2
    output = collection.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    return 1 if collection.warnings else 0


def _cdn_waf_fingerprint(args: argparse.Namespace) -> int:
    try:
        assets = _load_asset_jsonl_files(args.asset_file)
        dns_records = _load_dns_record_collections(args.dns_records)
        if not assets and not dns_records:
            raise ValueError("at least one --asset-file or --dns-records path is required")
        report = fingerprint_cdn_waf(assets, dns_records=dns_records)
    except (OSError, ValueError) as exc:
        print(f"cdn/waf fingerprint error: {exc}", file=sys.stderr)
        return 2

    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, cdn_waf_fingerprint_assets(report))
    return 0


def _asn_netblock_import(args: argparse.Namespace) -> int:
    try:
        records = [asn_netblock_record_from_spec(spec) for spec in args.record]
        warnings: list[str] = []
        for path in args.input:
            loaded, load_warnings = load_asn_netblock_records(path)
            records.extend(loaded)
            warnings.extend(load_warnings)
        if not records:
            raise ValueError("at least one --record or --input path is required")
        report = build_asn_netblock_report(records).model_copy(update={"warnings": warnings})
    except (OSError, ValueError) as exc:
        print(f"asn netblock import error: {exc}", file=sys.stderr)
        return 2

    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, asn_netblock_assets(report))
    return 1 if report.warnings else 0


def _reverse_ct_import(args: argparse.Namespace) -> int:
    try:
        if not args.reverse_ip and not args.ct:
            raise ValueError("at least one --reverse-ip or --ct path is required")
        report = build_reverse_ct_expansion_report(
            reverse_ip_files=args.reverse_ip,
            certificate_transparency_files=args.ct,
            scope_domains=args.scope_domain,
        )
    except (OSError, ValueError) as exc:
        print(f"reverse/ct import error: {exc}", file=sys.stderr)
        return 2

    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, passive_expansion_assets(report.records))
    return 1 if report.warnings else 0


def _subdomain_permute(args: argparse.Namespace) -> int:
    try:
        seeds = [*args.seed, *_host_values_from_asset_files(args.seed_file)]
        words = [*args.word]
        for path in args.word_file:
            words.extend(load_words(path))
        if not seeds:
            raise ValueError("at least one --seed or --seed-file host is required")
        config = SubdomainPermutationConfig(
            scope_domains=args.scope_domain,
            words=words,
            max_candidates=args.max_candidates,
            max_per_seed=args.max_per_seed,
        )
        report = generate_subdomain_permutations(seeds, config=config)
    except (OSError, ValueError) as exc:
        print(f"subdomain permutation error: {exc}", file=sys.stderr)
        return 2

    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, report.assets)
    return 1 if report.warnings else 0


def _recursive_passive_plan(args: argparse.Namespace) -> int:
    try:
        hosts = [*args.host, *_host_values_from_asset_files(args.asset_file)]
        if not hosts:
            raise ValueError("at least one --host or --asset-file host is required")
        config = RecursivePassiveConfig(
            seed_domains=args.seed_domain,
            max_depth=args.max_depth,
            max_queries=args.max_queries,
            min_hosts_per_zone=args.min_hosts_per_zone,
        )
        plan = build_recursive_passive_plan(hosts, config=config)
    except (OSError, ValueError) as exc:
        print(f"recursive passive plan error: {exc}", file=sys.stderr)
        return 2

    output = plan.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, recursive_passive_assets(plan))
    return 1 if plan.warnings else 0


def _historical_url_import(args: argparse.Namespace) -> int:
    try:
        if not args.wayback and not args.urlscan and not args.common_crawl:
            raise ValueError("at least one --wayback, --urlscan, or --common-crawl path is required")
        report = ingest_historical_url_files(
            wayback_files=args.wayback,
            urlscan_files=args.urlscan,
            common_crawl_files=args.common_crawl,
            scope_domains=args.scope_domain,
        )
    except (OSError, ValueError) as exc:
        print(f"historical url import error: {exc}", file=sys.stderr)
        return 2

    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, report.assets)
    return 1 if report.warnings else 0


def _endpoint_mine(args: argparse.Namespace) -> int:
    try:
        documents = [_load_web_content_document(spec) for spec in args.document]
        if not documents:
            raise ValueError("at least one --document URL=PATH is required")
        report = mine_javascript_and_api_endpoints(
            documents,
            config=EndpointMiningConfig(
                scope_domains=args.scope_domain,
                include_third_party=args.include_third_party,
                include_secret_notes=not args.no_secret_notes,
            ),
        )
    except (OSError, ValueError) as exc:
        print(f"endpoint mine error: {exc}", file=sys.stderr)
        return 2

    output = report.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, report.assets)
    return 0


def _owned_crawl_plan(args: argparse.Namespace) -> int:
    try:
        pages = [_load_owned_crawl_page(spec) for spec in args.page]
        if not pages:
            raise OwnedAccountCrawlError("at least one --page ACCOUNT=URL=PATH is required")
        result = build_owned_account_crawl_plan(
            pages,
            config=OwnedAccountCrawlConfig(
                scope_domains=args.scope_domain,
                max_links_per_page=args.max_links_per_page,
                max_forms_per_page=args.max_forms_per_page,
            ),
        )
    except (OSError, ValueError) as exc:
        print(f"owned crawl error: {exc}", file=sys.stderr)
        return 2

    output = result.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, result.assets)
    if args.plan_output is not None:
        args.plan_output.parent.mkdir(parents=True, exist_ok=True)
        args.plan_output.write_text(
            result.validation_plan.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
    return 0


def _owned_browser_check(args: argparse.Namespace) -> int:
    try:
        if args.cdp_url:
            result = run_owned_browser_check_cdp(
                account_id=args.account_id,
                cdp_url=args.cdp_url,
                url=args.url,
                confirm_owned_object=args.confirm_owned_object,
                timeout_ms=args.timeout_ms,
            )
        else:
            if args.profile_dir is None:
                raise BrowserCheckError("--profile-dir is required unless --cdp-url is used")
            result = run_owned_browser_check(
                account_id=args.account_id,
                profile_dir=args.profile_dir,
                url=args.url,
                confirm_owned_object=args.confirm_owned_object,
                headless=args.headless,
                timeout_ms=args.timeout_ms,
            )
    except BrowserCheckError as exc:
        print(f"owned browser check error: {exc}", file=sys.stderr)
        return 2
    output = result.model_dump_json(indent=2)
    if args.output_path is not None:
        args.output_path.parent.mkdir(parents=True, exist_ok=True)
        args.output_path.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


def _owned_browser_scenario(args: argparse.Namespace) -> int:
    if args.max_steps < 1:
        print("owned browser scenario error: --max-steps must be at least 1", file=sys.stderr)
        return 2
    try:
        scenario = load_owned_browser_scenario(args.scenario)
        if args.expand_derived:
            scenario = expand_owned_browser_scenario_derived_urls(
                scenario,
                max_steps=args.max_steps,
            )
        elif len(scenario.steps) > args.max_steps:
            raise OwnedBrowserScenarioError(f"scenario exceeds --max-steps={args.max_steps}")
        if args.yolo:
            scenario = scenario.model_copy(update={"stop_on_mismatch": False})
        result = run_owned_browser_scenario(scenario)
    except OwnedBrowserScenarioError as exc:
        print(f"owned browser scenario error: {exc}", file=sys.stderr)
        return 2

    output = result.model_dump_json(indent=2)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "scenario-result.json").write_text(output + "\n", encoding="utf-8")
    print(output)
    return 1 if result.mismatches or result.errors or result.stopped else 0


def _scenario_generate(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        result = write_generated_owned_browser_scenarios(catalog, args.output_dir)
    except OwnedBrowserScenarioError as exc:
        print(f"scenario generate error: {exc}", file=sys.stderr)
        return 2

    print(result.model_dump_json(indent=2))
    return 0


def _scenario_artifacts(args: argparse.Namespace) -> int:
    try:
        scenario = load_owned_browser_scenario(args.scenario)
        result = load_owned_browser_scenario_result(args.scenario_result)
        bundle = artifact_bundle_from_owned_browser_scenario(
            scenario,
            result,
            researcher_accounts=_artifact_researcher_accounts(args),
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
        )
    except OwnedBrowserScenarioError as exc:
        print(f"scenario artifacts error: {exc}", file=sys.stderr)
        return 2

    files = _write_scenario_artifacts(args.output_dir, bundle)
    output = {
        "artifacts": bundle.model_dump(mode="json"),
        "files": files,
    }
    print(json.dumps(output, indent=2))
    return 0


def _derived_http_check(args: argparse.Namespace) -> int:
    try:
        result = run_derived_http_check(
            account_id=args.account_id,
            owned_object_url=args.url,
            expected_state=cast(BrowserAccessState, args.expected_state),
            cookie_header=cookie_header_from_env(args.cookie_env),
            confirm_owned_object=args.confirm_owned_object,
            method=cast(DerivedHttpMethod, args.method),
            max_targets=args.max_targets,
            timeout_seconds=args.timeout_seconds,
            max_redirects=args.max_redirects,
        )
    except DerivedHttpCheckError as exc:
        print(f"derived http check error: {exc}", file=sys.stderr)
        return 2

    output = result.model_dump_json(indent=2)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "derived-http-result.json").write_text(output + "\n", encoding="utf-8")
    print(output)
    return 1 if result.high_signal_mismatches or result.errors else 0


def _derived_http_artifacts(args: argparse.Namespace) -> int:
    try:
        result = load_derived_http_check_result(args.derived_http_result)
        bundle = artifact_bundle_from_derived_http_check(
            result,
            researcher_accounts=_artifact_researcher_accounts(args),
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
        )
    except DerivedHttpCheckError as exc:
        print(f"derived http artifacts error: {exc}", file=sys.stderr)
        return 2

    files = _write_scenario_artifacts(args.output_dir, bundle)
    output = {
        "artifacts": bundle.model_dump(mode="json"),
        "files": files,
    }
    print(json.dumps(output, indent=2))
    return 0


def _owned_object_pipeline(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        result = run_owned_object_pipeline(
            catalog,
            args.output_dir,
            researcher_accounts=_artifact_researcher_accounts(args),
            yolo=args.yolo,
            expand_derived=not args.no_expand_derived,
            max_steps=args.max_steps,
            run_derived=not args.skip_derived_http,
            derived_method=cast(DerivedHttpMethod, args.derived_method),
            derived_max_targets=args.derived_max_targets,
            derived_max_redirects=args.derived_max_redirects,
            derived_timeout_seconds=args.derived_timeout_seconds,
            derive_cookies_from_cdp=args.derive_cookies_from_cdp,
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
        )
    except (OwnedBrowserScenarioError, OwnedObjectPipelineError, DerivedHttpCheckError) as exc:
        print(f"owned object pipeline error: {exc}", file=sys.stderr)
        return 2

    print(result.model_dump_json(indent=2))
    return 1 if result.errors or result.total_artifacts else 0


def _owned_permission_matrix(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        matrix = load_owned_permission_matrix(args.matrix)
        result = run_owned_permission_matrix(
            catalog,
            matrix,
            args.output_dir,
            researcher_accounts=_artifact_researcher_accounts(args),
            yolo=args.yolo,
            expand_derived=not args.no_expand_derived,
            max_steps=args.max_steps,
            run_derived=not args.skip_derived_http,
            derived_method=cast(DerivedHttpMethod, args.derived_method),
            derived_max_targets=args.derived_max_targets,
            derived_max_redirects=args.derived_max_redirects,
            derived_timeout_seconds=args.derived_timeout_seconds,
            derive_cookies_from_cdp=args.derive_cookies_from_cdp,
            product=args.product,
            component=args.component,
            platform=cast(Platform, args.platform),
            client=args.client,
            operating_system=args.operating_system,
            observed_from=args.observed_from,
            phase_ids=args.phase,
        )
    except (OwnedBrowserScenarioError, OwnedPermissionMatrixError) as exc:
        print(f"owned permission matrix error: {exc}", file=sys.stderr)
        return 2

    print(result.model_dump_json(indent=2))
    return 1 if result.errors or result.total_artifacts else 0


def _owned_permission_matrix_template(args: argparse.Namespace) -> int:
    try:
        catalog = load_owned_object_catalog(args.object_catalog)
        matrix = write_owned_permission_matrix_template(
            catalog,
            args.output_path,
            matrix_id=args.matrix_id,
            grantee_accounts=args.grantee_account or None,
            include_trash_phase=not args.no_trash_phase,
        )
    except (OwnedBrowserScenarioError, OwnedPermissionMatrixError) as exc:
        print(f"owned permission matrix template error: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "matrix_id": matrix.matrix_id,
                "phase_count": len(matrix.phases),
                "output_path": str(args.output_path),
            },
            indent=2,
        )
    )
    return 0


def _mobile_hypotheses(args: argparse.Namespace) -> int:
    if args.limit < 1:
        print("mobile hypotheses error: --limit must be at least 1", file=sys.stderr)
        return 2
    if not args.artifact_path.exists():
        print(f"mobile hypotheses error: artifact path does not exist: {args.artifact_path}", file=sys.stderr)
        return 2
    report = build_mobile_static_report(
        app_id=args.app_id,
        artifact_path=args.artifact_path,
        limit=args.limit,
    )
    output = report.model_dump_json(indent=2)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "mobile-static-report.json").write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


def _mobile_import(args: argparse.Namespace) -> int:
    try:
        report = import_mobile_artifacts(
            app_id=args.app_id,
            apk_path=args.apk_path,
            jadx_output_path=args.jadx_output,
            mobsf_report_path=args.mobsf_report,
            hypothesis_limit=args.limit,
        )
    except MobileArtifactImportError as exc:
        print(f"mobile import error: {exc}", file=sys.stderr)
        return 2
    output = report.model_dump_json(indent=2)
    if args.output_dir is not None:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "mobile-import-report.json").write_text(output + "\n", encoding="utf-8")
        _write_asset_jsonl(args.output_dir / "assets.jsonl", report.assets)
    if args.assets_output is not None:
        _write_asset_jsonl(args.assets_output, report.assets)
    print(output)
    return 0


def _submission_checklist(args: argparse.Namespace) -> int:
    try:
        report = ReportDraft.model_validate_json(args.report.read_text(encoding="utf-8"))
        registry = load_program_registry(args.registry) if args.registry else load_program_registry()
        assistance = build_submission_assistance(report, registry=registry)
    except (OSError, ValueError, ProgramRegistryLoadError) as exc:
        print(f"submission checklist error: {exc}", file=sys.stderr)
        return 2

    output = assistance.model_dump_json(indent=2)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    if args.markdown_output is not None:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(assistance.markdown, encoding="utf-8")
    print(output)
    return 0 if assistance.ready else 1


def _dashboard(args: argparse.Namespace) -> int:
    data = build_dashboard_data(
        title=args.title,
        asset_files=args.asset_file,
        approval_queues=args.approval_queue,
        artifact_bundles=args.artifact_bundle,
        findings=args.finding,
        reports=args.report,
        summary_json=args.summary_json,
    )
    write_dashboard(data, args.output)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "assets": len(data.assets),
                "approvals": len(data.approvals),
                "findings": len(data.findings),
                "evidence": len(data.evidence),
                "summaries": len(data.summaries),
                "warnings": len(data.warnings),
            },
            indent=2,
        )
    )
    return 0


def _live_recon(args: argparse.Namespace) -> int:
    try:
        operator_policy = load_operator_policy(args.operator_policy) if args.operator_policy else load_operator_policy()
    except LiveReconAuthorizationError as exc:
        print(f"operator policy error: {exc}", file=sys.stderr)
        return 2

    action = _live_recon_action(args)
    runner = LiveReconRunner(
        ApprovedSubprocessRunner(
            operator_policy=operator_policy,
            operator_id=args.operator_id,
            legal_liability_accepted=args.accept_legal_liability,
        ),
        operator_policy=operator_policy,
        operator_id=args.operator_id,
        legal_liability_accepted=args.accept_legal_liability,
        default_httpx_rate_limit_per_minute=args.rate_limit_per_minute,
    )
    result = AutonomousAgent(
        policy=AutonomyPolicy(dry_run=False),
        budget=ActionBudget(max_actions=1, max_live_requests=args.max_live_requests),
        runner=runner,
    ).run_plan(AgentPlan(actions=[action]))
    print(result.model_dump_json(indent=2))
    if result.stopped or result.blocked_actions or any(not obs.success for obs in result.observations):
        return 1
    return 0


def _live_recon_action(args: argparse.Namespace) -> AgentAction:
    if args.tool == "subfinder":
        return AgentAction(
            action_type="passive_recon",
            target_kind="host",
            target=args.target,
            intended_action="passive_recon",
            description=f"Run approved passive subfinder recon for {args.target}.",
            metadata={"tool": "subfinder"},
        )
    if args.tool == "httpx":
        if args.target.startswith(("http://", "https://")):
            return AgentAction(
                action_type="low_volume_probe",
                target_kind="url",
                target=args.target,
                intended_action="recon",
                description=f"Run approved low-volume httpx probe for {args.target}.",
                sends_traffic=True,
                request_budget=1,
                metadata={
                    "tool": "httpx",
                    "rate_limit_per_minute": str(args.rate_limit_per_minute),
                },
            )
        return AgentAction(
            action_type="low_volume_probe",
            target_kind="host",
            target=args.target,
            intended_action="recon",
            description=f"Run approved low-volume httpx probe for {args.target}.",
            sends_traffic=True,
            request_budget=1,
            metadata={
                "tool": "httpx",
                "rate_limit_per_minute": str(args.rate_limit_per_minute),
            },
        )
    if args.tool == "katana":
        target_kind = "url" if args.target.startswith(("http://", "https://")) else "host"
        return AgentAction(
            action_type="low_volume_probe",
            target_kind=cast(TargetKind, target_kind),
            target=args.target,
            intended_action="recon",
            description=f"Run approved scoped katana crawl for {args.target}.",
            sends_traffic=True,
            request_budget=max(1, args.max_live_requests),
            metadata={
                "tool": "katana",
                "rate_limit_per_minute": str(args.rate_limit_per_minute),
                "depth": str(args.depth),
                "field_scope": args.field_scope,
                "js_crawl": str(args.js_crawl).lower(),
                "crawl_duration_seconds": str(args.crawl_duration_seconds),
                **({"known_files": args.known_files} if args.known_files else {}),
            },
        )
    if args.tool == "nuclei":
        if not args.template:
            raise SystemExit("--template is required for --tool nuclei")
        target_kind = "url" if args.target.startswith(("http://", "https://")) else "host"
        return AgentAction(
            action_type="low_volume_probe",
            target_kind=cast(TargetKind, target_kind),
            target=args.target,
            intended_action="recon",
            description=f"Run approved explicit-template nuclei scan for {args.target}.",
            sends_traffic=True,
            request_budget=max(1, args.max_live_requests),
            metadata={
                "tool": "nuclei",
                "nuclei_templates": ",".join(args.template),
                "nuclei_tags": ",".join(args.tag),
                "nuclei_severity": ",".join(args.severity),
                "rate_limit_per_second": str(args.rate_limit_per_second),
            },
        )
    if args.artifact_path is None:
        raise SystemExit("--artifact-path is required for --tool jadx")
    if args.publisher is None:
        raise SystemExit("--publisher is required for --tool jadx")
    metadata = {
        "tool": "jadx",
        "artifact_path": args.artifact_path,
        "publisher": args.publisher,
    }
    if args.output_dir:
        metadata["output_dir"] = args.output_dir
    return AgentAction(
        action_type="passive_recon",
        target_kind="mobile_app",
        target=args.target,
        intended_action="passive_recon",
        description=f"Run approved jadx static analysis for {args.target}.",
        metadata=metadata,
    )


def _build_plan(args: argparse.Namespace) -> AgentPlan:
    assets = _load_assets(args.asset, args.asset_file)
    brain = build_agent_brain(
        provider=cast(ModelProviderName, args.model_provider),
        allow_remote_model=args.allow_remote_model,
        openai_model=args.model,
        openai_base_url=args.model_base_url,
        timeout_seconds=args.model_timeout_seconds,
        max_assets=args.model_max_assets,
    )
    if args.mode == "offline":
        return build_offline_analysis_plan(assets, brain=brain, max_actions=args.max_actions)
    return build_agent_plan(assets, brain=brain, max_actions=args.max_actions)


def _default_model_provider() -> str:
    value = os.getenv("VRP_HUNT_MODEL_PROVIDER", "heuristic").strip().lower()
    if value in {"heuristic", "openai"}:
        return value
    return "heuristic"


def _safe_runner_for_mode(mode: str) -> ActionRunner:
    if mode == "testing":
        return build_safe_validation_runner()
    return build_safe_offline_runner()


def _apply_cli_approval_gate(
    plan: AgentPlan,
    policy: AutonomyPolicy,
    args: argparse.Namespace,
) -> AgentPlan:
    mode = "approve-all" if args.approve_risky or args.yolo else args.approval_mode
    result = apply_approval_gate(
        plan,
        policy=policy,
        mode=cast(ApprovalMode, mode),
        approvals=args.approve_action,
        prompt=input,
        render=lambda text: print(text, file=sys.stderr),
    )
    if result.required_actions and mode == "block":
        print(
            "approval gate: risky actions were left unapproved and will be blocked by policy",
            file=sys.stderr,
        )
        print(
            "rerun with --approval-mode explicit --approve-action <index|id>, "
            "--approval-mode prompt, or --approve-risky",
            file=sys.stderr,
        )
    if result.approved_action_ids:
        print(
            f"approval gate: approved {len(result.approved_action_ids)} risky action(s)",
            file=sys.stderr,
        )
    return result.plan


def _artifact_researcher_accounts(args: argparse.Namespace) -> list[str]:
    return args.researcher_account or ["owned-test-account"]


def _write_auto_artifacts(output_dir: Path, output: Mapping[str, object]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for key, filename in {
        "plan": "plan.json",
        "run": "run.json",
        "artifacts": "artifact-bundle.json",
    }.items():
        (output_dir / filename).write_text(
            json.dumps(output[key], indent=2) + "\n",
            encoding="utf-8",
        )


def _write_scenario_artifacts(output_dir: Path, bundle: AgentArtifactBundle) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = output_dir / "artifact-bundle.json"
    bundle_path.write_text(bundle.model_dump_json(indent=2) + "\n", encoding="utf-8")
    written: list[dict[str, str]] = []
    for artifact in bundle.artifacts:
        finding_id = artifact.finding.finding_id
        finding_path = output_dir / f"{finding_id}-finding.json"
        report_path = output_dir / f"{finding_id}-report.json"
        markdown_path = output_dir / f"{finding_id}-report.md"
        finding_path.write_text(artifact.finding.model_dump_json(indent=2) + "\n", encoding="utf-8")
        report_path.write_text(artifact.report.model_dump_json(indent=2) + "\n", encoding="utf-8")
        markdown_path.write_text(render_markdown_report(artifact.report), encoding="utf-8")
        written.append(
            {
                "finding_id": finding_id,
                "finding": str(finding_path),
                "report": str(report_path),
                "markdown": str(markdown_path),
            }
        )
    return {
        "artifact_bundle": str(bundle_path),
        "artifacts": written,
    }


def _load_assets(asset_specs: list[str], asset_file: Path | None) -> list[Asset]:
    assets = [_parse_asset_spec(spec) for spec in asset_specs]
    if asset_file is not None:
        for line in asset_file.read_text(encoding="utf-8").splitlines():
            if line.strip():
                assets.append(Asset.model_validate_json(line))
    if not assets:
        raise SystemExit("at least one --asset or --asset-file is required")
    return assets


def _parse_asset_spec(spec: str) -> Asset:
    kind, separator, value = spec.partition(":")
    if not separator or not kind or not value:
        raise SystemExit(f"invalid asset spec: {spec!r}; expected kind:value")
    return Asset.model_validate({"kind": kind, "value": value, "source": "cli"})


def _load_web_content_document(spec: str) -> WebContentDocument:
    url, separator, path_text = spec.partition("=")
    if not separator or not url.strip() or not path_text.strip():
        raise ValueError(f"invalid document spec: {spec!r}; expected URL=PATH")
    path = Path(path_text).expanduser()
    return WebContentDocument(
        url=url,
        body=path.read_text(encoding="utf-8"),
        source=str(path),
    )


def _load_owned_crawl_page(spec: str) -> OwnedAccountCrawlPage:
    account_id, separator, remainder = spec.partition("=")
    url, path_separator, path_text = remainder.rpartition("=")
    if (
        not separator
        or not path_separator
        or not account_id.strip()
        or not url.strip()
        or not path_text.strip()
    ):
        raise OwnedAccountCrawlError(f"invalid page spec: {spec!r}; expected ACCOUNT=URL=PATH")
    path = Path(path_text).expanduser()
    return OwnedAccountCrawlPage(
        account_id=account_id,
        url=url,
        body=path.read_text(encoding="utf-8"),
        source=str(path),
    )


def _load_wildcard_dns_probes(probe_specs: list[str], probe_files: list[Path]) -> list[WildcardDnsProbe]:
    probes = [wildcard_probe_from_spec(spec) for spec in probe_specs]
    for path in probe_files:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            probe = wildcard_probe_from_asset(Asset.model_validate_json(line))
            if probe is not None:
                probes.append(probe)
    return probes


def _load_asset_jsonl_files(paths: list[Path]) -> list[Asset]:
    assets: list[Asset] = []
    for path in paths:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                assets.append(Asset.model_validate_json(line))
    return assets


def _host_values_from_asset_files(paths: list[Path]) -> list[str]:
    return [asset.value for asset in _load_asset_jsonl_files(paths) if asset.kind == "host"]


def _load_dns_record_collections(paths: list[Path]) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for path in paths:
        collection = DnsRecordCollection.model_validate_json(path.read_text(encoding="utf-8"))
        records.extend(collection.records)
    return records


def _write_asset_jsonl(path: Path, assets: list[Asset]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for asset in assets:
            handle.write(asset.model_dump_json() + "\n")


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
