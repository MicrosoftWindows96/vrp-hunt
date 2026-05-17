# Recon Feature Backlog

## Priority Track

- [X] Scope/program registry with in-scope, out-of-scope, reward, safe-harbor, and rate-limit records
- [X] Scope diff watcher for fresh-target alerts
- [X] Workflow YAML runner for recon phases
- [X] Passive source manager with provider health and API key status
- [X] Asset confidence and freshness scoring
- [X] JavaScript and API endpoint mining pipeline
- [X] Authenticated owned-account crawler feeding IDOR/OAuth/CSRF validators
- [ ] Mobile APK/MobSF/jadx importer
- [ ] UI dashboard for assets, approvals, evidence, and findings

## Scope And Program Intelligence

- [ ] Scope ingestion from HackerOne, Bugcrowd, Intigriti, and public JSON
- [X] Program profile records for rewards, exclusions, safe harbor, and rate limits
- [X] Scope-normalized target registry with in-scope/out-of-scope proofs
- [X] Scope diff watcher like bbscope's fresh-target model
- [X] Asset freshness scoring
- [X] Fresh-target alerts
- [ ] Submission checklist against program rules

## Passive Recon And Asset Discovery

- [X] Passive source manager for API keys and provider health
- [ ] Subdomain source attribution and confidence scoring
- [ ] Wildcard DNS detection and elimination
- [ ] DNS record collector for CNAME, MX, TXT, NS, CAA, DMARC, and SPF
- [ ] CDN/WAF fingerprinting
- [ ] ASN and owned netblock expansion
- [ ] Reverse IP and certificate transparency expansion
- [ ] Subdomain permutation engine with strict caps
- [ ] Recursive passive subdomain discovery
- [ ] Historical URL ingestion from Wayback, urlscan, and Common Crawl
- [ ] robots.txt parser
- [ ] sitemap.xml parser
- [ ] security.txt parser

## Web Recon And Endpoint Mining

- [X] JavaScript URL extraction and endpoint mining
- [ ] CSP endpoint extraction
- [ ] OpenAPI/Swagger/Postman collection discovery
- [ ] GraphQL endpoint discovery and safe introspection check
- [ ] Technology fingerprinting via httpx/Wappalyzer-style metadata
- [ ] Screenshot clustering and visual diffing
- [ ] Interesting-app ranking by auth, APIs, JS, cookies, forms, and tech
- [ ] App change monitor for headers, body hash, title, and JS hash
- [ ] Dead-host suppression and retry/backoff history
- [ ] Safe exposure checks for panels, debug pages, and config leaks

## Traffic Control And Safety

- [ ] Per-host request budget ledger
- [ ] Global traffic scheduler with robots and rate-limit awareness
- [ ] Passive/safe/active/aggressive module taxonomy
- [ ] Approval gates based on module risk class
- [ ] Run cache to avoid repeated target traffic
- [ ] Tool health check and version inventory
- [ ] Tool installer/doctor for subfinder, httpx, katana, nuclei, jadx, and MobSF

## Workflow Orchestration

- [X] YAML workflow definitions
- [ ] Workflow DAG with dependencies, conditions, and resumability
- [ ] Distributed worker mode with local-first execution
- [ ] Scheduled monitoring runs
- [ ] Run comparison timeline
- [ ] REST API mode
- [ ] Discord/Slack notification mode for completed runs

## Scanner Integrations

- [ ] Nuclei template allowlist profiles
- [ ] Nuclei template metadata audit before execution
- [ ] CVE-to-tech matching before any template scan
- [ ] KEV/CVSS enrichment for detected technologies
- [ ] Cloud bucket name candidate generation from owned domains
- [ ] Cloud bucket existence checks with non-invasive metadata only
- [ ] GitHub org/repo discovery for in-scope orgs
- [ ] GitHub code search integration for owned orgs
- [ ] Secret scanning result importer from gitleaks/trufflehog
- [ ] CI/CD exposure checks for public workflow artifacts, leaked logs, and Actions config
- [ ] Container/image metadata discovery for owned repos

## Mobile Analysis

- [ ] Mobile APK ingestion pipeline
- [ ] jadx decompile runner with endpoint extraction
- [ ] MobSF static-analysis importer
- [ ] Mobile deep-link extraction
- [ ] Mobile API base URL extraction
- [ ] Mobile certificate pinning indicator extraction
- [ ] Mobile manifest permission risk summary

## Authenticated Owned-Account Testing

- [ ] Owned-account scenario library for IDOR, OAuth, CSRF, XSS, and XSLeak
- [ ] Authenticated crawl using owned profiles only
- [ ] Cookie/session vault with redacted artifact references
- [ ] Role matrix builder from owned accounts
- [ ] Object catalog generator from user-created test objects
- [ ] IDOR candidate generator from owned object URLs
- [ ] OAuth flow mapper for redirect URI, scopes, client IDs, and consent screens
- [ ] CSRF form inventory with token, cookie, and SameSite metadata
- [ ] XSS reflection inventory without exploit payload automation
- [ ] XSLeak surface inventory for frames, redirects, and cacheable auth boundaries

## Evidence And Reporting

- [ ] Evidence bundle with HTTP logs, screenshots, HAR, video, and tool versions
- [ ] Finding deduper across runs
- [ ] Finding confidence score with needs-manual-proof states
- [ ] Report draft generator per platform
- [ ] False-positive review queue
- [ ] Impact helper tied to bug class
- [ ] Export to Markdown, JSON, SARIF, and Faraday-compatible formats

## UI And Review

- [ ] UI dashboard for assets, phases, findings, and approvals
- [ ] Approval queue review and action buttons
- [ ] Artifact browser with redaction-aware previews
- [ ] Finding triage board
- [ ] Run timeline and phase status view
- [ ] Program and scope overview page
