# Recon Feature Backlog

## Priority Track

- [X] Scope/program registry with in-scope, out-of-scope, reward, safe-harbor, and rate-limit records
- [X] Scope diff watcher for fresh-target alerts
- [X] Workflow YAML runner for recon phases
- [X] Passive source manager with provider health and API key status
- [X] Asset confidence and freshness scoring
- [X] JavaScript and API endpoint mining pipeline
- [X] Authenticated owned-account crawler feeding IDOR/OAuth/CSRF validators
- [x] Mobile APK/MobSF/jadx importer
- [x] UI dashboard for assets, approvals, evidence, and findings

## Scope And Program Intelligence

- [x] Scope ingestion from HackerOne, Bugcrowd, Intigriti, and public JSON
- [X] Program profile records for rewards, exclusions, safe harbor, and rate limits
- [X] Scope-normalized target registry with in-scope/out-of-scope proofs
- [X] Scope diff watcher like bbscope's fresh-target model
- [X] Asset freshness scoring
- [X] Fresh-target alerts
- [x] Submission checklist against program rules

## Passive Recon And Asset Discovery

- [X] Passive source manager for API keys and provider health
- [x] Subdomain source attribution and confidence scoring
- [x] Wildcard DNS detection and elimination
- [x] DNS record collector for CNAME, MX, TXT, NS, CAA, DMARC, and SPF
- [x] CDN/WAF fingerprinting
- [x] ASN and owned netblock expansion
- [x] Reverse IP and certificate transparency expansion
- [x] Subdomain permutation engine with strict caps
- [x] Recursive passive subdomain discovery
- [x] Historical URL ingestion from Wayback, urlscan, and Common Crawl
- [x] robots.txt parser
- [x] sitemap.xml parser
- [x] security.txt parser

## Web Recon And Endpoint Mining

- [X] JavaScript URL extraction and endpoint mining
- [x] CSP endpoint extraction
- [x] OpenAPI/Swagger/Postman collection discovery
- [x] GraphQL endpoint discovery and safe introspection check
- [x] Technology fingerprinting via httpx/Wappalyzer-style metadata
- [x] Screenshot clustering and visual diffing
- [x] Interesting-app ranking by auth, APIs, JS, cookies, forms, and tech
- [x] App change monitor for headers, body hash, title, and JS hash
- [x] Dead-host suppression and retry/backoff history
- [x] Safe exposure checks for panels, debug pages, and config leaks

## Traffic Control And Safety

- [x] Per-host request budget ledger
- [x] Global traffic scheduler with robots and rate-limit awareness
- [x] Passive/safe/active/aggressive module taxonomy
- [x] Approval gates based on module risk class
- [x] Run cache to avoid repeated target traffic
- [x] Tool health check and version inventory
- [x] Tool installer/doctor for subfinder, httpx, katana, nuclei, jadx, and MobSF

## Workflow Orchestration

- [X] YAML workflow definitions
- [x] Workflow DAG with dependencies, conditions, and resumability
- [x] Distributed worker mode with local-first execution
- [x] Scheduled monitoring runs
- [x] Run comparison timeline
- [x] REST API mode
- [x] Discord/Slack notification mode for completed runs

## Scanner Integrations

- [x] Nuclei template allowlist profiles
- [x] Nuclei template metadata audit before execution
- [x] CVE-to-tech matching before any template scan
- [x] KEV/CVSS enrichment for detected technologies
- [x] Cloud bucket name candidate generation from owned domains
- [x] Cloud bucket existence checks with non-invasive metadata only
- [x] GitHub org/repo discovery for in-scope orgs
- [x] GitHub code search integration for owned orgs
- [x] Secret scanning result importer from gitleaks/trufflehog
- [x] CI/CD exposure checks for public workflow artifacts, leaked logs, and Actions config
- [x] Container/image metadata discovery for owned repos

## Mobile Analysis

- [x] Mobile APK ingestion pipeline
- [x] jadx decompile runner with endpoint extraction
- [x] MobSF static-analysis importer
- [x] Mobile deep-link extraction
- [x] Mobile API base URL extraction
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

- [x] UI dashboard for assets, phases, findings, and approvals
- [ ] Approval queue review and action buttons
- [ ] Artifact browser with redaction-aware previews
- [ ] Finding triage board
- [ ] Run timeline and phase status view
- [ ] Program and scope overview page
