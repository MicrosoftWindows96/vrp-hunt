# Google & Alphabet Vulnerability Reward Program (VRP) — Rules Digest

## Scope

In scope: any Google/Alphabet (Bet) web service handling reasonably sensitive user data.

- `*.google.com`
- `*.youtube.com`
- `*.blogger.com`
- `*.deepmind.com`
- `*.waymo.com`
- `*.wing.com`
- Google- and Waymo-developed apps in Apple App Store

Separate programs (own rules): Abuse, AI, Android & Google Devices, Chrome, ChromeOS, Cloud, Google Mobile, Google OSS, Chrome Extensions, Verily (HackerOne).

Exclusions:

- Third-party websites — Google-branded but vendor/partner operated. Check WHOIS; ask if unsure.
- Recent acquisitions — 6-month blackout before reports qualify.

## Qualifying vulnerabilities

XSS, CSRF, mixed-content scripts, authn/authz flaws, server-side code execution, XSLeak.

Limited to technical vulns in Google-owned browser extensions, mobile, and web apps. No phishing of employees, no physical intrusion, no DoS, no black-hat SEO, no spam, no high-volume automated scanning.

## Non-qualifying (typical)

- Vulns in `*.bc.googleusercontent.com` or `*.appspot.com` (Cloud customer apps — not VRP authorized).
- XSS in sandbox domains (e.g. `*.googleusercontent.com`) without demonstrated sensitive-data impact.
- Owner-supplied JS in Blogger / `*.blogspot.com`.
- URL redirection.
- Legitimate content proxying/framing (e.g. Google Translate).
- Bugs needing exceedingly unlikely user interaction.
- Logout CSRF.
- Flaws affecting only out-of-date browsers/plugins.
- Banner/version disclosure alone.
- Email spoofing on Gmail / Google Groups.
- User enumeration (unless you show no rate limits).
- Bypassing SMS account-verification limit (two quotas exist: SMS and Call Me).

## Reward model

Two central factors: Domain Tier of the app + vulnerability category/impact (linked to Information Tier / Action Criticality).

### Information Tiers (IT)

- Tier 0 — credentials + sensitive data from internal systems (most sensitive).
- Tier 1 — high-impact user data + internal system data.
- Tier 2 — metadata + lower-impact user/product data (least sensitive).

### Action Criticality (AC) — for state-changing actions

- Critical Actions (CA) ↔ IT0. Examples: email/password change → ATO, adding SSH key, security-critical privesc, Workspace Admin takeover.
- Impactful Actions (IA) ↔ IT1. Examples: deleting user photos/Drive/Keep, purging contacts, sharing user docs, deleting business data with monetary loss (e.g. ad campaigns).
- Moderate Actions (MA) ↔ IT2. Examples: changing display name/profile pic, limited-scope deletions.

### Domain Tier columns

- T0 — Tier 0 domains (critical vuln → account compromise / code exec) or global impact (e.g. XSS in Google Analytics embedded JS). Ex: `*.google.com`, `*.youtube.com`, `*.blogger.com`, `*.admob.com`.
- T1 — Tier 1 domains (vuln could disclose particularly sensitive user data).
- T2 — Normal Google applications.
- T3a — Acquisition Tier 0/1 domains. Ex: `*.withgoogle.com`, `*.withyoutube.com`. Only after 6-mo blackout.
- T3b — Other acquisitions / sandboxed / lower-priority apps. Only after 6-mo blackout.

### Reward table (USD)

| Category                            | Examples                                              | T0      | T1      | T2      | T3a    | T3b          |
| ----------------------------------- | ----------------------------------------------------- | ------- | ------- | ------- | ------ | ------------ |
| RCE (S0)                            | command injection, deser, sandbox escape              | 101,010 | 101,010 | 75,000  | 10,000 | 1,337–5,000 |
| Unrestricted file/DB access (S1)    | unsandboxed XXE, SQLi                                 | 75,000  | 75,000  | 50,000  | 10,000 | 1,337–5,000 |
| Logic flaw — IT0 / Critical (S2a)  | IDOR, remote user impersonation                       | 50,000  | 50,000  | 31,337  | 5,000  | 500          |
| Logic flaw — IT1 / Impactful (S2b) | IDOR, remote user impersonation                       | 31,337  | 31,337  | 13,337  | 2,500  | 500          |
| Logic flaw — IT2 / Moderate (S2c)  | IDOR, remote user impersonation                       | 7,500   | 5,000   | 3,133.7 | 500    | 200          |
| Execute code on client (C0)         | web XSS; mobile/hw code exec                          | 20,000  | 15,000  | 10,000  | 500    | 200          |
| Other — IT0 / Critical (C1a)       | CSRF, XSLeaks, clickjacking; mobile info leak/privesc | 15,000  | 13,337  | 7,500   | 500    | 200          |
| Other — IT1 / Impactful (C1b)      | CSRF, XSLeaks, clickjacking; mobile info leak/privesc | 5,000   | 5,000   | 3,133.7 | 200    | 100          |
| Other — IT2 / Moderate (C1c)       | CSRF, XSLeaks, clickjacking; mobile info leak/privesc | 1,337   | 1,337   | 1,337   | 100    | 100          |

Final amount at panel discretion. Reward can be donated to charity; unclaimed >12 months → donated to a charity of Google's choosing.

### Report quality multiplier: 0.8x / 1x / 1.2x

All conditions must be met to reach good/exceptional. Dimensions: vuln description, attack preconditions, impact analysis, reproduction steps/PoC (automated PoC when possible for 1.2x), target/product info, reproduction output, researcher responsiveness.

- Low (0.8x): missing/incomplete/incorrect; theoretical impact; AI slop; significant comms delays.
- Good (1x): correct but incomplete; minor repro inaccuracies; best-effort responses <2 weeks.
- Exceptional (1.2x): effectively described; complete easy repro + automated PoC; full target info; fast (<3 workdays) concise technical responses.

Only info available before triage counts. Later additions usually don't change reward. Inapplicable dimensions can be disregarded by panel.

### Precedents (flat amounts)

- Incident (non-technical, e.g. Googler publicly shares confidential doc): $500
- 3rd-party system Google controls integration/config (not underlying app): $100–500
- Documentation update (security-impacting): $100–500
- Documentation update (plain): HOF credit only

### Upgrades

- Novelty (made teams think differently): +$1k–$5k (discretionary)
- Time-limited bonus (specific VRP targets): +75%
- Swag: mystery trigger

### Downgrades (fixed step down the table, not %; multiple stack)

Example: $5,000 always steps to $3,133.7.
Triggers: minor impact, prior access required, project access required, significant user interaction, unexploitable-in-practice, Drive-ID knowledge required (retrieval not shown), OAuth consent — standard (1 step, scopes beyond userinfo.email/profile), sensitive (+1 step), restricted (+2 steps).

### Worked examples

- RCE on `accounts.google.com`, exceptional (1.2x): T0,S0 → 101,010 × 1.2 = $121,212
- IDOR on `*.google.com` exfil saved address (PII), normal: T2,S2b → $13,337
- Easy XSS impacting all English Google Translate pages (global impact), normal: T0,C0 → $20,000
- `chat.google.com` IDOR revealing 24h message count, normal: T1,S2c + impact downgrade → $7,500
- XSS on Tier 0 acquisition domain, only after ~1M HTTP requests, exceptional: T3a,C1 + exploitability downgrade → 200 × 1.2 = $240

## Reporting

- Only ever target your own accounts. Never access others' data. Nothing disruptive/damaging.
- Submit via report form on bughunters.google.com. PGP key available.
- Be succinct: short PoC link > long video. Triaged by security engineers.
- Technical vuln reports only (account/help issues → Google Help Centers).
- Credited on Leaderboard (0x0A / Leaderboard / Honorable Mentions) if profile public.
- Appeal within 1 month via appeal button; should contain new info; exception if info only available later due to Google-side factors (e.g. fix bypass).

## FAQ key points

- Don't know how to exploit? Provide a valid attack scenario — required to qualify. Panel rates by max impact; will reconsider on new info (bug chains, revised scenario). Report early; routinely pays well-written reports where reporter couldn't fully analyze impact.
- Outdated software: must confirm noteworthy CVEs + explain exposure/risk in Google's specific use, else reject.
- Public disclosure before fix: coordinated disclosure expected; reasonable advance notice; case-by-case otherwise usually disqualifies.
- Vulnerability brokers / private 3rd-party disclosure: against program spirit → typically disqualified.
- Duplicates: first reporter only ("first in, best dressed").
- Privacy: no public mention unless "Make my profile public" selected; contact details only needed to pay.
- Honorable Mentions sorted by valid-submission volume, valid:invalid ratio, severity.
- Account disabled by testing: use dedicated test account (restoration not guaranteed); try Google Account → Try to Restore.

## Legal

- No reports/rewards to sanctioned individuals/entities or sanctioned territories (Cuba, Iran, North Korea, Syria, Crimea, DNR, LNR).
- No rewards to individuals/entities in Russia or Belarus (administrative).
- You handle your own tax. Local law may add restrictions.
- Experimental, discretionary; Google can cancel anytime; reward decision entirely at Google discretion.
- Testing must not violate law or disrupt/compromise data that is not your own.
