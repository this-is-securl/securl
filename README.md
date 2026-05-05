# External Posture Insight

[![npm version](https://img.shields.io/npm/v/%40ktbatterham%2Fexternal-posture-core)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![npm package](https://img.shields.io/badge/npm-package-red)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

External Posture Insight is a low-noise external posture analysis app for public web targets. It inspects a target URL through a local Node API, follows redirects, reads response headers, evaluates TLS certificate details, parses `Set-Cookie` flags, and produces a layered, client-ready report in the browser.

It is built for passive-first posture review: the kind of quick external read you can run before noisy scanners, sales calls, supplier reviews, monitoring checks, or deeper authorized testing.

In short: Shodan finds things. SecURL interprets them quietly.

## Published package

The reusable scanner core is now published on npm:

- [`@ktbatterham/external-posture-core`](https://www.npmjs.com/package/@ktbatterham/external-posture-core)

This app consumes that core package locally from the workspace during development.

CLI quick start:

```sh
npx @ktbatterham/external-posture-core scan example.com
npx @ktbatterham/external-posture-core scan example.com --format markdown --output report.md
npx @ktbatterham/external-posture-core scan example.com --format json --output report.json
npx @ktbatterham/external-posture-core compare current-report.json previous-report.json
```

Global install with the short command:

```sh
npm install -g @ktbatterham/external-posture-core
epi scan example.com
```

## Release status

- Latest published core package: `@ktbatterham/external-posture-core@0.8.0`
- Latest npm tag: `latest`
- Clean-install smoke test completed from a fresh npm project

## Features

- Live header analysis for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, and CORP
- Redirect chain inspection
- TLS certificate trust, issuer, expiry, protocol, cipher, and fingerprint reporting
- Cookie flag analysis for `Secure`, `HttpOnly`, and `SameSite`
- Conservative stack detection from origin, edge, and frontend signals
- Multi-page crawl summaries for important same-origin routes
- Platform-specific remediation snippets for `nginx`, `Apache`, `Cloudflare`, `Vercel`, and `Netlify`
- Local history snapshots with score and header diffs
- `security.txt` discovery and validation
- Domain and email posture checks for MX, SPF, DMARC, CAA, and MTA-STS
- Passive HTML inspection for forms, third-party assets, inline scripts/styles, and missing SRI
- Client config and API exposure signals from passive page analysis
- Auth surface and public data-collection surface summaries
- AI surface and third-party trust analysis
- OWASP/MITRE-aligned finding labels
- Low-noise exposure checks for a tiny set of high-signal paths
- CLI batch scanning and saved-report comparison workflows
- CI policy gating via CLI (`--fail-on` and `--fail-on-regression`)
- SARIF export for CI and security tooling ingestion
- JSON, Markdown, and HTML report export
- Recent scan history in the browser

## Why not Shodan?

Shodan is excellent at internet-scale discovery. It answers questions like:

- what is exposed on the public internet?
- which ports, banners, devices, and services are visible?
- where else does this software or infrastructure pattern appear?

SecURL is aimed at a different job:

- quiet, target-specific posture reads without broad reconnaissance noise
- browser-facing assessment of headers, redirects, cookies, TLS, and visible client code
- executive summaries and ranked actions that a real stakeholder can read quickly
- constrained-read handling when a site is blocked, rate-limited, or edge-gated
- drift comparison so teams can see what changed since the last scan

The simplest distinction is:

- Shodan is discovery-first.
- SecURL is posture-first.

If you want to inventory the whole internet, use Shodan.
If you want a low-noise, explainable read of a specific public target, use SecURL.

## What it can and cannot do

External Posture Insight can:

- highlight visible external hardening gaps across headers, TLS, cookies, DNS/mail posture, public trust signals, client-side exposure clues, CT-discovered hosts, and passive supply-chain signals
- provide OWASP/MITRE-aligned context for findings without pretending every finding is an exploit
- compare saved reports so regressions are visible over time
- generate browser-based exports that are suitable for stakeholder review

External Posture Insight cannot:

- prove a site is secure
- replace a penetration test, authenticated application review, SAST/DAST program, or formal compliance assessment
- see controls hidden behind bot challenges, authentication, IP allowlists, or different browser/user-agent behavior
- guarantee zero operational footprint; standard scans may perform DNS lookups, TLS handshakes, page fetches, public dataset lookups, and a small set of low-noise HTTP checks

## Safety and authorization

Use this only against systems you own or are authorized to assess. The tool is passive-first and intentionally conservative, but the author is not responsible for misuse, unauthorized scanning, operational impact, or decisions made from the output without appropriate validation.

## Stack

- React + Vite + TypeScript
- Tailwind + shadcn/ui
- Node.js API server using core `http`, `https`, and `tls`
- Reusable core package in `packages/core`

## Local development

```sh
npm install
npm run dev
```

That starts:

- the Vite frontend on `http://localhost:8080`
- the scan API on `http://127.0.0.1:8787`

The frontend proxies `/api/*` requests to the local API in development.

## Production-style run

```sh
npm run build
npm start
```

`npm start` serves the API and the built frontend from the same Node process.

## Railway deployment

This repo now includes [`railway.toml`](/Users/keith/Documents/Playground/secure-header-insight/railway.toml) so Railway can:

- build with `npm run build`
- start with `npm run start`
- health check the service at `/api/health`

Recommended environment variables for a first single-instance deployment:

```sh
NODE_ENV=production
ALLOW_UNAUTHENTICATED=true
DEPLOYMENT_MODE=single-instance
TRUST_PROXY=true
```

Notes:

- `ALLOW_UNAUTHENTICATED=true` is required if you want the browser app to call the scanner API directly without a private server-side API key.
- Unauthenticated browser scans use a local random `X-Scan-Owner` token so scan records are not shared by client IP alone.
- `EXPOSE_TELEMETRY=true` is required to expose `/api/telemetry` in production.
- `ALLOW_LEGACY_ANALYZE=true` is required to keep the legacy GET `/api/analyze` endpoint enabled in production.
- If you later scale beyond one instance, switch to `DEPLOYMENT_MODE=multi-instance` and configure Upstash-backed rate limiting.
- Run `npm run -s check:deploy` before promoting a public deployment.

## Public deployment guardrails

- In production, startup is blocked unless either `API_KEY` is set or `ALLOW_UNAUTHENTICATED=true` is explicitly set.
- In production, telemetry and legacy GET analysis are disabled unless explicitly enabled with `EXPOSE_TELEMETRY=true` or `ALLOW_LEGACY_ANALYZE=true`.
- `TRUST_PROXY=true` only applies forwarded-IP attribution when the direct peer is private/local.
- `DEPLOYMENT_MODE=multi-instance` requires a distributed limiter (`RATE_LIMIT_BACKEND=upstash` with Upstash REST credentials).
- Run `npm run -s check:deploy` before promoting a deployment.

See:

- [`docs/PUBLIC-DEPLOY-CHECKLIST.md`](/Users/keith/Documents/Playground/secure-header-insight/docs/PUBLIC-DEPLOY-CHECKLIST.md)
- [`docs/OWASP-MITRE-SELF-REVIEW.md`](/Users/keith/Documents/Playground/secure-header-insight/docs/OWASP-MITRE-SELF-REVIEW.md)
- [`docs/ABUSE-ALERTING.md`](/Users/keith/Documents/Playground/secure-header-insight/docs/ABUSE-ALERTING.md)
- [`docs/REVERSE-PROXY-VERIFICATION.md`](/Users/keith/Documents/Playground/secure-header-insight/docs/REVERSE-PROXY-VERIFICATION.md)

## Roadmap

The current release train is deliberately incremental. The aim is to improve trust, observability, and operational maturity without overstuffing single releases.

### 0.8.2

Monitoring and drift clarity

- refine `Since last scan`
- improve regression vs improvement wording
- slim monitoring controls and history surfaces
- make change summaries faster to read

### 0.8.3

Telemetry and product visibility

- add first-party usage counters
- distinguish page loads, scans, limited reads, and failures
- add a lightweight internal usage or ops view
- stop relying on raw Railway logs for product insight

### 0.8.4

Public-beta hardening

- tighten production defaults
- improve deployment and runtime validation
- review rate limiting for public exposure
- reduce operational sharp edges on Railway

### 0.8.5

Batching and scan behavior

- add concurrency limiting
- make repeated and batch scans bounded and polite
- improve graceful degradation on upstream failures
- tighten scan orchestration under load

### 0.8.6

Detection quality pass

- recheck platform-hosted targets
- reduce remaining false positives
- improve infrastructure and provider confidence wording
- keep score, narrative, and action alignment strong

### 0.8.7

Test and type confidence

- expand mocked integration coverage
- grow architecture strictness scope
- add more regression tests for limited reads, SPA fallback, and drift
- strengthen release confidence for public changes

### 0.8.8

Docs and operator readiness

- refresh README and screenshots to match the current product
- document deployment and runtime expectations
- document telemetry, limits, and public-beta cautions
- clarify the package/app story for new users

### 0.9.0

Operational maturity release

- concurrency, telemetry, drift, and deployment posture all feel deliberate
- public beta is safer and more observable
- engineering confidence is high enough that `1.0.0` becomes a product-contract milestone, not a stabilization scramble

## Notes

- Scans are based on what the origin returns for the requested URL at scan time.
- Technology detection is heuristic and intentionally conservative.
- Some sites may block automated requests or respond differently to bots versus browsers.
- The published package is intended for passive or near-passive posture assessment, not exploit testing.
