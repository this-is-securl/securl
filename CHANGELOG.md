# Changelog

## 2026-07-04 — core 1.17.0 certificate policy gates

### Added

- Added CI-friendly certificate policy gates to `securl cert`: fail on invalid/unavailable certificates, expiry windows, legacy TLS negotiation, or issuer mismatches.
- Added `ci-json` output for certificate checks with a compact TLS summary and policy result envelope.
- Documented certificate policy usage for release checks and Cert Watch-style automation.

### Verified

- `npm run build:core`
- `node --test packages/core/test/cli.test.mjs packages/core/test/package-surface.test.mjs`
- `npm run release:package:check`

## 2026-07-04 — core 1.16.1 CLI executable patch

### Fixed

- Added the Node shebang to the package CLI entrypoint so `npx securl`, `npm exec securl`, and global installs run the CLI with Node instead of the shell.
- Added package-surface coverage for the compiled CLI shebang so npm binary execution is protected.

### Verified

- `npm run release:package:check`
- `npm exec --yes securl@1.16.1 -- cert http://example.com`

## 2026-07-04 — core 1.16.0 certificate CLI

### Added

- Added `securl cert <target>` for fast TLS handshake-only certificate checks from the npm CLI.
- Added summary, JSON, and Markdown output modes for certificate checks so developers can inspect expiry, issuer, SANs, negotiated TLS details, key hints, chain entries, and issues without running a full posture scan.
- Documented the CLI workflow alongside the existing `scanLiveCertificate()` package API.

### Verified

- `npm run build:core`
- `node --test packages/core/test/cli.test.mjs packages/core/test/package-surface.test.mjs`
- `npm run release:package:check`

## 2026-07-03 — backend mobile telemetry attribution

### Added

- Added optional `X-SecURL-Client-Channel` support with normalized `app-store`, `testflight`, `development`, and `automation` channels.
- Added first-party app-id inference for `securl-ios`, `header-watch-ios`, and `cert-watch-ios` so live certificate reads, push registration, push health, notification tests, monitoring health, and mobile summaries can be attributed by app without storing device identifiers.
- Added product-pulse channel splits and better owner/target attribution for backend-owned mobile service events.

### Verified

- `npm run lint`
- `npm run test:server`
- GitHub package checks on PR #340.
- Railway backend deploy and smoke check.

## 2026-07-02 — backend product pulse telemetry

### Added

- Added protected `GET /api/product-pulse` for a compact admin readout of product usage, app events, active owner counts, unique target-origin counts, monitoring registration outcomes, target kinds, recent backend events, and notification delivery health.
- Added `npm run product:pulse` and extended `npm run telemetry` with product-pulse readouts.
- Added privacy-safe monitoring registration outcome and target-kind attribution by app.

### Verified

- `npm run lint`
- `npm run test:server`
- GitHub package checks on PR #339.
- Railway backend deploy and smoke check.

## 2026-07-02 — core 1.15.0 monitoring health control plane

### Added

- Added an owner-scoped `GET /api/monitoring-health` control-plane payload for monitoring reliability, due and overdue targets, certificate attention, posture failures, scheduler state, notification outbox state, and per-app push registration health.
- Added monitoring-health consumption telemetry so backend adoption can distinguish regular watch-list status reads from target registration and scan activity.
- Documented the health endpoint alongside the mobile monitoring and Cert Watch API surfaces.

### Verified

- Focused DTO, telemetry, and monitoring endpoint tests.

## 2026-07-01 — core 1.14.0 telemetry attribution and mobile API polish

### Added

- Surfaced signal clarity through backend API DTOs, capabilities, and mobile monitoring digest previews.
- Added daily backend telemetry attribution by source, mode, client, and client version.
- Added aggregate live-certificate failure telemetry for Cert Watch and other mobile clients.
- Updated the telemetry CLI with today-by-event/client/version/source readouts and recent backend events.

### Changed

- Refreshed small dependency updates, including `pg`, `lucide-react`, Radix switch/radio-group primitives, and `globals`.

### Verified

- `npm run lint`
- `npm run test:server`
- Railway deploy and live API smoke test.

## 2026-06-24 — core 1.11.1 dependency refresh

### Changed

- Updated the core HTML parser to 8.0.3 and retained the existing public engine API.
- Updated the Vite React plugin, Tailwind CSS, Radix UI primitives, and pinned GitHub checkout action.

### Verified

- Clean dependency installation and zero-vulnerability npm audit.
- Full core, backend, strict type, lint, production build, and package dry-run checks.

## 2026-06-20 — core 1.11.0 and continuous policy monitoring

### Added

- Added observation-level drift with regression, improvement, and neutral-change classification.
- Added bounded custom observation policies on monitoring targets and default baseline evaluation.
- Added newly introduced policy-violation routing to APNs, signed webhooks, and Resend email.
- Added authenticated alert-destination resources and a durable generic delivery outbox.

### Security

- Webhook destinations are HTTPS-only, reject credentials/query/fragment content, revalidate public DNS at send time, pin outbound sockets, and do not follow redirects.
- Webhook/email destinations require authenticated accounts and are capped per owner.

## 2026-06-20 — core 1.10.0 and durable backend jobs

### Added

- Added Observation Ledger v1 to the engine with deterministic signal IDs, explicit observed/inferred/missing/unavailable states, confidence, source evidence, and freshness windows.
- Added the `securl/observations` package export and `GET /api/scans/:id/observations` lightweight API resource.
- Added durable Postgres-backed scan job leases, restart recovery, bounded retries, and stale-worker write fencing.

### Compatibility

- Existing web and mobile scan DTOs remain valid; the ledger and resource links are additive.
- Backend lease and attempt metadata remains internal.

## 2026-06-15 — core 1.9.0

### Added

- Added `scanLiveCertificate(url)` and the `securl/live-certificate` package export for TLS handshake-only certificate reads.
- Added `GET /api/certificates/live?url=...` for fast Cert Watch refreshes without running a full posture scan.
- Added `GET /api/scans/:id/events` as an SSE lifecycle stream so clients can avoid polling scan detail while scans run.
- Added notification-device registration resources and APNs-backed monitoring drift notification plumbing.

### Changed

- Extended API capabilities and live smoke coverage for mobile-oriented scan events, notifications, and live certificate resources.

### Verified

- `npm run build:core`
- `node --test packages/core/test/package-surface.test.mjs server/test/scanStore.test.mjs`
- `npm run test:server`
- `npm run release:package:check`

## 2026-06-15 — core 1.8.0

### Added

- Added core `buildActionPlan(result)` support and the `securl/action-plan` package export for prioritized owner/effort/impact-ranked fix actions.
- Added `GET /api/scans/:id/action-plan` as an additive backend resource for web, mobile, CLI, and report clients that need a compact next-actions payload.
- Added consumer API map documentation covering stable product resources and when to use full scan reads.

### Verified

- `npm run build:core`
- `node --test packages/core/test/action-plan.test.mjs packages/core/test/package-surface.test.mjs`
- `npm run test:server`
- `npm run release:package:check`
- GitHub `verify-core` on PR #278.

## 2026-05-27 — app 1.0.0 / core 1.0.0

### Added

- Added `deep-passive` scan mode across the backend API, frontend API client, core package, and CLI for broader bounded passive recon.
- Added a bounded backend scan scheduler with configurable `SCAN_CONCURRENCY` and startup recovery for stale `running` scans.
- Added mode-aware scan timeouts, keeping standard/quiet scans at the normal bound and deep-passive scans at a 75 second default.

### Changed

- Deployed the backend as an API-only Railway service while keeping the Hostinger frontend on `app.securl.online`.
- Made the recent scan result cache mode-aware and bypassed it entirely for deep-passive scans so release-readiness checks always run fresh.
- Documented production scan modes and backend runtime controls in the API notes.

### Verified

- `npm run test:core`
- `npm run test:server`
- `npm run test:app:unit`
- `npm run lint`
- `npm run pack:core`
- GitHub `verify-core` and CodeQL checks on merged PRs.
- Live Railway/Hostinger smoke: health, API-only root behavior, Hostinger CORS preflight, and a fresh deep-passive scan with `timeoutMs: 75000`.

## 2026-05-11 — app 0.9.0

### Changed

- Replaced the flat score badge with a full SVG ring gauge (168 px, grade-coloured stroke, `stroke-dashoffset` fill) across both the report workspace `OverviewSection` and the `SecurityGrade` card used on the scan-input page.  Ring colour matches the per-grade palette (green A/A+, blue B, amber C, orange D, red F, slate U).
- Strengthened typography hierarchy throughout the report workspace: section eyebrows at `text-[11px]` tracking `0.18 em`, stat-tile numerals at `text-[2rem] font-bold tracking-[-0.04em]`, card titles at `text-xl font-semibold tracking-[-0.02em]`.
- Increased card padding, row gaps, and breathing room across `OverviewSection` stat tiles, scan-fact tiles, and category-bar cards.
- Reduced category bar height from `h-2` to `h-1.5` for a lighter data-forward feel.
- Removed inconsistent per-page footer text from the PDF report export.
- Changed Section 06 (Technical Details) in the PDF export from a two-column grid to a single stacked column so the six detail cards read without awkward overflow.

### Verified

- `npm run build` — clean
- `npm run test:app:unit` — 39/39 passing
- Live UX sign-off pass at app.securl.online:
  - ek.co → D / 69 (amber ring)
  - bbc.co.uk → C / 77 (amber ring, category bars, export buttons)
  - github.com → C / 74 (clean layout)
  - wsj.com → U / 26 (slate ring, assessment-limited banner)
- Responsive: 1280 / 1024 / 768 / 390 px — all layouts pass

## 2026-04-25

### Added

- Added a short `epi` CLI binary alias alongside `external-posture-insight`.
- Added lightweight interactive multi-target CLI progress on stderr while keeping report output pipe-friendly.
- Added structured SPF and DMARC policy evaluation so Domain & Email Security now reports hardfail/softfail, enforcing/monitor-only DMARC, rollout percentage, and reporting posture instead of only raw TXT records.
- Added passive infrastructure inference to the Trust report, using DNS, reverse DNS, response headers, and detected stack evidence to identify likely cloud, CDN, edge, PaaS, or hosting providers.
- Added deterministic core test coverage for passive infrastructure provider inference.
- Added quiet scan mode for CLI and hosted API usage, preserving core DNS/TLS/header checks while skipping deeper page-content and probe enrichment.

### Changed

- Treat HTTP 5xx target responses as limited availability reads, including a clearer banner and a lower grade cap so unavailable pages do not appear as normal `C` posture results.
- Recalibrated the overall grade around weighted posture areas instead of primarily header/TLS/cookie hardening, reducing the previous tendency for very different targets to cluster around `B`.
- Separated Posture Summary counts into `Priority Warnings`, `Supporting Watch Items`, and `Observed Signals` so contextual panel evidence is not presented as double-counted warnings.
- Reused a shared signal-list primitive across Identity Provider, Certificate Transparency, and WAF panels so neutral evidence no longer looks like a green strength.
- Added bounded concurrency for CT host sampling, OSV vulnerability detail lookups, and related-page crawling to keep scans less bursty and more predictable.
- Lazy-loaded Cheerio in the HTML analysis path so importing the core package is fast for CLI/help and non-HTML workflows.
- Tightened public README positioning with clearer quick-start, capability limits, and authorization/safety wording.

### Verified

- `npm run build`
- `npm run test:core`
- `npm run test:app:unit`

## 2026-04-23

### Added

- Added deploy and operations guidance for hosted mode:
  - requester plus target quota controls on `/api/analyze`
  - abuse threshold telemetry logging
  - reverse proxy verification runbook
- Added deployment-readiness validation coverage and updated server tests for hosted hardening behavior.
- Added app-level unit tests for:
  - posture score thresholds and clamping (`src/lib/posture.test.ts`)
  - priority action ordering and weakest-area fallback coverage (`src/lib/priorities.test.ts`)
- Added release notes draft for the upcoming version in `docs/RELEASE-NOTES-DRAFT.md`.

### Changed

- Normalized panel language so neutral-positive states remain in `Strengths`, and only actionable items show under `Watch points` (Identity Provider, Certificate Transparency, WAF & Edge).
- Updated daily QA tracking to include a live 3-target pass across mixed target profiles.
- Tightened Monitoring + Posture Summary readability with spacing/typography refinements.
- Clarified export headline behavior in Markdown/HTML reports by explicitly including the change headline and documenting why category deltas are not included.

### Verified

- `npm run build`
- `npm run test:core`
- `npm run test:server`
- `npm run test:app:unit`
- Live CLI batch QA:
  - `https://www.ek.co` -> `84/100 (B)`
  - `https://www.bbc.co.uk` -> `88/100 (B)`
  - `https://github.com` -> `96/100 (A)`

## 2026-04-16 (v0.6.0)

### Added

- Added CLI policy gates with `--fail-on info|warning|critical` and `--fail-on-regression` for CI exit-code workflows.
- Added richer batch scan summary/Markdown output with aggregate score plus strongest and weakest targets.
- Added CLI test coverage for policy failures and regression gating behavior.

### Changed

- Updated workspace dependency alignment to keep `npm ci` stable (`vite@^8.0.8`, `@vitejs/plugin-react-swc@^4.3.0`) and removed the legacy `lovable-tagger` integration.
- Hardened certificate issuer/subject normalization under stricter TypeScript typing.

### Verified

- `npm ci`
- `npm run build`
- `npm run test:core`
- `npm run lint`

## 2026-04-16

### Added

- Added `@ktbatterham/external-posture-core@0.5.0` release prep with a stronger CLI workflow.
- Added CLI batch scan support for scanning multiple targets in one run.
- Added direct CLI comparison mode for saved report vs baseline report analysis.
- Added SARIF output mode for scan and compare flows to support CI-oriented security workflows.
- Added expanded core CLI tests for compare behavior, SARIF output, and baseline input validation errors.

### Changed

- Updated core package documentation and CLI help examples to reflect batch, compare, and SARIF usage.
- Tightened CLI argument handling so baseline comparisons are explicitly constrained to single-target scans.

### Verified

- `npm run build`
- `npm run test:core`
- `npm run lint`

## 2026-04-09

### Added

- Added passive library version risk analysis backed by OSV for explicitly versioned client-side assets
- Added score trending in monitoring history plus shared diff helpers now exposed by the core package
- Added CLI baseline comparison mode for report-vs-report change summaries
- Added DNSSEC posture and passive takeover clues from CT/CNAME observations

### Changed

- Hardened outbound scan requests with stricter public-IP revalidation and tighter OIDC discovery timeout handling
- Added hosted-mode API key support, rate-limit bucket cleanup, and versioned browser-local monitoring storage
- Unified app and package diff generation so browser monitoring and CLI comparisons now share the same model

### Verified

- `npm run release:core:check`
- CLI smoke tests including `--baseline`
- Local build, core tests, lint, and server syntax checks

## 2026-04-08

### Added

- Added a real CLI for the published core package with summary, JSON, and Markdown output modes
- Added richer monitoring diff reporting across transport, providers, AI, identity, WAF, and CT host changes
- Added passive WAF and edge fingerprinting plus richer CT coverage rollups

### Changed

- Deepened passive IdP/OAuth posture analysis while reducing weak same-origin false positives
- Tightened passive signal panel messaging so neutral states no longer read as contradictory
- Polished domain, public trust, disclosure, and third-party trust panel rendering for more consistent report visuals
- Consolidated duplicated core helpers and documented scanner configuration limits

### Verified

- `npm run release:core:check`
- Local CLI smoke tests for summary, JSON, and Markdown output
- Browser sanity checks across the revised trust/identity/third-party panels

## 2026-04-07

### Added

- Added passive Identity Provider / OAuth discovery and Certificate Transparency enrichment to the product surface
- Added Dependabot config and npm provenance publishing support

### Changed

- Extracted more of the scanner core into dedicated modules for CT, identity, HTML insights, and surface enrichment
- Hardened the local analysis API with target validation, simple rate limiting, safer error handling, and static-response security headers
- Clarified in the UI that monitoring remains browser-local and does not continue after the tab is closed
- Removed the stray `bun.lockb` so the repo now follows a single npm lockfile path

### Verified

- `npm run release:core:check`
- Edge-case API checks against live local server instances, including private-target rejection and weird-site scans

## 2026-04-05

### Added

- Published the reusable scanner core as [`@ktbatterham/external-posture-core`](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
- Added package release workflows, changelog, and release checklist
- Migrated the core package to compiled TypeScript

### Changed

- Updated the repo README to reflect the broader External Posture Insight product
- Added npm badges and package links to the repo and package documentation
- Updated GitHub Actions workflow dependencies to current major versions

### Verified

- `npm run release:core:check`
- Clean consumer install from a fresh npm project
