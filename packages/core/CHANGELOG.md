# Changelog

All notable changes to `securl` will be documented in this file.

The format is based on Keep a Changelog and this package follows Semantic Versioning once published.

## [Unreleased]

## [1.13.0] - 2026-06-28

### Added
- Added `buildEvidenceQualitySummary()` and the `securl/evidence-quality` package export for scan confidence, coverage gaps, and recommended follow-up.
- Added `evidenceQuality` to completed analysis results and compact posture digests so API, mobile, and CLI clients can explain how trustworthy a scan read is.

## [1.12.0] - 2026-06-27

### Added
- Added `buildPostureInsights()` and the `securl/posture-insights` package export for display-ready risk themes, top insights, and next-best actions.
- Added `postureInsights` to completed analysis results so API, mobile, and CLI clients can render security judgement without reinterpreting raw findings.

## [1.11.1] - 2026-06-24

### Changed
- Updated `node-html-parser` to 8.0.3, replacing the retired entity decoder while preserving the existing parsing API and Node 22 runtime floor.

## [1.11.0] - 2026-06-20

### Added
- Added a bounded declarative observation policy engine, maintained baseline policy, validation helper, and `securl/observation-policy` export.
- Added `diffObservationLedgers()` and `securl/observation-drift` for deterministic observation-level regression and improvement classification.

## [1.10.0] - 2026-06-20

### Added
- Added `buildObservationLedger()` and the `securl/observations` package export for stable, source-aware posture observations.
- Added `observationLedger` to completed analysis results with deterministic IDs, confidence, status, and freshness metadata.

## [1.9.0] - 2026-06-15

### Added
- Added `scanLiveCertificate()` and the `securl/live-certificate` package export for bounded TLS handshake-only certificate reads.
- Added certificate chain, protocol, key-strength, and expiry metadata for lightweight certificate clients.

## [1.8.0] - 2026-06-15

### Added
- Added `buildActionPlan()` and the `securl/action-plan` package export for prioritized owner, effort, and impact-ranked remediation actions.

## [1.7.0] - 2026-06-15

### Added
- Added `buildVendorExposureBrief()` for compact vendor and supply-chain exposure summaries covering visible third-party providers, data-flow categories, SRI gaps, priority vendors, and next actions.
- Added `vendorExposure` to analysis results and the `securl/vendor-exposure` package export for SDK consumers.

## [1.6.0] - 2026-06-15

### Added
- Added `buildExposureBrief()` for compact outside-observer action briefs covering public entry points, sensitive exposures, trust gaps, abuse indicators, third-party risk, AI surface signals, and next actions.
- Added `exposureBrief` to analysis results and the `securl/exposure-brief` package export for SDK consumers.

## [1.5.1] - 2026-06-15

### Changed
- Tightened npm package positioning around passive URL security posture scanning and clarified that SecURL is not a URL shortener.
- Filtered public GitHub package signals to dependency-key matches so same-name projects are not counted as adoption.

## [1.5.0] - 2026-06-14

### Added
- Added `buildPostureEvidenceSummary()` for compact, API/mobile-friendly evidence metadata that explains score drivers and findings without requiring clients to inspect the full scan payload.
- Added the `securl/evidence-summary` package export for consumers that want the evidence summary helper directly.
- Added `evidenceSummary` to completed analysis results and posture digests.

## [1.4.1] - 2026-06-14

### Changed
- Refreshed package metadata and trust documentation after moving the source repository to `this-is-securl/securl`.

## [1.4.0] - 2026-06-13

### Added
- Added structured finding evidence references and a remediation plan builder for prioritized, owner-aware fix guidance.
- Added the `securl/remediation-plan` package export for clients that want to build fix plans from scan results.

## [1.3.0] - 2026-06-11

### Added
- Added posture drift reports that combine history diffs, risk events, severity counts, changed areas, and overall drift direction into one stable monitoring payload.
- Added the `securl/posture-drift` package export for clients building history, monitoring, or alerting workflows.

## [1.2.1] - 2026-06-06

### Changed
- Capped A-level posture grades when Domain & Trust is weak, so strong browser-facing headers no longer mask broad DNS, email, or public-trust gaps in quiet or standard scans.

## [1.2.0] - 2026-06-04

### Added
- Added `buildPostureDigest()` for producing compact, API/mobile-friendly summaries from full scan results.
- Added the `securl/posture-digest` package export for consumers that want the digest helper without importing the wider SDK surface.

## [1.1.1] - 2026-06-02

### Changed
- Refreshed npm package signalling with clearer CLI, CI, SDK, and monitoring examples for developer adoption.
- Expanded package keywords and shipped examples to make the engine easier to discover for posture, CI, and vendor-risk workflows.

## [1.1.0] - 2026-06-01

### Added
- Added posture risk event classification helpers for scan history diffs, including score, grade, certificate, security-header, WAF, CT-host, third-party, AI-vendor, identity-provider, and new critical-finding changes.
- Added the `securl/risk-events` package export for consumers that want to build monitoring or alerting workflows from scan comparisons.

### Changed
- Added `currentGrade` to `HistoryDiff` so consumers can render grade movement without carrying a separate current snapshot.

## [1.0.1] - 2026-05-30

### Added
- Added passive public IOC and abuse indicators, including off-origin credential-form review signals, suspicious script markers, CT takeover evidence, exposure findings, and visible client-library advisory matches.

## [1.0.0] - 2026-05-27

### Added
- Added score driver metadata to analysis results so callers can explain the largest score deductions and limited-assessment caps.
- Added deterministic scoring calibration profiles and passive signature registry tests to protect launch-facing grade expectations.
- Added `deep-passive` scan mode for broader bounded CT sampling, crawl, exposure, and API-surface checks.

### Changed
- Documented default, quiet, and deep-passive scan boundaries and CI policy modes more explicitly in CLI help and the package README.
- Hardened public-target validation coverage for normalized private IP literal forms, including IPv6-mapped loopback redirects.

## [0.11.2] - 2026-05-24

### Changed
- Replaced Cheerio with `node-html-parser` for passive HTML page analysis, reducing the core package dependency tree while preserving title, metadata, form, script, stylesheet, link, and SRI extraction behavior.

## [0.11.1] - 2026-05-21

### Changed
- Refreshed the npm package README and package metadata with clearer SecURL product positioning, hosted scanner links, and marketing site links.

## [0.11.0] - 2026-05-20

### Added
- Added redirect-chain analysis from the existing fetch flow, including mixed HTTP hops, long chains, and cross-domain final destination flags.
- Added aggregate cookie attribute analysis for `Secure`, `HttpOnly`, `SameSite`, session-cookie, `__Host-`, and `__Secure-` signals.
- Added DKIM common-selector discovery, deeper SPF mechanism analysis, and an email deliverability composite score.
- Added RFC 9116-oriented `security.txt` validation with valid, expired, incomplete, and missing states.
- Added Subresource Integrity coverage scoring for externally hosted scripts and stylesheets.
- Added passive framework/version leakage signals for common frontend frameworks and CMS markers found in fetched HTML.
- Added protocol and WAF summary fields to passive infrastructure analysis using response headers such as `Alt-Svc`, `cf-ray`, `x-iinfo`, and related edge signatures.

## [0.10.0] - 2026-05-19

### Added
- Added TLS-RPT DNS record detection to domain security analysis. Reports `_smtp._tls` records, flags missing TLS-RPT when MTA-STS is present, and exposes `tlsRpt` on the public `DomainSecurityInfo` type.
- Added BIMI DNS record detection (`default._bimi`) to domain security analysis, including detection of the BIMI `v=BIMI1` indicator and `bimi` on the public `DomainSecurityInfo` type.
- Added infrastructure provider detection for Bunny.net (CDN), Cloudflare Pages, Railway, Render, Fly.io, Hostinger, OVHcloud, and Hetzner.
- Added analytics and session-replay vendor detection for Plausible, Matomo, Segment, Mixpanel, Amplitude, Heap, Microsoft Clarity, LogRocket, Pendo, New Relic Browser, and Datadog RUM.
- Promoted analytics/telemetry and session-replay/experience-analytics to explicit third-party risk categories in HTML passive analysis.

## [0.9.0] - 2026-05-17

### Added
- Added `passiveIntelligence` to the public analysis result model, summarizing passive stack, infrastructure, telemetry, third-party, AI, trust, email, and exposure signals.
- Added a strict passive-collection boundary statement so downstream consumers can distinguish public-response intelligence from aggressive reconnaissance.
- Added deterministic core coverage for passive intelligence summaries and boundary wording.

### Changed
- Exposed passive intelligence through hosted scan evidence payloads for API clients and future report/export consumers.

## [0.8.2] - 2026-05-14

### Added
- Added optional scan timing metadata for total, core, and enrichment phases so callers can understand slow or partial scans.
- Added a configurable maximum scan duration option for callers that need bounded execution.

### Changed
- Bounded secondary enrichment so long-running scans return a partial timed-out posture result instead of hanging indefinitely.
- Tightened network and runtime safety around redirects, request failures, memory usage, and Node.js runtime support.
- Refined passive DNS, certificate-transparency, and secondary probe handling to reduce latency spikes while preserving useful evidence.

## [0.8.1] - 2026-05-07

### Changed
- Refined posture scoring so hosted-platform app URLs take a softer domain-trust penalty when the target is clearly a demo or PaaS-hosted surface rather than an owned apex domain.
- Recalibrated `AI & Automation` posture scoring so absent visible AI surface is treated as low exposure rather than perfect assurance.
- Improved surface-enrichment handling for SPA frontend fallbacks so successful responses on paths like `/.git/HEAD` or `/.env` are no longer misreported as exposed sensitive files when they clearly return the standard app shell.
- Simplified and modularized the core scan pipeline internals so scoring, enrichment, and summary assembly are easier to evolve without changing the public API.
- Expanded deterministic coverage for scoring calibration and frontend-fallback exposure detection.

## [0.8.0] - 2026-04-29

### Added
- Added structured limited-read handling for blocked, timeout, and TLS-validation failures so constrained scans return an explicit `U` posture result instead of crashing or overclaiming confidence.
- Added passive training or challenge-surface narrative detection so lab-style targets are called out in executive summaries without polluting posture scoring.
- Added `Client code signals` to summarize framework, vendor, API/config, and version-hint intelligence from visible client-side assets.

### Changed
- Recalibrated posture scoring again so weak public targets spread more honestly across grades, with stronger penalties for missing browser-layer controls and breadth-of-weakness across categories.
- Tightened executive summary wording so browser hardening, transport/access limits, and constrained reads drive the main visible risk more consistently.
- Cleaned certificate-transparency fallback messaging so unreadable public-source responses produce calm narrative output instead of raw parser errors.
- Improved exposure and API probe handling so repeated server-side errors on sensitive or API-style paths are surfaced as review-worthy signals.
- Hardened the server boundary by making `/api/analyze` `GET`-only, returning minimal `/api/health` output in production, and degrading distributed rate limiting into a safer local fallback.
- Expanded deterministic coverage for scoring, CT fallback, and server hardening behavior.

## [0.7.0] - 2026-04-25

### Added
- Added the short `epi` CLI binary alias alongside `external-posture-insight`.
- Added lightweight interactive multi-target CLI progress on stderr while keeping stdout report output pipe-friendly.
- Added structured SPF and DMARC policy evaluation to `DomainSecurityInfo`, including SPF all-mechanism strength, DNS lookup-mechanism count, DMARC enforcement policy, rollout percentage, and reporting presence.
- Added `analyzeInfrastructure()` for passive cloud/CDN/edge/hosting inference from DNS, reverse DNS, headers, and detected technology evidence.
- Added `InfrastructureInfo` and related provider signal types to the public result model.
- Added deterministic core test coverage for infrastructure provider inference.
- Added quiet scan mode via `analyzeUrl(target, { scanMode: "quiet" })` and CLI `--quiet`.

### Changed
- Treat HTTP 5xx target responses as limited availability reads and cap their posture grade below `C` so unavailable pages do not look like normal mixed posture results.
- Recalibrated `analyzeUrl()` scoring around weighted posture areas so the overall grade reflects domain/trust, exposure, API, third-party, and AI posture alongside core hardening controls.
- Added bounded concurrency for CT host sampling, OSV vulnerability detail lookups, and related-page crawl checks.
- Lazy-loaded Cheerio inside HTML analysis so importing the package is fast for CLI/help and workflows that do not parse page HTML.
- Clarified README safety wording, CLI quick-start examples, and package usage boundaries for public launch.

## [0.6.1] - 2026-04-19

### Changed
- Refreshed direct and transitive dependencies via Dependabot group update, including `react-router-dom` and multiple security-relevant parser/glob stack updates (`js-yaml`, `picomatch`, `brace-expansion`, `minimatch`, `glob`, `flatted`).
- Verified package build and test flows continue to pass after lockfile refresh.

## [0.6.0] - 2026-04-16

### Added
- CLI policy gating with `--fail-on info|warning|critical` for CI exit-code control.
- CLI regression policy mode with `--fail-on-regression` for baseline/compare workflows.
- Compact `ci-json` CLI output for scan/compare automation pipelines.
- CLI score-threshold gating with `--fail-if-score-below <0-100>`.
- Richer batch scan summaries in summary/Markdown output with aggregate score and strongest/weakest targets.

### Changed
- Updated Vite toolchain compatibility to keep installs stable with current plugin peer dependencies.
- Hardened TLS certificate issuer/subject normalization for stricter TypeScript handling.
- Expanded CLI tests and help-surface assertions for policy mode usage.

## [0.5.0] - 2026-04-16

### Added
- CLI batch scanning via `scan <target...>` with summary, Markdown table, and JSON output support.
- CLI report-to-report comparison via `compare <current-report.json> <baseline-report.json>`.
- CLI SARIF output for both scans and comparisons, including compare mode output focused on newly introduced findings.
- Core CLI test coverage for comparison workflows, JSON/SARIF output, malformed baseline handling, and invalid baseline usage in multi-target scans.

### Changed
- Expanded CLI help and package README examples/documentation to cover batch scans, direct comparisons, and SARIF output.
- Improved CLI argument parsing to support command-oriented workflows while keeping baseline comparisons scoped to single-target scans.

## [0.4.0] - 2026-04-09

### Added
- Passive library risk detection from explicitly versioned script URLs with OSV-backed advisory lookups.
- Score trending in the monitoring UI and a shared history-diff model exported from the core package.
- CLI baseline comparison support via `--baseline <report.json>`.
- Passive DNSSEC posture and certificate-transparency takeover clues from sampled CNAME evidence.

### Changed
- Hardened scan dispatch with stricter public-target revalidation on outbound requests.
- Added explicit timeout handling around OIDC discovery and improved hosted-mode server boundary controls.
- Versioned browser-local monitoring storage and surfaced clearer target-cap feedback in the app.
- Unified app and package diff logic so monitoring and CLI comparisons use the same change model.

## [0.3.0] - 2026-04-08

### Added
- A first-class CLI entrypoint with `scan`, summary/JSON/Markdown output, and file output support.
- Richer monitoring diffs covering certificate windows, third-party providers, AI vendors, identity-provider changes, WAF changes, and CT priority-host changes.
- WAF and edge fingerprinting with passive provider inference.
- Certificate Transparency coverage rollups with prioritized and sampled hosts.

### Changed
- Deepened passive identity discovery with stronger OAuth/OIDC heuristics and less eager same-origin redirect attribution.
- Improved passive-signal messaging and UI consistency for identity, CT, third-party trust, and disclosure/domain trust panels.
- Consolidated duplicated core helpers and documented scanner limits in shared config.

## [0.2.0] - 2026-04-07

### Added
- Passive Identity Provider and OAuth discovery, including public OpenID configuration checks.
- Certificate Transparency discovery with bounded, best-effort lookup behavior.
- Staged strict TypeScript verification for extracted core modules.
- Dependabot configuration and npm publish provenance support for release hygiene.

### Changed
- Replaced regex-driven HTML parsing with a Cheerio-based DOM inspection path.
- Extracted CT, identity, HTML insight, and surface-enrichment logic out of the core scanner monolith.
- Hardened the local server boundary with request validation, basic rate limiting, and safer API error responses.
- Added package `engines` metadata and simplified the repo to a single npm lockfile story.

## [0.1.0] - 2026-04-05

### Added
- Initial extracted scanner core package.
- Passive HTML/client exposure analysis.
- AI surface, third-party trust, DNS/mail posture, exposure, and API-surface analysis.
- OWASP/MITRE-aligned finding labeling.
- Regression fixtures for known false positives.
