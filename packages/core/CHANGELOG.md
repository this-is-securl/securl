# Changelog

All notable changes to `@ktbatterham/external-posture-core` will be documented in this file.

The format is based on Keep a Changelog and this package follows Semantic Versioning once published.

## [Unreleased]

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
