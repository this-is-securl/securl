# securl

[![npm version](https://img.shields.io/npm/v/securl)](https://www.npmjs.com/package/securl)
[![npm package](https://img.shields.io/badge/npm-package-red)](https://www.npmjs.com/package/securl)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![SecURL package checks](https://github.com/this-is-securl/securl/actions/workflows/core-package-checks.yml/badge.svg)](https://github.com/this-is-securl/securl/actions/workflows/core-package-checks.yml)

**The passive URL security posture engine behind SecURL.**

`securl` is the reusable scanner engine behind [SecURL](https://securl.online), a passive external security posture scanner for public URLs and web services.

It is designed for passive, low-noise assessment rather than active exploitation or broad reconnaissance. The engine turns public web signals into structured JSON, Markdown, SARIF, and CI-friendly output.

It is not a URL shortener. It assesses the external security posture of URLs you choose to scan.

Use it when you need a fast outside-in read on a public web service:

- run a security posture smoke check in CI before release
- generate JSON or SARIF evidence for internal review
- compare the current posture against a saved baseline
- classify monitoring changes into risk events for alerts or dashboards
- enrich vendor, supplier, or customer domain reviews without credentials or agents

<p>
  <a href="https://securl.online"><strong>Visit the SecURL site</strong></a>
  ·
  <a href="https://app.securl.online"><strong>Try the live scanner</strong></a>
  ·
  <a href="https://apps.apple.com/app/securl/id6774322464"><strong>Get the iOS app</strong></a>
  ·
  <a href="https://github.com/this-is-securl/securl"><strong>View the source</strong></a>
</p>

## Quick Start

Run a scan without installing:

```bash
npx securl scan example.com
```

Install globally for the `securl` command:

```bash
npm install -g securl
securl scan example.com
```

Prefer the hosted report workspace? Use [app.securl.online](https://app.securl.online). For the product overview, start at [securl.online](https://securl.online). Prefer mobile? Install [SecURL on the App Store](https://apps.apple.com/app/securl/id6774322464).

## Common use cases

### 1. Quick CLI posture check

```bash
npx securl scan https://example.com --format summary
```

Example summary output:

```text
example.com  A  93/100  2 findings
```

### 2. CI gate for public-facing deployments

Fail the job when a target drops below a minimum score or introduces warning-level findings:

```bash
npx securl scan https://example.com \
  --quiet \
  --format ci-json \
  --fail-if-score-below 75 \
  --fail-on warning
```

Compare a new scan with a saved baseline:

```bash
npx securl scan https://example.com \
  --baseline ./security-baseline.json \
  --fail-on-regression
```

### 3. Node.js SDK scan

```js
import { analyzeUrl } from "securl";

const result = await analyzeUrl("https://example.com", {
  scanMode: "quiet",
});

console.log({
  score: result.score,
  grade: result.grade,
  mainRisk: result.executiveSummary.mainRisk,
  findings: result.issues.map((issue) => ({
    severity: issue.severity,
    title: issue.title,
  })),
});
```

### 4. Monitoring and risk-event classification

Version `1.1.0+` includes helpers for turning two scan snapshots into alert-friendly posture events.

```js
import {
  buildHistoryDiffFromSnapshots,
  snapshotFromAnalysis,
} from "securl/history-diff";
import {
  buildPostureRiskEventsFromSnapshots,
} from "securl/risk-events";

const currentSnapshot = snapshotFromAnalysis(currentReport);
const previousSnapshot = snapshotFromAnalysis(previousReport);
const diff = buildHistoryDiffFromSnapshots(currentSnapshot, previousSnapshot);
const riskEvents = buildPostureRiskEventsFromSnapshots(
  currentSnapshot,
  previousSnapshot,
  diff,
);

console.log(riskEvents);
```

Risk events include score regressions, grade drops, new critical findings, certificates nearing expiry, security header regressions, WAF signal removals, new CT priority hosts, identity-provider changes, and new third-party or AI vendors.

Version `1.3.0+` also includes a higher-level posture drift report for monitoring and alerting surfaces that need one stable payload with the diff, risk events, changed areas, severity counts, and an overall direction.

```js
import {
  buildPostureDriftReportFromSnapshots,
} from "securl/posture-drift";

const drift = buildPostureDriftReportFromSnapshots(
  currentSnapshot,
  previousSnapshot,
);

console.log(drift.summary.direction, drift.summary.changedAreas);
```

Version `1.18.0+` adds monitoring event intelligence for backend schedulers, mobile push notifications, and history timelines. It turns posture drift or lightweight certificate checks into compact event objects with severity, changed evidence, next action, and push-safe copy.

```ts
import {
  buildCertificateMonitoringEvents,
  buildMonitoringEventsFromSnapshots,
} from "securl/monitoring-events";

const events = buildMonitoringEventsFromSnapshots(currentSnapshot, previousSnapshot);
const certEvents = buildCertificateMonitoringEvents(currentCertificate, previousCertificate);

console.log(events[0]?.push, certEvents[0]?.nextAction);
```

Certificate monitoring events can fire on the first observation when a certificate is already invalid or expiring; they do not require a prior transition.

Runnable examples are included in [`examples/`](./examples):

```bash
node examples/scan-url.mjs https://example.com
node examples/risk-events.mjs current-report.json previous-report.json
```

### 5. Compact posture digest for APIs and mobile clients

Version `1.2.0+` includes a digest helper for turning a full scan result into a smaller, stable summary payload.

```js
import { analyzeUrl } from "securl";
import { buildPostureDigest } from "securl/posture-digest";

const result = await analyzeUrl("https://example.com", {
  scanMode: "quiet",
});

const digest = buildPostureDigest(result);

console.log({
  grade: digest.posture.grade,
  score: digest.posture.score,
  headline: digest.signalClarity.headline,
  topFindings: digest.findings.top,
  topFixes: digest.remediationPlan?.topActions,
  riskIndicators: digest.intelligence.riskIndicators,
});
```

### 6. Prioritized action plans

Version `1.8.0+` includes an action-plan helper for client surfaces that need to show what to fix first without reinterpreting the full scan result.

```ts
import { analyzeUrl, buildActionPlan } from "securl";

const result = await analyzeUrl("https://example.com");
const actionPlan = buildActionPlan(result);

console.log({
  grade: actionPlan.posture.grade,
  mainRisk: actionPlan.posture.mainRisk,
  highImpactActions: actionPlan.highImpactActions,
  firstAction: actionPlan.items[0],
});
```

Action-plan items include owner, effort, impact, confidence, score impact where available, evidence references, and verification guidance.

### 7. Posture insights

Version `1.12.0+` includes a posture-insights helper for client surfaces that need display-ready risk themes and next-best actions.

```ts
import { analyzeUrl } from "securl";
import { buildPostureInsights } from "securl/posture-insights";

const result = await analyzeUrl("https://example.com");
const insights = buildPostureInsights(result);

console.log({
  summary: insights.summary,
  themes: insights.themes,
  topInsights: insights.topInsights,
  nextBestActions: insights.nextBestActions,
});
```

Posture insights are derived from the action plan, so clients can render security judgement without reinterpreting raw findings, score drivers, exposure details, or vendor context.

### 8. Signal clarity summary

Version `1.13.1+` includes a signal-clarity helper for clients that need a one-screen explanation of the grade, confidence, top score drivers, caveats, and next best action.

```ts
import { analyzeUrl } from "securl";
import { buildSignalClaritySummary } from "securl/signal-clarity";

const result = await analyzeUrl("https://example.com");
const clarity = buildSignalClaritySummary(result);

console.log({
  headline: clarity.headline,
  verdict: clarity.verdict,
  confidence: clarity.confidence,
  biggestDrivers: clarity.score.topNegativeDrivers,
  nextBestAction: clarity.nextBestAction,
});
```

Signal clarity is derived from the evidence quality summary, score drivers, and action plan. It is designed for mobile cards, API summaries, CLI reports, and future SaaS dashboards that need to explain "why this grade?" without loading or interpreting the full result.

### 9. Live certificate checks

Version `1.9.0+` includes a lightweight certificate helper for Cert Watch-style clients that only need the currently served TLS certificate.

```ts
import { scanLiveCertificate } from "securl/live-certificate";

const certificate = await scanLiveCertificate(new URL("https://example.com"));

console.log({
  issuer: certificate.issuer,
  daysRemaining: certificate.daysRemaining,
  protocol: certificate.protocol,
  chainLength: certificate.chain.length,
});
```

Version `1.16.0+` exposes the same TLS handshake-only workflow through the CLI:

```bash
npx securl cert example.com
npx securl cert example.com --format json
npx securl cert example.com --format markdown --output certificate.md
```

Use this when you only need the served certificate's expiry, issuer, subject alternative names, negotiated TLS details, key hints, and chain summary without running a full posture scan.

Version `1.17.0+` adds certificate policy gates for CI and release checks:

```bash
npx securl cert example.com --fail-if-invalid
npx securl cert example.com --fail-if-expiring-within 21 --format ci-json
npx securl cert example.com --fail-if-legacy-tls
npx securl cert example.com --expect-issuer "Let's Encrypt"
```

Certificate policy gates set exit code `1` when the selected condition fails. Use `--format ci-json` when you want a compact machine-readable certificate summary plus policy result.

### 10. Machine-readable observation ledger

Version `1.10.0+` adds stable posture observations for monitoring, inventory, policy, and future SaaS integrations. Each observation records what was seen, whether it was observed, inferred, missing, or unavailable, its confidence and source, and when that evidence should be refreshed.

```ts
import { analyzeUrl } from "securl";
import { buildObservationLedger } from "securl/observations";

const result = await analyzeUrl("https://example.com");
const ledger = result.observationLedger ?? buildObservationLedger(result);

console.log(ledger.summary, ledger.observations);
```

Observation IDs are deterministic across scans for the same subject and signal, making the ledger suitable for change detection without exposing backend job metadata.

Version `1.11.0+` adds `diffObservationLedgers(current, previous)` from `securl/observation-drift` to classify observation-level regressions, improvements, and neutral changes.

Use `evaluateObservationPolicy({ ledger, drift, policy })` from `securl/observation-policy` to apply bounded declarative rules. Rules can select an exact observation kind, kind prefix, or category, then assert equality, membership, or numeric thresholds against current observations or changes. `DEFAULT_OBSERVATION_POLICY` provides a maintained baseline for certificate validity/window, HSTS, CSP, DMARC, and critical regressions.

### 11. Evidence-backed remediation plans

Version `1.4.0+` includes a remediation plan helper that turns score drivers and findings into prioritized, owner-aware fix guidance. Findings can also carry structured evidence references so clients can show why a finding was raised.

```js
import {
  attachIssueEvidence,
  buildPostureRemediationPlan,
} from "securl/remediation-plan";

const resultWithEvidence = attachIssueEvidence(result);
const remediationPlan = buildPostureRemediationPlan(resultWithEvidence);

console.log(remediationPlan.items.map((item) => ({
  title: item.title,
  owner: item.owner,
  impact: item.impact,
  action: item.action,
})));
```

Version `1.5.0+` includes a compact evidence summary for API, mobile, and report clients that need to explain why a scan scored the way it did without walking the full result object.

```js
import { buildPostureEvidenceSummary } from "securl/evidence-summary";

const evidenceSummary = buildPostureEvidenceSummary(resultWithEvidence);

console.log({
  total: evidenceSummary.totalEvidenceReferences,
  observed: evidenceSummary.observedCount,
  topEvidence: evidenceSummary.topEvidence,
});
```

Version `1.13.0+` includes an evidence-quality helper for client surfaces that need to explain how much confidence to place in a scan result.

```js
import { buildEvidenceQualitySummary } from "securl/evidence-quality";

const quality = buildEvidenceQualitySummary(resultWithEvidence);

console.log({
  level: quality.level,
  score: quality.score,
  gaps: quality.gaps,
  followUp: quality.recommendedFollowUp,
});
```

Evidence quality is also included in `buildPostureDigest()` output, so mobile and API clients can display scan confidence without loading the full result.

## Package trust and release signals

- public source repository with package code under `packages/core`
- npm publishing from GitHub Actions with provenance enabled
- CI checks covering audit, build, lint, tests, and dry-run packaging
- no install scripts
- one runtime dependency (`node-html-parser`)
- published MIT license, changelog, release notes, and security policy
- explicit bounded network access through the scanner transport for target reads and public enrichment APIs such as Certificate Transparency and OSV

Security disclosure guidance:

- [`packages/core/SECURITY.md`](./SECURITY.md)
- [`/SECURITY.md`](../../SECURITY.md)

## Safety model

SecURL is passive-first and production-conscious, but it is not magic invisibility dust. A standard scan may make DNS queries, perform TLS handshakes, fetch the target page, follow redirects, query third-party public datasets such as Certificate Transparency / OSV, and run a small set of low-noise HTTP checks. It does not attempt exploitation, brute forcing, authentication bypass, form submission, fuzzing, password testing, or vulnerability exploitation.

Use it only against systems you own or are authorized to assess. Results are heuristic and should be treated as decision support, not a formal penetration test or compliance attestation.

## What it covers

- HTTP security headers and redirect posture
- TLS and certificate inspection
- Cookie hygiene
- Passive HTML inspection
- Passive public IOC and abuse indicators for suspicious scripts, off-origin credential flows, exposed paths, CT takeover clues, and visible vulnerable client libraries
- AI surface and third-party trust signals
- Low-noise exposure, CORS, API-surface, and DNS/mail posture checks
- OWASP/MITRE-aligned finding labels

## Current status

This package is published and consumable from npm:

- [`securl`](https://www.npmjs.com/package/securl)
- Product site: [securl.online](https://securl.online)
- Live scanner: [app.securl.online](https://app.securl.online)
- iOS app: [SecURL on the App Store](https://apps.apple.com/app/securl/id6774322464)

It is also used by the SecURL app from the local workspace during development.

## Release workflow

- local package check: `npm run pack:core`
- CI verification: `.github/workflows/core-package-checks.yml`
- publish workflow: `.github/workflows/publish-core-package.yml`
- publish uses npm Trusted Publishing through GitHub Actions OIDC
- publish uses npm provenance (`npm publish --provenance`)

Recommended release flow:

1. update the version in `packages/core/package.json`
2. run `npm run test:core`
3. run `npm run pack:core`
4. create and push a tag like `securl-v1.4.1`
5. let the publish workflow release the package

See also:

- `packages/core/CHANGELOG.md`
- `packages/core/RELEASING.md`

## Public API

Primary exports:

- `analyzeUrl(url, options)` - scan a public target and return a structured posture result.
- `analyzeTarget(url, options)` - compatibility alias for `analyzeUrl`.
- `analyzeHtmlDocument(url, html)` - run passive HTML/content analysis against already-fetched markup.
- `snapshotFromAnalysis(result)` - reduce a scan result to a comparison snapshot.
- `buildHistoryDiffFromSnapshots(current, previous)` - build a structured diff between scans.
- `buildPostureRiskEventsFromSnapshots(current, previous, diff)` - classify scan changes into alert-friendly risk events.
- `buildMonitoringEventsFromSnapshots(current, previous, diff?)` - turn posture drift into push/API/CI-friendly monitoring event payloads.
- `buildCertificateMonitoringEvents(current, previous?)` - turn live certificate observations into monitoring event payloads, including first-seen expiry and invalid-certificate alerts.
- `buildPostureDigest(result)` - reduce a full scan result to a compact API/mobile-friendly digest.
- `buildActionPlan(result)` - turn remediation, score drivers, exposure, and vendor context into prioritized fix actions.
- `buildPostureInsights(result)` - summarize risk themes, top insights, and next-best actions for client surfaces.
- `buildSignalClaritySummary(result)` - explain the grade, confidence, top score drivers, caveats, and next best action in a compact client-ready payload.
- `scanLiveCertificate(url)` - perform a TLS handshake-only certificate read for lightweight cert monitoring.
- `buildObservationLedger(result)` - produce stable source, confidence, status, and freshness-aware posture observations.
- `diffObservationLedgers(current, previous)` - compare stable observations and classify their operational impact.
- `evaluateObservationPolicy({ ledger, drift, policy })` - evaluate bounded declarative posture and change rules.
- `buildPostureDriftReportFromSnapshots(current, previous)` - produce a complete scan-to-scan drift report for monitoring, alerting, and history views.
- `buildPostureRemediationPlan(result)` - generate prioritized, owner-aware remediation actions from findings and score drivers.
- `attachIssueEvidence(result)` - add structured evidence references to findings without changing their existing fields.
- `buildPostureEvidenceSummary(result)` - produce compact evidence metadata for API, mobile, report, and explainability surfaces.
- `buildEvidenceQualitySummary(result)` - summarize scan confidence, collection gaps, and recommended follow-up.

Package subpath exports:

- `securl/history-diff`
- `securl/posture-digest`
- `securl/action-plan`
- `securl/posture-insights`
- `securl/signal-clarity`
- `securl/live-certificate`
- `securl/monitoring-events`
- `securl/observations`
- `securl/observation-drift`
- `securl/observation-policy`
- `securl/posture-drift`
- `securl/remediation-plan`
- `securl/evidence-quality`
- `securl/risk-events`
- `securl/types`

## CLI

The package includes a pipe-friendly CLI:

Scan multiple targets in one run:

```bash
npx securl scan example.com github.com bbc.co.uk
securl scan example.com github.com bbc.co.uk
```

Available output formats:

```bash
npx securl scan example.com --format summary
npx securl scan example.com --format json
npx securl scan example.com --format markdown
npx securl scan example.com --format sarif
npx securl scan example.com --format ci-json
```

Fast certificate checks:

```bash
npx securl cert example.com
npx securl cert example.com --format json
npx securl cert example.com --format ci-json --fail-if-invalid
npx securl cert example.com --fail-if-expiring-within 21 --expect-issuer "Let's Encrypt"
npx securl cert example.com --format markdown --output certificate.md
```

`securl cert` performs a bounded TLS handshake only. It is useful for Cert Watch-style automation, release checks, and lightweight inventory tasks where a full posture scan would be unnecessary.

The CLI writes machine-readable report output to stdout, and lightweight multi-target progress to stderr only when running interactively. This keeps JSON/SARIF output pipe-friendly.

Scan modes:

```bash
npx securl scan example.com
npx securl scan example.com --quiet
npx securl scan example.com --deep-passive
```

- default scan: primary response plus bounded passive enrichment, including HTML, DNS/mail, Certificate Transparency, OSV, exposure, CORS, API-surface, and public trust signals.
- `--quiet`: keeps primary response, TLS, headers, cookies, redirects, DNS/mail, Certificate Transparency summary, infrastructure, and public trust checks; skips page-body analysis, related-page crawl, security.txt fetch, identity discovery, exposure probes, CORS probes, API probes, OSV lookups, and CT host sampling. Use this for lower-noise CI smoke checks or frequent regression monitoring.
- `--deep-passive`: expands passive CT host sampling, related-page crawl, exposure probes, and API-surface probes while keeping request counts and scan duration bounded. Use this for pre-release or scheduled posture reviews where a broader passive pass is worth the extra time.

CI policy modes:

```bash
npx securl scan example.com github.com --fail-on warning
npx securl scan example.com --baseline previous-report.json --fail-on-regression
npx securl scan example.com github.com --fail-if-score-below 75
npx securl compare current-report.json baseline-report.json --fail-on critical --fail-on-regression
```

- `--fail-on` sets exit code `1` when findings at or above the selected severity are present.
- `--fail-on-regression` sets exit code `1` when the baseline comparison detects a regression (score drop, new issues, or worse HTTP status class).
- `--fail-if-score-below` sets exit code `1` when any scanned target score is below the given threshold.
- `--fail-if-invalid` sets exit code `1` for certificate checks when the served certificate is unavailable, invalid, or unauthorized.
- `--fail-if-expiring-within` sets exit code `1` for certificate checks when the served certificate expires within the selected number of days.
- `--fail-if-legacy-tls` sets exit code `1` for certificate checks when TLS 1.0 or TLS 1.1 is negotiated.
- `--expect-issuer` sets exit code `1` for certificate checks when the observed issuer does not contain the expected text.

Write results to a file:

```bash
npx securl scan example.com --format json --output report.json
```

Compare against a previously saved JSON report:

```bash
npx securl scan example.com --baseline previous-report.json
```

Compare two saved reports directly:

```bash
npx securl compare current-report.json baseline-report.json
npx securl compare current-report.json baseline-report.json --format sarif
```

Batch scans return:

- summary: one line per target
- markdown: a compact comparison table
- sarif: one SARIF log containing findings across all scanned targets
- ci-json: compact machine-readable output with policy pass/fail status
- json:

```json
{
  "analyses": [{ "...": "scan result" }]
}
```

Direct report comparison returns:

- summary: score, status, and change summary
- markdown: a compact comparison report
- sarif: only findings that are newly introduced in the current report versus the baseline
- ci-json: compact machine-readable output with policy pass/fail status and diff details
- json:

```json
{
  "current": { "...": "latest saved report" },
  "baseline": { "...": "older saved report" },
  "diff": { "...": "structured change summary" }
}
```

Show usage:

```bash
npx securl --help
```

### `analyzeUrl(url)`

Run a full posture analysis for a public target.

```js
import { analyzeUrl } from "securl";

const result = await analyzeUrl("https://example.com");
console.log(result.score, result.grade);
```

`analyzeTarget` remains available as a compatibility alias, but `analyzeUrl` is the primary public entrypoint.

`analyzeUrl("https://example.com", { scanMode: "quiet" })` uses the same quiet boundary as CLI `--quiet`. `analyzeUrl("https://example.com", { scanMode: "deep-passive" })` uses the expanded passive recon boundary as CLI `--deep-passive`.

When a baseline report is supplied to the CLI, summary and Markdown output append a `Changes Since Baseline` section. JSON output returns:

```json
{
  "analysis": { "...": "latest scan result" },
  "diff": { "...": "structured change summary" }
}
```

### `analyzeHtmlDocument(url, html)`

Run passive HTML/content analysis against a fetched HTML document.

```js
import { analyzeHtmlDocument } from "securl";

const htmlSecurity = analyzeHtmlDocument("https://example.com", "<html>...</html>");
console.log(htmlSecurity.clientExposureSignals);
```

## Notes

- Only use this against targets you are authorized to assess.
- The package is intentionally conservative about active probing.
- Default scans perform bounded passive enrichment; quiet scans skip page-body and probe-heavy enrichment to keep request volume lower.
- Scoring is heuristic and should be treated as a prioritization aid, not an absolute security truth.
- The author is not responsible for misuse, unauthorized scanning, operational impact, or decisions made from the output without appropriate validation.
