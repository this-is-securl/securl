# @ktbatterham/external-posture-core

[![npm version](https://img.shields.io/npm/v/%40ktbatterham%2Fexternal-posture-core)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![npm package](https://img.shields.io/badge/npm-package-red)](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Core package checks](https://github.com/ktbatterham/external-posture-insight/actions/workflows/core-package-checks.yml/badge.svg)](https://github.com/ktbatterham/external-posture-insight/actions/workflows/core-package-checks.yml)

**The passive security posture engine behind SecURL.**

`@ktbatterham/external-posture-core` is the reusable scanner engine behind [SecURL](https://securl.online), a posture-first external security review tool for public web targets.

It is designed for passive, low-noise assessment rather than active exploitation or broad reconnaissance. The engine turns public web signals into structured JSON, Markdown, SARIF, and CI-friendly output.

<p>
  <a href="https://securl.online"><strong>Visit the SecURL site</strong></a>
  ·
  <a href="https://app.securl.online"><strong>Try the live scanner</strong></a>
  ·
  <a href="https://github.com/ktbatterham/external-posture-insight"><strong>View the source</strong></a>
</p>

## Quick Start

Run a scan without installing:

```bash
npx @ktbatterham/external-posture-core scan example.com
```

Install globally for the short `epi` command:

```bash
npm install -g @ktbatterham/external-posture-core
epi scan example.com
```

Prefer the hosted report workspace? Use [app.securl.online](https://app.securl.online).

## Package trust and release signals

- public source repository with package code under `packages/core`
- npm publishing from GitHub Actions with provenance enabled
- CI checks covering audit, build, lint, tests, and dry-run packaging
- no install scripts
- one runtime dependency (`cheerio`)
- published MIT license, changelog, release notes, and security policy

Security disclosure guidance:

- [`packages/core/SECURITY.md`](./SECURITY.md)
- [`/SECURITY.md`](../../SECURITY.md)

## Safety model

External Posture Insight is passive-first and production-conscious, but it is not magic invisibility dust. A standard scan may make DNS queries, perform TLS handshakes, fetch the target page, follow redirects, query third-party public datasets such as Certificate Transparency / OSV, and run a small set of low-noise HTTP checks. It does not attempt exploitation, brute forcing, authentication bypass, form submission, fuzzing, password testing, or vulnerability exploitation.

Use it only against systems you own or are authorized to assess. Results are heuristic and should be treated as decision support, not a formal penetration test or compliance attestation.

## What it covers

- HTTP security headers and redirect posture
- TLS and certificate inspection
- Cookie hygiene
- Passive HTML inspection
- AI surface and third-party trust signals
- Low-noise exposure, CORS, API-surface, and DNS/mail posture checks
- OWASP/MITRE-aligned finding labels

## Current status

This package is published and consumable from npm:

- [`@ktbatterham/external-posture-core`](https://www.npmjs.com/package/@ktbatterham/external-posture-core)
- Product site: [securl.online](https://securl.online)
- Live scanner: [app.securl.online](https://app.securl.online)

It is also used by the External Posture Insight app from the local workspace during development.

## Release workflow

- local package check: `npm run pack:core`
- CI verification: `.github/workflows/core-package-checks.yml`
- publish workflow: `.github/workflows/publish-core-package.yml`
- publish requires an `NPM_TOKEN` repository secret
- publish uses npm provenance (`npm publish --provenance`)

Recommended release flow:

1. update the version in `packages/core/package.json`
2. run `npm run test:core`
3. run `npm run pack:core`
4. create and push a tag like `core-v0.1.1`
5. let the publish workflow release the package

See also:

- `packages/core/CHANGELOG.md`
- `packages/core/RELEASING.md`

## Public API

## CLI

The package includes a pipe-friendly CLI:

Scan multiple targets in one run:

```bash
npx @ktbatterham/external-posture-core scan example.com github.com bbc.co.uk
epi scan example.com github.com bbc.co.uk
```

Available output formats:

```bash
npx @ktbatterham/external-posture-core scan example.com --format summary
npx @ktbatterham/external-posture-core scan example.com --format json
npx @ktbatterham/external-posture-core scan example.com --format markdown
npx @ktbatterham/external-posture-core scan example.com --format sarif
npx @ktbatterham/external-posture-core scan example.com --format ci-json
```

The CLI writes machine-readable report output to stdout, and lightweight multi-target progress to stderr only when running interactively. This keeps JSON/SARIF output pipe-friendly.

CI policy modes:

```bash
npx @ktbatterham/external-posture-core scan example.com github.com --fail-on warning
npx @ktbatterham/external-posture-core scan example.com --baseline previous-report.json --fail-on-regression
npx @ktbatterham/external-posture-core scan example.com github.com --fail-if-score-below 75
npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json --fail-on critical --fail-on-regression
```

- `--fail-on` sets exit code `1` when findings at or above the selected severity are present.
- `--fail-on-regression` sets exit code `1` when the baseline comparison detects a regression (score drop, new issues, or worse HTTP status class).
- `--fail-if-score-below` sets exit code `1` when any scanned target score is below the given threshold.

Write results to a file:

```bash
npx @ktbatterham/external-posture-core scan example.com --format json --output report.json
```

Compare against a previously saved JSON report:

```bash
npx @ktbatterham/external-posture-core scan example.com --baseline previous-report.json
```

Compare two saved reports directly:

```bash
npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json
npx @ktbatterham/external-posture-core compare current-report.json baseline-report.json --format sarif
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
npx @ktbatterham/external-posture-core --help
```

### `analyzeUrl(url)`

Run a full posture analysis for a public target.

```js
import { analyzeUrl } from "@ktbatterham/external-posture-core";

const result = await analyzeUrl("https://example.com");
console.log(result.score, result.grade);
```

`analyzeTarget` remains available as a compatibility alias, but `analyzeUrl` is the primary public entrypoint.

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
import { analyzeHtmlDocument } from "@ktbatterham/external-posture-core";

const htmlSecurity = analyzeHtmlDocument("https://example.com", "<html>...</html>");
console.log(htmlSecurity.clientExposureSignals);
```

## Notes

- Only use this against targets you are authorized to assess.
- The package is intentionally conservative about active probing.
- Scoring is heuristic and should be treated as a prioritization aid, not an absolute security truth.
- The author is not responsible for misuse, unauthorized scanning, operational impact, or decisions made from the output without appropriate validation.
