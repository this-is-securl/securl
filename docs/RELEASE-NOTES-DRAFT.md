# Release Notes Draft (Next Version)

## Highlights

- Recalibrated the overall security grade so it reflects weighted posture areas, not just the older header/TLS/cookie hardening baseline.
- Added passive infrastructure inference for likely cloud, CDN, edge, PaaS, and hosting providers.
- Reduced scan burstiness with bounded concurrency across CT sampling, crawl checks, and OSV detail lookups.
- Added quiet scan mode for lower-noise CLI/API use cases where page-content enrichment is not required.
- Improved report clarity by making neutral-positive states read as strengths and reserving watch language for actionable items.
- Tightened monitoring UX with clearer trend behavior when only one saved snapshot exists.
- Expanded app-level test coverage with unit tests for posture scoring and priority-action ranking logic.
- Completed dependency maintenance and PR backlog cleanup for current `main`.

## What Changed

### UX and report clarity

- Standardized panel copy from `Review points` to `Watch points` where applicable.
- Updated Monitoring and Posture Summary spacing/typography for better readability and consistency.
- Added explicit single-snapshot trend empty state messaging.

### Priority and scoring behavior

- Weighted the headline grade across Edge Security, Content Security, Domain & Trust, Exposure Control, API Surface, Third-Party Trust, and AI & Automation so mixed targets no longer over-cluster around `B`.
- Split Posture Summary into priority warnings, supporting watch items, and observed signals to avoid implying double-counting between normalized findings and contextual panel evidence.
- Ensured weakest posture category is always represented in Priority Actions via a fallback rule.
- Added unit tests for:
  - category scoring thresholds and clamping
  - priority action ordering and fallback behavior

### Passive infrastructure read

- Added an Infrastructure Read panel under Trust.
- Infers likely provider context from DNS, reverse DNS, response headers, and detected technology evidence without adding active cloud enumeration.
- Added core test coverage for provider inference.

### Scanner execution behavior

- Added bounded concurrency for Certificate Transparency host sampling, related-page crawl checks, and OSV vulnerability detail lookups.
- Added `--quiet` CLI mode and `mode=quiet` API support to keep scans to core transport, header, DNS, CT, HSTS preload, and infrastructure reads while skipping deeper page-content/crawl/probe enrichment.
- Lazy-loaded HTML parsing internals so CLI/help and non-HTML package imports stay fast.

### Export behavior

- Added an explicit export headline change summary for Markdown/PDF exports.
- Documented decision: per-category deltas are intentionally not included in the export headline because per-category historical baselines are not embedded in exports.

## Validation

- `npm run build`
- `npm run test:core`
- `npm run test:app:unit`
- `npm run test:server`

## Follow-ups

- If we want category deltas in export headlines later, we should extend exported artifacts to include previous snapshot area scores.
- Tailwind CSS v4 migration remains intentionally deferred as a dedicated planned migration.
