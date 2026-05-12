# Release Notes — app 0.9.0 / core 0.8.1

## Highlights

- **Premium SVG ring gauge** replaces the flat score badge throughout the report workspace and scan-input page. The ring fills to the exact score percentage with a grade-coloured stroke (green A/A+, blue B, amber C, orange D, red F, slate U) and a restrained radial glow — data-forward, not decorative.
- **Stronger typography hierarchy** — section eyebrows, stat-tile numerals, card titles, and category bars have all been tuned for clearer visual weight and breathing room.
- **Cleaner PDF export** — inconsistent footer text removed; Section 06 (Technical Details) now stacks its cards in a single column instead of an awkward two-column grid.
- Recalibrated the overall security grade so it reflects weighted posture areas, not just the older header/TLS/cookie hardening baseline.
- Added passive infrastructure inference for likely cloud, CDN, edge, PaaS, and hosting providers.
- Reduced scan burstiness with bounded concurrency across CT sampling, crawl checks, and OSV detail lookups.
- Added quiet scan mode for lower-noise CLI/API use cases where page-content enrichment is not required.
- Improved report clarity by making neutral-positive states read as strengths and reserving watch language for actionable items.
- Tightened monitoring UX with clearer trend behavior when only one saved snapshot exists.
- Expanded app-level test coverage with unit tests for posture scoring and priority-action ranking logic.
- Completed dependency maintenance and PR backlog cleanup for current `main`.

## What Changed

### Report workspace UI (app 0.9.0)

- Replaced flat score badge with a 168 px SVG ring gauge using `stroke-dashoffset` fill and per-grade colour tokens (`GRADE_PALETTE`). Applies to both `OverviewSection` (workspace) and `SecurityGrade` (scan-input card).
- Grade letter renders at `text-6xl font-bold` (single-char) or `text-5xl` (two-char, e.g. A+); score at `text-sm font-medium text-slate-400`.
- Section eyebrows standardised at `text-[11px] tracking-[0.18em]`; stat-tile numerals at `text-[2rem] font-bold tracking-[-0.04em]`; card titles at `text-xl font-semibold tracking-[-0.02em]`.
- Category bar height reduced from `h-2` → `h-1.5` for a lighter read.
- Card padding and row gap increased throughout `OverviewSection` for better breathing room.
- `SecurityGrade` card border now uses grade-specific `borderColor` token from `GRADE_PALETTE`.

### PDF report export

- Removed per-page footer text that appeared inconsistently across pages.
- Section 06 (Technical Details) changed from `.two-col` grid to `.stacked-cards` single-column layout; sections 05, 07, 08 retain two-column.

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

- `npm run build` — clean
- `npm run test:core` — passing
- `npm run test:app:unit` — 39/39 passing
- `npm run test:server` — passing
- Live UX sign-off at app.securl.online (1280 / 1024 / 768 / 390 px):
  - ek.co → D / 69 — orange ring ✅
  - bbc.co.uk → C / 77 — amber ring, category bars, export buttons ✅
  - github.com → C / 74 — clean layout ✅
  - wsj.com → U / 26 — slate ring, assessment-limited banner ✅

## Follow-ups

- If we want category deltas in export headlines later, we should extend exported artifacts to include previous snapshot area scores.
- Tailwind CSS v4 migration remains intentionally deferred as a dedicated planned migration.
