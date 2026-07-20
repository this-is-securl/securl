# Growth experiments

SecURL is pre-revenue. Acquisition, activation, retention, referral, and eventually
monetization are product outcomes, not a separate marketing backlog. Low traffic should
trigger small reversible experiments; it limits causal certainty but does not justify
holding a funnel that is not producing users.

## Experiment 001 — one-promise hosted scanner hero

- **Owner/surface:** SecURL backend/public web; `src/` deployed to
  `app.securl.online` through the established Hostinger workflow.
- **Started:** 2026-07-20.
- **Baseline:** 64 page loads / 42 aggregate unique visitors lifetime; 0 shared-report
  views; 0 copied links; no observable npm/docs-to-first-watch conversion. The baseline
  predates the local `utm_source=sec7_local_smoke` verification visit.
- **Problem:** the first screen offered a scan form plus three competing outbound links
  and several product narratives before the user experienced value.
- **Hypothesis:** one promise (scan once, know when the site changes) and one primary CTA
  (scan my site free) will improve page-to-scan activation. Monitoring and mobile remain
  the post-result path rather than competing pre-scan choices.
- **Change:** focused hero copy and CTA, removed hero link pills, retained explicit free /
  no-sign-up / passive trust signals, aligned page metadata, and repaired cross-origin
  Safari beacon delivery with a CORS-safelisted MIME type.
- **Primary read:** genuine page loads → `scan_started` → `scan_completed`, by aggregate
  source. Secondary read: `monitoring_saved`; guardrails: scan failures, auth rejects, and
  runtime latency. Smoke, deploy, scratch, and incomplete-day traffic remain separate.
- **Review:** first directional review on 2026-07-27, with an earlier adjustment allowed
  if traffic stays flat or a clear usability failure appears. Do not require statistical
  significance for another reversible copy, hierarchy, or routing iteration.
- **Rollback:** redeploy the previous known-good Hostinger build or revert the focused PR;
  backend contracts, mobile clients, downloads, and npm consumers are unaffected.

## Experiment rules

1. One primary hypothesis and CTA per acquisition experiment.
2. Record the baseline before deployment and use privacy-safe aggregate attribution.
3. Separate real usage from smoke, deploy, scratch, and incomplete-day data.
4. Prefer cheap reversible changes; require stronger evidence for security-sensitive,
   expensive, irreversible, or contract-breaking decisions.
5. Keep a short decision log: keep, iterate, or revert, and why.

## Experiment 002 — acquisition site / product workspace split

- **Owner/surfaces:** `securl.online` remains the acquisition and education surface;
  `app.securl.online` is the scan/report/monitoring/account workspace.
- **Started:** 2026-07-20, immediately after Experiment 001.
- **Problem:** both domains repeated positioning, capabilities, engine, package, adoption,
  and mobile copy. Users arriving from the main-site scan form encountered a second
  landing page before reaching the product workspace.
- **Hypothesis:** removing repeated marketing from the app will reduce distraction and
  make the attributed main-site → scan → report → monitoring path easier to understand.
- **Change:** the app renders only the focused scan entry for new visitors. A completed
  scan or returning workspace reveals monitoring and account continuity; mobile apps are
  promoted contextually after the report. The main site's existing attributed URL handoff
  remains the acquisition bridge.
- **Why not an iframe:** separate top-level navigation preserves accessibility, responsive
  layout, SEO, browser history, deep links, owner storage, authentication, CSP boundaries,
  and unambiguous telemetry attribution.
- **Primary read:** attributed `securl_landing` handoffs and scan starts/completions.
  Secondary read: monitoring saves after completed reports. Guardrails: scan failures,
  auth rejects, report/share routing, and mobile/download links.
- **Review:** assess direction with Experiment 001 on 2026-07-27; iterate earlier if low
  traffic or visible abandonment indicates another reversible funnel change.
- **Rollback:** re-enable the legacy app landing composition and redeploy the previous
  Hostinger build. No backend, package, mobile, or download rollback is required.
